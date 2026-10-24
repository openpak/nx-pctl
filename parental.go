package main

// The parental core as pctl's backing store (NX_PCTL_BACKEND=parental; unset keeps the file
// store, which stays the default). moon.go is unchanged: the records still live in
// Store.PctlDevices, which is now loaded from the core at start, and every save -- after the
// file is written, which stays as a mirror for rollback -- also writes what changed to the
// core: PutDevice with the version last read, IngestUsage with the events the core does not
// hold, DeleteDevice for a record that left. A version conflict (an account deletion purged
// the record, or another writer changed it) re-reads that record from the core. A core that
// does not answer leaves the change in memory and in the mirror; the next save retries it.
// Design and cut-over: the parental repository, docs/design.md section 9.
//
// Nothing here logs a pairing code, a PIN or an account id: device refs and counts only.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	parentalv1 "nx-pctl/parentalpb"
)

type parentalSync struct {
	c   parentalv1.ParentalClient
	key string
	// version is what the core holds for each record, written is the digest of the blob
	// last written, sent the digests of the events the core holds.
	version map[string]uint64
	written map[string][32]byte
	sent    map[string]map[[32]byte]bool
}

func newParentalSync(c parentalv1.ParentalClient, key string) *parentalSync {
	return &parentalSync{c: c, key: key, version: map[string]uint64{}, written: map[string][32]byte{}, sent: map[string]map[[32]byte]bool{}}
}

// dialParental connects to NX_PARENTAL_ADDR with the switch adapter key (NX_PARENTAL_KEY, or
// the file NX_PARENTAL_KEY_FILE names). Insecure on purpose: the internal network is the
// boundary, as for every internal caller.
func dialParental() (*parentalSync, error) {
	addr := os.Getenv("NX_PARENTAL_ADDR")
	key := os.Getenv("NX_PARENTAL_KEY")
	if f := os.Getenv("NX_PARENTAL_KEY_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("NX_PARENTAL_KEY_FILE: %w", err)
		}
		key = strings.TrimSpace(string(b))
	}
	if addr == "" || key == "" {
		return nil, errors.New("the parental backend needs NX_PARENTAL_ADDR and NX_PARENTAL_KEY (or _FILE)")
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return newParentalSync(parentalv1.NewParentalClient(conn), key), nil
}

func (p *parentalSync) ctx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	return metadata.AppendToOutgoingContext(ctx, "x-internal-key", p.key), cancel
}

// pctlBlob is a record as the core keeps it: the record without its events, which travel as
// usage reports.
func pctlBlob(d *PctlDevice) []byte {
	c := *d
	c.Events = nil
	b, _ := json.Marshal(&c)
	return b
}

func pctlCoreDevice(hex string, d *PctlDevice, blob []byte) *parentalv1.Device {
	sup := []string{}
	for _, p := range d.Parents {
		sup = append(sup, p.AccountID)
	}
	return &parentalv1.Device{DeviceRef: hex, OwnerId: d.ManagedBy, SupervisorIds: sup, Subject: d.DauthID,
		PairingCode: d.PairingCode, PairingExpiresUnix: d.PairingExpires, PairedAtUnix: d.ActivatedAt, StateJson: blob}
}

func pctlUsage(raw json.RawMessage) *parentalv1.UsageEvent {
	kind, at := pctlEvent(raw)
	return &parentalv1.UsageEvent{PayloadJson: raw, Kind: kind, OccurredAtUnix: at}
}

func eventDigests(evs []json.RawMessage) map[[32]byte]bool {
	out := map[[32]byte]bool{}
	for _, e := range evs {
		out[sha256.Sum256(e)] = true
	}
	return out
}

// fromCore turns a core record back into pctl's, with the events the core holds.
func (p *parentalSync) fromCore(cd *parentalv1.Device) (*PctlDevice, error) {
	d := &PctlDevice{}
	if err := json.Unmarshal(cd.GetStateJson(), d); err != nil {
		return nil, fmt.Errorf("record %s: %w", cd.GetDeviceRef(), err)
	}
	if d.Hex() != cd.GetDeviceRef() {
		return nil, fmt.Errorf("record %s holds moon id %s", cd.GetDeviceRef(), d.Hex())
	}
	ctx, cancel := p.ctx()
	defer cancel()
	u, err := p.c.ListUsage(ctx, &parentalv1.ListUsageRequest{DeviceRef: cd.GetDeviceRef()})
	if err != nil {
		return nil, fmt.Errorf("record %s usage: %w", cd.GetDeviceRef(), err)
	}
	for _, e := range u.GetEvents() {
		d.Events = append(d.Events, json.RawMessage(e.GetPayloadJson()))
	}
	hex := cd.GetDeviceRef()
	p.version[hex] = cd.GetVersion()
	p.written[hex] = sha256.Sum256(pctlBlob(d))
	p.sent[hex] = eventDigests(d.Events)
	return d, nil
}

func (p *parentalSync) forget(hex string) {
	delete(p.version, hex)
	delete(p.written, hex)
	delete(p.sent, hex)
}

// loadParentalStore starts pctl on the core's records. The file at path becomes the mirror:
// the first start keeps the file as it was beside it (path.before-parental), and a core
// that holds no Switch records while the file holds some refuses to start -- that is the
// importer not having run, and starting would overwrite the file with nothing.
func loadParentalStore(path string, p *parentalSync, key *sealKey) (*Store, error) {
	devs := map[string]*PctlDevice{}
	page := ""
	for {
		ctx, cancel := p.ctx()
		resp, err := p.c.ListDevices(ctx, &parentalv1.ListDevicesRequest{PageToken: page})
		cancel()
		if err != nil {
			return nil, fmt.Errorf("parental: list: %w", err)
		}
		for _, cd := range resp.GetDevices() {
			d, err := p.fromCore(cd)
			if err != nil {
				return nil, fmt.Errorf("parental: %w", err)
			}
			devs[cd.GetDeviceRef()] = d
		}
		if page = resp.GetNextPageToken(); page == "" {
			break
		}
	}
	local := &Store{path: path}
	if b, err := os.ReadFile(path); err == nil {
		plain, err := openFile(key, b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if err := json.Unmarshal(plain, local); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if len(devs) == 0 && len(local.PctlDevices) > 0 {
			return nil, fmt.Errorf("the parental core holds no Switch records but %s holds %d: run nx-pctl -import-parental %s first", path, len(local.PctlDevices), path)
		}
		if _, err := os.Stat(path + ".before-parental"); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(path+".before-parental", b, 0o600); err != nil {
				return nil, err
			}
		}
	}
	s := &Store{path: path, PctlDevices: devs, remote: p, seal: key}
	s.mu.Lock()
	s.save()
	s.mu.Unlock()
	return s, nil
}

// sync writes what changed since the last save. Called by save with the store's lock held,
// so the records cannot move under it.
func (p *parentalSync) sync(devs map[string]*PctlDevice) {
	for _, hex := range slices.Sorted(maps.Keys(devs)) {
		d := devs[hex]
		blob := pctlBlob(d)
		sum := sha256.Sum256(blob)
		if p.written[hex] != sum {
			ctx, cancel := p.ctx()
			resp, err := p.c.PutDevice(ctx, &parentalv1.PutDeviceRequest{Device: pctlCoreDevice(hex, d, blob), ExpectedVersion: p.version[hex]})
			cancel()
			switch status.Code(err) {
			case codes.OK:
				p.version[hex], p.written[hex] = resp.GetDevice().GetVersion(), sum
			case codes.Aborted, codes.FailedPrecondition:
				log.Printf("%s parental: record %s changed in the core; re-reading it", logPrefix, hex)
				p.reread(devs, hex)
				continue
			case codes.InvalidArgument:
				// Nothing to retry until the record itself changes (a record minted without
				// a managing account, for one): it stays in the file mirror only.
				log.Printf("%s parental: record %s refused: %s", logPrefix, hex, status.Convert(err).Message())
				p.written[hex] = sum
				continue
			default:
				log.Printf("%s parental: record %s not written (%v); retried at the next change", logPrefix, hex, status.Code(err))
				continue
			}
		}
		p.ingest(hex, d)
	}
	for _, hex := range slices.Sorted(maps.Keys(p.version)) {
		if _, ok := devs[hex]; !ok {
			p.remove(hex)
		}
	}
}

// ingest sends the record's events the core does not hold yet.
func (p *parentalSync) ingest(hex string, d *PctlDevice) {
	if p.version[hex] == 0 {
		return
	}
	evs := pctlEvents(d.Events)
	var fresh []*parentalv1.UsageEvent
	for _, e := range evs {
		if !p.sent[hex][sha256.Sum256(e)] {
			fresh = append(fresh, pctlUsage(e))
		}
	}
	for len(fresh) > 0 {
		n := min(len(fresh), 1000)
		ctx, cancel := p.ctx()
		_, err := p.c.IngestUsage(ctx, &parentalv1.IngestUsageRequest{DeviceRef: hex, Events: fresh[:n]})
		cancel()
		if err != nil {
			log.Printf("%s parental: record %s events not written (%v); retried at the next change", logPrefix, hex, status.Code(err))
			return
		}
		fresh = fresh[n:]
	}
	p.sent[hex] = eventDigests(evs)
}

// remove deletes a record that left the map (a console unlinked, a parent removed it). The
// local delete wins over a concurrent change in the core.
func (p *parentalSync) remove(hex string) {
	for range 2 {
		ctx, cancel := p.ctx()
		_, err := p.c.DeleteDevice(ctx, &parentalv1.DeleteDeviceRequest{DeviceRef: hex, ExpectedVersion: p.version[hex]})
		cancel()
		switch status.Code(err) {
		case codes.OK, codes.NotFound:
			p.forget(hex)
			return
		case codes.Aborted:
			ctx, cancel := p.ctx()
			cur, err := p.c.GetDevice(ctx, &parentalv1.GetDeviceRequest{DeviceRef: hex})
			cancel()
			if status.Code(err) == codes.NotFound {
				p.forget(hex)
				return
			}
			if err != nil {
				break
			}
			p.version[hex] = cur.GetVersion()
			continue
		}
		log.Printf("%s parental: record %s not deleted (%v); retried at the next change", logPrefix, hex, status.Code(err))
		return
	}
}

// reread replaces a record with the core's, or drops it when the core has none. Events not
// yet sent are kept: the next save sends them.
func (p *parentalSync) reread(devs map[string]*PctlDevice, hex string) {
	ctx, cancel := p.ctx()
	cd, err := p.c.GetDevice(ctx, &parentalv1.GetDeviceRequest{DeviceRef: hex})
	cancel()
	if status.Code(err) == codes.NotFound {
		log.Printf("%s parental: record %s is gone from the core; dropped here too", logPrefix, hex)
		delete(devs, hex)
		p.forget(hex)
		return
	}
	if err != nil {
		log.Printf("%s parental: record %s not re-read (%v)", logPrefix, hex, status.Code(err))
		return
	}
	local := devs[hex].Events
	d, err := p.fromCore(cd)
	if err != nil {
		log.Printf("%s parental: %v", logPrefix, err)
		return
	}
	d.Events = pctlEvents(append(d.Events, local...))
	devs[hex] = d
}

// importParental is the one-shot import (nx-pctl -import-parental <file>): every record in a
// pctl.json (or nx-baas's baas.json, which keeps them under the same key) that the core does
// not hold yet is created there with its events. Records the core holds are left alone, so
// a second run changes nothing. The file is only read.
func importParental(r io.Reader, p *parentalSync) (created, skipped, failed int, err error) {
	var file struct {
		PctlDevices map[string]*PctlDevice `json:"pctlDevices"`
	}
	if err := json.NewDecoder(r).Decode(&file); err != nil {
		return 0, 0, 0, err
	}
	for _, hex := range slices.Sorted(maps.Keys(file.PctlDevices)) {
		d := file.PctlDevices[hex]
		if d == nil || d.Hex() != hex {
			log.Printf("%s import: record %s does not hold its own moon id; skipped", logPrefix, hex)
			failed++
			continue
		}
		ctx, cancel := p.ctx()
		_, err := p.c.PutDevice(ctx, &parentalv1.PutDeviceRequest{Device: pctlCoreDevice(hex, d, pctlBlob(d))})
		cancel()
		p.version[hex] = 1 // any non-zero: the core holds the record, its events may follow
		switch status.Code(err) {
		case codes.OK:
			created++
		case codes.Aborted:
			// Held already: only the events, which the core deduplicates, so a run that
			// stopped between a record and its events is completed by the next one.
			skipped++
		case codes.InvalidArgument, codes.FailedPrecondition:
			log.Printf("%s import: record %s refused: %s", logPrefix, hex, status.Convert(err).Message())
			failed++
			continue
		default:
			return created, skipped, failed, fmt.Errorf("record %s: %w", hex, err)
		}
		p.ingest(hex, d)
		if len(p.sent[hex]) == 0 && len(pctlEvents(d.Events)) > 0 {
			return created, skipped, failed, fmt.Errorf("record %s: its events were not written; run the import again", hex)
		}
	}
	return created, skipped, failed, nil
}
