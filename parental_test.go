package main

// The parental backend (NX_PCTL_BACKEND=parental) against a stand-in parental core that keeps
// the core's rules: versions, a subject bound for good, owners that are account ids, usage
// deduplicated by digest. The console's flow runs through moon.go exactly as with the file
// store; what is checked is that the core ends up holding the same records, and that a
// restart on the core serves the console the same thing.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	parentalv1 "nx-pctl/parentalpb"
)

const fakeParentalKey = "switch-test-key-0123456789abcdef0123"

type fakeParental struct {
	parentalv1.UnimplementedParentalServer
	mu      sync.Mutex
	devices map[string]*parentalv1.Device
	usage   map[string][]*parentalv1.UsageEvent
	down    bool
	puts    int
}

var accountRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (f *fakeParental) check(ctx context.Context) error {
	if md, _ := metadata.FromIncomingContext(ctx); len(md.Get("x-internal-key")) == 0 || md.Get("x-internal-key")[0] != fakeParentalKey {
		return status.Error(codes.Unauthenticated, "key")
	}
	if f.down {
		return status.Error(codes.Unavailable, "down")
	}
	return nil
}

func (f *fakeParental) PutDevice(ctx context.Context, req *parentalv1.PutDeviceRequest) (*parentalv1.PutDeviceResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(ctx); err != nil {
		return nil, err
	}
	in := proto.Clone(req.GetDevice()).(*parentalv1.Device)
	if !accountRe.MatchString(in.OwnerId) {
		return nil, status.Error(codes.InvalidArgument, "owner_id must be an account id")
	}
	cur := f.devices[in.DeviceRef]
	switch {
	case cur == nil && req.ExpectedVersion != 0, cur != nil && cur.Version != req.ExpectedVersion:
		return nil, status.Error(codes.Aborted, "version conflict")
	case cur != nil && cur.Subject != "" && cur.Subject != in.Subject:
		return nil, status.Error(codes.FailedPrecondition, "subject")
	}
	in.Version = req.ExpectedVersion + 1
	in.SupervisorIds = append([]string{in.OwnerId}, in.SupervisorIds...)
	f.devices[in.DeviceRef] = in
	f.puts++
	return &parentalv1.PutDeviceResponse{Device: proto.Clone(in).(*parentalv1.Device)}, nil
}

func (f *fakeParental) GetDevice(ctx context.Context, req *parentalv1.GetDeviceRequest) (*parentalv1.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(ctx); err != nil {
		return nil, err
	}
	if d := f.devices[req.DeviceRef]; d != nil {
		return proto.Clone(d).(*parentalv1.Device), nil
	}
	return nil, status.Error(codes.NotFound, "not found")
}

func (f *fakeParental) ListDevices(ctx context.Context, req *parentalv1.ListDevicesRequest) (*parentalv1.ListDevicesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(ctx); err != nil {
		return nil, err
	}
	out := &parentalv1.ListDevicesResponse{}
	for _, d := range f.devices {
		out.Devices = append(out.Devices, proto.Clone(d).(*parentalv1.Device))
	}
	return out, nil
}

func (f *fakeParental) DeleteDevice(ctx context.Context, req *parentalv1.DeleteDeviceRequest) (*parentalv1.DeleteDeviceResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(ctx); err != nil {
		return nil, err
	}
	d := f.devices[req.DeviceRef]
	if d == nil {
		return nil, status.Error(codes.NotFound, "not found")
	}
	if d.Version != req.ExpectedVersion {
		return nil, status.Error(codes.Aborted, "version conflict")
	}
	delete(f.devices, req.DeviceRef)
	delete(f.usage, req.DeviceRef)
	return &parentalv1.DeleteDeviceResponse{}, nil
}

func (f *fakeParental) IngestUsage(ctx context.Context, req *parentalv1.IngestUsageRequest) (*parentalv1.IngestUsageResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(ctx); err != nil {
		return nil, err
	}
	if f.devices[req.DeviceRef] == nil {
		return nil, status.Error(codes.NotFound, "not found")
	}
	n := 0
	for _, e := range req.Events {
		dup := false
		for _, have := range f.usage[req.DeviceRef] {
			if sha256.Sum256(have.PayloadJson) == sha256.Sum256(e.PayloadJson) {
				dup = true
			}
		}
		if !dup {
			f.usage[req.DeviceRef] = append(f.usage[req.DeviceRef], proto.Clone(e).(*parentalv1.UsageEvent))
			n++
		}
	}
	return &parentalv1.IngestUsageResponse{Accepted: int32(n), Held: int32(len(f.usage[req.DeviceRef]))}, nil
}

func (f *fakeParental) ListUsage(ctx context.Context, req *parentalv1.ListUsageRequest) (*parentalv1.ListUsageResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(ctx); err != nil {
		return nil, err
	}
	if f.devices[req.DeviceRef] == nil {
		return nil, status.Error(codes.NotFound, "not found")
	}
	return &parentalv1.ListUsageResponse{Events: f.usage[req.DeviceRef]}, nil
}

func (f *fakeParental) setDown(v bool) { f.mu.Lock(); f.down = v; f.mu.Unlock() }

// startFakeParental serves a fake core on a loopback port and returns a client for it.
func startFakeParental(t *testing.T) (*fakeParental, func() *parentalSync) {
	t.Helper()
	f := &fakeParental{devices: map[string]*parentalv1.Device{}, usage: map[string][]*parentalv1.UsageEvent{}}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	parentalv1.RegisterParentalServer(gs, f)
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return f, func() *parentalSync { return newParentalSync(parentalv1.NewParentalClient(conn), fakeParentalKey) }
}

// remoteServer is moonServer on the parental backend, its mirror at path.
func remoteServer(t *testing.T, path string, client func() *parentalSync) *server {
	t.Helper()
	s, _ := moonServer(t)
	st, err := loadParentalStore(path, client())
	if err != nil {
		t.Fatal(err)
	}
	s.store = st
	return s
}

func recordJSON(t *testing.T, d *PctlDevice) string {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParentalBackendKeepsTheRecordsInTheCore(t *testing.T) {
	fake, client := startFakeParental(t)
	path := filepath.Join(t.TempDir(), "pctl.json")
	s := remoteServer(t, path, client)
	parent, other := testAccount(1), testAccount(2)

	// The parent mints a code: the core holds the record, the code and its deadline.
	minted := s.store.PctlNewPairing(parent)
	hex := minted.Hex()
	cd := fake.devices[hex]
	if cd == nil || cd.OwnerId != parent || cd.PairingCode != minted.PairingCode || cd.PairingExpiresUnix != minted.PairingExpires || cd.Version != 1 {
		t.Fatalf("core after minting: %v", cd)
	}

	// The console pairs and syncs, through moon.go as ever.
	tok := deviceTokenFor(s, "cert-aaaaaaaaaaaaaaaa")
	activate := `{"parentalControlSetting":{"functionalRestrictionLevel":"NONE"},"notificationToken":"penne-test","unlockCode":"1234"}`
	if w, _ := moonReq(t, s, "POST", "/moon/v1/devices/"+hex+"/activate", tok, activate); w.Code != 200 {
		t.Fatalf("activate %d %s", w.Code, w.Body)
	}
	if cd := fake.devices[hex]; cd.Subject != "cert-aaaaaaaaaaaaaaaa" || cd.PairingCode != "" || cd.PairedAtUnix == 0 {
		t.Fatalf("core after activate: %v", cd)
	}
	now := time.Now().Unix()
	upload := `[{"eventType":"DID_WRONG_UNLOCK_CODE","eventTimestamp":` + jsonNum(now) + `},{"eventType":"DID_UNLOCK","eventTimestamp":` + jsonNum(now) + `}]`
	if w, _ := moonReq(t, s, "POST", "/moon/v1/devices/"+hex+"/events", tok, upload); w.Code != 200 {
		t.Fatalf("events %d", w.Code)
	}
	if n := len(fake.usage[hex]); n != 2 {
		t.Fatalf("core holds %d events, want 2", n)
	}
	if _, err := s.store.PctlSetParent(hex, other, "Made Up"); err != nil {
		t.Fatal(err)
	}
	if sup := fake.devices[hex].SupervisorIds; len(sup) != 2 || sup[1] != other {
		t.Fatalf("supervisors %v", sup)
	}
	putsBefore := fake.puts
	if w, _ := moonReq(t, s, "POST", "/moon/v1/devices/"+hex+"/events", tok, upload); w.Code != 200 || len(fake.usage[hex]) != 2 {
		t.Fatalf("a retried upload: %d, %d held", w.Code, len(fake.usage[hex]))
	}
	if fake.puts > putsBefore+1 {
		t.Fatalf("an event upload wrote the record %d times", fake.puts-putsBefore)
	}

	// The core down: the change stands locally and in the mirror, and goes out with the next one.
	fake.setDown(true)
	s.store.PctlSetLabel(hex, "Living room")
	fake.setDown(false)
	s.store.PctlSetLabel(hex, "Den")
	if !strings.Contains(string(fake.devices[hex].StateJson), `"label":"Den"`) {
		t.Fatalf("the change after an outage did not reach the core: %s", fake.devices[hex].StateJson)
	}

	// A restart on the core serves the console exactly what it was served before. The
	// events differ in one way only: the file store kept the retried upload twice, the core
	// once (it deduplicates by digest).
	before := s.store.PctlByMoonID(hex)
	if len(before.Events) != 4 {
		t.Fatalf("the file store's own count changed: %d", len(before.Events))
	}
	wantBlob, wantTag := string(pctlBlob(before)), pctlServedETag(before)
	s2 := remoteServer(t, path, client)
	after := s2.store.PctlByMoonID(hex)
	if after == nil || string(pctlBlob(after)) != wantBlob || pctlServedETag(after) != wantTag || len(after.Events) != 2 {
		t.Fatalf("after a restart:\n got %s\nwant %s", pctlBlob(after), wantBlob)
	}
	wantJSON := recordJSON(t, after)
	if got := s2.store.PctlWrongUnlocks(hex); len(got) != 1 || got[0] != now {
		t.Fatalf("wrong PINs after a restart: %v", got)
	}

	// Rollback: the mirror is the file store's own format, with the same records.
	mirror := loadStore(path, "")
	if d := mirror.PctlByMoonID(hex); d == nil || recordJSON(t, d) != wantJSON {
		t.Fatalf("the mirror is not the current state")
	}

	// The console unlinking removes the record from the core too.
	if w, _ := moonReq(t, s2, "DELETE", "/moon/v1/devices/"+hex, deviceTokenFor(s2, "cert-aaaaaaaaaaaaaaaa"), ""); w.Code != 204 {
		t.Fatalf("unlink %d", w.Code)
	}
	if fake.devices[hex] != nil || fake.usage[hex] != nil {
		t.Fatalf("the core kept an unlinked console")
	}
}

func jsonNum(n int64) string { b, _ := json.Marshal(n); return string(b) }

// A record the core removed behind pctl's back (an account deletion) is dropped at pctl's
// next write instead of being written back.
func TestParentalBackendRereadsAConflict(t *testing.T) {
	fake, client := startFakeParental(t)
	s := remoteServer(t, filepath.Join(t.TempDir(), "pctl.json"), client)
	d := pairedFor(t, s, testAccount(1))
	hex := d.Hex()

	fake.mu.Lock()
	delete(fake.devices, hex)
	fake.mu.Unlock()
	s.store.PctlSetLabel(hex, "Den")
	if s.store.PctlByMoonID(hex) != nil || fake.devices[hex] != nil {
		t.Fatalf("a purged record came back")
	}

	// Changed in the core by another writer: the core's version wins.
	d = pairedFor(t, s, testAccount(2))
	hex = d.Hex()
	fake.mu.Lock()
	cd := fake.devices[hex]
	cd.StateJson = bytes.Replace(cd.StateJson, []byte(`"moonId"`), []byte(`"label":"From the core","moonId"`), 1)
	cd.Version++
	fake.mu.Unlock()
	s.store.PctlSetLabel(hex, "Local")
	if got := s.store.PctlByMoonID(hex); got == nil || got.Label != "From the core" {
		t.Fatalf("after a conflict: %+v", got)
	}
}

// A record the core refuses (no managing account) stays in the mirror and is not retried
// on every save.
func TestParentalBackendRefusedRecord(t *testing.T) {
	fake, client := startFakeParental(t)
	s := remoteServer(t, filepath.Join(t.TempDir(), "pctl.json"), client)
	d := s.store.PctlNewPairing("acct-not-a-uuid")
	puts := fake.puts
	s.store.PctlSetPlayer(d.Hex(), "p1", nil)
	if fake.devices[d.Hex()] != nil || fake.puts != puts || s.store.PctlByMoonID(d.Hex()) == nil {
		t.Fatalf("refused record: in core %v, retried %d", fake.devices[d.Hex()] != nil, fake.puts-puts)
	}
}

func TestParentalImporter(t *testing.T) {
	fake, client := startFakeParental(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "pctl.json")

	// A file store as production has it: one paired console with events, one record the
	// core cannot take.
	file := loadStore(path, "")
	d := file.PctlNewPairing(testAccount(3))
	file.PctlActivate(d.Hex(), "cert-bbbbbbbbbbbbbbbb")
	file.PctlAddEvents(d.Hex(), []byte(`[{"eventType":"DID_APP_PLAY","eventTimestamp":`+jsonNum(time.Now().Unix())+`,"elapsedTime":60}]`))
	file.PctlNewPairing("acct-not-a-uuid")
	want := recordJSON(t, file.PctlByMoonID(d.Hex()))

	// Starting on an empty core is refused: the importer has not run.
	if _, err := loadParentalStore(path, client()); err == nil || !strings.Contains(err.Error(), "-import-parental") {
		t.Fatalf("empty core: %v", err)
	}

	run := func() (int, int, int) {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		c, sk, fl, err := importParental(f, client())
		if err != nil {
			t.Fatal(err)
		}
		return c, sk, fl
	}
	if c, sk, fl := run(); c != 1 || sk != 0 || fl != 1 {
		t.Fatalf("first import: %d created, %d skipped, %d refused", c, sk, fl)
	}
	if c, sk, fl := run(); c != 0 || sk != 1 || fl != 1 || len(fake.usage[d.Hex()]) != 1 {
		t.Fatalf("second import: %d created, %d skipped, %d refused, %d events", c, sk, fl, len(fake.usage[d.Hex()]))
	}

	s := remoteServer(t, path, client)
	if got := s.store.PctlByMoonID(d.Hex()); got == nil || recordJSON(t, got) != want {
		t.Fatalf("imported record differs")
	}
	if _, err := os.Stat(path + ".before-parental"); err != nil {
		t.Fatalf("the file as it was is not kept: %v", err)
	}
}
