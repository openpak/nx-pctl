package main

// At-rest encryption of pctl.json. The console needs its PIN in clear (the setting GET and
// the device object carry it, and the console checks it locally), so the PIN cannot be
// hashed; the whole file is sealed instead, with AES-256-GCM under NX_PCTL_BLOB_KEY. The
// whole file and not the PIN fields: the record also keeps hashes over documents that hold
// the PIN (ETag, SyncedEtag), and a four-digit PIN falls out of those by brute force, so
// sealing the fields alone would not hide it.
//
// Only the file changes. The records in memory, and so every byte a console or the website
// receives, are exactly what they were.
//
// A sealed file is one JSON object, {"sealed":"aes-256-gcm/v1","kid":…,"nonce":…,
// "ciphertext":…}; anything else is a plaintext file from before, sealed in place at the
// first start with a key (sealAtRest), backups beside it included. kid names the key, so a
// later rotation can tell which key a file was sealed under.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const sealScheme = "aes-256-gcm/v1"

// sealAAD binds the ciphertext to what it is: a sealed pctl.json from another service
// would not open as one.
var sealAAD = []byte("openpak nx-pctl pctl.json")

type sealKey struct {
	id   string
	aead cipher.AEAD
}

type sealedFile struct {
	Sealed     string `json:"sealed"`
	KID        string `json:"kid"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// parseSealKey takes 32 bytes in standard base64 (openssl rand -base64 32).
func parseSealKey(b64 string) (*sealKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != 32 {
		return nil, errors.New("NX_PCTL_BLOB_KEY must be 32 bytes in base64 (openssl rand -base64 32)")
	}
	block, _ := aes.NewCipher(raw)
	aead, _ := cipher.NewGCM(block)
	sum := sha256.Sum256(append([]byte("openpak blob key id\x00"), raw...))
	return &sealKey{id: hex.EncodeToString(sum[:8]), aead: aead}, nil
}

// sealKeyFromEnv is NX_PCTL_BLOB_KEY (or the file NX_PCTL_BLOB_KEY_FILE names). Without
// one nx-pctl does not start, unless NX_PCTL_BLOB_INSECURE_PLAINTEXT=1 says it may keep
// the file in clear (tests and development only, never production): then the key is nil.
func sealKeyFromEnv() (*sealKey, error) {
	v := os.Getenv("NX_PCTL_BLOB_KEY")
	if f := os.Getenv("NX_PCTL_BLOB_KEY_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("NX_PCTL_BLOB_KEY_FILE: %w", err)
		}
		v = string(b)
	}
	if strings.TrimSpace(v) == "" {
		if os.Getenv("NX_PCTL_BLOB_INSECURE_PLAINTEXT") == "1" {
			return nil, nil
		}
		return nil, errors.New("NX_PCTL_BLOB_KEY (or _FILE) is required: pctl.json holds console PINs (NX_PCTL_BLOB_INSECURE_PLAINTEXT=1 for development only)")
	}
	return parseSealKey(v)
}

func (k *sealKey) seal(plain []byte) []byte {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	b, _ := json.Marshal(sealedFile{Sealed: sealScheme, KID: k.id, Nonce: nonce, Ciphertext: k.aead.Seal(nil, nonce, plain, sealAAD)})
	return b
}

// isSealed reports whether b is a sealed file: a JSON object with a "sealed" member. A
// plaintext file never has one (its only member is pctlDevices).
func isSealed(b []byte) bool {
	var top map[string]json.RawMessage
	return json.Unmarshal(b, &top) == nil && top["sealed"] != nil
}

// openFile is the plaintext of a file as read: a sealed one is opened with k, anything
// else is returned as it is (a file from before sealing, or one kept in clear).
func openFile(k *sealKey, b []byte) ([]byte, error) {
	if !isSealed(b) {
		return b, nil
	}
	var f sealedFile
	err := json.Unmarshal(b, &f)
	switch {
	case err != nil:
		return nil, errors.New("the sealed file is corrupt")
	case f.Sealed != sealScheme:
		return nil, fmt.Errorf("sealed with an unknown scheme %q", f.Sealed)
	case k == nil:
		return nil, errors.New("the file is sealed and no NX_PCTL_BLOB_KEY is configured")
	case f.KID != k.id:
		return nil, fmt.Errorf("the file is sealed under key %s, the configured key is %s", f.KID, k.id)
	}
	plain, err := k.aead.Open(nil, f.Nonce, f.Ciphertext, sealAAD)
	if err != nil {
		return nil, errors.New("the file does not open with the configured key (corrupt, or not ours)")
	}
	return plain, nil
}

// encodeFile is what save writes: sealed when there is a key.
func encodeFile(k *sealKey, plain []byte) []byte {
	if k == nil {
		return plain
	}
	return k.seal(plain)
}

// sealAtRest seals, in place, pctl.json and the copies kept beside it (.before-parental,
// .before-import-*) that are still in clear. Idempotent: a sealed file is left as it is,
// so every start may run it. Without a key it changes nothing.
func sealAtRest(path string, k *sealKey) (int, error) {
	if k == nil {
		return 0, nil
	}
	backups, _ := filepath.Glob(path + ".before-*")
	n := 0
	for _, p := range append([]string{path}, backups...) {
		b, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return n, err
		}
		if isSealed(b) {
			continue
		}
		if err := os.WriteFile(p+".tmp", k.seal(b), 0o600); err != nil {
			return n, err
		}
		if err := os.Rename(p+".tmp", p); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// resealFile is the contents of a sealed file moved from oldK to newK. A file already under
// newK is returned as it is (so an interrupted run can be repeated), one in clear is sealed
// under newK, one under any other key is an error. The result is opened under newK before it
// is returned.
func resealFile(oldK, newK *sealKey, b []byte) (out []byte, how string, err error) {
	if oldK == nil || newK == nil || oldK.id == newK.id {
		return nil, "", errors.New("rekey needs an old and a new key that differ")
	}
	var plain []byte
	switch {
	case !isSealed(b):
		plain, how = b, "sealed"
	default:
		var f sealedFile
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, "", errors.New("the sealed file is corrupt")
		}
		switch f.KID {
		case newK.id:
			if _, err := openFile(newK, b); err != nil {
				return nil, "", err
			}
			return b, "already-new", nil
		case oldK.id:
			if plain, err = openFile(oldK, b); err != nil {
				return nil, "", err
			}
			how = "rekeyed"
		default:
			return nil, "", fmt.Errorf("sealed under key %s, which is neither the old (%s) nor the new (%s) key", f.KID, oldK.id, newK.id)
		}
	}
	out = newK.seal(plain)
	if got, err := openFile(newK, out); err != nil || !bytes.Equal(got, plain) {
		return nil, "", errors.New("the re-sealed file does not open under the new key")
	}
	return out, how, nil
}

// rekeyAtRest moves pctl.json and the copies beside it from oldK to newK, each one written
// to a temporary file and renamed, and returns the counts. Run it with the service stopped.
func rekeyAtRest(path string, oldK, newK *sealKey) (rekeyed, already, sealed int, err error) {
	backups, _ := filepath.Glob(path + ".before-*")
	// Work out every result first, so a file that cannot be moved changes none.
	type job struct {
		p   string
		out []byte
	}
	var jobs []job
	for _, p := range append([]string{path}, backups...) {
		b, rerr := os.ReadFile(p)
		if errors.Is(rerr, os.ErrNotExist) {
			continue
		}
		if rerr != nil {
			return 0, 0, 0, rerr
		}
		out, how, rerr := resealFile(oldK, newK, b)
		if rerr != nil {
			return 0, 0, 0, fmt.Errorf("%s: %w", filepath.Base(p), rerr)
		}
		switch how {
		case "already-new":
			already++
		case "sealed":
			sealed++
			jobs = append(jobs, job{p, out})
		default:
			rekeyed++
			jobs = append(jobs, job{p, out})
		}
	}
	for _, j := range jobs {
		if err := os.WriteFile(j.p+".tmp", j.out, 0o600); err != nil {
			return 0, 0, 0, err
		}
		if err := os.Rename(j.p+".tmp", j.p); err != nil {
			return 0, 0, 0, err
		}
	}
	return rekeyed, already, sealed, nil
}

// oldSealKeyFromEnv is NX_PCTL_BLOB_KEY_OLD (or the file NX_PCTL_BLOB_KEY_OLD_FILE names).
func oldSealKeyFromEnv() (*sealKey, error) {
	v := os.Getenv("NX_PCTL_BLOB_KEY_OLD")
	if f := os.Getenv("NX_PCTL_BLOB_KEY_OLD_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("NX_PCTL_BLOB_KEY_OLD_FILE: %w", err)
		}
		v = string(b)
	}
	if strings.TrimSpace(v) == "" {
		return nil, errors.New("NX_PCTL_BLOB_KEY_OLD (or _FILE) is required for -rekey")
	}
	return parseSealKey(v)
}
