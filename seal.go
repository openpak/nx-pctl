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
