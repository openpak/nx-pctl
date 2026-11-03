package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testSealKey(t *testing.T) *sealKey {
	t.Helper()
	raw := make([]byte, 32)
	rand.Read(raw)
	k, err := parseSealKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// served is every byte a console and the website receive for one record: the setting GET
// (status, ETag, body), the device object, and the parent-side list.
func served(t *testing.T, s *server, tok, hex string) string {
	t.Helper()
	var out strings.Builder
	w, _ := moonReq(t, s, "GET", "/moon/v1/devices/"+hex+"/parental_control_setting", tok, "")
	out.WriteString(w.Header().Get("ETag") + "\n" + w.Body.String() + "\n")
	w, _ = moonReq(t, s, "GET", "/moon/v1/devices/"+hex, tok, "")
	out.WriteString(w.Body.String() + "\n")
	r := httptest.NewRequest("GET", "/internal/pctl/devices?account_id=acct-parent", nil)
	rec := httptest.NewRecorder()
	s.pctlDeviceList(rec, r)
	out.WriteString(rec.Body.String())
	return out.String()
}

// Sealing pctl.json changes the file and nothing a console receives: the setting document
// and its ETag, the device object and the parent list are byte for byte what they were.
func TestSealingLeavesWhatTheConsoleReceivesUnchanged(t *testing.T) {
	s, token := moonServer(t)
	tok := token("cert-aaaaaaaaaaaaaaaa")
	d := s.store.PctlNewPairing("acct-parent")
	moonReq(t, s, "POST", "/moon/v1/devices/"+d.Hex()+"/activate", tok,
		`{"parentalControlSetting":{"unlockCode":"8759","functionalRestrictionLevel":"NONE"}}`)
	s.store.PctlSetUnlockCode(d.Hex(), "4826")
	moonReq(t, s, "POST", "/moon/v1/devices/"+d.Hex(), tok, `{"synchronizedUnlockCode":"8759"}`)
	path := s.store.path

	before := served(t, s, tok, d.Hex())
	if !strings.Contains(before, `"unlockCode":"4826"`) {
		t.Fatalf("the PIN is not served at all:\n%s", before)
	}
	clear, _ := os.ReadFile(path)
	if !bytes.Contains(clear, []byte("4826")) {
		t.Fatalf("the plaintext file does not hold the PIN; the test proves nothing")
	}

	// The first start with a key: the clear file is sealed in place.
	key := testSealKey(t)
	if n, err := sealAtRest(path, key); err != nil || n != 1 {
		t.Fatalf("sealAtRest: %d, %v", n, err)
	}
	sealed, _ := os.ReadFile(path)
	for _, pin := range []string{"4826", "8759", "unlockCode", "etag"} {
		if bytes.Contains(sealed, []byte(pin)) {
			t.Fatalf("the sealed file still shows %q", pin)
		}
	}
	// Idempotent: a second start leaves the sealed file as it is.
	if n, err := sealAtRest(path, key); err != nil || n != 0 {
		t.Fatalf("second sealAtRest: %d, %v", n, err)
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(again, sealed) {
		t.Fatalf("a second start rewrote the sealed file")
	}

	s2 := &server{key: s.key, idKid: s.idKid, store: loadStore(path, "", key)}
	if after := served(t, s2, tok, d.Hex()); after != before {
		t.Fatalf("what the console receives changed with sealing:\nbefore\n%s\nafter\n%s", before, after)
	}

	// A save under the key stays sealed, and a restart reads it back the same.
	s2.store.PctlSetUnlockCode(d.Hex(), "4826")
	resaved, _ := os.ReadFile(path)
	if !isSealed(resaved) || bytes.Contains(resaved, []byte("4826")) {
		t.Fatalf("a save under the key wrote the file in clear")
	}
	s3 := &server{key: s.key, idKid: s.idKid, store: loadStore(path, "", key)}
	if got := served(t, s3, tok, d.Hex()); !strings.Contains(got, `"unlockCode":"4826"`) || got == "" {
		t.Fatalf("after a sealed save and restart:\n%s", got)
	}
}

func TestSealingCoversTheCopiesKeptBeside(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pctl.json")
	for _, p := range []string{path, path + ".before-parental", path + ".before-import-20261001T000000"} {
		os.WriteFile(p, []byte(`{"pctlDevices":{"00000000000000aa":{"moonId":170,"unlockCode":"4826"}}}`), 0o600)
	}
	key := testSealKey(t)
	if n, err := sealAtRest(path, key); err != nil || n != 3 {
		t.Fatalf("sealAtRest: %d, %v", n, err)
	}
	for _, p := range []string{path, path + ".before-parental", path + ".before-import-20261001T000000"} {
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte("4826")) {
			t.Fatalf("%s still holds the PIN in clear", filepath.Base(p))
		}
		plain, err := openFile(key, b)
		if err != nil || !bytes.Contains(plain, []byte(`"unlockCode":"4826"`)) {
			t.Fatalf("%s does not open back: %v", filepath.Base(p), err)
		}
	}
}

func TestASealedFileNeedsItsOwnKey(t *testing.T) {
	key, other := testSealKey(t), testSealKey(t)
	b := key.seal([]byte(`{"pctlDevices":{}}`))
	if _, err := openFile(nil, b); err == nil {
		t.Fatalf("a sealed file opened without a key")
	}
	if _, err := openFile(other, b); err == nil || !strings.Contains(err.Error(), key.id) {
		t.Fatalf("another key: %v", err)
	}
	b[len(b)-5] ^= 1 // inside the base64 ciphertext
	if _, err := openFile(key, b); err == nil {
		t.Fatalf("a tampered file opened")
	}
	if plain, err := openFile(nil, []byte(`{"pctlDevices":{}}`)); err != nil || string(plain) != `{"pctlDevices":{}}` {
		t.Fatalf("a clear file: %q, %v", plain, err)
	}
}

func TestTheKeyIsRequiredUnlessPlaintextIsAskedFor(t *testing.T) {
	t.Setenv("NX_PCTL_BLOB_KEY", "")
	t.Setenv("NX_PCTL_BLOB_KEY_FILE", "")
	t.Setenv("NX_PCTL_BLOB_INSECURE_PLAINTEXT", "")
	if _, err := sealKeyFromEnv(); err == nil {
		t.Fatalf("no key and no opt-out started")
	}
	t.Setenv("NX_PCTL_BLOB_INSECURE_PLAINTEXT", "1")
	if k, err := sealKeyFromEnv(); err != nil || k != nil {
		t.Fatalf("the opt-out: %v, %v", k, err)
	}
	t.Setenv("NX_PCTL_BLOB_KEY", "c2hvcnQ=")
	if _, err := sealKeyFromEnv(); err == nil {
		t.Fatalf("a short key was taken")
	}
	t.Setenv("NX_PCTL_BLOB_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if k, err := sealKeyFromEnv(); err != nil || k == nil {
		t.Fatalf("a good key: %v", err)
	}
}
