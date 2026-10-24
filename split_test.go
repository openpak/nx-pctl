package main

// What is new in parental controls as their own service: only the pctl hostnames, the
// website's routes and nx-baas's forwards on the internal listener, the one-time import of
// the records from baas.json, and the push going to the penne API over HTTP.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openpak/nx-common/nxapi"
)

func TestForeignHostsAreMisrouted(t *testing.T) {
	s := &server{store: pctlStore(t)}
	for _, host := range []string{"m-lp1.baas.nintendo.com", "god.hac.lp1.penne.srv.nintendo.net", "hac.lp1.savanna.srv.nintendo.net"} {
		r := httptest.NewRequest("GET", "https://"+host+"/moon/v1/devices", nil)
		r.Host = host
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusMisdirectedRequest {
			t.Errorf("%s = %d, want 421", host, w.Code)
		}
	}
	for host, want := range map[string]int{"api-lp1.pctl.srv.nintendo.net": 200, "parentalcontrols-movie-lp1.cdn.nintendo.net": 404} {
		r := httptest.NewRequest("GET", "https://"+host+"/v1/status", nil)
		r.Host = host
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s = %d, want %d", host, w.Code, want)
		}
	}
}

// The website's parent routes and nx-baas's forwarded console requests share the internal
// listener; the website's key is checked as nx-baas checked it.
func TestInternalListener(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "k")
	s := &server{store: pctlStore(t)}
	h := s.internalAPI()
	r := httptest.NewRequest("POST", "http://openpak-nx-pctl:20070/internal/pctl/pairing", strings.NewReader(`{"account_id":"acct-1","display_name":"Leia"}`))
	r.Header.Set("X-Internal-Key", "k")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var got map[string]any
	json.Unmarshal(w.Body.Bytes(), &got)
	code, _ := got["pairing_code"].(string)
	if w.Code != 200 || code == "" {
		t.Fatalf("pairing = %d %s", w.Code, w.Body)
	}
	r = httptest.NewRequest("POST", "http://openpak-nx-pctl:20070/internal/pctl/pairing", strings.NewReader(`{}`))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("pairing without the key = %d", w.Code)
	}
	// A console's search, forwarded by nx-baas with its Host.
	r = httptest.NewRequest("GET", "http://openpak-nx-pctl:20070/moon/v1/devices?filter.links.pairingCode.code.$eq="+code, nil)
	r.Host = "api-lp1.pctl.srv.nintendo.net"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[{`) {
		t.Fatalf("forwarded search = %d %s", w.Code, w.Body)
	}
}

// The first start takes the records out of nx-baas's baas.json (and nothing else in it);
// later starts keep their own file.
func TestFirstStartImportsTheRecordsFromBaasJSON(t *testing.T) {
	dir := t.TempDir()
	old := &Store{path: filepath.Join(dir, "old.json")}
	d := old.PctlNewPairing("acct-parent")
	old.PctlActivate(d.Hex(), "cert-aaaaaaaaaaaaaaaa")
	// nx-baas's file carries users and devices beside the records.
	var doc map[string]any
	b, _ := os.ReadFile(old.path)
	json.Unmarshal(b, &doc)
	doc["users"] = map[string]any{"u1": map[string]any{"id": "u1", "naId": "secret"}}
	doc["devices"] = map[string]any{}
	b, _ = json.Marshal(doc)
	baas := filepath.Join(dir, "baas.json")
	os.WriteFile(baas, b, 0o600)

	mine := filepath.Join(dir, "pctl.json")
	s := loadStore(mine, baas, nil)
	if got := s.PctlByMoonID(d.Hex()); got == nil || got.DauthID != "cert-aaaaaaaaaaaaaaaa" {
		t.Fatalf("imported record = %+v", got)
	}
	written, _ := os.ReadFile(mine)
	if strings.Contains(string(written), "secret") || strings.Contains(string(written), `"users"`) {
		t.Fatalf("pctl.json carries more than the records: %s", written)
	}
	s.PctlNewPairing("acct-other")
	// nx-baas keeps writing baas.json (logins, presence); its records stay as they were.
	doc["users"] = map[string]any{"u2": map[string]any{"id": "u2"}}
	b, _ = json.Marshal(doc)
	os.WriteFile(baas, b, 0o600)
	again := loadStore(mine, baas, nil)
	if len(again.PctlDevicesFor("acct-other")) != 1 || again.PctlByMoonID(d.Hex()) == nil {
		t.Fatal("a restart re-imported baas.json over our own file")
	}

	// Rollback: nx-baas serves parental controls again and its records move on; the second
	// cut-over takes them rather than resuming from our stale copy.
	old.PctlNewPairing("acct-third")
	b, _ = os.ReadFile(old.path)
	json.Unmarshal(b, &doc)
	b, _ = json.Marshal(doc)
	os.WriteFile(baas, b, 0o600)
	recut := loadStore(mine, baas, nil)
	if len(recut.PctlDevicesFor("acct-third")) != 1 {
		t.Fatal("the second cut-over resumed from our stale records instead of nx-baas's")
	}
	if kept, _ := filepath.Glob(mine + ".before-import-*"); len(kept) != 1 {
		t.Fatalf("our replaced records were not kept aside: %v", kept)
	}
}

// With no records left the file still carries the key, so a rollback can apply it.
func TestNoRecordsIsStillAnObject(t *testing.T) {
	s := loadStore(filepath.Join(t.TempDir(), "pctl.json"), "", nil)
	d := s.PctlNewPairing("a")
	s.PctlUnlink(d.Hex())
	b, _ := os.ReadFile(s.path)
	if !strings.Contains(string(b), `"pctlDevices": {}`) {
		t.Fatalf("pctl.json with no records = %s", b)
	}
}

// A console host on the internal listener never reaches the parent routes.
func TestConsoleHostNeverReachesTheParentRoutes(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "k")
	s := &server{store: pctlStore(t)}
	r := httptest.NewRequest("POST", "http://openpak-nx-pctl:20070/internal/pctl/pairing", strings.NewReader(`{"account_id":"a"}`))
	r.Host = "api-lp1.pctl.srv.nintendo.net"
	r.Header.Set("X-Internal-Key", "k")
	w := httptest.NewRecorder()
	s.internalAPI().ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "pairing_code") {
		t.Fatalf("console host reached the parent routes: %d %s", w.Code, w.Body)
	}
}

// A push the push side did not take is an error, not "no notification token".
func TestFailedPushIsAnError(t *testing.T) {
	s, _ := moonServer(t)
	s.penne = &fakePenne{down: true}
	if _, _, err := s.penneDeviceMessage("", "cert-1", "x", "pctl", "{}"); err == nil {
		t.Fatal("an unreachable push side was not an error")
	}
}

// The push reaches the penne API over HTTP in nxapi's shape.
func TestPushGoesToThePenneAPI(t *testing.T) {
	t.Setenv("NX_INTERNAL_KEY", "k")
	got := make(chan nxapi.DeviceMessage, 1)
	penne := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/penne/device-messages" || r.Header.Get("X-Internal-Key") != "k" {
			w.WriteHeader(404)
			return
		}
		var m nxapi.DeviceMessage
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &m)
		got <- m
		w.Write([]byte(`{"penne_id":"pz-1","connections":1}`))
	}))
	defer penne.Close()
	s, _ := moonServer(t)
	s.penne = nxapi.New(penne.URL)
	if id, n, err := s.penneDeviceMessage("", "cert-1", "DID_CHANGE_PARENTAL_CONTROL_SETTING", "pctl", "{}"); id != "pz-1" || n != 1 || err != nil {
		t.Fatalf("push = %q %d %v", id, n, err)
	}
	if m := <-got; m.DauthUser != "cert-1" || m.Receivers != "pctl" {
		t.Fatalf("penne got %+v", m)
	}
}
