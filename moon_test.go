package main

// Phase 0 has one job beyond logging: refuse in the shape pctl recognises, and
// leave the rest of the host alone. Both are asserted here because getting either
// wrong makes the hardware log -- the whole point of the phase -- unreadable.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

func moonCall(t *testing.T, method, path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	s := &server{store: pctlStore(t)}
	r := httptest.NewRequest(method, "https://api-lp1.pctl.srv.nintendo.net"+path, nil)
	r.Host = "api-lp1.pctl.srv.nintendo.net"
	w := httptest.NewRecorder()
	s.moon(w, r, nil)

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, w.Body.String())
	}
	return w, got
}

func TestMoonRefusalNamesAnIdentityPctlCarries(t *testing.T) {
	// A path with no handler at all: the refusal must name a literal the
	// firmware carries, or the client cannot classify what went wrong.
	w, got := moonCall(t, "GET", "/moon/v1/nothing-here")

	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", w.Code)
	}
	if got["type"] != "https://moon.nintendo.com/errors/v1/404/resource_is_not_found" {
		t.Fatalf("type %q -- must be the firmware's own literal", got["type"])
	}
	if got["status"] != float64(http.StatusNotFound) {
		t.Fatalf("status field %v, want 404 -- the type URI and the status line must agree", got["status"])
	}
}

func TestUnknownPairingCodeIsAnEmptyListNotAnError(t *testing.T) {
	// "Which device has this code" is a question; "none" answers it. A 404 here
	// would read to the console as the service being broken.
	w, got := moonCall(t, "GET", "/moon/v1/devices?filter.links.pairingCode.code.$eq=NOSUCH")

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	if got["count"] != float64(0) {
		t.Fatalf("count %v, want 0", got["count"])
	}
	if items, ok := got["items"].([]any); !ok || len(items) != 0 {
		t.Fatalf("items %v -- must be an empty list, never absent", got["items"])
	}
}

func TestMoonLeavesTheRestOfThePctlHostAlone(t *testing.T) {
	// Before moon.go every path here answered "service available". Only
	// /moon/v1 is being taken over, so a stray path must still get that.
	w, got := moonCall(t, "GET", "/v1/status")

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	if got["status"] != "available" {
		t.Fatalf("body %v -- non-moon paths must keep the service-status answer", got)
	}
}

func TestMoonStatusComesFromTheIdentity(t *testing.T) {
	for slug, want := range map[string]int{
		moonNotFound:         404,
		moonMethodNotAllowed: 405,
		moonInvalidToken:     401,
		moonOverTheTimeLimit: 409,
		moonDevicesMaxed:     400,
		moonInternalError:    500,
		"nonsense":           500,
	} {
		w := httptest.NewRecorder()
		moonError(w, slug)
		if w.Code != want {
			t.Fatalf("%s -> %d, want %d", slug, w.Code, want)
		}
	}
}

// ---------- the pairing store ----------

func pctlStore(t *testing.T) *Store {
	t.Helper()
	// The guessing cap is process-wide, so every test starts with a clean minute
	// rather than inheriting the previous one's misses.
	pctlSearchMisses.Lock()
	pctlSearchMisses.window, pctlSearchMisses.n = time.Now(), 0
	pctlSearchMisses.Unlock()
	return &Store{path: filepath.Join(t.TempDir(), "store.json")}
}

func TestPairingCodeIsGoodOnceAndOnlyBeforeItExpires(t *testing.T) {
	st := pctlStore(t)
	d := st.PctlNewPairing("acct-parent")

	if got := st.PctlByPairingCode(d.PairingCode); got == nil || got.MoonID != d.MoonID {
		t.Fatalf("a live code must find its record")
	}
	if st.PctlByPairingCode("NOTACODE") != nil {
		t.Fatalf("an unknown code found a record")
	}

	// Activation burns it: a second console must not be able to walk in on the
	// same code.
	if st.PctlActivate(d.Hex(), "cert-aaaaaaaaaaaaaaaa") == nil {
		t.Fatalf("activation with the record's own console failed")
	}
	if st.PctlByPairingCode(d.PairingCode) != nil {
		t.Fatalf("the code still resolves after activation")
	}
	if st.PctlByDauth("cert-aaaaaaaaaaaaaaaa") == nil {
		t.Fatalf("the activated console cannot be found by its bearer's device id")
	}
	// Retry of the same activation is fine; a different console is not.
	if st.PctlActivate(d.Hex(), "cert-aaaaaaaaaaaaaaaa") == nil {
		t.Fatalf("re-activating the same console must be idempotent, not a loss")
	}
	if st.PctlActivate(d.Hex(), "cert-bbbbbbbbbbbbbbbb") != nil {
		t.Fatalf("a second console took over an activated record")
	}
}

func TestExpiredPairingCodeIsNotAWayIn(t *testing.T) {
	st := pctlStore(t)
	d := st.PctlNewPairing("")
	d.PairingExpires = time.Now().Add(-time.Second).Unix()

	if st.PctlByPairingCode(d.PairingCode) != nil {
		t.Fatalf("an expired code still paired")
	}
	if st.PctlActivate(d.Hex(), "") != nil {
		t.Fatalf("activation with no device id must refuse")
	}
}

func TestSettingETagTracksTheDocument(t *testing.T) {
	st := pctlStore(t)
	d := st.PctlNewPairing("acct-parent")

	// The store hands back the live record, so hold the tag as a string: reading
	// it off the pointer later would only ever show the newest value.
	first := st.PctlSetSetting(d.Hex(), map[string]any{"ratingAge": 12, "snsPostRestriction": true}).ETag
	if first == "" {
		t.Fatalf("a stored setting must carry an ETag -- the console's If-None-Match has nothing to compare otherwise")
	}
	// Same document, keys written the other way round: the validator must not
	// move, or every poll re-downloads.
	same := st.PctlSetSetting(d.Hex(), map[string]any{"snsPostRestriction": true, "ratingAge": 12}).ETag
	if same != first {
		t.Fatalf("ETag moved for an unchanged document: %s -> %s", first, same)
	}
	changed := st.PctlSetSetting(d.Hex(), map[string]any{"ratingAge": 18, "snsPostRestriction": true}).ETag
	if changed == first {
		t.Fatalf("ETag stayed put while the document changed -- the console would keep the old restriction")
	}
	if st.PctlSetSetting("0000000000000000", map[string]any{}) != nil {
		t.Fatalf("a setting was stored against a device that does not exist")
	}
}

func TestPairingRouteMintsACodeTheConsoleCouldType(t *testing.T) {
	s := &server{store: pctlStore(t)}
	r := httptest.NewRequest("POST", "/internal/pctl/pairing", strings.NewReader(`{"account_id":"acct-parent"}`))
	w := httptest.NewRecorder()
	s.pctlPairing(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var got struct {
		MoonID string `json:"moon_id"`
		Code   string `json:"pairing_code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body: %v", err)
	}
	if len(got.MoonID) != 16 {
		t.Fatalf("moon_id %q -- the console's paths spell it as 16 hex digits", got.MoonID)
	}
	// The console's entry field takes six digits and nothing else, so a letter
	// here is a code nobody can type (hardware, 2026-09-27).
	if len(got.Code) != pctlPairingCodeDigits || strings.TrimFunc(got.Code, unicode.IsDigit) != "" {
		t.Fatalf("code %q -- must be exactly %d digits", got.Code, pctlPairingCodeDigits)
	}
	if s.store.PctlByPairingCode(got.Code) == nil {
		t.Fatalf("the minted code does not resolve in the store")
	}
}

func TestMovieIsA404UntilOneIsConfigured(t *testing.T) {
	t.Setenv("PCTL_MOVIE", "")
	s := &server{}
	r := httptest.NewRequest("GET", "http://parentalcontrols-movie-lp1.cdn.nintendo.net/default/switchpc_en.mp4", nil)
	r.Host = "parentalcontrols-movie-lp1.cdn.nintendo.net"
	w := httptest.NewRecorder()
	s.pctlMovie(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 while no clip is configured", w.Code)
	}

	dir := t.TempDir()
	clip := filepath.Join(dir, "switchpc_en.mp4")
	os.WriteFile(clip, []byte("not really an mp4, but a body with a length"), 0o600)
	t.Setenv("PCTL_MOVIE", clip)
	w = httptest.NewRecorder()
	s.pctlMovie(w, r)
	if w.Code != http.StatusOK || w.Body.Len() == 0 {
		t.Fatalf("status %d, %d bytes -- a configured clip must be served", w.Code, w.Body.Len())
	}
	if ct := w.Header().Get("Content-Type"); ct != "video/mp4" {
		t.Fatalf("Content-Type %q", ct)
	}
}

func TestDeviceListIsScopedAndHidesADeadCode(t *testing.T) {
	st := pctlStore(t)
	mine := st.PctlNewPairing("acct-parent")
	st.PctlNewPairing("acct-someone-else")

	s := &server{store: st}
	list := func() []map[string]any {
		r := httptest.NewRequest("GET", "/internal/pctl/devices?account_id=acct-parent", nil)
		w := httptest.NewRecorder()
		s.pctlDeviceList(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d", w.Code)
		}
		var got struct {
			Devices []map[string]any `json:"devices"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("body: %v", err)
		}
		return got.Devices
	}

	devices := list()
	if len(devices) != 1 {
		t.Fatalf("%d devices -- another account's record leaked into this list", len(devices))
	}
	if devices[0]["pairing_code"] != mine.PairingCode {
		t.Fatalf("a live code must be shown: %v", devices[0]["pairing_code"])
	}
	if devices[0]["paired"] != false {
		t.Fatalf("an unclaimed record must not read as paired")
	}

	// Expired: the record stays, the code does not travel -- a dead code on a
	// screen is worse than none, because someone types it.
	mine.PairingExpires = time.Now().Add(-time.Minute).Unix()
	if _, shown := list()[0]["pairing_code"]; shown {
		t.Fatalf("an expired code was still sent to the app")
	}

	st.PctlActivate(mine.Hex(), "cert-aaaaaaaaaaaaaaaa")
	if list()[0]["paired"] != true {
		t.Fatalf("an activated record must read as paired")
	}

	r := httptest.NewRequest("GET", "/internal/pctl/devices", nil)
	w := httptest.NewRecorder()
	s.pctlDeviceList(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d -- a list with no account would be every household's", w.Code)
	}
}

// ---------- the console's own flow ----------

// moonServer is a server a console can actually talk to: the bearer on every
// moon request is a dauth device token this key signed, so it needs one.
func moonServer(t *testing.T) (*server, func(device string) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{key: key, idKid: "test-kid", store: pctlStore(t)}
	return s, func(device string) string { return deviceTokenFor(s, device) }
}

func moonReq(t *testing.T, s *server, method, path, token, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, "https://api-lp1.pctl.srv.nintendo.net"+path, strings.NewReader(body))
	r.Host = "api-lp1.pctl.srv.nintendo.net"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.moon(w, r, []byte(body))
	out := map[string]any{}
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &out)
	}
	return w, out
}

// The whole pairing walk, in the order the console's executors run it.
func TestAConsolePairsAndSyncs(t *testing.T) {
	s, token := moonServer(t)
	tok := token("cert-aaaaaaaaaaaaaaaa")
	minted := s.store.PctlNewPairing("acct-parent")

	// 1. RequestPairing: find the record by the code typed on the console.
	_, found := moonReq(t, s, "GET", "/moon/v1/devices?filter.links.pairingCode.code.$eq="+minted.PairingCode, tok, "")
	items, _ := found["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("search found %v", found)
	}
	// A hex string of at most sixteen digits: pctl's search table types `id`
	// as a string and parses it base 16. A number aborts the parse (2142-0234).
	id, ok := items[0].(map[string]any)["id"].(string)
	if !ok {
		t.Fatalf("id %#v is not a JSON string -- pctl's parse table refuses anything else", items[0].(map[string]any)["id"])
	}
	if parsed, err := strconv.ParseUint(id, 16, 64); err != nil || len(id) > 16 || parsed != minted.MoonID {
		t.Fatalf("id %q does not parse base 16 to %d", id, minted.MoonID)
	}
	if id != minted.Hex() {
		t.Fatalf("id is %q, want %q -- the console asks with %%016llx of it", id, minted.Hex())
	}

	// 2. AuthorizePairing/activate: the console claims it, using the id our own
	// answer gave it.
	if w, _ := moonReq(t, s, "POST", "/moon/v1/devices/"+id+"/activate", tok, "{}"); w.Code != 200 {
		t.Fatalf("activate status %d", w.Code)
	}
	if got := s.store.PctlByDauth("cert-aaaaaaaaaaaaaaaa"); got == nil {
		t.Fatalf("activation did not bind the console")
	}

	// 3. RetrieveSettings: an empty document means no restrictions, and it
	// carries an ETag so the next poll can be a 304.
	w, doc := moonReq(t, s, "GET", "/moon/v1/devices/"+id+"/parental_control_setting", tok, "")
	etag := w.Header().Get("ETag")
	if w.Code != 200 || etag == "" {
		t.Fatalf("setting status %d etag %q", w.Code, etag)
	}
	// Nothing was set by a parent, so the document states "nothing restricted"
	// in full. An empty one is what the console answered 2142-0234 to: its check
	// refuses when the allowed age is unset (hardware, 2026-09-27).
	// The names and the nesting are the moon document's, not the local
	// savedata's: `safetyLevel` and the `is...Restricted` booleans belong to the
	// other schema, and the console refused a document built from those.
	// NONE: the restriction check permits everything while the state is empty,
	// and a level meaning "custom rules" is what fills it (four hardware rounds).
	if doc["functionalRestrictionLevel"] != "NONE" {
		t.Fatalf("default level %v -- a record nobody has restricted must not read as restricted", doc["functionalRestrictionLevel"])
	}
	age, _ := doc["customSettings"].(map[string]any)["ageRestriction"].(map[string]any)
	if age["ratingAge"] != float64(18) || age["restriction"] != "UNRESTRICTED" {
		t.Fatalf("ageRestriction %v -- an unset age is the branch that returns 2142-0234", age)
	}

	// 4. The same poll again, with the validator: no body, no restriction churn.
	r := httptest.NewRequest("GET", "https://api-lp1.pctl.srv.nintendo.net/moon/v1/devices/"+id+"/parental_control_setting", nil)
	r.Host = "api-lp1.pctl.srv.nintendo.net"
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	s.moon(w, r, nil)
	if w.Code != http.StatusNotModified {
		t.Fatalf("status %d, want 304 -- an unchanged document must not be re-sent every poll", w.Code)
	}

	// 5. A parent sets a limit: the ETag moves, so the console's next poll is a
	// 200 with the new document.
	s.store.PctlSetSetting(id, map[string]any{
		"functionalRestrictionLevel": "CUSTOM",
		"customSettings":             map[string]any{"ageRestriction": map[string]any{"restriction": "RESTRICTED", "ratingAge": 12}},
	})
	w, doc = moonReq(t, s, "GET", "/moon/v1/devices/"+id+"/parental_control_setting", tok, "")
	if w.Header().Get("ETag") == etag {
		t.Fatalf("ETag did not move after a parent changed the setting")
	}
	if got := doc["customSettings"].(map[string]any)["ageRestriction"].(map[string]any)["ratingAge"]; got != float64(12) {
		t.Fatalf("doc %v", doc)
	}
	// The body names its own validator and time, as the parse table expects.
	if doc["etag"] != w.Header().Get("ETag") || doc["updatedAt"] == nil {
		t.Fatalf("doc %v carries no etag/updatedAt", doc)
	}

	// 6. Owners and events, the two writes the console makes on its own.
	if w, _ := moonReq(t, s, "PUT", "/moon/v1/devices/"+id+"/owners/bbbbbbbbbbbb0001", tok, "{}"); w.Code != 200 {
		t.Fatalf("owner link status %d", w.Code)
	}
	_, owners := moonReq(t, s, "GET", "/moon/v1/devices/"+id+"/owners", tok, "")
	if owners["count"] != float64(1) {
		t.Fatalf("owners %v", owners)
	}
	owner := owners["items"].([]any)[0].(map[string]any)
	if owner["deviceId"] != id || owner["user"].(map[string]any)["nintendoAccountId"] != "bbbbbbbbbbbb0001" {
		t.Fatalf("owner %v is not {deviceId, user{nintendoAccountId}} in hex strings", owner)
	}
	if w, _ := moonReq(t, s, "POST", "/moon/v1/devices/"+id+"/events", tok, `{"items":[{"eventType":"AppEvent"}]}`); w.Code != 200 {
		t.Fatalf("events status %d", w.Code)
	}
	if got := s.store.PctlByMoonID(id); len(got.Events) != 1 {
		t.Fatalf("%d events held", len(got.Events))
	}
}

func TestAnotherConsoleCannotReadOrTakeAPairedRecord(t *testing.T) {
	s, token := moonServer(t)
	mine, theirs := token("cert-aaaaaaaaaaaaaaaa"), token("cert-bbbbbbbbbbbbbbbb")
	d := s.store.PctlNewPairing("acct-parent")
	id := d.Hex()

	if w, _ := moonReq(t, s, "POST", "/moon/v1/devices/"+id+"/activate", mine, "{}"); w.Code != 200 {
		t.Fatalf("first activate %d", w.Code)
	}
	// A second console with a valid token of its own: the record is not its.
	if w, got := moonReq(t, s, "POST", "/moon/v1/devices/"+id+"/activate", theirs, "{}"); w.Code != http.StatusForbidden {
		t.Fatalf("second activate %d %v -- a claimed record must not change hands", w.Code, got)
	}
	if w, _ := moonReq(t, s, "GET", "/moon/v1/devices/"+id+"/parental_control_setting", theirs, ""); w.Code != http.StatusForbidden {
		t.Fatalf("stranger read %d -- one household would read another's restrictions", w.Code)
	}
	// No bearer at all is not a way in either.
	if w, _ := moonReq(t, s, "GET", "/moon/v1/devices/"+id, "", ""); w.Code != http.StatusForbidden {
		t.Fatalf("anonymous read %d", w.Code)
	}
}

// The id shape is the one thing the firmware's strings could not settle (study
// §7 P2): the path is `%016llx`, but whether the console re-renders our number
// as decimal is unproven. Both resolve, so a wrong guess costs a log line and
// not a failed pairing.
func TestADeviceIdResolvesInEitherSpelling(t *testing.T) {
	s, token := moonServer(t)
	tok := token("cert-aaaaaaaaaaaaaaaa")
	d := s.store.PctlNewPairing("acct-parent")

	if got := s.store.PctlByMoonID(d.Hex()); got == nil {
		t.Fatalf("hex id did not resolve")
	}
	decimal := strconv.FormatUint(d.MoonID, 10)
	if got := s.store.PctlByMoonID(decimal); got == nil {
		t.Fatalf("decimal id %q did not resolve", decimal)
	}
	if w, _ := moonReq(t, s, "POST", "/moon/v1/devices/"+decimal+"/activate", tok, "{}"); w.Code != 200 {
		t.Fatalf("activate by decimal id %d", w.Code)
	}
}

func TestPairingCodesAreTypableAndSpreadAcrossTheSpace(t *testing.T) {
	seen := map[string]int{}
	first := map[byte]int{}
	for i := 0; i < 300; i++ {
		c := pctlPairingCode()
		if len(c) != pctlPairingCodeDigits || strings.TrimFunc(c, unicode.IsDigit) != "" {
			t.Fatalf("code %q is not %d digits", c, pctlPairingCodeDigits)
		}
		seen[c]++
		first[c[0]]++
	}
	if len(seen) < 295 {
		t.Fatalf("%d distinct codes in 300 -- too many collisions for a million-wide space", len(seen))
	}
	// Leading zeros must survive, and the first digit must not favour a slice of
	// the range: modulo over random bytes would show up here.
	if len(first) < 8 {
		t.Fatalf("first digit only took %d of 10 values across 300 codes", len(first))
	}
}

func TestBlindGuessingIsCapped(t *testing.T) {
	st := pctlStore(t)
	mine := st.PctlNewPairing("acct-parent")
	s := &server{store: st}

	search := func(code string) map[string]any {
		r := httptest.NewRequest("GET", "https://api-lp1.pctl.srv.nintendo.net/moon/v1/devices?filter.links.pairingCode.code.$eq="+code, nil)
		r.Host = "api-lp1.pctl.srv.nintendo.net"
		w := httptest.NewRecorder()
		s.moon(w, r, nil)
		out := map[string]any{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}

	// A household's own mistakes stay well inside the budget.
	for i := 0; i < pctlSearchMissBudget; i++ {
		search(fmt.Sprintf("%06d", i))
	}
	// Past it, even the right code is refused for the rest of the minute: the
	// guesser learns nothing, and the parent can mint another in a moment.
	if got := search(mine.PairingCode); got["count"] != float64(0) {
		t.Fatalf("a real code answered %v while throttled -- enumeration would walk the whole space", got)
	}

	// The window is what lifts it, so a later minute works again.
	pctlSearchMisses.Lock()
	pctlSearchMisses.window = time.Now().Add(-2 * time.Minute)
	pctlSearchMisses.Unlock()
	if got := search(mine.PairingCode); got["count"] != float64(1) {
		t.Fatalf("after the window the real code must resolve: %v", got)
	}
}

// The id must survive a reader that keeps JSON numbers in a double: past 2^53
// the console would round it and ask for a device that does not exist.
func TestDeviceIdsStayExactInADouble(t *testing.T) {
	for i := 0; i < 200; i++ {
		id := randU64()
		if id > 1<<53 {
			t.Fatalf("id %d is past the exact range of a double", id)
		}
		if float64(id) != float64(uint64(float64(id))) || uint64(float64(id)) != id {
			t.Fatalf("id %d does not round-trip through a double", id)
		}
		if len(fmt.Sprintf("%016x", id)) != 16 {
			t.Fatalf("id %d is not sixteen hex digits", id)
		}
	}
}

// The device object carries what pctl's own strings name and nothing else. The
// build that added an `id` key beside `deviceId` came back as 2142-0234 with no
// request behind it -- a parse, not a network failure -- so an unknown field is
// treated as a fault here rather than as harmless generosity.
func TestTheDeviceObjectHasNoFieldPctlDoesNotName(t *testing.T) {
	st := pctlStore(t)
	d := st.PctlNewPairing("acct-parent")
	obj := moonDeviceObj(d)

	// Every name here appears in pctl's rodata (the docs-repo study, §4).
	// Every name here is one pctl's own field tables carry (the docs-repo study;
	// the device table reads language, region, serialNumber, firmwareVersion,
	// displayedVersion, internalVersion, activated, lastOnlineCheckedAt,
	// parentalControlSetting, unlockCode).
	known := map[string]bool{
		"deviceId": true, "nickname": true, "pairingActive": true, "updatedAt": true,
		"etag": true, "owners": true, "synchronizedAt": true, "links": true,
		"activated": true, "unlockCode": true, "parentalControlSetting": true,
		// `id` is what the console actually reads the device id from: the build
		// without it asked for /devices/0000000000000000/owners. A hex string.
		"id": true,
	}
	for k := range obj {
		if !known[k] {
			t.Fatalf("field %q is not one pctl names -- it is what 2142-0234 looked like", k)
		}
	}
	if _, ok := obj["deviceId"].(uint64); !ok {
		t.Fatalf("deviceId is %T, must stay a number", obj["deviceId"])
	}
}

// The console lifts a restriction with an eight-digit code: pctl copies at most
// eight bytes into its PIN slot and validates the eighth as a digit.
func TestUnlockCodesAreEightDigits(t *testing.T) {
	st := pctlStore(t)
	for i := 0; i < 50; i++ {
		d := st.PctlNewPairing(fmt.Sprintf("acct-%d", i))
		if len(d.UnlockCode) != 8 || strings.TrimFunc(d.UnlockCode, unicode.IsDigit) != "" {
			t.Fatalf("unlock code %q is not eight digits", d.UnlockCode)
		}
	}
}

// The embedded setting and the polled document are the same thing: two answers
// would mean the console applying one and the app editing the other.
func TestTheEmbeddedSettingIsThePolledOne(t *testing.T) {
	st := pctlStore(t)
	d := st.PctlNewPairing("acct-parent")
	st.PctlSetSetting(d.Hex(), map[string]any{"functionalRestrictionLevel": "OLDER_TEENS"})

	obj := moonDeviceObj(st.PctlByMoonID(d.Hex()))
	embedded, _ := obj["parentalControlSetting"].(map[string]any)
	if embedded["functionalRestrictionLevel"] != "OLDER_TEENS" {
		t.Fatalf("embedded setting %v is not what the parent stored", embedded)
	}
}

// A stored document is served only in the shape the console parses: a wrong
// type on a key it knows ends its parse as 2142-0234, so that part is dropped,
// and a document with no level at all falls back to the default.
func TestAStoredSettingIsServedInTheParsedShape(t *testing.T) {
	got := pctlConform(map[string]any{
		"functionalRestrictionLevel": "CUSTOM",
		"safetyLevel":                "CHILDREN", // the serialiser's name
		"customSettings": map[string]any{
			"snsPostRestriction": map[string]any{"restriction": "RESTRICTED"}, // object where a string is parsed
			"vrRestriction":      "SOMETIMES",                                 // not in the enum
			"ratingOrganization": "USK",
			"ageRestriction":     map[string]any{"ratingAge": float64(300)},
			"ugcRestriction": map[string]any{"applications": map[string]any{
				"0100abcd12340000": map[string]any{"restriction": "RESTRICTED"},
			}},
		},
	}, pctlSettingSchema).(map[string]any)
	want := map[string]any{
		"functionalRestrictionLevel": "CUSTOM",
		"customSettings": map[string]any{
			"ratingOrganization": "USK",
			"ageRestriction":     map[string]any{},
			"ugcRestriction": map[string]any{"applications": map[string]any{
				"0100abcd12340000": map[string]any{"restriction": "RESTRICTED"},
			}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}

	st := pctlStore(t)
	d := st.PctlNewPairing("acct-parent")
	st.PctlSetSetting(d.Hex(), map[string]any{"safetyLevel": "CHILDREN"})
	if !reflect.DeepEqual(pctlSettingOf(st.PctlByMoonID(d.Hex())), pctlDefaultSetting()) {
		t.Fatalf("a document with no level must be served as the default")
	}
}

// Before activate the console asks whose record it found; refusing that is
// 2142-2008 (hardware, v0.41.0). The answer names the account that minted the
// code, and a claimed record still answers only its own console.
func TestOwnersAnswerBeforeActivation(t *testing.T) {
	s, token := moonServer(t)
	d := s.store.PctlNewPairing("acct-parent")
	w, owners := moonReq(t, s, "GET", "/moon/v1/devices/"+d.Hex()+"/owners", token("cert-aaaaaaaaaaaaaaaa"), "")
	if w.Code != 200 || owners["count"] != float64(1) {
		t.Fatalf("status %d, owners %v", w.Code, owners)
	}
	na, _ := owners["items"].([]any)[0].(map[string]any)["user"].(map[string]any)["nintendoAccountId"].(string)
	if !pctlHexID(na) {
		t.Fatalf("owner id %q is not hex", na)
	}
	if w, _ := moonReq(t, s, "GET", "/moon/v1/devices/"+d.Hex()+"/owners", "", ""); w.Code != 403 {
		t.Fatalf("no token: status %d, want 403", w.Code)
	}
	s.store.PctlActivate(d.Hex(), "cert-aaaaaaaaaaaaaaaa")
	if w, _ := moonReq(t, s, "GET", "/moon/v1/devices/"+d.Hex()+"/owners", token("cert-bbbbbbbbbbbbbbbb"), ""); w.Code != 403 {
		t.Fatalf("another console: status %d, want 403", w.Code)
	}
}

// The default setting matches the console's typed parse table (pctl 22.5.0,
// vaddr 0x13c8c0): a wrong JSON type on a key it knows ends the parse as
// 2142-0234.
func TestTheDefaultSettingHasTheTypesPctlParses(t *testing.T) {
	custom := pctlDefaultSetting()["customSettings"].(map[string]any)
	for _, k := range []string{"snsPostRestriction", "ratingOrganization", "vrRestriction"} {
		if _, ok := custom[k].(string); !ok {
			t.Fatalf("customSettings.%s is %T, the console parses a string", k, custom[k])
		}
	}
	ugc := custom["ugcRestriction"].(map[string]any)
	if _, ok := ugc["applications"].(map[string]any); !ok {
		t.Fatalf("ugcRestriction.applications is %T, the console parses an object keyed by title id", ugc["applications"])
	}
	if age := custom["ageRestriction"].(map[string]any)["ratingAge"]; age != 18 {
		t.Fatalf("ratingAge %v", age)
	}
}

// The activate body is the console's own state, in the shape hardware sent it
// (v0.42.0): its setting is kept, and its PIN replaces the minted one.
func TestActivateKeepsTheConsolesSettingAndPin(t *testing.T) {
	s, token := moonServer(t)
	d := s.store.PctlNewPairing("acct-parent")
	body := `{"activated":true,"parentalControlSetting":{"unlockCode":"8759","functionalRestrictionLevel":"NONE",
		"customSettings":{"ageRestriction":{"restriction":"UNRESTRICTED","ratingAge":2},
		"ugcRestriction":{"restriction":"UNRESTRICTED","applications":{"0100B3C014BDA000":{"applicationId":"0100B3C014BDA000","restriction":"RESTRICTED"}}},
		"snsPostRestriction":"UNRESTRICTED","ratingOrganization":"PEGI_BBFC","vrRestriction":"UNRESTRICTED"}}}`
	if w, _ := moonReq(t, s, "POST", "/moon/v1/devices/"+d.Hex()+"/activate", token("cert-aaaaaaaaaaaaaaaa"), body); w.Code != 200 {
		t.Fatalf("activate status %d", w.Code)
	}
	got := s.store.PctlByMoonID(d.Hex())
	if got.UnlockCode != "8759" {
		t.Fatalf("unlock code %q, want the console's own", got.UnlockCode)
	}
	custom := pctlSettingOf(got)["customSettings"].(map[string]any)
	if custom["ratingOrganization"] != "PEGI_BBFC" || custom["ageRestriction"].(map[string]any)["ratingAge"] != 2 {
		t.Fatalf("served setting %v is not the console's", custom)
	}
}

// The console shows the owner's nickname as the parent, so it is the name of
// the account that minted the code, within the 32 bytes the console copies.
func TestTheOwnerIsNamedAfterTheParentAccount(t *testing.T) {
	st := pctlStore(t)
	d := st.PctlNewPairing("acct-parent")
	nick := func() string {
		return moonOwners(st.PctlByMoonID(d.Hex()), "")[0].(map[string]any)["user"].(map[string]any)["nickname"].(string)
	}
	if nick() != "OpenPak" {
		t.Fatalf("unnamed parent is %q", nick())
	}
	st.PctlNameParent(d.Hex(), " Alexis ")
	if nick() != "Alexis" {
		t.Fatalf("nickname %q", nick())
	}
	st.PctlNameParent(d.Hex(), strings.Repeat("é", 20))
	if got := nick(); len(got) > 32 || !utf8.ValidString(got) {
		t.Fatalf("nickname %q is %d bytes", got, len(got))
	}
}

// The parent's picture is a link back to this host, and the relay behind it
// forwards only a well-formed account id to the website.
func TestTheOwnerCarriesAPictureLink(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/media/avatars/10c5a846-9005-474b-8e60-494fad24bdf8/console.jpg" {
			t.Errorf("website asked for %s", r.URL.Path)
		}
		jpeg.Encode(w, image.NewRGBA(image.Rect(0, 0, 256, 256)), nil)
	}))
	defer site.Close()
	t.Setenv("WEBSITE_INTERNAL_URL", site.URL)

	resetPctlIcons(t)
	s, _ := moonServer(t)
	d := s.store.PctlNewPairing("10c5a846-9005-474b-8e60-494fad24bdf8")
	user := moonOwners(d, "api-lp1.pctl.srv.nintendo.net")[0].(map[string]any)["user"].(map[string]any)
	link, _ := user["miiUri"].(map[string]any)["small"].(string)
	if !regexp.MustCompile(`^https://api-lp1\.pctl\.srv\.nintendo\.net/moon/v1/mii/10c5a846-9005-474b-8e60-494fad24bdf8/face-[0-9a-f]{8}\.png$`).MatchString(link) || len(link) > 255 {
		t.Fatalf("link %q", link)
	}
	if icon, _ := user["iconUri"].(map[string]any)["small"].(string); icon != link {
		t.Fatalf("iconUri.small %q, miiUri.small %q -- 23.x reads the one, 22.5 the other", icon, link)
	}
	if w, _ := moonReq(t, s, "GET", strings.TrimPrefix(link, "https://api-lp1.pctl.srv.nintendo.net"), "", ""); w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("picture status %d type %q", w.Code, w.Header().Get("Content-Type"))
	} else if cfg, err := png.DecodeConfig(w.Body); err != nil || cfg.Width != 128 || cfg.Height != 128 {
		t.Fatalf("picture is %dx%d, err %v -- want a 128px PNG", cfg.Width, cfg.Height, err)
	}
	if w, _ := moonReq(t, s, "GET", "/moon/v1/mii/..%2Fadmin/face.png", "", ""); w.Code != 404 {
		t.Fatalf("a malformed account id answered %d", w.Code)
	}
}

// After pairing the console reports each of its users; refusing that was a 404
// on hardware (v0.42.0).
func TestTheConsoleReportsItsPlayers(t *testing.T) {
	s, token := moonServer(t)
	tok := token("cert-aaaaaaaaaaaaaaaa")
	d := s.store.PctlNewPairing("acct-parent")
	s.store.PctlActivate(d.Hex(), "cert-aaaaaaaaaaaaaaaa")
	path := "/moon/v1/devices/" + d.Hex() + "/players/10000000_00a10001_00000000_00000001"
	if w, _ := moonReq(t, s, "PUT", path, tok, `{"nickname":"hansolo","imageData":"/9j/4AAQ"}`); w.Code != 200 {
		t.Fatalf("player put status %d", w.Code)
	}
	if p := s.store.PctlByMoonID(d.Hex()).Players["10000000_00a10001_00000000_00000001"]; p == nil || p.Nickname != "hansolo" {
		t.Fatalf("player %v", p)
	}
	if w, _ := moonReq(t, s, "DELETE", path, tok, ""); w.Code != 204 || len(s.store.PctlByMoonID(d.Hex()).Players) != 0 {
		t.Fatalf("player delete status %d", w.Code)
	}
}

// A console unlinks by deleting its owners; the record must stop being a
// paired console when the last one goes (hardware, v0.43.0).
func TestDeletingTheLastOwnerUnlinks(t *testing.T) {
	s, token := moonServer(t)
	tok := token("cert-aaaaaaaaaaaaaaaa")
	d := s.store.PctlNewPairing("acct-parent")
	s.store.PctlActivate(d.Hex(), "cert-aaaaaaaaaaaaaaaa")
	_, owners := moonReq(t, s, "GET", "/moon/v1/devices/"+d.Hex()+"/owners", tok, "")
	na := owners["items"].([]any)[0].(map[string]any)["user"].(map[string]any)["nintendoAccountId"].(string)
	if w, _ := moonReq(t, s, "DELETE", "/moon/v1/devices/"+d.Hex()+"/owners/"+na, tok, ""); w.Code != 204 {
		t.Fatalf("owner delete status %d", w.Code)
	}
	// The record goes, not just the binding: re-pairing starts fresh and the
	// parent's list stops showing the console.
	if got := s.store.PctlByMoonID(d.Hex()); got != nil {
		t.Fatalf("record is still held, bound to %q", got.DauthID)
	}
	if n := len(s.store.PctlDevicesFor("acct-parent")); n != 0 {
		t.Fatalf("the parent still lists %d consoles", n)
	}
}

// The receipt POST after a setting GET is the console naming what it holds.
// It is kept, its PIN replaces a minted one, and a parent-side change makes the
// record read as not synced until the next receipt.
func TestTheReceiptIsKeptAndThePinComesFromTheConsole(t *testing.T) {
	s, token := moonServer(t)
	tok := token("cert-aaaaaaaaaaaaaaaa")
	d := s.store.PctlNewPairing("acct-parent")
	s.store.PctlActivate(d.Hex(), "cert-aaaaaaaaaaaaaaaa")
	list := func() map[string]any {
		r := httptest.NewRequest("GET", "/internal/pctl/devices?account_id=acct-parent", nil)
		w := httptest.NewRecorder()
		s.pctlDeviceList(w, r)
		var got struct {
			Devices []map[string]any `json:"devices"`
		}
		json.Unmarshal(w.Body.Bytes(), &got)
		return got.Devices[0]
	}
	// A record paired before activate was kept holds a minted code, which
	// unlocks nothing: the parent is not shown it.
	if _, shown := list()["unlock_code"]; shown {
		t.Fatalf("a minted code was shown as the console's PIN")
	}

	w, _ := moonReq(t, s, "GET", "/moon/v1/devices/"+d.Hex()+"/parental_control_setting", tok, "")
	etag := w.Header().Get("ETag")
	receipt := `{"synchronizedUnlockCode":"4321","synchronizedParentalControlSetting":{"synchronizedEtag":` +
		strconv.Quote(etag) + `,"synchronizedAt":1790512000}}`
	if w, _ := moonReq(t, s, "POST", "/moon/v1/devices/"+d.Hex(), tok, receipt); w.Code != 200 {
		t.Fatalf("receipt status %d", w.Code)
	}
	got := list()
	if got["unlock_code"] != "4321" || got["synced"] != true || got["synced_at"] != float64(1790512000) {
		t.Fatalf("after the receipt: pin %v synced %v at %v", got["unlock_code"], got["synced"], got["synced_at"])
	}
	if got["setting"].(map[string]any)["functionalRestrictionLevel"] != "NONE" {
		t.Fatalf("setting %v is not the served one", got["setting"])
	}

	s.store.PctlSetSetting(d.Hex(), map[string]any{"functionalRestrictionLevel": "CHILDREN"})
	if list()["synced"] != false {
		t.Fatalf("a changed document still reads as held by the console")
	}
}

// A player's picture goes only to the account that manages the console, and
// another account cannot tell the record exists.
func TestAPlayerImageIsTheManagingAccountsOnly(t *testing.T) {
	s := &server{store: pctlStore(t)}
	d := s.store.PctlNewPairing("acct-parent")
	s.store.PctlSetPlayer(d.Hex(), "10000000_00a10001", &PctlPlayer{Nickname: "hansolo", ImageData: "/9j/2Q=="})
	get := func(account string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/internal/pctl/devices/"+d.Hex()+"/players/10000000_00a10001/image?account_id="+account, nil)
		w := httptest.NewRecorder()
		s.pctlDeviceRoute(w, r)
		return w
	}
	if w := get("acct-parent"); w.Code != 200 || w.Header().Get("Content-Type") != "image/jpeg" || w.Body.String() != "\xff\xd8\xff\xd9" {
		t.Fatalf("own image: status %d type %q body %q", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	if w := get("acct-someone-else"); w.Code != 404 {
		t.Fatalf("another account got %d, want 404", w.Code)
	}
	if w := get(""); w.Code != 404 {
		t.Fatalf("no account got %d, want 404", w.Code)
	}
}

// Uploads are JSON arrays of events. They are held one event each, 30 days, and
// a store from before that change -- whole uploads -- still reads. Wrong-PIN
// attempts come out newest first; anything not shaped like an event adds none.
func TestEventsAgeOutAndWrongPinsAreListed(t *testing.T) {
	st := pctlStore(t)
	d := st.PctlNewPairing("acct-parent")
	now := time.Now().Unix()
	old := now - 31*24*3600
	// As v0.44.0 stored it: one entry per upload.
	d.Events = []json.RawMessage{json.RawMessage(fmt.Sprintf(
		`[{"eventType":"DID_WRONG_UNLOCK_CODE","eventTimestamp":%d},{"eventType":"IDLE","eventTimestamp":%d}]`, now-60, now-50))}
	if got := st.PctlWrongUnlocks(d.Hex()); !reflect.DeepEqual(got, []int64{now - 60}) {
		t.Fatalf("from a whole upload: %v", got)
	}

	st.PctlAddEvents(d.Hex(), []byte(fmt.Sprintf(
		`[{"eventType":"DID_WRONG_UNLOCK_CODE","eventTimestamp":%d},{"eventType":"DID_WRONG_UNLOCK_CODE","eventTimestamp":%d}]`, now-10, old)))
	st.PctlAddEvents(d.Hex(), []byte(`{"not":"an array"}`))
	st.PctlAddEvents(d.Hex(), []byte(`[1, "two"]`))
	if got := st.PctlWrongUnlocks(d.Hex()); !reflect.DeepEqual(got, []int64{now - 10, now - 60}) {
		t.Fatalf("wrong-PIN attempts %v, want the two inside 30 days, newest first", got)
	}
	// 2 kept from the old upload, 1 new inside the window, the object, and the
	// two stray array elements: the 31-day-old one is gone.
	if n := len(st.PctlByMoonID(d.Hex()).Events); n != 6 {
		t.Fatalf("%d events held", n)
	}
}

// The parent's write: refused whole rather than thinned, for the managing
// account only, and a code of the console's own shape.
func TestTheParentSettingIsRefusedRatherThanThinned(t *testing.T) {
	s := &server{store: pctlStore(t)}
	d := s.store.PctlNewPairing("acct-parent")
	put := func(account, body string) (*httptest.ResponseRecorder, map[string]any) {
		r := httptest.NewRequest("PUT", "/internal/pctl/devices/"+d.Hex()+"/setting?account_id="+account, strings.NewReader(body))
		w := httptest.NewRecorder()
		s.pctlDeviceRoute(w, r)
		out := map[string]any{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return w, out
	}
	good := `{"setting":{"functionalRestrictionLevel":"CUSTOM","customSettings":{"ageRestriction":{"restriction":"RESTRICTED","ratingAge":3}}}}`
	if w, _ := put("acct-someone-else", good); w.Code != 404 {
		t.Fatalf("another account: status %d, want 404", w.Code)
	}
	w, out := put("acct-parent", `{"setting":{"functionalRestrictionLevel":"CUSTOM","customSettings":{"snsPostRestriction":{"restriction":"RESTRICTED"}}}}`)
	if w.Code != 400 || !strings.HasSuffix(out["error"].(string), "customSettings.snsPostRestriction") {
		t.Fatalf("thinned document: status %d %v", w.Code, out)
	}
	if w, _ := put("acct-parent", `{"unlock_code":"12a4"}`); w.Code != 400 {
		t.Fatalf("bad code: status %d", w.Code)
	}
	if got := s.store.PctlByMoonID(d.Hex()); got.Setting != nil || got.UnlockCodeSet {
		t.Fatalf("a refused write stored something: %v %v", got.Setting, got.UnlockCodeSet)
	}
	w, out = put("acct-parent", good)
	if w.Code != 200 || out["etag"] != pctlServedETag(s.store.PctlByMoonID(d.Hex())) {
		t.Fatalf("good write: status %d %v", w.Code, out)
	}
}

// A console's own code is not sent back to it; a parent's is, the ETag covers
// it, and a receipt still naming the old code does not undo it.
func TestOnlyAParentSetCodeIsServed(t *testing.T) {
	s, token := moonServer(t)
	tok := token("cert-aaaaaaaaaaaaaaaa")
	d := s.store.PctlNewPairing("acct-parent")
	activate := `{"parentalControlSetting":{"unlockCode":"8759","functionalRestrictionLevel":"NONE"}}`
	moonReq(t, s, "POST", "/moon/v1/devices/"+d.Hex()+"/activate", tok, activate)
	path := "/moon/v1/devices/" + d.Hex() + "/parental_control_setting"

	w, doc := moonReq(t, s, "GET", path, tok, "")
	before := w.Header().Get("ETag")
	if _, sent := doc["unlockCode"]; sent {
		t.Fatalf("the console's own code was served back to it")
	}

	s.store.PctlSetUnlockCode(d.Hex(), "1234")
	w, doc = moonReq(t, s, "GET", path, tok, "")
	after := w.Header().Get("ETag")
	if doc["unlockCode"] != "1234" || after == before || doc["etag"] != after {
		t.Fatalf("parent code: served %v, etag %s -> %s", doc["unlockCode"], before, after)
	}
	// The tag is over the document as served, so it is what activate reports too.
	if pctlServedETag(s.store.PctlByMoonID(d.Hex())) != after {
		t.Fatalf("served etag and computed etag disagree")
	}
	r := httptest.NewRequest("GET", "https://api-lp1.pctl.srv.nintendo.net"+path, nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("If-None-Match", after)
	rec := httptest.NewRecorder()
	s.moon(rec, r, nil)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("unchanged document: status %d, want 304", rec.Code)
	}

	receipt := `{"synchronizedUnlockCode":"8759","synchronizedParentalControlSetting":{"synchronizedEtag":` + strconv.Quote(after) + `}}`
	moonReq(t, s, "POST", "/moon/v1/devices/"+d.Hex(), tok, receipt)
	if got := s.store.PctlByMoonID(d.Hex()); got.UnlockCode != "1234" || got.SyncedUnlockCode != "8759" {
		t.Fatalf("after a receipt naming the old code: code %q, reported %q", got.UnlockCode, got.SyncedUnlockCode)
	}
}

// A parent can remove a console from their list, and only their own.
func TestAParentRemovesAConsole(t *testing.T) {
	s, _ := moonServer(t)
	t.Setenv("NX_INTERNAL_KEY", "k")
	d := s.store.PctlNewPairing("acct-parent")
	del := func(account string) int {
		r := httptest.NewRequest("DELETE", "/internal/pctl/devices/"+d.Hex()+"?account_id="+account, nil)
		r.Header.Set("X-Internal-Key", "k")
		w := httptest.NewRecorder()
		s.pctlDeviceRoute(w, r)
		return w.Code
	}
	if code := del("acct-other"); code != 404 || s.store.PctlByMoonID(d.Hex()) == nil {
		t.Fatalf("another account: status %d", code)
	}
	if code := del("acct-parent"); code != 204 || s.store.PctlByMoonID(d.Hex()) != nil {
		t.Fatalf("own console: status %d, record still there: %v", code, s.store.PctlByMoonID(d.Hex()) != nil)
	}
}

// Each number has the bound the console's own handler enforces, a parent's PIN
// is exactly the four digits the console can be typed, and the PIN never
// reaches the log.
func TestBoundsPinLengthAndTheLoggedPin(t *testing.T) {
	for spec, tc := range map[string]struct{ ok, bad any }{
		"i360": {360, 361}, "i23": {23, 24}, "i59": {float64(59), 60}, "i255": {255, 256},
	} {
		if pctlConform(tc.ok, spec) == nil || pctlConform(tc.bad, spec) != nil || pctlConform(1.5, spec) != nil {
			t.Fatalf("%s: accepts %v, refuses %v and 1.5", spec, tc.ok, tc.bad)
		}
	}
	day := map[string]any{"dailyRegulations": map[string]any{"timeToPlayInOneDay": map[string]any{"enabled": true, "limitTime": 300}}}
	got := pctlConform(map[string]any{"playTimerRegulations": day}, pctlSettingSchema)
	if !reflect.DeepEqual(got, map[string]any{"playTimerRegulations": day}) {
		t.Fatalf("a five-hour limit was thinned: %v", got)
	}

	s, _ := moonServer(t)
	d := s.store.PctlNewPairing("acct-parent")
	for code, want := range map[string]int{"4827": 200, "48270": 400, "482": 400} {
		r := httptest.NewRequest("PUT", "/internal/pctl/devices/"+d.Hex()+"/setting?account_id=acct-parent", strings.NewReader(`{"unlock_code":"`+code+`"}`))
		w := httptest.NewRecorder()
		s.pctlDeviceRoute(w, r)
		if w.Code != want {
			t.Fatalf("unlock_code %q: status %d, want %d", code, w.Code, want)
		}
	}

	masked := string(pctlPinInBody.ReplaceAll([]byte(`{"synchronizedUnlockCode":"4827","a":{"unlockCode": "6816","ratingAge":2}}`), []byte(`${1}****"`)))
	if strings.Contains(masked, "4827") || strings.Contains(masked, "6816") || !json.Valid([]byte(masked)) || !strings.Contains(masked, `"ratingAge":2`) {
		t.Fatalf("masked body %s", masked)
	}
}

// Play time per day in the console's calendar, from running totals: the gain
// between events, the whole value after a restart, never more than the clock
// allows, and nothing from an event of another shape.
func TestActivityIsTheGainBetweenEventsPerConsoleDay(t *testing.T) {
	at := func(s string) int64 { // console-local time in London summer time
		tm, _ := time.Parse("2006-01-02 15:04", s)
		return tm.Unix() - 3600
	}
	ev := func(when string, elapsed int, apps string) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"eventType":"IDLE","eventTimestamp":%d,"timeZoneUtcOffsetSeconds":3600,"elapsedTime":%d,"applicationTimes":{%s}}`, at(when), elapsed, apps))
	}
	events := []json.RawMessage{
		ev("2026-09-26 21:00", 4200, `"0100B3C014BDA000":{"elapsedTime":3000},"01001B300B9BE000":{"elapsedTime":1000}`),
		ev("2026-09-10 12:00", 900, ``),
		ev("2026-09-26 20:00", 600, `"0100B3C014BDA000":{"elapsedTime":500}`), // restarted since 09-10
		ev("2026-09-27 09:00", 120, ``),                                       // restarted overnight
		ev("2026-09-27 09:01", 100000, ``),                                    // no more than the minute that passed
		json.RawMessage(`{"eventType":"IDLE","eventTimestamp":"x","elapsedTime":5}`),
		json.RawMessage(fmt.Sprintf(`{"eventTimestamp":%d,"elapsedTime":5,"applicationTimes":[]}`, at("2026-09-27 10:00"))),
		json.RawMessage(`[1]`),
	}
	now := time.Unix(at("2026-09-27 12:00"), 0)
	got, _ := json.Marshal(pctlActivity(events, 7, now))
	want := `[{"date":"2026-09-27","titles":[],"total_minutes":3},` +
		`{"date":"2026-09-26","titles":[{"anonymous_minutes":0,"minutes":50,"players":[],"title_id":"0100b3c014bda000"},` +
		`{"anonymous_minutes":0,"minutes":17,"players":[],"title_id":"01001b300b9be000"}],"total_minutes":70}]`
	if string(got) != want {
		t.Fatalf("activity\n got %s\nwant %s", got, want)
	}
	if all := pctlActivity(events, 30, now); len(all) != 3 || all[2]["date"] != "2026-09-10" || all[2]["total_minutes"] != int64(15) {
		t.Fatalf("30 days: %v", all)
	}

	s, _ := moonServer(t)
	d := s.store.PctlNewPairing("acct-parent")
	for path, want := range map[string]int{
		"/activity?account_id=acct-parent": 200, "/activity?account_id=acct-parent&days=30": 200,
		"/activity?account_id=acct-parent&days=31": 400, "/activity?account_id=acct-other": 404,
	} {
		w := httptest.NewRecorder()
		s.pctlDeviceRoute(w, httptest.NewRequest("GET", "/internal/pctl/devices/"+d.Hex()+path, nil))
		if w.Code != want || (want == 200 && w.Body.String() != "{\"days\":[]}\n") {
			t.Fatalf("%s: status %d body %q", path, w.Code, w.Body.String())
		}
	}
}

// A parent's save pushes DID_CHANGE_PARENTAL_CONTROL_SETTING to the console's
// own connection -- the one named by the token it sent at activate -- in the
// shape pctl parses; with no connection the save still succeeds.
func TestAParentSaveIsPushedToTheConsole(t *testing.T) {
	s, token := moonServer(t)
	push := &fakePenne{}
	s.penne = push
	tok := token("cert-aaaaaaaaaaaaaaaa")
	d := s.store.PctlNewPairing("acct-parent")
	moonReq(t, s, "POST", "/moon/v1/devices/"+d.Hex()+"/activate", tok,
		`{"notificationToken":"pzxi59sl","parentalControlSetting":{"functionalRestrictionLevel":"NONE"}}`)
	if got := s.store.PctlByMoonID(d.Hex()).NotificationToken; got != "pzxi59sl" {
		t.Fatalf("token kept as %q", got)
	}
	put := func() int {
		w := httptest.NewRecorder()
		s.pctlDeviceRoute(w, httptest.NewRequest("PUT", "/internal/pctl/devices/"+d.Hex()+"/setting?account_id=acct-parent", strings.NewReader(`{"unlock_code":"4827"}`)))
		return w.Code
	}
	// The push side unreachable: the save still stands.
	push.down = true
	if code := put(); code != 200 {
		t.Fatalf("with no push side: status %d", code)
	}
	push.down = false
	if code := put(); code != 200 || len(push.sent) != 1 {
		t.Fatalf("status %d, %d push(es)", code, len(push.sent))
	}
	m := push.sent[0]
	if m.PenneID != "pzxi59sl" || m.DauthUser != "cert-aaaaaaaaaaaaaaaa" || m.Receivers != "pctl" || m.Name != "DID_CHANGE_PARENTAL_CONTROL_SETTING" ||
		m.Body != `{"deviceId":"`+d.Hex()+`","eventId":"DID_CHANGE_PARENTAL_CONTROL_SETTING"}` {
		t.Fatalf("pushed %+v", m)
	}
	if masked := pctlPinInBody.ReplaceAllString(`{"unlock_code":"4827"}`, `${1}****"`); masked != `{"unlock_code":"****"}` {
		t.Fatalf("the parent's code is logged as %s", masked)
	}
}

// The console never names itself, so the parent does, and until then it goes by
// the end of the serial number printed on it.
func TestAParentNamesAConsole(t *testing.T) {
	s, token := moonServer(t)
	d := s.store.PctlNewPairing("acct-parent")
	moonReq(t, s, "POST", "/moon/v1/devices/"+d.Hex()+"/activate", token("cert-aaaaaaaaaaaaaaaa"),
		`{"serialNumber":"XKJ70000000001","firmwareVersion":{"displayedVersion":"22.5.0"}}`)
	if got := pctlConsoleName(s.store.PctlByMoonID(d.Hex())); got != "Switch ···0001" {
		t.Fatalf("unnamed console is %q", got)
	}
	put := func(account, body string) int {
		r := httptest.NewRequest("PUT", "/internal/pctl/devices/"+d.Hex()+"/name?account_id="+account, strings.NewReader(body))
		w := httptest.NewRecorder()
		s.pctlDeviceRoute(w, r)
		return w.Code
	}
	if code := put("acct-other", `{"name":"Theirs"}`); code != 404 {
		t.Fatalf("another account: status %d", code)
	}
	if code := put("acct-parent", `{"name":"`+strings.Repeat("é", 33)+`"}`); code != 400 {
		t.Fatalf("33 characters: status %d", code)
	}
	if code := put("acct-parent", `{"name":" Living room "}`); code != 204 || pctlConsoleName(s.store.PctlByMoonID(d.Hex())) != "Living room" {
		t.Fatalf("status %d, name %q", code, pctlConsoleName(s.store.PctlByMoonID(d.Hex())))
	}
	if code := put("acct-parent", `{"name":""}`); code != 204 || pctlConsoleName(s.store.PctlByMoonID(d.Hex())) != "Switch ···0001" {
		t.Fatalf("clearing the name: status %d", code)
	}
}

// Who played: the event shape is the one a console uploaded (hardware,
// 2026-09-27), and the times are running totals like the rest.
func TestActivityNamesWhoPlayed(t *testing.T) {
	ev := func(at, total, title, anon, leia int) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"eventType":"DID_APP_PLAY","eventTimestamp":%d,"timeZoneUtcOffsetSeconds":3600,
			"elapsedTime":%d,"applicationTimes":{"010065D018172000":{"elapsedTime":%d,"anonymousPlayTime":%d,
			"devicePlayers":{"10000000_00b20002_00000000_00000001":{"elapsedTime":%d}}}}}`, at, total, title, anon, leia))
	}
	base := 1790532000
	days := pctlActivity([]json.RawMessage{ev(base, 18000, 0, 0, 0), ev(base+400, 18400, 400, 21, 379), ev(base+790, 18790, 790, 21, 769)},
		7, time.Unix(int64(base+790), 0))
	if len(days) != 1 {
		t.Fatalf("days %v", days)
	}
	titles := days[0]["titles"].([]map[string]any)
	if len(titles) != 1 || titles[0]["minutes"] != int64(13) || titles[0]["anonymous_minutes"] != int64(0) {
		t.Fatalf("titles %v", titles)
	}
	who := titles[0]["players"].([]map[string]any)
	if len(who) != 1 || who[0]["id"] != "10000000_00b20002_00000000_00000001" || who[0]["minutes"] != int64(13) {
		t.Fatalf("players %v", who)
	}
}
