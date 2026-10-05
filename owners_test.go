package main

// Firmware 23.x reads the owners list differently (scratch pctl.md, 23.0.1 audit): the picture
// is `user.iconUri` and may not be null, the console re-downloads it only when the URL's last
// segment changes, and a device keeps up to five parents.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"testing"
)

// resetPctlIcons empties the picture cache, so a test sees its own website.
func resetPctlIcons(t *testing.T) {
	t.Helper()
	clear := func() {
		pctlIcons.Lock()
		pctlIcons.m = map[string]pctlIcon{}
		pctlIcons.Unlock()
	}
	clear()
	t.Cleanup(clear)
}

// fakeSite is the website's media store: one flat-colour console JPEG per account, 404 for an
// account with no picture.
type fakeSite struct {
	mu     sync.Mutex
	colour map[string]uint8
}

func newFakeSite(t *testing.T) *fakeSite {
	t.Helper()
	resetPctlIcons(t)
	f := &fakeSite{colour: map[string]uint8{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/media/avatars/"), "/console.jpg")
		f.mu.Lock()
		c, ok := f.colour[account]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		img := image.NewRGBA(image.Rect(0, 0, 256, 256))
		for i := range img.Pix {
			img.Pix[i] = c
		}
		jpeg.Encode(w, img, nil)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("WEBSITE_INTERNAL_URL", srv.URL)
	return f
}

func (f *fakeSite) set(account string, c uint8) {
	f.mu.Lock()
	f.colour[account] = c
	f.mu.Unlock()
}

// testAccount is the n-th OpenPak account id (UUID-shaped, as pctlAccountID wants).
func testAccount(n int) string {
	return "00000000-0000-4000-8000-00000000000" + string(rune('0'+n))
}

// ownersBody is the owners answer exactly as the console receives it.
func ownersBody(t *testing.T, s *server, d *PctlDevice) (string, []map[string]any) {
	t.Helper()
	w, _ := moonReq(t, s, "GET", "/moon/v1/devices/"+d.Hex()+"/owners", deviceTokenFor(s, d.DauthID), "")
	if w.Code != 200 {
		t.Fatalf("owners status %d %s", w.Code, w.Body)
	}
	var doc struct {
		Count int              `json:"count"`
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || doc.Count != len(doc.Items) {
		t.Fatalf("owners body %s (%v)", w.Body, err)
	}
	users := []map[string]any{}
	for _, it := range doc.Items {
		users = append(users, it["user"].(map[string]any))
	}
	return w.Body.String(), users
}

// pairedFor is a record managed by account, claimed by a console.
func pairedFor(t *testing.T, s *server, account string) *PctlDevice {
	t.Helper()
	d := s.store.PctlNewPairing(account)
	s.store.PctlActivate(d.Hex(), "cert-aaaaaaaaaaaaaaaa")
	return s.store.PctlByMoonID(d.Hex())
}

// The picture travels under both keys with the same object, and never as null: 23.0.1 types
// iconUri as a non-nullable object (2142-0234 on null), 22.5 reads miiUri. Every owner has its
// own name and its own picture, and one without a picture carries neither key.
func TestOwnersCarryIconUriNeverNull(t *testing.T) {
	for _, tc := range []struct {
		name    string
		parents int          // further parents beside the managing account
		without map[int]bool // owners (by index) whose account has no picture
	}{
		{"one owner with a picture", 0, nil},
		{"one owner without a picture", 0, map[int]bool{0: true}},
		{"five owners with pictures", 4, nil},
		{"five owners, two without a picture", 4, map[int]bool{0: true, 3: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := newFakeSite(t)
			s, _ := moonServer(t)
			for i := 0; i <= tc.parents; i++ {
				if !tc.without[i] {
					site.set(testAccount(i+1), uint8(30*i))
				}
			}
			d := pairedFor(t, s, testAccount(1))
			s.store.PctlNameParent(d.Hex(), "Parent 1")
			for i := 1; i <= tc.parents; i++ {
				if _, err := s.store.PctlSetParent(d.Hex(), testAccount(i+1), "Parent "+string(rune('1'+i))); err != nil {
					t.Fatal(err)
				}
			}
			body, users := ownersBody(t, s, d)
			if strings.Contains(body, "null") {
				t.Fatalf("owners carry a null: %s", body)
			}
			if len(users) != tc.parents+1 {
				t.Fatalf("%d owners, want %d", len(users), tc.parents+1)
			}
			links := map[string]bool{}
			for i, u := range users {
				if want := "Parent " + string(rune('1'+i)); u["nickname"] != want {
					t.Fatalf("owner %d is named %v, want %q", i, u["nickname"], want)
				}
				if na, _ := u["nintendoAccountId"].(string); na != pctlNaID(testAccount(i+1)) {
					t.Fatalf("owner %d id %q", i, na)
				}
				icon, hasIcon := u["iconUri"].(map[string]any)
				mii, hasMii := u["miiUri"].(map[string]any)
				if tc.without[i] {
					if _, present := u["iconUri"]; present || u["miiUri"] != nil {
						t.Fatalf("owner %d has no picture, yet names one: %v", i, u)
					}
					continue
				}
				if !hasIcon || !hasMii || icon["small"] == nil || icon["small"] != mii["small"] {
					t.Fatalf("owner %d: iconUri %v, miiUri %v: want the same {small} under both", i, u["iconUri"], u["miiUri"])
				}
				link := icon["small"].(string)
				if len(link) > 255 || !strings.Contains(link, "/mii/"+testAccount(i+1)+"/") || links[link] {
					t.Fatalf("owner %d link %q is not its own", i, link)
				}
				links[link] = true
			}
		})
	}
}

// A console keeps five parents: a sixth is refused, the managing account is not a further
// parent of its own record, and ids the console linked itself never push the list past five.
func TestAConsoleKeepsAtMostFiveParents(t *testing.T) {
	s, _ := moonServer(t)
	d := pairedFor(t, s, testAccount(1))
	put := func(account string) int {
		w := httptest.NewRecorder()
		s.pctlDeviceRoute(w, httptest.NewRequest("PUT", "/internal/pctl/devices/"+d.Hex()+"/parents/"+account+"?account_id="+testAccount(1),
			strings.NewReader(`{"display_name":"P"}`)))
		return w.Code
	}
	for _, tc := range []struct {
		name    string
		account string
		want    int
	}{
		{"second parent", testAccount(2), 204},
		{"third", testAccount(3), 204},
		{"fourth", testAccount(4), 204},
		{"fifth", testAccount(5), 204},
		{"the fifth again, renamed", testAccount(5), 204},
		{"a sixth", testAccount(6), 409},
		{"the managing account", testAccount(1), 400},
		{"not an account id", "Not-An-Account", 400},
	} {
		if got := put(tc.account); got != tc.want {
			t.Fatalf("%s: status %d, want %d", tc.name, got, tc.want)
		}
	}
	for _, na := range []string{"bbbbbbbbbbbb0001", "fa2b2acb886a4cfe"} {
		s.store.PctlAddOwner(d.Hex(), na)
	}
	if n := len(pctlOwnerList(s.store.PctlByMoonID(d.Hex()))); n != pctlMaxOwners {
		t.Fatalf("%d owners served, the console keeps %d", n, pctlMaxOwners)
	}
}

// A console unlinks by deleting every owner it was listed, in its own order; whichever goes
// first, every delete succeeds and the record is gone at the end. Taking one further parent off
// is not an unlink.
func TestUnlinkingWithFurtherParents(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order []int // owner indexes, in the order the console deletes them
	}{
		{"managing parent first", []int{0, 1, 2}},
		{"managing parent last", []int{2, 1, 0}},
		{"managing parent in the middle", []int{1, 0, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := moonServer(t)
			d := pairedFor(t, s, testAccount(1))
			s.store.PctlSetParent(d.Hex(), testAccount(2), "B")
			s.store.PctlSetParent(d.Hex(), testAccount(3), "C")
			_, users := ownersBody(t, s, d)
			tok := deviceTokenFor(s, d.DauthID)
			for _, i := range tc.order {
				w, _ := moonReq(t, s, "DELETE", "/moon/v1/devices/"+d.Hex()+"/owners/"+users[i]["nintendoAccountId"].(string), tok, "")
				if w.Code != 204 {
					t.Fatalf("delete of owner %d: status %d", i, w.Code)
				}
			}
			if s.store.PctlByMoonID(d.Hex()) != nil {
				t.Fatal("the record outlived its unlink")
			}
		})
	}
	s, _ := moonServer(t)
	d := pairedFor(t, s, testAccount(1))
	s.store.PctlSetParent(d.Hex(), testAccount(2), "B")
	moonReq(t, s, "DELETE", "/moon/v1/devices/"+d.Hex()+"/owners/"+pctlNaID(testAccount(2)), deviceTokenFor(s, d.DauthID), "")
	if got := s.store.PctlByMoonID(d.Hex()); got == nil || len(got.Parents) != 0 {
		t.Fatalf("removing one further parent: record %+v", got)
	}
}

// The console caches `icon/<naId>-<last segment>` and fetches only when that changes, so the
// segment follows the picture; and the URL answers with exactly the bytes it names.
func TestIconNameFollowsThePicture(t *testing.T) {
	site := newFakeSite(t)
	s, _ := moonServer(t)
	account := testAccount(2)
	d := pairedFor(t, s, account)
	link := func() string {
		_, users := ownersBody(t, s, d)
		return users[0]["iconUri"].(map[string]any)["small"].(string)
	}
	fetch := func(link string) []byte {
		w, _ := moonReq(t, s, "GET", strings.TrimPrefix(link, "https://api-lp1.pctl.srv.nintendo.net"), "", "")
		if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
			t.Fatalf("GET %s = %d %q", link, w.Code, w.Header().Get("Content-Type"))
		}
		return w.Body.Bytes()
	}

	var prev string
	for i, step := range []struct {
		name    string
		colour  uint8
		refresh bool // the parent's profile change, which drops the cached picture
		changed bool
	}{
		{"first picture", 10, false, true},
		{"same picture, asked again", 10, false, false},
		{"same picture after a refresh", 10, true, false},
		{"new picture after a refresh", 200, true, true},
	} {
		site.set(account, step.colour)
		if step.refresh {
			pctlIconOf(account, true)
		}
		cur := link()
		if i > 0 && (cur != prev) != step.changed {
			t.Fatalf("%s: link %q after %q, changed=%t want %t", step.name, cur, prev, cur != prev, step.changed)
		}
		seg := path.Base(cur)
		if !strings.HasPrefix(seg, "face-") || len("icon/0000000000000000-"+seg) > 0x29 {
			t.Fatalf("%s: last segment %q (the console keeps 0x29 characters of its cache name)", step.name, seg)
		}
		img := fetch(cur)
		sum := sha256.Sum256(img)
		if seg != "face-"+hex.EncodeToString(sum[:4])+".png" || len(img) > 96<<10 {
			t.Fatalf("%s: %s served %d bytes hashing to %x", step.name, seg, len(img), sum[:4])
		}
		// A console still holding the old face.png link gets the same picture.
		if old := fetch(strings.TrimSuffix(cur, seg) + "face.png"); !bytes.Equal(old, img) {
			t.Fatalf("%s: face.png answers other bytes than %s", step.name, seg)
		}
		prev = cur
	}
}
