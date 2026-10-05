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
// iconUri as a non-nullable object (2142-0234 on null), 22.5 reads miiUri.
func TestOwnersCarryIconUriNeverNull(t *testing.T) {
	for _, tc := range []struct {
		name       string
		hasPicture bool
	}{
		{"one owner with a picture", true},
		{"one owner without a picture", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := newFakeSite(t)
			s, _ := moonServer(t)
			if tc.hasPicture {
				site.set(testAccount(1), 40)
			}
			d := pairedFor(t, s, testAccount(1))
			body, users := ownersBody(t, s, d)
			if strings.Contains(body, "null") {
				t.Fatalf("owners carry a null: %s", body)
			}
			if len(users) != 1 {
				t.Fatalf("%d owners", len(users))
			}
			u := users[0]
			icon, hasIcon := u["iconUri"].(map[string]any)
			mii, hasMii := u["miiUri"].(map[string]any)
			if !tc.hasPicture {
				if _, present := u["iconUri"]; present || u["miiUri"] != nil {
					t.Fatalf("no picture, yet the owner names one: %v", u)
				}
				return
			}
			if !hasIcon || !hasMii || icon["small"] == nil || icon["small"] != mii["small"] {
				t.Fatalf("iconUri %v, miiUri %v: want the same {small} under both", u["iconUri"], u["miiUri"])
			}
			if link := icon["small"].(string); len(link) > 255 || !strings.Contains(link, "/mii/"+testAccount(1)+"/") {
				t.Fatalf("link %q", link)
			}
		})
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
