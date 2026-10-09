package main

// moon is the parental-controls API: `api-<env>.pctl.srv.nintendo.net/moon/v1/…`,
// the only thing the pctl sysmodule (22.5.0 title 010000000000002E) needs from a
// server. Everything the console does on its own -- the PIN, the restriction
// level, the play timer, the bedtime alarm -- lives in pctl's system savedata and
// works offline. What dies without a server is pairing with the parent app and
// the settings sync. Contract: the docs repo, switch/parental-controls-firmware-2026-09-26.md.
//
// Phase 0 of the PRD (docs repo, switch/native-switch-parental-controls-prd.md): log what the
// console sends and refuse in the shape it recognises. The ten paths, their
// verbs and their bodies are not invented here -- one on-console pairing attempt
// against this handler prints them, and the phases after this are written against
// that log.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"log"
	"maps"
	"math/big"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// The error identities pctl carries as literals (study §5). A refusal that does
// not name one of these is a refusal the client cannot classify, which is why
// this handler never answers a bare status.
const (
	moonErrorBase        = "https://moon.nintendo.com/errors/v1/"
	moonNotFound         = "404/resource_is_not_found"
	moonForbidden        = "403/forbidden"
	moonMethodNotAllowed = "405/method_not_allowed"
	moonInvalidToken     = "401/invalid_token"
	moonOverTheTimeLimit = "409/over_the_time_limit"
	moonDevicesMaxed     = "400/devices_maxed"
	moonInternalError    = "500/internal_server_error"
)

// pctlPinInBody finds a PIN in a body about to be logged: the console's own
// keys, and the parent side's `unlock_code`.
var pctlPinInBody = regexp.MustCompile(`("(?:synchronizedUnlockCode|unlockCode|unlock_code)"\s*:\s*")[^"]*"`)

// moonError writes a refusal, in the five keys of the console's error parse
// table (pctl 22.5.0, vaddr 0x13bb20): `type` is the identity above and the only
// one it classifies by; `title`, `errorCode` and `detail` are strings, `status`
// an integer.
func moonError(w http.ResponseWriter, slug string) {
	status, code, _ := strings.Cut(slug, "/")
	writeJSON(w, statusOf(status), map[string]any{
		"type":      moonErrorBase + slug,
		"title":     code,
		"errorCode": code,
		"status":    statusOf(status),
		"detail":    code,
	})
}

// statusOf reads the HTTP status out of the identity's own first segment, so the
// status line and the type URI can never disagree.
func statusOf(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 500
		}
		n = n*10 + int(c-'0')
	}
	if n < 100 || n > 599 {
		return 500
	}
	return n
}

// moon answers the pctl host. Anything under /moon/v1 is the parental-controls
// API; anything else on this host keeps the service-status answer it got before
// this handler existed, so nothing regresses while the surface is being learned.
//
// Every request is still dumped in full. The shapes below are built from the
// firmware's own field names (study §4) and are not yet runtime-confirmed: the
// log beside each answer is what corrects them, so it stays on.
func (s *server) moon(w http.ResponseWriter, r *http.Request, body []byte) {
	if !strings.HasPrefix(r.URL.Path, "/moon/v1") {
		s.serviceStatus(w, r, body)
		return
	}
	// In full, except the PIN: the console sends it in `activate` and in every
	// receipt, and a log is read by more people than a parent's PIN should be.
	dump(r, pctlPinInBody.ReplaceAll(body, []byte(`${1}****"`)), "[moon] pctl")

	// The bearer is a dauth device token, signed by this server, so its `sub`
	// is the device id (dauth.go). A request without one can still search for a
	// pairing code -- the console has nothing else to identify itself with
	// before it has claimed a record -- but nothing else.
	device := ""
	if claims := s.bearer(r); claims != nil {
		device = str(claims, "sub")
	}

	rest := strings.TrimPrefix(r.URL.Path, "/moon/v1")
	switch {
	case rest == "/devices" && r.Method == http.MethodGet:
		s.moonSearch(w, r)
	case strings.HasPrefix(rest, "/mii/") && r.Method == http.MethodGet:
		s.moonMii(w, strings.TrimPrefix(rest, "/mii/"))
	case strings.HasPrefix(rest, "/devices/"):
		s.moonDevice(w, r, body, device, strings.TrimPrefix(rest, "/devices/"))
	default:
		log.Printf("[moon] no handler for %s %s", r.Method, r.URL.Path)
		moonError(w, moonNotFound)
	}
}

// moonSearch is the console's first call: find the record whose pairing code
// this is. Nothing is claimed here -- the console follows with `activate`.
func (s *server) moonSearch(w http.ResponseWriter, r *http.Request) {
	// The query is `filter.links.pairingCode.code.$eq=<code>`. Read it by
	// suffix rather than by exact key, so a different filter spelling still
	// finds the code instead of answering an empty list.
	code := ""
	for k, v := range r.URL.Query() {
		if strings.HasSuffix(k, "pairingCode.code.$eq") && len(v) > 0 {
			code = v[0]
		}
	}
	if code == "" {
		log.Printf("[moon] search with no pairing-code filter: %s", r.URL.RawQuery)
		moonItems(w, nil)
		return
	}
	if !pctlSearchAllowed() {
		// Six digits is a million codes, and this host is reachable from the
		// internet: without a cap, a guesser gets the whole space in minutes and
		// attaches their console to someone else's record.
		// ponytail: one global counter per minute, not per-IP -- Traefik splices
		// the console connection so no handler here sees a source address
		// (docs/switch, §U3). Per-IP when PROXY protocol lands.
		log.Printf("[moon] pairing-code lookups throttled; refusing %q", code)
		moonItems(w, nil)
		return
	}
	d := s.store.PctlByPairingCode(strings.TrimSpace(code))
	if d == nil {
		pctlSearchMiss()
		// An empty list, not a 404: the console asked a question ("which device
		// has this code"), and "none" is an answer to it.
		log.Printf("[moon] pairing code %q: no record", code)
		moonItems(w, nil)
		return
	}
	log.Printf("[moon] pairing code %q -> device %s", code, d.Hex())
	moonItems(w, []any{moonDeviceObj(d)})
}

// moonDevice routes everything under /devices/{id}. The id the console sends is
// whatever it read out of our own search answer, so it is matched tolerantly:
// hex as we spell it, and decimal in case it re-rendered the number.
func (s *server) moonDevice(w http.ResponseWriter, r *http.Request, body []byte, device, rest string) {
	id, tail, _ := strings.Cut(rest, "/")
	d := s.store.PctlByMoonID(id)
	if d == nil && r.Method == http.MethodDelete && strings.HasPrefix(tail, "owners/") && device != "" {
		// A console unlinking deletes every owner it was listed, in its own
		// order. The record goes with the managing account's owner, so a
		// further parent's delete after that has nothing left to do.
		log.Printf("[moon] device %s is gone; owner delete %s answered as done", id, tail)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if d == nil {
		log.Printf("[moon] device id %q not found (console spelled it that way)", id)
		moonError(w, moonNotFound)
		return
	}

	switch {
	// activate is where a console claims the record the code found, and the
	// only call that may arrive before this device is bound to it.
	case tail == "activate" && r.Method == http.MethodPost:
		if device == "" {
			moonError(w, moonInvalidToken)
			return
		}
		bound := s.store.PctlActivate(d.Hex(), device)
		if bound == nil {
			log.Printf("[moon] activate refused: %s is claimed by another console", d.Hex())
			moonError(w, moonForbidden)
			return
		}
		log.Printf("[moon] device %s activated by %s", bound.Hex(), device)
		// The console hands over its whole state here, setting and PIN included
		// (hardware, v0.42.0). That is the document the parent side edits from.
		if set, ok := jsonObj(body)["parentalControlSetting"].(map[string]any); ok {
			bound = s.store.PctlSetSetting(bound.Hex(), set)
		}
		// And its notificationToken, which is where a push reaches it.
		bound = s.store.PctlUpdateDevice(bound.Hex(), jsonObj(body))
		writeJSON(w, 200, moonDeviceObj(bound))
		return
	}

	// Between the search and `activate` the console asks whose record this is,
	// so it can show the parent before anything is claimed (hardware, v0.41.0:
	// a 403 here is 2142-2008). An unclaimed record answers any console holding
	// a device token; the id is only known to one that typed the code.
	if tail == "owners" && r.Method == http.MethodGet && d.DauthID == "" && device != "" {
		moonItems(w, moonOwners(d, hostOf(r)))
		return
	}

	// Everything else needs this console to be the one that claimed the record.
	if device == "" || d.DauthID != device {
		log.Printf("[moon] %s %s: bearer device %q is not %q", r.Method, r.URL.Path, device, d.DauthID)
		moonError(w, moonForbidden)
		return
	}

	switch {
	case tail == "" && r.Method == http.MethodGet:
		writeJSON(w, 200, moonDeviceObj(d))
	case tail == "" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		// The console renaming itself or reporting its firmware. Stored as sent.
		s.store.PctlUpdateDevice(d.Hex(), jsonObj(body))
		writeJSON(w, 200, moonDeviceObj(d))
	case tail == "" && r.Method == http.MethodDelete:
		s.store.PctlUnlink(d.Hex())
		log.Printf("[moon] device %s unlinked by the console", d.Hex())
		w.WriteHeader(http.StatusNoContent)
	case tail == "parental_control_setting" && r.Method == http.MethodGet:
		s.moonSetting(w, r, d)
	case strings.HasPrefix(tail, "parental_control_setting") && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		// Includes .../whitelisted_applications: both write the document the
		// parent side owns, and the console only writes when a parent changed
		// something on the console itself.
		s.store.PctlSetSetting(d.Hex(), jsonObj(body))
		s.moonSetting(w, r, s.store.PctlByMoonID(d.Hex()))
	case tail == "owners" && r.Method == http.MethodGet:
		moonItems(w, moonOwners(d, hostOf(r)))
	case strings.HasPrefix(tail, "owners/"):
		na := strings.TrimPrefix(tail, "owners/")
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			s.store.PctlAddOwner(d.Hex(), na)
			log.Printf("[moon] device %s owner %s linked", d.Hex(), na)
			writeJSON(w, 200, map[string]any{"nintendoAccountId": na})
		case http.MethodDelete:
			// This is how a console unlinks: it lists the owners and deletes
			// each one, and sends nothing after the last (hardware, v0.43.0).
			// So a record left with none of the managing account's owners is
			// a console that has left; a further parent's id only takes that
			// parent off.
			if s.store.PctlRemoveOwner(d.Hex(), na) == 0 {
				s.store.PctlUnlink(d.Hex())
				log.Printf("[moon] device %s unlinked: its last owner %s was removed", d.Hex(), na)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			moonError(w, moonMethodNotAllowed)
		}
	case tail == "events" && r.Method == http.MethodPost:
		// Play-time and state events, a JSON array per upload. Stored as sent;
		// the parent side reads wrong-PIN attempts and play time out of them. A
		// console that cannot hand them over spools retries instead.
		n := s.store.PctlAddEvents(d.Hex(), body)
		log.Printf("[moon] device %s uploaded events (%d bytes, %d held)", d.Hex(), len(body), n)
		writeJSON(w, 200, map[string]any{"result": "ok"})
	case strings.HasPrefix(tail, "players/") && (r.Method == http.MethodPut || r.Method == http.MethodDelete):
		// The console's own users, one call each after pairing: a nickname and
		// a 256px JPEG in base64, about 40 KiB (hardware, v0.42.0). Kept so the
		// parent side can show who plays; removed when the console says so.
		player := strings.TrimPrefix(tail, "players/")
		if r.Method == http.MethodDelete {
			s.store.PctlSetPlayer(d.Hex(), player, nil)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		doc := jsonObj(body)
		nick, _ := doc["nickname"].(string)
		img, _ := doc["imageData"].(string)
		s.store.PctlSetPlayer(d.Hex(), player, &PctlPlayer{Nickname: nick, ImageData: img})
		log.Printf("[moon] device %s player %s is %q", d.Hex(), player, nick)
		writeJSON(w, 200, map[string]any{"nickname": nick})
	case strings.HasPrefix(tail, "players") && r.Method == http.MethodGet:
		// The console's players, for the parent app's icons. Empty until the
		// app asks for them.
		moonItems(w, nil)
	case tail == "copy" && r.Method == http.MethodPost:
		// Copying settings from another paired console. There is never a source
		// to copy from on a first console, and inventing one would be a lie.
		moonError(w, moonNotFound)
	default:
		log.Printf("[moon] no handler for %s %s (tail %q)", r.Method, r.URL.Path, tail)
		moonError(w, moonNotFound)
	}
}

// moonSetting answers the conditional GET the console polls with. The ETag is a
// hash of the document as served, so one that has not changed costs a 304 and
// no body, and a changed PIN alone is a changed document.
func (s *server) moonSetting(w http.ResponseWriter, r *http.Request, d *PctlDevice) {
	if d == nil {
		moonError(w, moonNotFound)
		return
	}
	// The same document the record embeds: an empty one refuses everything on
	// the console rather than nothing (2142-0234), so "no restrictions" is
	// stated in full.
	doc := pctlServedSetting(d)
	tag := pctlETag(doc)
	w.Header().Set("ETag", tag)
	if match := r.Header.Get("If-None-Match"); match != "" && match == tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	// `etag` and `updatedAt` are in the document's parse table too; the body is
	// a copy so the stored document and its hash stay as they were.
	body := maps.Clone(doc)
	body["etag"], body["updatedAt"] = tag, d.UpdatedAt
	writeJSON(w, 200, body)
}

// pctlServedSetting is the document the setting GET answers: the setting, and
// `unlockCode` only once a parent has set one. A code the console reported is
// its own already, and sending it back is the untested half of Q2 (the
// parent-surface PRD), so a console nobody has set a code for gets exactly the
// document it got before codes could be set.
func pctlServedSetting(d *PctlDevice) map[string]any {
	doc := pctlSettingOf(d)
	if d.UnlockCodeSet && pctlValidUnlockCode(d.UnlockCode) {
		doc = maps.Clone(doc)
		doc["unlockCode"] = d.UnlockCode
	}
	return doc
}

// pctlServedETag is the validator moonSetting answers with, over the document
// as served (without its own etag and updatedAt). A receipt naming it is a
// console holding the document the parent side sees.
func pctlServedETag(d *PctlDevice) string {
	return pctlETag(pctlServedSetting(d))
}

// pctlSynced reports whether the console's last receipt names the served
// document. The quotes are the header's, so they are not what is compared.
func pctlSynced(d *PctlDevice) bool {
	return d.SyncedEtag != "" && strings.Trim(d.SyncedEtag, `"`) == strings.Trim(pctlServedETag(d), `"`)
}

// moonItems is the `{items,count}` envelope pctl's strings carry (992493, 986719).
func moonItems(w http.ResponseWriter, items []any) {
	if items == nil {
		items = []any{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "count": len(items)})
}

// moonDeviceObj is one device as the console reads it. The names are the
// firmware's (study §4); the id is spelled the way the console spells it in its
// own paths, `%016llx`, which is the one shape we know it can render.
func moonDeviceObj(d *PctlDevice) map[string]any {

	obj := map[string]any{
		// `id` is the only field the search reads from an item, and its parse
		// table (pctl 22.5.0, vaddr 0x13c6f0) types it as a STRING: at most
		// sixteen hex digits through strtoull base 16 (.text 0x50f00). A number
		// here makes the SAX handler refuse the token, RapidJSON reports
		// kParseErrorTermination, and pctl maps that to 2142-0234 -- which is
		// what every build carrying a numeric `id` got. Builds without `id`
		// parsed cleanly and read zero. `deviceId` is not in that table and is
		// skipped; it stays as it was so this build changes one thing.
		"id":       d.Hex(),
		"deviceId": d.MoonID,
		"nickname": d.Nickname,
		// `activated` and `parentalControlSetting` sit beside each other in
		// pctl's own field table, and the console reads the setting straight out
		// of this object: it made no second call before refusing, so an absent
		// setting is what it judged.
		"activated":              d.DauthID != "",
		"pairingActive":          d.DauthID == "" && d.PairingCode != "",
		"parentalControlSetting": pctlSettingOf(d),
		// No unlockCode here, deliberately. The restriction check returns
		// "permitted" unconditionally while the eight-byte slot at +0x799 is
		// empty, and an eight-digit code is exactly what fills it -- so sending
		// one during setup is what switches restrictions on before the console
		// has any allowance to judge against. The console says parental controls
		// are *not* set up, so nothing else can be filling that slot. It stays on
		// the record (the parent needs it once paired) and travels only after
		// activation.
		"updatedAt": d.UpdatedAt,
		"etag":      d.ETag,
		"owners":    moonOwners(d, ""),
	}
	if d.ActivatedAt != 0 {
		obj["synchronizedAt"] = d.ActivatedAt
		// What the console reads from the activate answer, and all it reads
		// (parse table vaddr 0x13c580): a string and an integer.
		obj["synchronizedParentalControlSetting"] = map[string]any{
			"synchronizedEtag": pctlServedETag(d),
			"synchronizedAt":   d.ActivatedAt,
		}
		// Once the console has claimed the record it is managed, and the unlock
		// code is what lifts a restriction rather than what creates one.
		obj["unlockCode"] = d.UnlockCode
	}
	if d.PairingCode != "" {
		// The console found the record by this code; echoing the link back is
		// how the shape it filtered on reads.
		obj["links"] = map[string]any{"pairingCode": map[string]any{"code": d.PairingCode}}
	}
	return obj
}

// pctlSettingOf is the record's setting, or the stated permissive default when a
// parent has set nothing. One place decides it, so the document the console
// polls and the one embedded here can never disagree.
func pctlSettingOf(d *PctlDevice) map[string]any {
	// A stored document is whatever its writer sent -- the console's own PUT
	// uses the serialiser's shape, not the parser's -- so only what the parse
	// table would accept travels back.
	if doc, _ := pctlConform(d.Setting, pctlSettingSchema).(map[string]any); doc["functionalRestrictionLevel"] != nil {
		return doc
	}
	return pctlDefaultSetting()
}

// pctlSettingSchema is the console's parse table for the setting document
// (vaddr 0x13c8c0; docs study section 5b). "s" string, "i360" an integer from 0 to 360, "b" boolean,
// a list is an enum, "*" is any hex-id or day-name key.
var pctlSettingSchema = func() map[string]any {
	restriction := []string{"UNRESTRICTED", "RESTRICTED", "UNDEFINED"}
	clock := map[string]any{"hour": "i23", "minute": "i59"}
	day := map[string]any{
		"timeToPlayInOneDay": map[string]any{"enabled": "b", "limitTime": "i360"},
		"bedtime":            map[string]any{"enabled": "b", "endingTime": clock, "startingTime": clock},
	}
	return map[string]any{
		"functionalRestrictionLevel": []string{"NONE", "CUSTOM", "CHILDREN", "YOUNG_TEENS", "OLDER_TEENS"},
		"customSettings": map[string]any{
			"ageRestriction": map[string]any{"restriction": restriction, "ratingAge": "i255"},
			"ugcRestriction": map[string]any{
				"restriction":  restriction,
				"applications": map[string]any{"*": map[string]any{"restriction": restriction}},
			},
			"snsPostRestriction": restriction,
			"ratingOrganization": []string{"CERO", "GRAC_GCRB", "GSRMR", "ESRB", "CLASS_IND", "USK", "PEGI",
				"PEGI_PORTUGAL", "PEGI_BBFC", "RUSSIAN", "ACB", "OFLC", "IARC_GENERIC", "GMEDIA"},
			"vrRestriction": restriction,
		},
		"playTimerRegulations": map[string]any{
			"timerMode":                   []string{"DAILY", "EACH_DAY_OF_THE_WEEK"},
			"restrictionMode":             []string{"ALARM", "FORCED_TERMINATION"},
			"dailyRegulations":            day,
			"eachDayOfTheWeekRegulations": map[string]any{"*": day},
			"bedtimeStartingTime":         clock,
		},
		"whitelistedApplications": map[string]any{"*": map[string]any{"safeLaunch": []string{"NONE", "ALLOW"}}},
	}
}()

// pctlConform keeps the parts of v the schema names with the type it names, and
// drops the rest: a wrong type on a known key is what ends the console's parse.
// Returns nil when v itself does not fit.
func pctlConform(v, schema any) any {
	switch want := schema.(type) {
	case string:
		switch n := v.(type) {
		case string:
			if want == "s" {
				return n
			}
		case bool:
			if want == "b" {
				return n
			}
		case int:
			return pctlConform(float64(n), schema)
		case float64: // what a document read back from the store holds
			// "i360" is an integer from 0 to 360: each bound is the one the
			// console's own handler enforces (limitTime .text 0x60940, hour
			// and minute 0x60a10, ratingAge 0x60520), and a value past it ends
			// the console's parse.
			if max, err := strconv.Atoi(strings.TrimPrefix(want, "i")); err == nil && want[0] == 'i' &&
				n >= 0 && n <= float64(max) && n == float64(int(n)) {
				return int(n)
			}
		}
	case []string:
		if s, ok := v.(string); ok && slices.Contains(want, s) {
			return s
		}
	case map[string]any:
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		out := map[string]any{}
		for k, sub := range m {
			spec, named := want[k]
			if !named {
				spec = want["*"]
			}
			if spec == nil {
				continue
			}
			if c := pctlConform(sub, spec); c != nil {
				out[k] = c
			}
		}
		return out
	}
	return nil
}

// The shape is the console's parse table for this list (vaddr 0x13d240):
// `deviceId` and `user.nintendoAccountId` are strings of at most sixteen hex
// digits, and anything else in either ends the parse as 2142-0234 -- so an owner
// that is not hex is left out rather than sent.
//
// pctlOwnerList says who they are (the managing account first, then the
// further parents, each with their own name and picture).
//
// The picture is a URL the console downloads (at most 255 bytes), under two
// keys: 22.5 reads `miiUri.small` (nullable), 23.x reads `iconUri.small` and
// ignores `miiUri` (pctl 23.0.1 owners table 0x2484a8). `iconUri` is typed as a
// plain object there, so `"iconUri": null` ends the parse as 2142-0234; an
// absent key is fine. So both keys carry the same object, or neither is sent.
// The console files the picture as `icon/<naId>-<last path segment>` and only
// fetches again when that name changes, so the segment is the picture's own
// hash (pctlIconOf). It points back at this host so it resolves like every
// other moon call; host is empty where no console will follow the link.
func moonOwners(d *PctlDevice, host string) []any {
	out := []any{}
	for _, o := range pctlOwnerList(d) {
		user := map[string]any{"nintendoAccountId": o.NaID, "nickname": o.Name}
		if link := pctlIconURL(host, o.Account); link != "" {
			icon := map[string]any{"small": link}
			user["miiUri"], user["iconUri"] = icon, icon
		}
		out = append(out, map[string]any{"deviceId": d.Hex(), "user": user})
	}
	return out
}

// pctlMaxOwners is how many parents a console keeps per device: pctl 23.0.1
// parses at most five owners (.text 0x153850 passes capacity 5) and refuses a
// GetAllPairingAccountInfos buffer of six or more. 22.5 shows the first.
const pctlMaxOwners = 5

// pctlOwner is one owner as the console lists it: its NA-shaped id, and the
// OpenPak account whose name and picture it shows.
type pctlOwner struct{ NaID, Account, Name string }

// pctlOwnerList is a record's owners, at most pctlMaxOwners, managing account
// first (it is the owner 22.5 and command 1411 show).
//
// A record nobody has been linked to yet is owned by the account that minted
// its code: that is who the console is about to be paired with. Ids a console
// linked itself (owners/%016llx) are the managing account's too. Then come the
// further parents the managing account added, each under its own name and
// picture. An owner that is not hex would end the parse, so it is left out.
func pctlOwnerList(d *PctlDevice) []pctlOwner {
	owners := d.Owners
	if len(owners) == 0 && d.ManagedBy != "" {
		owners = []string{pctlNaID(d.ManagedBy)}
	}
	out := []pctlOwner{}
	add := func(na, account, name string) {
		if len(out) >= pctlMaxOwners || !pctlHexID(na) || slices.ContainsFunc(out, func(o pctlOwner) bool { return o.NaID == na }) {
			return
		}
		if name == "" {
			name = "OpenPak"
		}
		out = append(out, pctlOwner{NaID: na, Account: account, Name: name})
	}
	for _, na := range owners {
		add(na, d.ManagedBy, d.ParentName)
	}
	for _, p := range d.Parents {
		add(pctlNaID(p.AccountID), p.AccountID, p.Name)
	}
	return out
}

// pctlNaID is the Nintendo-Account-shaped id an OpenPak account goes by on a
// console: sixteen hex digits, stable, and not the account id itself.
func pctlNaID(account string) string {
	sum := sha256.Sum256([]byte(account))
	return hex.EncodeToString(sum[:8])
}

// pctlIconURL is where the console fetches an account's picture, or "" when
// there is no host to point at or no picture to serve.
func pctlIconURL(host, account string) string {
	if host == "" {
		return ""
	}
	if _, file := pctlIconOf(account, false); file != "" {
		return "https://" + host + "/moon/v1/mii/" + account + "/" + file
	}
	return ""
}

// pctlIcons holds each parent's picture as the console is served it, so the
// owners list names exactly the bytes the picture route then answers with.
var pctlIcons = struct {
	sync.Mutex
	m map[string]pctlIcon
}{m: map[string]pctlIcon{}}

type pctlIcon struct {
	png  []byte
	file string // face-<first 8 hex of its sha256>.png
	at   time.Time
}

// pctlIconTTL is how long a picture is used before the website is asked
// again; a parent's profile change (pctlParentProfile) refreshes it at once.
const pctlIconTTL = 10 * time.Minute

// pctlIconMax: the console refuses more than 96 KiB (pctl 23.0.1 .text
// 0x162b00, 0x18000; 22.5 0x15e994). 64 KiB is what was kept before that was known.
const pctlIconMax = 64 << 10

// pctlIconOf is an account's picture as the 128px PNG the console is served,
// and the file name it goes by: the hash of those bytes, so a new picture is
// a new name and the console fetches it, and an unchanged one is the same name
// and costs nothing. nil and "" when there is no picture. A website that fails
// to answer leaves the last picture in place rather than taking it away.
func pctlIconOf(account string, refresh bool) ([]byte, string) {
	site := getenv("WEBSITE_INTERNAL_URL", "")
	if site == "" || !pctlAccountID(account) {
		return nil, ""
	}
	pctlIcons.Lock()
	c, ok := pctlIcons.m[account]
	pctlIcons.Unlock()
	if ok && !refresh && time.Since(c.at) < pctlIconTTL {
		return c.png, c.file
	}
	img, err := fetchAvatar(site + "/media/avatars/" + account + "/console.jpg")
	if err == nil {
		img, err = pctlFacePNG(img)
	}
	if err == nil && len(img) > pctlIconMax {
		err = fmt.Errorf("%d bytes, over %d", len(img), pctlIconMax)
	}
	if err != nil {
		log.Printf("[moon] picture of %s: %v", account, err)
	} else {
		sum := sha256.Sum256(img)
		c = pctlIcon{png: img, file: "face-" + hex.EncodeToString(sum[:4]) + ".png"}
	}
	c.at = time.Now()
	if c.file != "" {
		pctlIcons.Lock()
		pctlIcons.m[account] = c
		pctlIcons.Unlock()
	}
	return c.png, c.file
}

// pctlAccountID reports whether s is safe to put in a path: an OpenPak account
// id is a UUID, and nothing else is forwarded to the website.
func pctlAccountID(s string) bool {
	return s != "" && len(s) <= 36 && strings.Trim(s, "0123456789abcdef-") == ""
}

// moonMii is the parent's picture, relayed from the website's media store and
// re-encoded: the website keeps a console JPEG, and the console showed nothing
// for one (hardware, v0.43.0) -- Nintendo's own are small PNGs. The console
// files the picture under the URL's last segment, so a new name is what makes
// it fetch again (pctlIconOf). Any last segment answers with the current
// picture: the hashed name with the bytes it names, and the `face.png` links
// consoles were given before the hash still work.
func (s *server) moonMii(w http.ResponseWriter, path string) {
	account, _, _ := strings.Cut(path, "/")
	img, _ := pctlIconOf(account, false)
	if img == nil {
		log.Printf("[moon] mii %s: no picture", path)
		moonError(w, moonNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(img)))
	w.Write(img)
}

// pctlFacePNG turns a JPEG into the 128x128 PNG the console draws: qlaunch
// 23.0.1 decodes it with libpng and draws it only when width x height x 4 is
// its 128x128 texture (0x09112420, texture at 0x08EE2E70), so any other size
// shows the grey silhouette. The centre square is box-averaged down (or
// sampled up) to exactly 128 pixels a side.
func pctlFacePNG(jpg []byte) ([]byte, error) {
	src, err := jpeg.Decode(bytes.NewReader(jpg))
	if err != nil {
		return nil, err
	}
	const side = 128
	b := src.Bounds()
	sq := min(b.Dx(), b.Dy())
	if sq <= 0 {
		return nil, fmt.Errorf("empty picture")
	}
	x0, y0 := b.Min.X+(b.Dx()-sq)/2, b.Min.Y+(b.Dy()-sq)/2
	dst := image.NewRGBA(image.Rect(0, 0, side, side))
	for y := 0; y < side; y++ {
		sy0, sy1 := y*sq/side, max((y+1)*sq/side, y*sq/side+1)
		for x := 0; x < side; x++ {
			sx0, sx1 := x*sq/side, max((x+1)*sq/side, x*sq/side+1)
			var r, g, bl, k uint32
			for sy := sy0; sy < sy1; sy++ {
				for sx := sx0; sx < sx1; sx++ {
					cr, cg, cb, _ := src.At(x0+sx, y0+sy).RGBA()
					r, g, bl, k = r+cr>>8, g+cg>>8, bl+cb>>8, k+1
				}
			}
			dst.SetRGBA(x, y, color.RGBA{uint8(r / k), uint8(g / k), uint8(bl / k), 255})
		}
	}
	var out bytes.Buffer
	err = png.Encode(&out, dst)
	return out.Bytes(), err
}

// pctlHexID is what the console's id parser accepts (.text 0x50f00): one to
// sixteen hex digits.
func pctlHexID(s string) bool {
	if len(s) > 16 {
		return false
	}
	_, err := strconv.ParseUint(s, 16, 64)
	return err == nil
}

// jsonObj reads a request body as an object, or nil when it is not one. A body
// we cannot parse is logged by dump already; it must not panic a handler.
func jsonObj(body []byte) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	return m
}

// ---------- the pairing store ----------
//
// Phase 1's data model, and only the part the wire cannot change. A device
// record, an owner, a pairing code with a deadline, and the setting document
// held as received: the console-facing envelope is still unknown (study §7 P1),
// but what has to be *remembered* is not, and the ETag is computed over whatever
// the parent side stores rather than over named fields.

// PctlDevice is one console's parental-controls record. Nintendo's flow creates
// it on the parent side first -- a record with a pairing code and no console --
// and the console adopts it: it searches by code
// (`/devices?filter.links.pairingCode.code.$eq=`) and then calls
// `/devices/{id}/activate`. So DauthID is empty until a console claims it.
type PctlDevice struct {
	// MoonID is the id in every path after the search. The console formats it
	// with `%016llx`, so it is a u64 here and rendered at the edge -- whether
	// the JSON carries it as a number or a hex string is P2, and one line.
	MoonID uint64 `json:"moonId"`
	// DauthID is the device id dauth issued ("cert-<8 bytes>"), which is what
	// the bearer on every moon request proves. Empty until activation.
	DauthID string `json:"dauthId,omitempty"`
	// ManagedBy is the OpenPak account that created the record and manages it
	// from the app. It is ours, and the console never sees it.
	ManagedBy string `json:"managedBy,omitempty"`
	// Players are the console's users as it reported them, by its own ids.
	Players map[string]*PctlPlayer `json:"players,omitempty"`
	// ParentName is the managing account's display name, as the app's user
	// had it when the code was minted. It is what the console shows as the
	// parent; "OpenPak" stands in when there is none.
	ParentName string `json:"parentName,omitempty"`
	// Nickname is what the console calls itself, as it sent it. No console has
	// sent one: pctl's device document has no name in it (hardware, 22.5.0).
	Nickname string `json:"nickname,omitempty"`
	// Label is what the parent calls the console, which is how two consoles
	// under one account are told apart.
	Label string `json:"label,omitempty"`
	// SerialNumber and Firmware are what the console says of itself at
	// `activate`: the serial is printed on the console, so it identifies one
	// the parent has not named yet.
	SerialNumber string `json:"serialNumber,omitempty"`
	Firmware     string `json:"firmware,omitempty"`
	// NotificationToken is what the console sends at `activate`: its Penne
	// registration id (hardware: the `penne_id` its frontline connection was
	// minted under), so it names the connection a push goes out on.
	NotificationToken string `json:"notificationToken,omitempty"`
	// UnlockCode is the console's PIN, four to eight digits. It is minted with
	// the record and replaced by the console's own as soon as the console names
	// it (activate, or a sync receipt). The parent side holds it, which is why a
	// forgotten PIN is recoverable here rather than through Nintendo support.
	UnlockCode string `json:"unlockCode,omitempty"`
	// UnlockCodeReported is set once the console itself has named UnlockCode.
	// Until then the code is the minted one, which unlocks nothing, so the
	// parent side is not shown it.
	UnlockCodeReported bool `json:"unlockCodeReported,omitempty"`
	// UnlockCodeSet is a code the parent set. From then on UnlockCode is served
	// in the setting document, and a console reporting another code has not
	// applied it yet: its report never overwrites the parent's.
	UnlockCodeSet bool `json:"unlockCodeSet,omitempty"`
	// SyncedUnlockCode is the code the console's last receipt reported.
	SyncedUnlockCode string `json:"syncedUnlockCode,omitempty"`
	// SyncedEtag and SyncedAt are the console's last receipt: after a setting
	// GET it POSTs /devices/{id} naming the etag it applied (hardware, v0.43.1).
	// SyncedEtag equal to the served ETag is a console holding the current
	// document.
	SyncedEtag string `json:"syncedEtag,omitempty"`
	SyncedAt   int64  `json:"syncedAt,omitempty"`
	// Events are the console's play-time and state events, one entry each, as
	// received. An upload is a JSON array of them (hardware, v0.43.0); a store
	// written before v0.45.0 holds whole uploads, which pctlEvents splits. Read
	// for wrong-PIN attempts and for play time (pctlActivity).
	Events []json.RawMessage `json:"events,omitempty"`
	// Owners are what the console spells in `owners/%016llx`: Nintendo-Account
	// -shaped ids. They are learned when the console links an owner, which is
	// why a record can be managed by an account and own none yet.
	Owners []string `json:"owners,omitempty"`
	// Parents are further OpenPak accounts the managing one made parents of
	// this console. Each is a console owner of its own, with its own name and
	// picture (firmware 23.x shows up to pctlMaxOwners); the managing account
	// is never one of them.
	Parents []PctlParent `json:"parents,omitempty"`
	// PairingCode is live until PairingExpires; both are cleared on activation
	// so a code is good exactly once.
	PairingCode    string `json:"pairingCode,omitempty"`
	PairingExpires int64  `json:"pairingExpires,omitempty"`
	ActivatedAt    int64  `json:"activatedAt,omitempty"`
	// Setting is the parental_control_setting document, stored as the parent
	// side wrote it. Opaque on purpose: the field names are known (study §4) but
	// which of them a phase-2 editor sends is not, and nothing here needs to
	// read them to serve a conditional GET.
	Setting map[string]any `json:"setting,omitempty"`
	// ETag is what `If-None-Match` is compared against, derived from Setting so
	// it cannot drift from the document it describes.
	ETag      string `json:"etag,omitempty"`
	UpdatedAt int64  `json:"updatedAt,omitempty"`
}

// PctlParent is a further parent of a console: an OpenPak account, and the
// name the console shows for it.
type PctlParent struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name,omitempty"`
}

// Hex renders MoonID the way the console's own paths spell it.
func (d *PctlDevice) Hex() string { return fmt.Sprintf("%016x", d.MoonID) }

// pctlPairingTTL: long enough to walk to the console, short enough that an
// abandoned code stops being a way in.
const pctlPairingTTL = 15 * time.Minute

// pctlPairingCodeDigits: the console's entry field takes six digits and nothing
// else (observed on hardware 2026-09-27, which settles study §7 P3). A letter in
// the code is a code that cannot be typed, so the space is 10^6 and leading
// zeros are kept.
const pctlPairingCodeDigits = 6

// randU64 is the moon device id: random, not a counter, so a record cannot be
// guessed from another one. Capped at 48 bits because the console reads the id
// as a JSON *number* (hardware, 2026-09-27) and a reader that keeps numbers in a
// double would silently round anything past 2^53. 2^48 is still 281 trillion
// ids, and it formats as the same sixteen hex digits the console's paths use.
func randU64() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:]) >> 16
}

// pctlPairingCode is uniform over the whole six-digit space: modulo over random
// bytes would lean on the low digits, and a code an attacker can predict is a
// console they can attach to someone else's record.
func pctlPairingCode() string {
	max := big.NewInt(1)
	for i := 0; i < pctlPairingCodeDigits; i++ {
		max.Mul(max, big.NewInt(10))
	}
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		// Never serve a guessable code: an empty one fails the mint instead.
		return ""
	}
	return fmt.Sprintf("%0*d", pctlPairingCodeDigits, n)
}

// pctlSearchMisses caps blind guessing at the pairing-code search. A miss is
// cheap for a console typing a real code once; a guesser makes nothing but
// misses, so the misses are what is counted.
var pctlSearchMisses = struct {
	sync.Mutex
	window time.Time
	n      int
}{}

// pctlSearchMissBudget is generous for a household -- a mistyped code, a retry,
// a second console -- and useless for enumeration: at 30 a minute, a million
// codes take a year.
const pctlSearchMissBudget = 30

func pctlSearchAllowed() bool {
	pctlSearchMisses.Lock()
	defer pctlSearchMisses.Unlock()
	if time.Since(pctlSearchMisses.window) > time.Minute {
		pctlSearchMisses.window, pctlSearchMisses.n = time.Now(), 0
	}
	return pctlSearchMisses.n < pctlSearchMissBudget
}

func pctlSearchMiss() {
	pctlSearchMisses.Lock()
	defer pctlSearchMisses.Unlock()
	pctlSearchMisses.n++
}

// pctlUnlockCode is the eight-digit code that lifts a restriction on the
// console. Same generator shape as the pairing code and for the same reason: a
// predictable one is somebody else's console unlocked.
func pctlUnlockCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%08d", n)
}

// pctlDefaultSetting is what a record carries until a parent sets anything: a
// stated "nothing is restricted", not an absent document.
//
// The shape is the console's own PARSE table for this document (pctl 22.5.0,
// vaddr 0x13c8c0), which is typed -- a value of the wrong JSON type makes the
// handler refuse the token and the whole parse ends as 2142-0234:
//
//	etag, unlockCode (4-8 digits), functionalRestrictionLevel   strings
//	customSettings {
//	  ageRestriction { restriction, ratingAge (int < 256) }
//	  ugcRestriction { restriction, applications { <%016llx>: { restriction } } }
//	  snsPostRestriction, ratingOrganization, vrRestriction      strings
//	}
//	playTimerRegulations {...}, whitelistedApplications {...}, updatedAt (int)
//
// So snsPostRestriction and vrRestriction are bare strings, ratingOrganization
// sits in customSettings rather than in ageRestriction, and applications is an
// object keyed by title id inside ugcRestriction. The earlier shapes were read
// off the *serialiser* tables, which nest differently. Enum values are pctl's:
// a level is NONE/CUSTOM/CHILDREN/YOUNG_TEENS/OLDER_TEENS, a restriction is
// UNRESTRICTED/RESTRICTED/UNDEFINED, and an unknown value refuses the parse.
//
// ponytail: no playTimerRegulations or whitelistedApplications -- unknown keys
// are skipped and absent ones left alone; add them when the parent app edits them.
func pctlDefaultSetting() map[string]any {
	return map[string]any{
		"functionalRestrictionLevel": "NONE",
		"customSettings": map[string]any{
			"ageRestriction": map[string]any{
				"restriction": "UNRESTRICTED",
				"ratingAge":   18,
			},
			"ugcRestriction": map[string]any{
				"restriction":  "UNRESTRICTED",
				"applications": map[string]any{},
			},
			"snsPostRestriction": "UNRESTRICTED",
			"ratingOrganization": "PEGI",
			"vrRestriction":      "UNRESTRICTED",
		},
	}
}

// pctlDevices is the map, created on first use so no migration is needed for a
// store written before parental controls existed. Called with mu held.
func (s *Store) pctlDevices() map[string]*PctlDevice {
	if s.PctlDevices == nil {
		s.PctlDevices = map[string]*PctlDevice{}
	}
	return s.PctlDevices
}

// PctlNewPairing mints the record a console can adopt, managed by one OpenPak
// account.
func (s *Store) PctlNewPairing(managedBy string) *PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	// One live code per account, ever. Asking again replaces the last one rather
	// than adding a record: a code is a pairing capability, so four of them on a
	// screen is four ways in, and only the newest is the one being typed.
	// Records a console has claimed are consoles, not codes, and are untouched.
	for hex, old := range s.pctlDevices() {
		if old.ManagedBy == managedBy && old.DauthID == "" {
			delete(s.pctlDevices(), hex)
		}
	}
	now := time.Now()
	d := &PctlDevice{
		MoonID:         randU64(),
		PairingCode:    pctlPairingCode(),
		PairingExpires: now.Add(pctlPairingTTL).Unix(),
		UpdatedAt:      now.Unix(),
		ManagedBy:      managedBy,
		UnlockCode:     pctlUnlockCode(),
	}
	s.pctlDevices()[d.Hex()] = d
	s.save()
	return d
}

// PctlPlayer is one user on a paired console.
type PctlPlayer struct {
	Nickname  string `json:"nickname"`
	ImageData string `json:"imageData,omitempty"` // base64 JPEG, as sent
}

// PctlSetPlayer stores a console user, or forgets one when p is nil.
// ponytail: capped at 8 players, the number of users a Switch holds, so a
// console cannot grow the store without bound.
func (s *Store) PctlSetPlayer(moonHex, id string, p *PctlPlayer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil {
		return
	}
	if p == nil {
		delete(d.Players, id)
	} else if _, known := d.Players[id]; known || len(d.Players) < 8 {
		if d.Players == nil {
			d.Players = map[string]*PctlPlayer{}
		}
		d.Players[id] = p
	}
	s.save()
}

// PctlNameParent records what the console should call the account behind a
// record. The console copies at most 32 bytes of a nickname, so it is cut on a
// rune boundary here rather than mid-character there.
func (s *Store) PctlNameParent(moonHex, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil {
		return
	}
	d.ParentName = pctlNickname(name)
	s.save()
}

// pctlNickname is a name as the console can hold it: trimmed, and at most the
// 32 bytes it copies, cut on a rune boundary.
func pctlNickname(name string) string {
	name = strings.TrimSpace(name)
	for len(name) > 32 {
		_, n := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-n]
	}
	return name
}

// errPctlOwnersFull is a further parent the console would not keep.
var errPctlOwnersFull = fmt.Errorf("a console keeps at most %d parents", pctlMaxOwners)

// errPctlManagingParent is the managing account added as a further parent of
// its own record.
var errPctlManagingParent = fmt.Errorf("the managing account is already this console's parent")

// PctlSetParent makes account a further parent of a record, or renames it.
// It reports whether the console's owner list changed.
func (s *Store) PctlSetParent(moonHex, account, name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil {
		return false, nil
	}
	if account == d.ManagedBy {
		return false, errPctlManagingParent
	}
	name = pctlNickname(name)
	i := slices.IndexFunc(d.Parents, func(p PctlParent) bool { return p.AccountID == account })
	switch {
	case i >= 0 && d.Parents[i].Name == name:
		return false, nil
	case i >= 0:
		d.Parents[i].Name = name
	case len(pctlOwnerList(d)) >= pctlMaxOwners:
		return false, errPctlOwnersFull
	default:
		d.Parents = append(d.Parents, PctlParent{AccountID: account, Name: name})
	}
	d.UpdatedAt = time.Now().Unix()
	s.save()
	return true, nil
}

// PctlRenameAccount gives account the name the console shows on every record
// it is a parent of (managing or further), and returns those records by moon
// id, true where the name changed. A nil name renames nothing.
func (s *Store) PctlRenameAccount(account string, name *string) map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]bool{}
	rename := func(cur *string) bool {
		if name == nil || pctlNickname(*name) == *cur {
			return false
		}
		*cur = pctlNickname(*name)
		return true
	}
	for hex, d := range s.pctlDevices() {
		if d.ManagedBy == account {
			out[hex] = rename(&d.ParentName)
		}
		for i := range d.Parents {
			if d.Parents[i].AccountID == account {
				out[hex] = rename(&d.Parents[i].Name) || out[hex]
			}
		}
	}
	for _, renamed := range out {
		if renamed {
			s.save()
			break
		}
	}
	return out
}

// PctlRemoveParent takes a further parent off a record, reporting whether it
// was one.
func (s *Store) PctlRemoveParent(moonHex, account string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil {
		return false
	}
	n := len(d.Parents)
	d.Parents = slices.DeleteFunc(d.Parents, func(p PctlParent) bool { return p.AccountID == account })
	if len(d.Parents) == n {
		return false
	}
	d.UpdatedAt = time.Now().Unix()
	s.save()
	return true
}

// PctlByPairingCode answers the console's search. An expired code is not found:
// the record stays (the parent can see it went stale) but it is no longer a way
// to claim a console. It is dropped the next time that account asks for a code.
func (s *Store) PctlByPairingCode(code string) *PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for _, d := range s.pctlDevices() {
		if d.PairingCode != "" && d.PairingCode == code && d.PairingExpires > now {
			return d
		}
	}
	return nil
}

// PctlByDauth finds the record a bearer belongs to.
// ponytail: a scan, because a household has a handful of consoles. An index if
// that ever stops being true.
func (s *Store) PctlByDauth(dauthID string) *PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	if dauthID == "" {
		return nil
	}
	for _, d := range s.pctlDevices() {
		if d.DauthID == dauthID {
			return d
		}
	}
	return nil
}

// PctlDevicesFor is what the app lists: every record this account manages,
// newest first so a code just minted is at the top.
func (s *Store) PctlDevicesFor(managedBy string) []*PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []*PctlDevice{}
	if managedBy == "" {
		return out
	}
	for _, d := range s.pctlDevices() {
		if d.ManagedBy == managedBy {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt > out[j].UpdatedAt })
	return out
}

// PctlByMoonID finds a record by the id the console put in the path. The console
// echoes back whatever our search answer gave it, so both spellings of a u64 are
// accepted: hex as we send it, and decimal in case it re-rendered the number.
// ponytail: try hex, then decimal. One of the two is right, and the log says
// which the first time a console asks.
func (s *Store) PctlByMoonID(id string) *PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.pctlDevices()[strings.ToLower(id)]; d != nil {
		return d
	}
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return nil
	}
	return s.pctlDevices()[fmt.Sprintf("%016x", n)]
}

// PctlUpdateDevice keeps the few fields a console sends about itself. Unknown
// keys are ignored rather than stored: this record is read by the parent app,
// and a console cannot be allowed to invent fields in it.
func (s *Store) PctlUpdateDevice(moonHex string, doc map[string]any) *PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil {
		return nil
	}
	if v, ok := doc["nickname"].(string); ok && v != "" {
		d.Nickname = v
	}
	if v, ok := doc["notificationToken"].(string); ok && v != "" {
		d.NotificationToken = v
	}
	if v, ok := doc["serialNumber"].(string); ok && v != "" && len(v) <= 32 {
		d.SerialNumber = v
	}
	if fw, ok := doc["firmwareVersion"].(map[string]any); ok {
		if v, ok := fw["displayedVersion"].(string); ok && v != "" && len(v) <= 32 {
			d.Firmware = v
		}
	}
	// The sync receipt names the console's PIN as it stands. No parent-set code
	// exists yet, so the console's is authoritative, and it corrects a record
	// paired before activate was kept (docs repo, the parent-surface PRD).
	if code, ok := doc["synchronizedUnlockCode"].(string); ok && pctlValidUnlockCode(code) {
		d.SyncedUnlockCode = code
		// A parent-set code the console reports otherwise is "not applied yet",
		// never "revert ours".
		if !d.UnlockCodeSet {
			d.UnlockCode, d.UnlockCodeReported = code, true
		}
	}
	if sync, ok := doc["synchronizedParentalControlSetting"].(map[string]any); ok {
		if tag, ok := sync["synchronizedEtag"].(string); ok && tag != "" {
			d.SyncedEtag, d.SyncedAt = tag, time.Now().Unix()
			if at, ok := sync["synchronizedAt"].(float64); ok && at > 0 {
				d.SyncedAt = int64(at)
			}
		}
	}
	d.UpdatedAt = time.Now().Unix()
	s.save()
	return d
}

// pctlConsoleName is what the parent's list calls a console: the name they gave
// it, else the end of its serial number, else nothing and the surface says
// "Console".
func pctlConsoleName(d *PctlDevice) string {
	switch {
	case d.Label != "":
		return d.Label
	case d.Nickname != "":
		return d.Nickname
	case len(d.SerialNumber) >= 4:
		return "Switch ···" + d.SerialNumber[len(d.SerialNumber)-4:]
	}
	return ""
}

// PctlSetLabel names a console for its parent; an empty name clears it.
func (s *Store) PctlSetLabel(moonHex, label string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.pctlDevices()[moonHex]; d != nil {
		d.Label = label
		s.save()
	}
}

// PctlUnlink is the console saying it is no longer managed. The record goes
// with everything in it -- players, events, setting and PIN -- so the parent's
// list stops showing the console and pairing again starts fresh.
func (s *Store) PctlUnlink(moonHex string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pctlDevices(), moonHex)
	s.save()
}

// PctlAddOwner links a Nintendo-Account-shaped owner id, once.
func (s *Store) PctlAddOwner(moonHex, naID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil || naID == "" {
		return
	}
	for _, o := range d.Owners {
		if o == naID {
			return
		}
	}
	d.Owners = append(d.Owners, naID)
	d.UpdatedAt = time.Now().Unix()
	s.save()
}

// PctlRemoveOwner reports how many of the managing account's owners are left;
// 0 is a console that has left. A further parent's id takes only that parent
// off, so it never reads as 0: the managing account is still there.
func (s *Store) PctlRemoveOwner(moonHex, naID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil {
		return 0
	}
	kept := d.Owners[:0]
	for _, o := range d.Owners {
		if o != naID {
			kept = append(kept, o)
		}
	}
	d.Owners = kept
	n := len(d.Parents)
	d.Parents = slices.DeleteFunc(d.Parents, func(p PctlParent) bool { return pctlNaID(p.AccountID) == naID })
	d.UpdatedAt = time.Now().Unix()
	s.save()
	if len(d.Parents) < n {
		return max(1, len(kept))
	}
	return len(kept)
}

// Play activity is kept 30 days, and pctlEventsCap bounds a console that
// uploads far more than a household's play: 5000 is about one event every nine
// minutes around the clock for the whole 30 days.
const (
	pctlEventsDays = 30
	pctlEventsCap  = 5000
)

// pctlEvents splits held entries into single events: an entry that is a JSON
// array is an upload a store before v0.45.0 kept whole. Anything else is one
// entry, kept as it came.
func pctlEvents(held []json.RawMessage) []json.RawMessage {
	out := []json.RawMessage{}
	for _, raw := range held {
		var each []json.RawMessage
		if json.Unmarshal(raw, &each) == nil {
			out = append(out, each...)
		} else {
			out = append(out, raw)
		}
	}
	return out
}

// pctlEvent reads the two fields the parent side uses; a zero timestamp is an
// event that did not carry one.
func pctlEvent(raw json.RawMessage) (kind string, at int64) {
	var e struct {
		EventType      string  `json:"eventType"`
		EventTimestamp float64 `json:"eventTimestamp"`
	}
	json.Unmarshal(raw, &e)
	return e.EventType, int64(e.EventTimestamp)
}

// PctlAddEvents holds one upload, event by event, drops what is older than
// pctlEventsDays and the oldest past pctlEventsCap, and returns how many are held.
func (s *Store) PctlAddEvents(moonHex string, body []byte) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil || len(body) == 0 {
		return 0
	}
	cut := time.Now().AddDate(0, 0, -pctlEventsDays).Unix()
	kept := []json.RawMessage{}
	for _, e := range pctlEvents(append(d.Events, json.RawMessage(append([]byte(nil), body...)))) {
		// An event with no timestamp cannot age out; the cap still bounds it.
		if _, at := pctlEvent(e); at == 0 || at >= cut {
			kept = append(kept, e)
		}
	}
	if len(kept) > pctlEventsCap {
		kept = kept[len(kept)-pctlEventsCap:]
	}
	d.Events = kept
	d.UpdatedAt = time.Now().Unix()
	s.save()
	return len(d.Events)
}

// PctlWrongUnlocks is when someone typed a wrong PIN on the console, newest
// first, at most 20: the DID_WRONG_UNLOCK_CODE events it uploaded.
func (s *Store) PctlWrongUnlocks(moonHex string) []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []int64{}
	d := s.pctlDevices()[moonHex]
	if d == nil {
		return out
	}
	for _, e := range pctlEvents(d.Events) {
		if kind, at := pctlEvent(e); kind == "DID_WRONG_UNLOCK_CODE" && at > 0 {
			out = append(out, at)
		}
	}
	slices.SortFunc(out, func(a, b int64) int { return int(b - a) })
	return out[:min(len(out), 20)]
}

// PctlEventList is a copy of a record's events, one each, read under the lock.
func (s *Store) PctlEventList(moonHex string) []json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.pctlDevices()[moonHex]; d != nil {
		return pctlEvents(d.Events)
	}
	return nil
}

// pctlActivity is play time per day, in the console's own calendar, newest day
// first: `{date, total_minutes, titles: [{title_id, minutes}]}`, for the last
// `days` dates counting today. A day with nothing counted is left out.
//
// Every event carries the console's counters as they stand, not what happened
// since the last event. Evidence (hardware, 2026-09-27, 20 events over two
// pairings): `elapsedTime` grows second for second with `eventTimestamp`
// (447 at 13:04:53, 767 at 13:10:13, 320 s apart), stands still while the
// console is temporarily unlocked (299 at DID_UNLOCK and DID_LOCK 27 s later,
// when `disabledTime` went 0 -> 27), and restarted near zero about 24 s after
// each `activate`. So they are running totals in seconds, and a total that goes
// down is a counter that restarted. Whether it also restarts at the console's
// midnight has not been seen; the reading below holds either way.
//
// `applicationTimes` is keyed by title id as `%016llX`; each value holds that
// title's `elapsedTime` in seconds, the same kind of running total (hardware:
// 790 s after thirteen minutes of one title), and who played it.
//
// So a day's time is the sum of the increases between consecutive events, the
// whole value after a restart, each bounded by the wall-clock gap since the
// previous event (a counter cannot gain more than that); the first event is
// bounded by the time since its own midnight. It is credited to the day of the
// later event. `total_minutes` is `elapsedTime`, which is what the play timer
// counts (HOME menu included); `titles` are the per-title times. An event of
// any other shape counts for nothing.
func pctlActivity(events []json.RawMessage, days int, now time.Time) []map[string]any {
	type counters struct {
		at, offset, elapsed int64
		titles              map[string]int64
		// players is who played each title, keyed title + "/" + player id; an
		// empty player id is the title's `anonymousPlayTime`, played with no
		// user selected.
		players map[string]int64
	}
	var evs []counters
	for _, raw := range events {
		var e struct {
			EventTimestamp   *float64                   `json:"eventTimestamp"`
			Offset           float64                    `json:"timeZoneUtcOffsetSeconds"`
			ElapsedTime      *float64                   `json:"elapsedTime"`
			ApplicationTimes map[string]json.RawMessage `json:"applicationTimes"`
		}
		if json.Unmarshal(raw, &e) != nil || e.EventTimestamp == nil || e.ElapsedTime == nil || *e.ElapsedTime < 0 {
			continue
		}
		c := counters{at: int64(*e.EventTimestamp), offset: int64(e.Offset), elapsed: int64(*e.ElapsedTime),
			titles: map[string]int64{}, players: map[string]int64{}}
		for id, v := range e.ApplicationTimes {
			// Seen on hardware (2026-09-27, DID_APP_PLAY): the title's seconds,
			// the part played with no user, and the rest split by the console's
			// own player ids -- the ids its `players` uploads carry.
			var app struct {
				ElapsedTime       float64 `json:"elapsedTime"`
				AnonymousPlayTime float64 `json:"anonymousPlayTime"`
				DevicePlayers     map[string]struct {
					ElapsedTime float64 `json:"elapsedTime"`
				} `json:"devicePlayers"`
			}
			if len(id) != 16 || !pctlHexID(id) || json.Unmarshal(v, &app) != nil || app.ElapsedTime <= 0 {
				continue
			}
			id = strings.ToLower(id)
			c.titles[id] = int64(app.ElapsedTime)
			if app.AnonymousPlayTime > 0 {
				c.players[id+"/"] = int64(app.AnonymousPlayTime)
			}
			for player, p := range app.DevicePlayers {
				if p.ElapsedTime > 0 && !strings.Contains(player, "/") {
					c.players[id+"/"+player] = int64(p.ElapsedTime)
				}
			}
		}
		evs = append(evs, c)
	}
	slices.SortStableFunc(evs, func(a, b counters) int { return int(a.at - b.at) })

	total, titles, players := map[string]int64{}, map[string]map[string]int64{}, map[string]map[string]int64{}
	for i, e := range evs {
		local := time.Unix(e.at+e.offset, 0).UTC()
		day := local.Format("2006-01-02")
		gap := int64(local.Hour()*3600 + local.Minute()*60 + local.Second())
		prev := counters{}
		if i > 0 {
			gap = e.at - evs[i-1].at
			if e.elapsed >= evs[i-1].elapsed {
				prev = evs[i-1]
			}
		}
		gain := func(cur, before int64) int64 {
			if cur < before {
				before = 0
			}
			return max(0, min(cur-before, gap))
		}
		total[day] += gain(e.elapsed, prev.elapsed)
		for id, secs := range e.titles {
			if titles[day] == nil {
				titles[day] = map[string]int64{}
			}
			titles[day][id] += gain(secs, prev.titles[id])
		}
		for key, secs := range e.players {
			if players[day] == nil {
				players[day] = map[string]int64{}
			}
			players[day][key] += gain(secs, prev.players[key])
		}
	}

	offset := int64(0)
	if len(evs) > 0 {
		offset = evs[len(evs)-1].offset
	}
	first := now.Add(time.Duration(offset)*time.Second).UTC().AddDate(0, 0, 1-days).Format("2006-01-02")
	out := []map[string]any{}
	for _, day := range slices.Sorted(maps.Keys(total)) {
		list := []map[string]any{}
		for id, secs := range titles[day] {
			if m := (secs + 30) / 60; m > 0 {
				who := []map[string]any{}
				for key, secs := range players[day] {
					if player, ok := strings.CutPrefix(key, id+"/"); ok && player != "" && (secs+30)/60 > 0 {
						who = append(who, map[string]any{"id": player, "minutes": (secs + 30) / 60})
					}
				}
				slices.SortFunc(who, func(a, b map[string]any) int {
					if d := b["minutes"].(int64) - a["minutes"].(int64); d != 0 {
						return int(d)
					}
					return strings.Compare(a["id"].(string), b["id"].(string))
				})
				list = append(list, map[string]any{"title_id": id, "minutes": m, "players": who,
					"anonymous_minutes": (players[day][id+"/"] + 30) / 60})
			}
		}
		slices.SortFunc(list, func(a, b map[string]any) int {
			if d := b["minutes"].(int64) - a["minutes"].(int64); d != 0 {
				return int(d)
			}
			return strings.Compare(a["title_id"].(string), b["title_id"].(string))
		})
		if m := (total[day] + 30) / 60; day >= first && (m > 0 || len(list) > 0) {
			out = append([]map[string]any{{"date": day, "total_minutes": m, "titles": list}}, out...)
		}
	}
	return out
}

// PctlActivate binds a console to the record its code found and burns the code.
// Activating twice with the same console is not an error -- a retried request
// must not lose the console -- but another console cannot take the record.
func (s *Store) PctlActivate(moonHex, dauthID string) *PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil || dauthID == "" || (d.DauthID != "" && d.DauthID != dauthID) {
		return nil
	}
	d.DauthID = dauthID
	d.PairingCode, d.PairingExpires = "", 0
	if d.ActivatedAt == 0 {
		d.ActivatedAt = time.Now().Unix()
	}
	d.UpdatedAt = time.Now().Unix()
	s.save()
	return d
}

// PctlSetSetting stores the setting document and recomputes its ETag. An
// unchanged document keeps its ETag, which is what makes the console's
// `If-None-Match` answer 304 instead of re-downloading every poll.
func (s *Store) PctlSetSetting(moonHex string, doc map[string]any) *PctlDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil {
		return nil
	}
	// The console's own PIN replaces the one minted with the record: the parent
	// has to be shown the code that actually unlocks the console.
	if code, ok := doc["unlockCode"].(string); ok && pctlValidUnlockCode(code) && !d.UnlockCodeSet {
		d.UnlockCode, d.UnlockCodeReported = code, true
	}
	tag := pctlETag(doc)
	if tag == d.ETag {
		s.save()
		return d
	}
	d.Setting, d.ETag, d.UpdatedAt = doc, tag, time.Now().Unix()
	s.save()
	return d
}

// PctlSetUnlockCode is a parent setting the console's PIN.
func (s *Store) PctlSetUnlockCode(moonHex, code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.pctlDevices()[moonHex]
	if d == nil {
		return
	}
	d.UnlockCode, d.UnlockCodeSet, d.UpdatedAt = code, true, time.Now().Unix()
	s.save()
}

// pctlValidUnlockCode is what the console's parse table accepts for a PIN: four
// to eight digits.
func pctlValidUnlockCode(code string) bool {
	return len(code) >= 4 && len(code) <= 8 && strings.Trim(code, "0123456789") == ""
}

// PctlPlayerList is a record's players by id, read under the lock: the console
// adds and removes them while the parent side lists them.
func (s *Store) PctlPlayerList(moonHex string) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []map[string]any{}
	d := s.pctlDevices()[moonHex]
	if d == nil {
		return out
	}
	for _, id := range slices.Sorted(maps.Keys(d.Players)) {
		out = append(out, map[string]any{"id": id, "nickname": d.Players[id].Nickname})
	}
	return out
}

// PctlPlayerImage is one player's picture as the console sent it, in base64.
func (s *Store) PctlPlayerImage(moonHex, id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.pctlDevices()[moonHex]; d != nil && d.Players[id] != nil {
		return d.Players[id].ImageData
	}
	return ""
}

// pctlETag is a strong validator over the document's canonical JSON. Go's
// encoder sorts map keys, so the same document always hashes the same.
func pctlETag(doc map[string]any) string {
	b, err := json.Marshal(doc)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// POST /internal/pctl/pairing {"account_id":"…"} -> the code to type on the console.
// The parent surface is a screen in the app; this is the call behind it, and
// until that screen exists it is also how a pairing attempt gets a real code to
// type -- which is what turns the phase-0 log from "unknown code" into the
// matched path.
func (s *server) pctlPairing(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	if r.Method != http.MethodPost {
		apiErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var in struct {
		AccountID   string `json:"account_id"`
		DisplayName string `json:"display_name"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in)
	d := s.store.PctlNewPairing(in.AccountID)
	s.store.PctlNameParent(d.Hex(), in.DisplayName)
	log.Printf("[moon] pairing code %s for account=%q device=%s (expires %ds)",
		d.PairingCode, in.AccountID, d.Hex(), int(pctlPairingTTL.Seconds()))
	writeJSON(w, 200, map[string]any{
		"moon_id": d.Hex(), "pairing_code": d.PairingCode, "expires_at": d.PairingExpires,
	})
}

// ---------- the explainer video ----------

// pctlMovie serves `parentalcontrols-movie-<env>.cdn.nintendo.net/default/
// switchpc_<lang>.mp4`, the clip the Parental Controls setup screen offers
// (firmware follow-up §22c; study §7 P5). Whether the screen *blocks* on it is
// unproven, so this stays a file we hand over when there is one and a logged 404
// when there is not -- no invented video, and no guess at a codec the console
// would then have to decode.
//
// ponytail: one env var, no asset in the repo. PCTL_MOVIE=/path/to.mp4 and
// http.ServeFile does the Range handling a video player needs.
func (s *server) pctlMovie(w http.ResponseWriter, r *http.Request) {
	path := getenv("PCTL_MOVIE", "")
	if path == "" {
		log.Printf("[moon] movie %s%s -- no PCTL_MOVIE configured, answering 404", hostOf(r), r.URL.Path)
		http.NotFound(w, r)
		return
	}
	log.Printf("[moon] movie %s%s -> %s", hostOf(r), r.URL.Path, path)
	w.Header().Set("Content-Type", "video/mp4")
	http.ServeFile(w, r, path)
}

// GET /internal/pctl/devices?account_id=… -> the records that account manages,
// as the app's list. The pairing code travels only while it is still live: a
// dead code on a screen is worse than none, because someone types it.
//
// A paired record also carries what the parent reads: the setting as served,
// the players (their pictures are a separate call), the last receipt and
// whether it names the served document, and the PIN once the console has named
// it. The PIN is never logged.
func (s *server) pctlDeviceList(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	account := r.URL.Query().Get("account_id")
	if account == "" {
		apiErr(w, http.StatusBadRequest, "account_id required")
		return
	}
	now := time.Now().Unix()
	out := []map[string]any{}
	for _, d := range s.store.PctlDevicesFor(account) {
		item := map[string]any{
			"moon_id":            d.Hex(),
			"paired":             d.DauthID != "",
			"activated_at":       d.ActivatedAt,
			"updated_at":         d.UpdatedAt,
			"owners":             d.Owners,
			"parents":            pctlParentList(d),
			"has_setting":        len(d.Setting) > 0,
			"nickname":           pctlConsoleName(d),
			"named":              d.Label != "",
			"serial_number":      d.SerialNumber,
			"firmware":           d.Firmware,
			"setting":            pctlSettingOf(d),
			"players":            s.store.PctlPlayerList(d.Hex()),
			"etag":               pctlServedETag(d),
			"synced_etag":        d.SyncedEtag,
			"synced_at":          d.SyncedAt,
			"synced":             pctlSynced(d),
			"wrong_pin_attempts": s.store.PctlWrongUnlocks(d.Hex()),
		}
		if d.DauthID != "" && (d.UnlockCodeReported || d.UnlockCodeSet) {
			item["unlock_code"] = d.UnlockCode
		}
		if d.PairingCode != "" && d.PairingExpires > now {
			item["pairing_code"] = d.PairingCode
			item["expires_at"] = d.PairingExpires
		}
		out = append(out, item)
	}
	writeJSON(w, 200, map[string]any{"devices": out})
}

// pctlParentList is a record's further parents as the parent surface reads
// them.
func pctlParentList(d *PctlDevice) []map[string]any {
	out := []map[string]any{}
	for _, p := range d.Parents {
		out = append(out, map[string]any{"account_id": p.AccountID, "display_name": p.Name})
	}
	return out
}

// /internal/pctl/devices/{moon_id}/…?account_id=… is one record, for the account
// that manages it. Another account's record is a 404, the same as one that does
// not exist, so ids cannot be probed.
func (s *server) pctlDeviceRoute(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/internal/pctl/devices/"), "/")
	account := r.URL.Query().Get("account_id")
	d := s.store.PctlByMoonID(parts[0])
	if d == nil || account == "" || d.ManagedBy != account {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	switch {
	case len(parts) == 2 && parts[1] == "name" && r.Method == http.MethodPut:
		var in struct {
			Name string `json:"name"`
		}
		json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in)
		name := strings.TrimSpace(in.Name)
		if utf8.RuneCountInString(name) > 32 || strings.ContainsFunc(name, unicode.IsControl) {
			apiErr(w, http.StatusBadRequest, "name must be at most 32 characters")
			return
		}
		s.store.PctlSetLabel(d.Hex(), name)
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 1 && r.Method == http.MethodDelete:
		// The parent removing a console from their list. The console is not
		// told: it stays linked on its own side and gets a 404 at its next
		// sync, so this is for a console that is already gone or reset.
		s.store.PctlUnlink(d.Hex())
		log.Printf("[moon] device %s removed by account %q", d.Hex(), account)
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 2 && parts[1] == "setting" && r.Method == http.MethodPut:
		s.pctlPutSetting(w, r, d)
	case len(parts) == 2 && parts[1] == "activity" && r.Method == http.MethodGet:
		days := 7
		if v := r.URL.Query().Get("days"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > pctlEventsDays {
				apiErr(w, http.StatusBadRequest, "days must be 1 to 30")
				return
			}
			days = n
		}
		writeJSON(w, 200, map[string]any{"days": pctlActivity(s.store.PctlEventList(d.Hex()), days, time.Now())})
	case len(parts) == 4 && parts[1] == "players" && parts[3] == "image" && r.Method == http.MethodGet:
		s.pctlPlayerImage(w, d, parts[2])
	case len(parts) == 3 && parts[1] == "parents" && (r.Method == http.MethodPut || r.Method == http.MethodDelete):
		s.pctlParentRoute(w, r, d, parts[2])
	default:
		apiErr(w, http.StatusNotFound, "not found")
	}
}

// PUT …/parents/{account_id} {"display_name"} makes another OpenPak account a
// parent of the console, or renames it; DELETE takes it off. Only the managing
// account calls this (pctlDeviceRoute). The console lists each parent as its
// own owner, under that name and that account's picture.
func (s *server) pctlParentRoute(w http.ResponseWriter, r *http.Request, d *PctlDevice, account string) {
	if !pctlAccountID(account) {
		apiErr(w, http.StatusBadRequest, "account id")
		return
	}
	if r.Method == http.MethodDelete {
		if s.store.PctlRemoveParent(d.Hex(), account) {
			log.Printf("[moon] device %s: parent %s removed", d.Hex(), account)
			s.pctlOwnersPush(s.store.PctlByMoonID(d.Hex()))
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var in struct {
		DisplayName string `json:"display_name"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in)
	changed, err := s.store.PctlSetParent(d.Hex(), account, in.DisplayName)
	switch {
	case errors.Is(err, errPctlOwnersFull):
		apiErr(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		apiErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if changed {
		log.Printf("[moon] device %s: parent %s set", d.Hex(), account)
		s.pctlOwnersPush(s.store.PctlByMoonID(d.Hex()))
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /internal/pctl/parents/{account_id} {"display_name"} -> {"pushed": n}:
// the website saying an account's name or picture changed (display_name only
// when the name did). The name is taken on every record the account is a
// parent of, its picture is fetched again, and each paired console that now
// shows something different is told (UPDATE_DEVICE_OWNERS). An account that is
// nobody's parent costs nothing.
func (s *server) pctlParentProfile(w http.ResponseWriter, r *http.Request) {
	if !s.internalOK(r) {
		apiErr(w, http.StatusUnauthorized, "internal")
		return
	}
	if r.Method != http.MethodPost {
		apiErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	account := strings.TrimPrefix(r.URL.Path, "/internal/pctl/parents/")
	if !pctlAccountID(account) {
		apiErr(w, http.StatusBadRequest, "account id")
		return
	}
	var in struct {
		DisplayName *string `json:"display_name"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in)
	records := s.store.PctlRenameAccount(account, in.DisplayName)
	if len(records) == 0 {
		writeJSON(w, 200, map[string]any{"pushed": 0})
		return
	}
	pctlIcons.Lock()
	before := pctlIcons.m[account].file
	pctlIcons.Unlock()
	_, after := pctlIconOf(account, true)
	pushed := 0
	for _, hex := range slices.Sorted(maps.Keys(records)) {
		if d := s.store.PctlByMoonID(hex); d != nil && d.DauthID != "" && (records[hex] || before != after) {
			s.pctlOwnersPush(d)
			pushed++
		}
	}
	log.Printf("[moon] parent %s changed (picture %q -> %q): %d console(s) told", account, before, after, pushed)
	writeJSON(w, 200, map[string]any{"pushed": pushed})
}

// GET …/players/{id}/image -> the player's JPEG, decoded from what the console
// uploaded.
func (s *server) pctlPlayerImage(w http.ResponseWriter, d *PctlDevice, player string) {
	img, err := base64.StdEncoding.DecodeString(s.store.PctlPlayerImage(d.Hex(), player))
	if err != nil || len(img) == 0 {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Write(img)
}

// PUT …/setting {"setting": {…}, "unlock_code": "1234"}, either key optional ->
// {"etag", "updated_at"}. The parent's write. A document is refused, not
// thinned: anything the console's parse table would not take is a 400 naming
// its path, and nothing is stored -- a parent who set a limit must not be shown
// a save that quietly dropped it. The code is never logged.
func (s *server) pctlPutSetting(w http.ResponseWriter, r *http.Request, d *PctlDevice) {
	var in struct {
		Setting    map[string]any `json:"setting"`
		UnlockCode *string        `json:"unlock_code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "body is not a JSON object")
		return
	}
	if in.Setting == nil && in.UnlockCode == nil {
		apiErr(w, http.StatusBadRequest, "setting or unlock_code required")
		return
	}
	var doc map[string]any
	if in.Setting != nil {
		if in.Setting["functionalRestrictionLevel"] == nil {
			apiErr(w, http.StatusBadRequest, "setting.functionalRestrictionLevel required")
			return
		}
		doc, _ = pctlConform(in.Setting, pctlSettingSchema).(map[string]any)
		if bad := pctlDropped(in.Setting, doc, ""); bad != "" {
			apiErr(w, http.StatusBadRequest, "not in the console's parse table: "+bad)
			return
		}
	}
	// Exactly four: the console's parser takes up to eight, but its entry field
	// has four places, so a longer PIN could never be typed (hardware).
	if in.UnlockCode != nil && (len(*in.UnlockCode) != 4 || !pctlValidUnlockCode(*in.UnlockCode)) {
		apiErr(w, http.StatusBadRequest, "unlock_code must be 4 digits")
		return
	}
	if doc != nil {
		s.store.PctlSetSetting(d.Hex(), doc)
	}
	if in.UnlockCode != nil {
		s.store.PctlSetUnlockCode(d.Hex(), *in.UnlockCode)
	}
	d = s.store.PctlByMoonID(d.Hex())
	tag := pctlServedETag(d)
	log.Printf("[moon] device %s: parent set setting=%t code=%t, served etag %s", d.Hex(), doc != nil, in.UnlockCode != nil, tag)
	s.pctlPush(d)
	writeJSON(w, 200, map[string]any{"etag": tag, "updated_at": d.UpdatedAt})
}

// pctlPush tells a console that its setting changed, so it fetches it now
// rather than at its next scheduled retrieve (`pctl!intermittent_task_interval_seconds`,
// 21600 s by default). Best effort: with no live connection, or a console
// that ignores it, the save already stands and the console catches up on its
// own schedule.
//
// The shape is pctl 22.5.0's (docs repo, parental-controls-firmware-2026-09-26.md
// §5c): pctl listens on npns under the name `pctl` (npns cmd 8 with that
// string, .text 0x7abb0), parses a message body with the table at vaddr
// 0x13a9a0, drops it unless `deviceId` (a hex string) is its own paired id,
// and for `eventId` DID_CHANGE_PARENTAL_CONTROL_SETTING asks for a retrieve
// at once (.text 0x4fdec). No account id: pctl never reads it. The carrier
// is the frontline connection whose Penne id the console gave as its
// notificationToken, the way news.go reaches a console.
func (s *server) pctlPush(d *PctlDevice) { s.pctlPushEvent(d, pctlSettingChanged) }

// pctlPushEvent sends one of pctl's push events to the console, in the shape
// and on the carrier pctlPush describes.
func (s *server) pctlPushEvent(d *PctlDevice, event string) {
	// The token is the console's Penne id. Paired before v0.47.0, when the token was not
	// kept, the Penne registration made under the same device certificate is the same
	// console's: penneDeviceMessage looks that up from DauthID.
	if d.NotificationToken == "" && d.DauthID == "" {
		log.Printf("[moon] device %s: no notification token; the console fetches on its own schedule", d.Hex())
		return
	}
	body, _ := json.Marshal(map[string]any{"deviceId": d.Hex(), "eventId": event})
	token, n, err := s.penneDeviceMessage(d.NotificationToken, d.DauthID, event, "pctl", string(body))
	if err != nil {
		log.Printf("[moon] device %s: push not delivered (%v); the console fetches on its own schedule", d.Hex(), err)
		return
	}
	if token == "" {
		log.Printf("[moon] device %s: no notification token; the console fetches on its own schedule", d.Hex())
		return
	}
	log.Printf("[moon] device %s: pushed %s on %d connection(s) of registration %s", d.Hex(), event, n, token)
}

// pctlSettingChanged is the first value of pctl's eventId enum (vaddr 0x13ab20).
const pctlSettingChanged = "DID_CHANGE_PARENTAL_CONTROL_SETTING"

// pctlOwnersChanged is the sixth value, new in 23.x (pctl 23.0.1 enum 0x245ca0,
// handler 0x152960): the console re-reads GET …/owners at once and redraws its
// parents. 22.5 does not know the value and drops the message, which is
// harmless. Sent when a paired console's owners change on the parent side:
// a further parent added, renamed or removed, or a parent's name or picture
// changed. Owner changes the console made itself (owners/%016llx) are not
// pushed back to it.
const pctlOwnersChanged = "UPDATE_DEVICE_OWNERS"

// pctlOwnersPush tells a paired console its owners changed. A record no
// console has claimed has nobody to tell.
func (s *server) pctlOwnersPush(d *PctlDevice) {
	if d != nil && d.DauthID != "" {
		s.pctlPushEvent(d, pctlOwnersChanged)
	}
}

// pctlDropped names the first path (sorted, dotted) where the conformed
// document differs from what was sent, or "" when nothing was dropped or
// changed.
func pctlDropped(in, out any, path string) string {
	m, ok := in.(map[string]any)
	if !ok {
		a, _ := json.Marshal(in)
		b, _ := json.Marshal(out)
		if out == nil || string(a) != string(b) {
			return path
		}
		return ""
	}
	o, _ := out.(map[string]any)
	if o == nil {
		return path
	}
	for _, k := range slices.Sorted(maps.Keys(m)) {
		sub := k
		if path != "" {
			sub = path + "." + k
		}
		if bad := pctlDropped(m[k], o[k], sub); bad != "" {
			return bad
		}
	}
	return ""
}
