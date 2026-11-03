package main

// pctl's state: the parental-controls records nx-baas kept inside baas.json, now alone in
// $NX_DATA/pctl.json under the same JSON key ("pctlDevices"), so nx-baas's baas.json is itself
// a file this type reads. The Pctl* methods on it are moon.go's, unchanged.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

type Store struct {
	mu   sync.Mutex
	path string
	// PctlDevices are the parental-controls records, keyed by the moon device id as the
	// console spells it (moon.go).
	PctlDevices map[string]*PctlDevice `json:"pctlDevices"`
	// remote is the parental core when NX_PCTL_BACKEND=parental (parental.go): the records'
	// source of truth, written on every save; the file is then its mirror. nil: the file
	// is the store, as before.
	remote *parentalSync
	// seal is the at-rest key (seal.go): every save writes the file sealed under it. nil
	// keeps the file in clear (NX_PCTL_BLOB_INSECURE_PLAINTEXT=1, and tests).
	seal *sealKey
}

// loadStore reads pctl.json. With importFrom naming nx-baas's baas.json, a start takes the
// records from there whenever they are not the ones already imported: on the first cut-over,
// and again on a second cut-over after a rollback, when nx-baas served parental controls for
// a while and its records moved on. Only the pctlDevices value is compared and taken --
// baas.json changes on every login, its records do not while parental controls are here --
// and its fingerprint is kept beside ours (pctl.json.imported). A local file an import
// replaces is kept as pctl.json.before-import-<time>. Everything else in baas.json is ignored.
// key opens a sealed pctl.json and seals every save (seal.go); nil reads and writes clear.
func loadStore(path, importFrom string, key *sealKey) *Store {
	s := &Store{path: path, seal: key}
	read := func() *Store {
		if b, err := os.ReadFile(path); err == nil {
			plain, err := openFile(key, b)
			if err != nil {
				log.Fatalf("%s %s: %v", logPrefix, path, err)
			}
			if err := json.Unmarshal(plain, s); err != nil {
				log.Fatalf("%s %s: %v", logPrefix, path, err)
			}
		}
		return s
	}
	if importFrom == "" {
		return read()
	}
	b, err := os.ReadFile(importFrom)
	if err != nil {
		log.Printf("%s NX_PCTL_IMPORT %s: %v; keeping our own records", logPrefix, importFrom, err)
		return read()
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		log.Fatalf("%s import %s: %v", logPrefix, importFrom, err)
	}
	raw := top["pctlDevices"]
	sum := sha256.Sum256(raw)
	mark := hex.EncodeToString(sum[:])
	prev, _ := os.ReadFile(path + ".imported")
	_, statErr := os.Stat(path)
	if statErr == nil && string(prev) == mark {
		return read()
	}
	if statErr == nil {
		old := path + ".before-import-" + time.Now().UTC().Format("20060102T150405")
		if err := os.Rename(path, old); err != nil {
			log.Fatalf("%s import: cannot set our own records aside: %v", logPrefix, err)
		}
		log.Printf("%s the records in %s changed since our last import (nx-baas served parental controls meanwhile); ours are kept as %s", logPrefix, importFrom, old)
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s.PctlDevices); err != nil {
			log.Fatalf("%s import %s: pctlDevices: %v", logPrefix, importFrom, err)
		}
	}
	s.mu.Lock()
	s.save()
	s.mu.Unlock()
	if err := os.WriteFile(path+".imported", []byte(mark), 0o600); err != nil {
		log.Fatalf("%s import: cannot record the fingerprint: %v", logPrefix, err)
	}
	log.Printf("%s imported %d parental-controls record(s) from %s into %s", logPrefix, len(s.PctlDevices), importFrom, path)
	return s
}

// save is called with mu held.
func (s *Store) save() {
	if s.PctlDevices == nil {
		// Always an object, never absent or null: nx-baas's rollback refuses a file without
		// one, so "no records" has to be written as {}.
		s.PctlDevices = map[string]*PctlDevice{}
	}
	if s.remote != nil {
		// First, so a record the core no longer holds leaves the mirror too.
		s.remote.sync(s.PctlDevices)
	}
	b, _ := json.MarshalIndent(s, "", " ")
	os.WriteFile(s.path+".tmp", encodeFile(s.seal, b), 0o600)
	os.Rename(s.path+".tmp", s.path)
}
