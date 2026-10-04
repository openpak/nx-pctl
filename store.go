package main

// pctl's state: the parental-controls records nx-baas kept inside baas.json, now alone in
// $NX_DATA/pctl.json under the same JSON key ("pctlDevices"), so nx-baas's baas.json is itself
// a file this type reads. The Pctl* methods on it are moon.go's, unchanged.

import (
	"encoding/json"
	"log"
	"os"
	"sync"
)

type Store struct {
	mu   sync.Mutex
	path string
	// PctlDevices are the parental-controls records, keyed by the moon device id as the
	// console spells it (moon.go).
	PctlDevices map[string]*PctlDevice `json:"pctlDevices,omitempty"`
}

// loadStore reads pctl.json. On the first start -- no pctl.json yet -- with importFrom naming
// nx-baas's baas.json, the records are taken from there and written here at once, so
// paired consoles keep their pairing across the move. Everything else in baas.json is
// ignored.
func loadStore(path, importFrom string) *Store {
	s := &Store{path: path}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, s); err != nil {
			log.Fatalf("%s %s: %v", logPrefix, path, err)
		}
		return s
	}
	if importFrom == "" {
		return s
	}
	b, err := os.ReadFile(importFrom)
	if err != nil {
		log.Printf("%s NX_PCTL_IMPORT %s: %v; starting empty", logPrefix, importFrom, err)
		return s
	}
	if err := json.Unmarshal(b, s); err != nil {
		log.Fatalf("%s import %s: %v", logPrefix, importFrom, err)
	}
	s.mu.Lock()
	s.save()
	s.mu.Unlock()
	log.Printf("%s imported %d parental-controls record(s) from %s into %s", logPrefix, len(s.PctlDevices), importFrom, path)
	return s
}

// save is called with mu held.
func (s *Store) save() {
	b, _ := json.MarshalIndent(s, "", " ")
	os.WriteFile(s.path+".tmp", b, 0o600)
	os.Rename(s.path+".tmp", s.path)
}
