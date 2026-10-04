package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/openpak/nx-common/nxapi"
)

// deviceTokenFor is nx-baas's dauth device token: what the console presents on moon.
func deviceTokenFor(s *server, device string) string {
	now := time.Now().Unix()
	return signJWT(map[string]any{"alg": "RS256", "kid": s.idKid, "typ": "JWT"},
		map[string]any{"iss": "dauth-lp1.ndas.srv.nintendo.net", "jti": uuid4(), "iat": now - 600, "exp": now + 86400, "sub": device, "aud": "pctl-test"}, s.key)
}

// fakePenne records the device messages pctl sends.
type fakePenne struct {
	mu   sync.Mutex
	sent []nxapi.DeviceMessage
	down bool
}

func (p *fakePenne) DeviceMessage(_ context.Context, m nxapi.DeviceMessage) (*nxapi.DeviceResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.down {
		return nil, errors.New("fake penne: connection refused")
	}
	p.sent = append(p.sent, m)
	return &nxapi.DeviceResult{PenneID: m.PenneID, Connections: 1}, nil
}
