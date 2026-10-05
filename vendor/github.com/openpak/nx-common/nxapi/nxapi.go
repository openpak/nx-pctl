// Package nxapi is the internal contract between the Switch services: the JSON each one
// answers on its internal listener (plain HTTP on the openpak network, X-Internal-Key), and a
// client for it. docs/service-split.md in nx-baas is the prose version; nx-baas implements
// the server side of both families without importing this module, so a change here is a
// change to that document and to nx-baas's internal_*.go together.
//
// Two families:
//
//   - identity, served by nx-baas (the core): who a BAAS user or a Nintendo Account is, whether
//     the account is locked, its picture, a friend preference, and the presence a console
//     publishes over Penne (which the core owns, because presence is part of the friend
//     graph);
//   - penne, served by whichever process holds the push state (nx-baas until the cut-over,
//     nx-penne after): registrations, console bindings, notification submission and the
//     direct messages news and parental controls send.
//
// Every call is small and synchronous, with a short timeout; a caller treats an unreachable
// peer as "unknown", logs it, and degrades the one request rather than failing the process.
package nxapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openpak/nx-common/internalkey"
)

// ---------- identity (nx-baas) ----------

// User is a BAAS user as the other services need it. Lock is the account's ban state from
// the core ("" when it may use the network).
type User struct {
	ID       string `json:"id"`
	NaID     string `json:"na_id"`
	PID      uint64 `json:"pid"`
	Nickname string `json:"nickname"`
	Lock     string `json:"lock"`
}

// NA is a Nintendo Account id as the core maps it. An id the core has never seen is still a
// 200 with an empty BaasUserID: an NA id token we signed names an account even before any
// console linked to it.
type NA struct {
	NaID       string `json:"na_id"`
	BaasUserID string `json:"baas_user_id"`
	PID        uint64 `json:"pid"`
	Lock       string `json:"lock"`
}

// Account maps an OpenPak core account to its Switch Nintendo Account id.
type Account struct {
	AccountID string `json:"account_id"`
	NaID      string `json:"na_id"`
}

// Presence is one DAPresence frame, decoded by the Penne frontline and owned by the core.
type Presence struct {
	UserID   string `json:"user_id"`
	Device   string `json:"device"`
	State    string `json:"state"`
	AppID    string `json:"app_id,omitempty"`
	AppField string `json:"app_field,omitempty"`
	GroupID  string `json:"group_id,omitempty"`
	ACDIndex int    `json:"acd_index"`
}

// PresenceRenewal keeps a published presence's lease alive.
type PresenceRenewal struct {
	UserID string `json:"user_id"`
	Device string `json:"device"`
}

// FriendPreference is the one preference the push side reads: whether the viewer wants an
// alert when this friend comes online.
type FriendPreference struct {
	OnlineNotification bool `json:"online_notification"`
}

// ---------- penne (nx-baas until the cut-over, then nx-penne) ----------

// Registration is a Penne registration (penne_id) as the shop's pushmo /p/<id> reads it.
type Registration struct {
	PenneID string   `json:"penne_id"`
	Live    bool     `json:"live"`
	UserID  string   `json:"user_id"`
	Users   []string `json:"users"`
}

// ConsoleBinding records which BAAS user is signed in on the console a device certificate
// names (what the core learns at /1.0.0/login).
type ConsoleBinding struct {
	DeviceID string `json:"device_id"`
	UserID   string `json:"user_id"`
}

// PushChannel is the BAAS push_channels association.
type PushChannel struct {
	UserID          string `json:"user_id"`
	DeviceAccountID string `json:"device_account_id"`
	Service         string `json:"service"`
	DeviceToken     string `json:"device_token"`
}

// Notification is one semantic notification for one BAAS user.
type Notification struct {
	ID      string         `json:"id"`
	UserID  string         `json:"user_id"`
	Kind    string         `json:"kind"`
	Payload map[string]any `json:"payload"`
}

// Submission is the outcome of a Notification: Accepted means persisted or already known.
type Submission struct {
	Accepted  bool   `json:"accepted"`
	Duplicate bool   `json:"duplicate"`
	Outcome   string `json:"outcome"`
	ID        string `json:"id"`
}

// TopicMessage is one message to every live connection subscribed to a topic (news).
type TopicMessage struct {
	Topic     string `json:"topic"`
	Name      string `json:"name"`
	Receivers string `json:"receivers"`
	Body      string `json:"body"`
}

// TopicResult says how many subscriptions matched and how many connections got the message.
type TopicResult struct {
	Subscribers int `json:"subscribers"`
	Delivered   int `json:"delivered"`
}

// TokenBinding is olsc's upload of a profile's notification token with the user's own
// token: it tells the push side which user a console profile is.
type TokenBinding struct {
	NotificationToken string `json:"notification_token"`
	UserID            string `json:"user_id"`
}

// DeviceMessage is one message to the live connections of one Penne registration: PenneID
// when the caller kept the console's notification token, else DauthUser, the device
// certificate the registration was made under (parental controls).
type DeviceMessage struct {
	PenneID   string `json:"penne_id,omitempty"`
	DauthUser string `json:"dauth_user,omitempty"`
	Name      string `json:"name"`
	Receivers string `json:"receivers"`
	Body      string `json:"body"`
}

// DeviceResult names the registration the message went to and how many connections took it.
type DeviceResult struct {
	PenneID     string `json:"penne_id"`
	Connections int    `json:"connections"`
}

// Paths. Identity under /internal/identity, push under /internal/penne.
const (
	PathIdentityUsers    = "/internal/identity/users/"    // GET {id}; GET {id}/avatar; GET {id}/friends/{friend}/preference
	PathIdentityNA       = "/internal/identity/na/"       // GET {na_id}
	PathIdentityAccounts = "/internal/identity/accounts/" // GET {account_id}
	PathIdentityPresence = "/internal/identity/presence"  // POST Presence; POST /renew PresenceRenewal

	PathPenneRegistrations  = "/internal/penne/registrations/"  // GET {penne_id}
	PathPenneConsoleRegs    = "/internal/penne/console-registrations/" // GET {device certificate id}
	PathPenneConsoles       = "/internal/penne/consoles"        // POST ConsoleBinding
	PathPennePushChannels   = "/internal/penne/push-channels"   // POST PushChannel
	PathPenneNotifications  = "/internal/penne/notifications"   // POST Notification -> Submission
	PathPenneTopicMessages  = "/internal/penne/topic-messages"  // POST TopicMessage -> TopicResult
	PathPenneTokenBindings  = "/internal/penne/token-bindings"  // POST TokenBinding -> {"bound":bool}
	PathPenneDeviceMessages = "/internal/penne/device-messages" // POST DeviceMessage -> DeviceResult
	PathPenneUsers          = "/internal/penne/users/"          // POST {id}/close -> {"closed":n}
)

// Client calls one peer's internal listener.
type Client struct {
	Base string
	Key  string
	HTTP *http.Client
}

// New is a client for base (e.g. http://openpak-nx-baas:20070) with the configured key.
func New(base string) *Client {
	return &Client{Base: strings.TrimRight(base, "/"), Key: internalkey.Key(), HTTP: &http.Client{Timeout: 5 * time.Second}}
}

// ErrNotFound is a 404 from the peer: the thing asked about does not exist there.
var ErrNotFound = fmt.Errorf("nxapi: not found")

// Do sends in as JSON (nil sends no body) and decodes the reply into out (nil discards it).
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	resp, err := c.Raw(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("nxapi: %s %s: %d %s", method, path, resp.StatusCode, bytes.TrimSpace(msg))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Raw sends a request and hands back the response unread; the caller closes it.
func (c *Client) Raw(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(internalkey.Header, c.Key)
	return c.HTTP.Do(req)
}

// ---------- identity calls ----------

func (c *Client) User(ctx context.Context, id string) (*User, error) {
	var u User
	if err := c.Do(ctx, http.MethodGet, PathIdentityUsers+url.PathEscape(id), nil, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (c *Client) NA(ctx context.Context, naID string) (*NA, error) {
	var n NA
	if err := c.Do(ctx, http.MethodGet, PathIdentityNA+url.PathEscape(naID), nil, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

func (c *Client) Account(ctx context.Context, accountID string) (*Account, error) {
	var a Account
	if err := c.Do(ctx, http.MethodGet, PathIdentityAccounts+url.PathEscape(accountID), nil, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// Avatar is the user's picture exactly as the core's cdn-image host serves /1/<id>.
func (c *Client) Avatar(ctx context.Context, userID string) (*http.Response, error) {
	return c.Raw(ctx, http.MethodGet, PathIdentityUsers+url.PathEscape(userID)+"/avatar", nil)
}

func (c *Client) FriendPreference(ctx context.Context, viewer, friend string) (*FriendPreference, error) {
	var p FriendPreference
	err := c.Do(ctx, http.MethodGet, PathIdentityUsers+url.PathEscape(viewer)+"/friends/"+url.PathEscape(friend)+"/preference", nil, &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (c *Client) Presence(ctx context.Context, p Presence) error {
	return c.Do(ctx, http.MethodPost, PathIdentityPresence, p, nil)
}

func (c *Client) RenewPresence(ctx context.Context, userID, device string) error {
	return c.Do(ctx, http.MethodPost, PathIdentityPresence+"/renew", PresenceRenewal{UserID: userID, Device: device}, nil)
}

// ---------- penne calls ----------

func (c *Client) Registration(ctx context.Context, penneID string) (*Registration, error) {
	var r Registration
	if err := c.Do(ctx, http.MethodGet, PathPenneRegistrations+url.PathEscape(penneID), nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ConsoleRegistration is the Penne registration of the console a device certificate names
// (cert-…, the subject of its dauth device token), with every user signed in on it. Licence
// checks arrive with that certificate only, so this is how they find every profile's account.
func (c *Client) ConsoleRegistration(ctx context.Context, deviceCert string) (*Registration, error) {
	var r Registration
	if err := c.Do(ctx, http.MethodGet, PathPenneConsoleRegs+url.PathEscape(deviceCert), nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) BindConsole(ctx context.Context, deviceID, userID string) error {
	return c.Do(ctx, http.MethodPost, PathPenneConsoles, ConsoleBinding{DeviceID: deviceID, UserID: userID}, nil)
}

func (c *Client) PushChannel(ctx context.Context, p PushChannel) error {
	return c.Do(ctx, http.MethodPost, PathPennePushChannels, p, nil)
}

func (c *Client) Notify(ctx context.Context, n Notification) (*Submission, error) {
	var s Submission
	if err := c.Do(ctx, http.MethodPost, PathPenneNotifications, n, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Client) TopicMessage(ctx context.Context, m TopicMessage) (*TopicResult, error) {
	var r TopicResult
	if err := c.Do(ctx, http.MethodPost, PathPenneTopicMessages, m, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) BindToken(ctx context.Context, token, userID string) (bool, error) {
	var r struct {
		Bound bool `json:"bound"`
	}
	err := c.Do(ctx, http.MethodPost, PathPenneTokenBindings, TokenBinding{NotificationToken: token, UserID: userID}, &r)
	return r.Bound, err
}

func (c *Client) CloseUser(ctx context.Context, userID string) (int, error) {
	var r struct {
		Closed int `json:"closed"`
	}
	err := c.Do(ctx, http.MethodPost, PathPenneUsers+url.PathEscape(userID)+"/close", struct{}{}, &r)
	return r.Closed, err
}

func (c *Client) DeviceMessage(ctx context.Context, m DeviceMessage) (*DeviceResult, error) {
	var r DeviceResult
	if err := c.Do(ctx, http.MethodPost, PathPenneDeviceMessages, m, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
