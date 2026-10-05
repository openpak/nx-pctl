# nx-pctl

Nintendo Switch parental controls for OpenPak — the pctl sysmodule's moon API — split out of
[nx-baas](../nx-baas) so the core and parental controls release independently.

It owns:

- `api-<env>.pctl.srv.nintendo.net`: moon (`/moon/v1`): the pairing-code search, `activate`,
  the setting the console polls (ETag), owners and the parent's picture, players, play-time
  and wrong-PIN events; everything else on the host keeps the old service-status answer;
- `parentalcontrols-movie-<env>.cdn.nintendo.net`: the explainer clip (`PCTL_MOVIE`);
- `/internal/pctl/*` on the internal listener, which the website's parent screens call:
  pairing codes, the device list, settings, PIN, names, activity, player pictures, and up to
  four further parents per console (`PUT/DELETE /internal/pctl/devices/{moon_id}/parents/{account_id}`,
  each shown to the console as its own owner with its own name and picture);
- `$NX_DATA/pctl.json`: the records, under the same `pctlDevices` key nx-baas kept them in
  inside `baas.json`.

A parent's save is pushed to the console at once (`DID_CHANGE_PARENTAL_CONTROL_SETTING`)
through the penne API's device messages — nx-penne, or nx-baas while it still serves Penne;
best effort, as before: the console also fetches on its own schedule. A change to a paired
console's owners — a further parent added, renamed or removed, or a parent's name or picture
changed — is pushed the same way as `UPDATE_DEVICE_OWNERS` (firmware 23.x re-reads its owners;
22.5 drops it). The parent's picture comes from the website (`WEBSITE_INTERNAL_URL`), under a
URL named after its content hash so a console downloads a new picture once; the website reports
a changed name or picture with `POST /internal/pctl/parents/{account_id}` (`{"display_name"}`
only when the name changed). Design and firmware notes: the docs
repository (`switch/native-switch-parental-controls-prd.md`,
`switch/parental-controls-firmware-2026-09-26.md`, `switch/parental-controls-parent-surface-prd.md`).

## Running

| env | default | |
|---|---|---|
| `NX_PENNE_URL` | `NX_CORE_URL` | who delivers the push (`/internal/penne/device-messages`) |
| `NX_CORE_URL` | | nx-baas's internal listener; enough on its own, nx-baas forwards Penne once it moved |
| `NX_INTERNAL_KEY` | | the website's key for `/internal/pctl` (checked as nx-baas did: required once configured) |
| `NX_ADDR` | `:21000` | TLS for consoles (Traefik SNI passthrough) |
| `NX_API_ADDR` | `:20070` | plain HTTP: `/internal/pctl/*` and the console routes nx-baas forwards |
| `NX_DATA` | `/data` | `pctl.json` |
| `NX_PCTL_IMPORT` | | first start only: nx-baas's `baas.json`, to take the records from |
| `NX_CA_DIR` | `/data/ca` | `ca.pem`/`ca.key` that sign the listener's certificates |
| `BAAS_SIGNING_KEY`, `BAAS_KID` | `/keys/baas_signing_key.pem` | verifies the console's dauth device token |
| `WEBSITE_INTERNAL_URL` | | the parent's picture |
| `PCTL_MOVIE` | | the explainer clip; 404 while unset |
| `NX_DEBUG` | | log every request and reply (PINs masked) |

A hostname this service does not own is answered 421 and logged. `deploy/` has a sample
quadlet and the Traefik router; neither is applied anywhere.

## Building

`nx-common` is a sibling module with no remote yet: `go.mod` replaces it with `../nx-common`
and `vendor/` holds the copy the image build uses. After changing nx-common, run
`go mod vendor` here and commit `vendor/`.

    go vet ./... && go test ./...

Releases are tags: `v*.*.*` runs `.github/workflows/release.yml` on the self-hosted podman
runner and publishes `ghcr.io/openpak/nx-pctl`.

## Porting a fix from nx-baas

`moon.go` and `moon_test.go` are nx-baas's (branch `split-services`, which changed only
`pctlPush` to go through the penne API), with the helpers they call kept under their nx-baas
names (`common.go`, `store.go`), so a fix made there applies here as a patch until nx-baas
drops its copy:

    git -C ../nx-baas diff <the last ported commit> origin/main -- moon.go moon_test.go | git apply -3

The one test that differs is `TestAParentSaveIsPushedToTheConsole`, which checks the device
message sent to the push side instead of a frame on a local connection.
