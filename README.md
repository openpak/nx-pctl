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
| `NX_PCTL_BACKEND` | (unset: the file) | `parental`: keep the records in the parental core (below). **Off by default** |
| `NX_PARENTAL_ADDR` | | the parental core's gRPC (`openpak-parental:20171`), with the backend on |
| `NX_PARENTAL_KEY`, `NX_PARENTAL_KEY_FILE` | | this adapter's key there (namespace `switch`) |

A hostname this service does not own is answered 421 and logged. `deploy/` has a sample
quadlet and the Traefik router; neither is applied anywhere.

## The parental core backend (off by default)

With `NX_PCTL_BACKEND=parental` the records live in the console-neutral parental core
(`platforms/core/infra/parental`, design and cut-over in its `docs/design.md`); moon.go is
unchanged and the console sees the same answers. `parental.go` loads the records from the core
at start and, on every save, writes what changed (`PutDevice` with the version it read,
`IngestUsage` for new events, `DeleteDevice` for a record that left); a version conflict
re-reads that record. `pctl.json` stays as a mirror, so unsetting the variable is the
rollback; the first start keeps the file as it was in `pctl.json.before-parental`, and a
start on a core with no Switch records while the file has some is refused.

The one-shot importer copies a `pctl.json` (or nx-baas's `baas.json`) into the core, records
the core does not hold yet, with their events; a second run changes nothing:

    NX_PARENTAL_ADDR=… NX_PARENTAL_KEY_FILE=… nx-pctl -import-parental /app/data/pctl.json

The core deduplicates events by content, so a retried upload the file store kept twice is
held once there. Records with no managing account id are refused by the core and stay in the
mirror only.

## Building

`nx-common` is a sibling module with no remote yet: `go.mod` replaces it with `../nx-common`
and `vendor/` holds the copy the image build uses (and gRPC, for the parental backend). After
changing nx-common, run `go mod vendor` here and commit `vendor/`. `parentalpb/` is a copy of
the parental core's generated stubs; refresh by re-copying.

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
