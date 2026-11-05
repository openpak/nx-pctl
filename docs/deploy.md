# Deploy: nx-pctl

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
| `NX_PCTL_BLOB_KEY` (or `_FILE`) | | **required**: 32 bytes, base64 (`openssl rand -base64 32`), seals `pctl.json`. To change it: stop the service, run `nx-pctl -rekey` once with `NX_PCTL_BLOB_KEY_OLD` set to the previous key, start the service on the new one |
| `NX_PCTL_BLOB_INSECURE_PLAINTEXT` | | `1`: start without a key, file in clear. Tests and development only |
| `NX_PCTL_BACKEND` | (unset: the file) | `parental`: keep the records in the parental core (below). **Off by default** |
| `NX_PARENTAL_ADDR` | | the parental core's gRPC (`openpak-parental:20171`), with the backend on |
| `NX_PARENTAL_KEY`, `NX_PARENTAL_KEY_FILE` | | this adapter's key there (namespace `switch`) |

A hostname this service does not own is answered 421 and logged. `deploy/` has a sample
quadlet and the Traefik router; neither is applied anywhere.

## PINs at rest

The console needs its PIN in clear (the setting GET and the device object carry it; the
console checks it locally), so it is encrypted, not hashed. `pctl.json` is sealed whole with
AES-256-GCM under `NX_PCTL_BLOB_KEY` (`seal.go`): `{"sealed":"aes-256-gcm/v1","kid",
"nonce","ciphertext"}`, the kid naming the key for a later rotation. Whole file rather than
the PIN fields because the record also keeps hashes over documents holding the PIN (`etag`,
`syncedEtag`), and four digits fall out of those by brute force. What consoles and the
website receive, ETag included, is byte for byte the same.

Every start seals, in place, `pctl.json` and the copies beside it (`.before-parental`,
`.before-import-*`) still in clear; a sealed file is left alone, so this is idempotent. A
start without a key is refused; `NX_PCTL_BLOB_INSECURE_PLAINTEXT=1` keeps the file in clear
for tests and development, never in production. `-import-parental` opens a sealed file with
the same key. A rollback to nx-baas (`pctl-rollback.json`) needs the records in clear: nx-baas
refuses a sealed file and keeps its own.

## The parental core backend

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

Production (2026-11-03): the box runs the parental backend; `NX_PARENTAL_KEY` and
`NX_PCTL_BLOB_KEY` come from the shared `deploy/.env`.

## Building

`nx-common` is a sibling module with no remote yet: `go.mod` replaces it with `../nx-common`
and `vendor/` holds the copy the image build uses. After changing nx-common, run
`go mod vendor` here and commit `vendor/`.

    go vet ./... && go test ./...

Releases are tags: `v*.*.*` runs `.github/workflows/release.yml` on the self-hosted podman
runner and publishes `ghcr.io/openpak/nx-pctl`.
