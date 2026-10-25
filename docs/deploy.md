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

A hostname this service does not own is answered 421 and logged. `deploy/` has a sample
quadlet and the Traefik router; neither is applied anywhere.

## Building

`nx-common` is a sibling module with no remote yet: `go.mod` replaces it with `../nx-common`
and `vendor/` holds the copy the image build uses. After changing nx-common, run
`go mod vendor` here and commit `vendor/`.

    go vet ./... && go test ./...

Releases are tags: `v*.*.*` runs `.github/workflows/release.yml` on the self-hosted podman
runner and publishes `ghcr.io/openpak/nx-pctl`.
