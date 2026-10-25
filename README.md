# Switch Parental Controls Server

OpenPak's Switch Parental Controls Server.

| | |
| --- | --- |
| Network | Switch |
| Role | Parental controls for Switch: the pctl sysmodule's moon API, the explainer clip, and the internal `/internal/pctl/*` routes the website's parent screens call |
| Depends on | [`nx-baas`](https://github.com/openpak/nx-baas) (core listener, forwards Penne), [`nx-penne`](https://github.com/openpak/nx-penne) (device-message push), the OpenPak website (`WEBSITE_INTERNAL_URL`) |
| Image | `ghcr.io/openpak/nx-pctl` |
| Licence | AGPL-3.0-only |

## What it serves

| Endpoint | What |
| --- | --- |
| `api-<env>.pctl.srv.nintendo.net` | moon (`/moon/v1`): pairing-code search, activate, settings, owners and the parent's picture, players, play-time and wrong-PIN events |
| `parentalcontrols-movie-<env>.cdn.nintendo.net` | The explainer clip (`PCTL_MOVIE`) |
| `/internal/pctl/*` (internal listener) | Pairing codes, device list, settings, PIN, names, activity, player pictures; called by the website |

## Run

```sh
go run .   # configured by the environment variables in docs/deploy.md
```

## Build

```sh
go vet ./... && go test ./...
```

## Docs

- [Protocol](docs/protocol.md)
- [Evidence](docs/evidence.md)
- [Deploy](docs/deploy.md)
- [Notes](docs/notes.md)

## Licence

AGPL-3.0-only. See [LICENSE](LICENSE).
