# Changelog -- nx-pctl

## v0.2.3 -- 2026-11-05

- `nx-pctl -rekey`: re-seals `pctl.json` and the copies beside it (`pctl.json.before-*`) from `NX_PCTL_BLOB_KEY_OLD` to `NX_PCTL_BLOB_KEY`. Every result is computed and opened under the new key before any file is replaced (a file under a third key stops the run with nothing changed); repeatable; counts only on stderr. Run with the service stopped, then start it on the new key

## v0.2.2 -- 2026-11-03

- Every HTTP request now writes one access line to stderr: `http <method> <host> <path> -> <status> <ms>ms ua=...` (shared `nx-common/httplog`, vendored); before, the line had no status or duration. The query string, headers and bodies are never logged. `/healthz` is skipped.
