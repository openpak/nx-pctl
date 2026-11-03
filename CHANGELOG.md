# Changelog -- nx-pctl

## v0.2.2 -- 2026-11-03

- Every HTTP request now writes one access line to stderr: `http <method> <host> <path> -> <status> <ms>ms ua=...` (shared `nx-common/httplog`, vendored); before, the line had no status or duration. The query string, headers and bodies are never logged. `/healthz` is skipped.
