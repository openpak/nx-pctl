# Notes: nx-pctl

Nintendo Switch parental controls for OpenPak — the pctl sysmodule's moon API — split out of
[nx-baas](../../nx-baas) so the core and parental controls release independently.

## Porting a fix from nx-baas

`moon.go` and `moon_test.go` are nx-baas's (branch `split-services`, which changed only
`pctlPush` to go through the penne API), with the helpers they call kept under their nx-baas
names (`common.go`, `store.go`), so a fix made there applies here as a patch until nx-baas
drops its copy:

    git -C ../nx-baas diff <the last ported commit> origin/main -- moon.go moon_test.go | git apply -3

The one test that differs is `TestAParentSaveIsPushedToTheConsole`, which checks the device
message sent to the push side instead of a frame on a local connection.
