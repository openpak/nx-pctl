# Protocol: nx-pctl

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
