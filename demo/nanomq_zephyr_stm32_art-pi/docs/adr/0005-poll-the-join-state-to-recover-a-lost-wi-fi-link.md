# A lost Wi-Fi link has no event; the demo polls the join state

The ART-Pi demo associates once at boot and then serves the LAN for as long as
it runs.  Because its listeners sit on `0.0.0.0`, the broker itself survives a
link that goes away — the board just becomes unreachable at its old address
and stays that way.  The only symptom is the 60 s status heartbeat printing
itself without the `ipv4 ...` part, and the only way back used to be a reset
(`src/main.c`: "nothing retries the association for us, so a reset is the way
back").

Nothing in the demo watched the link after the boot-time association, and the
driver's event stream does not report the loss either.
`drivers/wifi/infineon/airoc_wifi.c` raises
`NET_EVENT_WIFI_DISCONNECT_RESULT` only from `airoc_mgmt_disconnect()` — an
explicit `NET_REQUEST_WIFI_DISCONNECT`.  Its event task reacts to
`WLC_E_DEAUTH_IND` and `WLC_E_DISASSOC_IND` by marking the interface dormant,
but passes `WLC_E_LINK` through untouched, and `WLC_E_LINK` with the link flag
clear is how the firmware reports the third way a link ends: beacon loss.

The state that does cover all three is WHD's `JOIN_LINK_READY` bit.
`whd_wifi_api.c` clears it for `WLC_E_LINK` (link flag clear),
`WLC_E_DEAUTH_IND` and `WLC_E_DISASSOC_IND`, and
`whd_wifi_is_ready_to_transceive()` is derived from it.
`NET_REQUEST_WIFI_IFACE_STATUS` is the mgmt request that reaches that
function, so the interface status is what distinguishes "still associated"
from "the AP is gone" however it went away.

## Considered Options

- **Wait for `NET_EVENT_WIFI_DISCONNECT_RESULT`.**  The cleanest signal when
  it fires, and the demo does handle it — but it only fires for an explicit
  disconnect, which is not how a broker's link usually dies.
- **Watch `net_if_is_dormant()`.**  Free and immediate for deauth and
  disassoc; blind to beacon loss, where the driver's event task never touches
  the flag, so a board that walked out of range stays "up" forever.
- **Patch the driver's event task to handle `WLC_E_LINK`.**  That would make
  the dormant flag complete, and it is arguably an upstream bug fix — but the
  signal the application needs ("is this link usable?") already lives in WHD,
  and another out-of-tree driver change buys no additional information for
  this demo.
- **Poll `NET_REQUEST_WIFI_IFACE_STATUS`** (chosen): one mgmt round trip every
  `CONFIG_BROKER_WIFI_MONITOR_PERIOD_S` seconds (default 10) from a dedicated
  supervisor thread.  It sees all three kinds of loss, costs a few SDIO
  ioctls per tick, and needs no west-tree change.

## Consequences

- A lost AP is noticed within the monitor period, or immediately when the
  driver does raise the disconnect event (the supervisor waits on that too).
  It then re-associates and calls `net_dhcpv4_restart()`; while the AP stays
  away the retry backoff is 5 s doubling to 60 s.
- The supervisor is a 4 KB thread (priority 12) that spends nearly all of its
  time blocked, so the recurring cost is the poll, not the thread.
- The broker is untouched.  A reconnect that gets the same lease back is
  invisible to clients beyond their own reconnects, and a different lease is
  fine too — only the address in the status heartbeat changes.
- Boot behaviour is unchanged: the initial association is still bounded
  (3 × 30 s), so a board that cannot associate still starts the broker and
  says so.  The supervisor keeps trying from then on, which replaces the old
  "reset the board to retry" advice.
- `CONFIG_BROKER_WIFI_MONITOR_PERIOD_S=0` keeps the monitor out of the image.
  The boot path still associates, and a link that drops afterwards is then
  unrecoverable — the pre-ADR behaviour.
