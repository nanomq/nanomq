# Keep the ART-Pi's Wi-Fi chip awake instead of letting it KSO-sleep

From about 50 s after association the console filled with
`sdhc_stm32: Command response timeout` — rate-limited to one line per 5 s, but
with a `Skipped ~1500 messages` counter beside it, i.e. ~300 failures a second
— for as long as the board ran, while the broker and its data path stayed
healthy.

Instrumenting the SDHC driver by command class (temporary `[DEBUG-a4f2]`
probes, removed once they had answered the question) gave a signature that
settled it:

| command class | sent | failed |
| --- | --- | --- |
| CMD52, any function (register access, no data phase) | ~215 000 | ~108 000 |
| CMD53, function 1, byte mode (the SDIO backplane) | ~20 000 | **0** |
| CMD53, function 1, block mode (the SDIO backplane) | 412 | **0** |
| CMD53, function 2 (WLAN data) | ~2 100 | **0** |

Only CMD52 failed, about half of them, and the first one to fail was always
`CMD52 write, function 1, address 0x1001F, value 1` — that is
`SBSDIO_SLPCSR_KEEP_WL_KSO` written to `SDIO_SLEEP_CSR`, the first write of
WHD's device-wake sequence.  WHD's own comment at that write reads "1st KSO
write goes to AOS wake up core if device is asleep / Possibly device might not
respond to this cmd. So, don't check return value here": with its power save
enabled the chip enters that KSO sleep once the connection settles, and while
asleep **it does not answer that write on purpose**.

A host controller cannot know that a card's silence is expected.  The STM32
SDHC driver reports every command that gets no response as a command-response
timeout, and `sdhc_stm32_request()` logs it at error level (it only carves out
CMD8, which is silent for the same reason on a card that does not support it).
So the flood was the chip doing exactly what its firmware documents, rendered
as ~300 error lines a second.

## Considered Options

- **Leave the chip's sleep alone and keep the logging quiet.**  The rate
  limiter added while chasing this (patch 0001) turns the stream into one line
  per 5 s plus a count.  It keeps the console usable, but a permanent error
  stream reads as "something is broken" to anyone who looks — which is how
  this was reported.
- **Log command timeouts at debug level in the driver.**  The driver cannot
  tell an expected silence from a broken card, and this would hide real
  timeouts on every other board.
- **Keep the chip out of the sleep** (chosen): call
  `whd_wifi_disable_powersave()` once `whd_wifi_on()` succeeds, gated by
  `CONFIG_AIROC_WIFI_DISABLE_POWERSAVE` and on in this demo's `wifi.conf`.  It
  is a mains-powered broker; the chip has no reason to sleep, and awake it
  never issues the wake-up writes.

## Consequences

- Measured after the change: a boot that previously produced ~300 failures a
  second from ~50 s onward now runs with **zero** `Command response timeout`
  lines and zero CMD52 failures; the three functional gates still pass, and a
  continuous three-minute console capture showed heartbeats and the DHCP lease
  steady, with no other error output.
- The rate limiter stays in patch 0001 as a safety net for genuine timeouts.
- Power draw is higher than with the vendor default.  Turning the option off
  restores the vendor behaviour *and* the log noise.
- Worth remembering beyond this board: a silent SDIO card is not necessarily a
  broken one.  This chip stays silent on purpose while it sleeps, and the only
  way the host can tell the difference is by knowing the protocol position of
  the command — here, the sleep/wake register of a device that has a documented
  reason to stay quiet.
