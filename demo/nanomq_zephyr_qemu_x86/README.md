# NanoMQ broker on Zephyr (qemu_x86)

Runs the full NanoMQ broker core (`nanomq/nanomq/` application sources +
the NanoNNG submodule `nng/`, the nng fork with the nanolib/MQTT stack) on
Zephyr, demonstrated on `qemu_x86` with a SLIRP user-net bridge so real
host MQTT clients (mosquitto) can reach the broker.

Protocol support is the standard NanoMQ TCP/WebSocket surface: MQTT
v3.1.1 and v5, QoS 0/1/2, retained messages, will messages, $SYS, and the
`nmq-tcp://`/`nmq-ws://` transports — no TLS, no QUIC, no SQLite (built
out of the NanoNNG library, same as the NanoNNG Zephyr port itself).

## What was needed to get here

Three layers of changes, kept apart deliberately:

| Layer | Change | Where |
|---|---|---|
| NanoNNG port | already Zephyr-ready (branch `develop`, no TLS/Parquet) | `nng/` submodule |
| NanoMQ core | POSIX-only bits gated behind `__ZEPHYR__`: signal handlers in `apps/broker.c`, `ptrace.h` in `nanomq.c`, `W_OK` file-log check in `mqtt_api.c` | this repo |
| broker bug fix | `nano_nni_lmq_fini`/`nano_nni_lmq_resize` freed the in-struct `lmq_buf` when the rlmq never grew (guard `lmq_alloc > 0`, mirroring `core/lmq.c`) — heap corruption on client disconnect on Zephyr | `nng/` submodule (commit in this branch) |
| Demo | this directory | `demo/nanomq_zephyr_qemu_x86` |

The one POSIX-only piece nng itself cannot build on Zephyr is the
broker's `process.c` (fork/kill/chdir) — a small app-side stand-in
([src/process_stub.c](src/process_stub.c)) provides its symbols.  The
NanoNNG no-FS file gap this demo originally papered over
(`nni_plat_file_exists/size` missing from `zephyr_file.c`, which broke
linking `nanolib`'s file.c/log.c) is fixed in the submodule instead:
both `zephyr_file.c` branches now implement the probes (commit
`21daab5`), exposed as a public API — `nng_file_exists` /
`nng_file_size` in `nng.h` (commit `c66e0cb`).

## Environment prerequisite — Zephyr e1000 driver patch

**Required.** The qemu_x86 emulated NIC is an Intel e1000.  QEMU's e1000
device model clears RCTL after reset — including **RCTL_BAM** (Broadcast
Accept Mode, bit 15), which real hardware defaults to set.  Zephyr's
`eth_e1000` driver programs `RCTL_EN | RCTL_MPE` but never sets BAM, so
**all broadcast frames (ARP!) are silently dropped by the device model**
and SLIRP cannot deliver the first TCP connection (no ARP resolution).
Upstream Zephyr has the same bug (checked on main, 2026-06).

Patch (two lines on a Zephyr ≥ 4.x tree, e.g. 4.4 @ 11a87708d41):

```c
// drivers/ethernet/eth_e1000_priv.h, next to RCTL_MPE
#define RCTL_BAM    (1 << 15) /* Broadcast Accept Mode */

// drivers/ethernet/eth_e1000.c, e1000_eth_init() RCTL write
iow32(dev, RCTL, RCTL_EN | RCTL_MPE | RCTL_BAM | DT_INST_PROP(inst, rdmts) << RDMTS_OFFSET);
```

## Build

Needs a Zephyr 4.x SDK workspace with the NanoNNG submodule checked out and
the e1000 patch above applied.  `west` comes from that workspace's python
venv, not from the system `PATH`, so activate it first — the ESP32-S3 demo
gets `west` from ESP-IDF instead, this one does not need ESP-IDF at all:

```sh
source <workspace>/.venv/bin/activate
export ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1
```

From the repo root:

```sh
git submodule update --init nng
west build -b qemu_x86 -d build/nanomq_zephyr_qemu_x86 demo/nanomq_zephyr_qemu_x86
```

> **NanoNNG dependency.**  The `nng` gitlink recorded in this PR is still
> the existing upstream pin, and that commit does **not** carry the Zephyr
> platform layer — that half of the port lives on the NanoNNG side
> (NanoNNG PR #1647).  Until it lands and the pin is bumped, a fresh
> checkout has to point the submodule at the branch explicitly, or the
> build fails in `nanonng_build` with a missing `platform/zephyr/`:
>
> ```sh
> git -C nng fetch origin alvin/zephyr-port
> git -C nng checkout alvin/zephyr-port
> ```
>
> Bumping the pin is deliberately left to the nanomq maintainers rather
> than being folded into this PR.

The NanoNNG library is built by an ExternalProject
([demo/cmake/nanonng_external.cmake](../cmake/nanonng_external.cmake))
into `<build-dir>/nanonng_build/`, mirroring the NanoNNG `zephyr_mqtt`
demo's build.  RAM footprint of the linked image: ~2.5 MB of the qemu_x86
31 MB RAM (≈1 MB of it the libc malloc arena — see below).

### Why the big malloc arena

qemu_x86 enables the MMU, so Zephyr's libc uses a **16 KB malloc arena**
by default (`CONFIG_COMMON_LIBC_MALLOC_ARENA_SIZE`); nng's Zephyr
platform allocator is plain `malloc()` and per-pipe queue growth alone
(`rlmq`, `msq_len * 8` bytes) exceeds 16 KB, making every allocation
fail.  [prj.conf](prj.conf) raises the arena to 1 MB.  `CONFIG_HEAP_MEM_POOL_SIZE`
only serves `k_malloc()` and is irrelevant to nng.

## Run

SLIRP forwards the three ports to the host, so clients connect through
`127.0.0.1` (table below).  `west build -t run` applies the `hostfwd` triple
from [prj.conf](prj.conf)'s `CONFIG_NET_QEMU_USER_EXTRA_ARGS` automatically,
but keeps the serial console on stdio and occupies the terminal.  To run
detached, with the console going to a file you can still read after a
crash:

```sh
qemu-system-i386 -m 32 -cpu qemu32,+nx,+pae,sse,sse2,pni -machine q35 \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 -no-reboot -machine acpi=off \
    -serial file:/tmp/qemu.log -display none \
    -netdev user,id=n1,hostfwd=tcp:127.0.0.1:1883-:1883,hostfwd=tcp:127.0.0.1:8081-:8081,hostfwd=tcp:127.0.0.1:8083-:8083 \
    -device e1000,netdev=n1 \
    -kernel build/nanomq_zephyr_qemu_x86/zephyr/zephyr.elf &
```

`qemu-system-i386` is not provided by Zephyr itself: `-t run` locates it in
the Zephyr SDK's hosttools, so when launching by hand make sure it is on
`PATH` — a distribution package (Fedora's `qemu-system-x86`) works too.

**Confirm the broker came up** — within a second or two the log shows the
interface address, the HTTP/REST listener and the broker banner.  Log
timestamps are real wall-clock (UTC): at boot, main.c seeds Zephyr's
CLOCK_REALTIME from the QEMU-emulated CMOS RTC (QEMU initialises it from
the host clock; without this the nanolib log module — log.c formats
`time(NULL)` — would print the 1970 epoch):

```
$ tail -f /tmp/qemu.log
rtc: CMOS clock 2026-09-08 06:49:01 UTC, realtime seeded
net: iface 0x1991b4 dev=eth0 up=1
net: ipv4 10.0.2.15
2026-09-08 06:49:01 [0] WARN  ... broker: NanoMQ (ver 0.25.1) Serving HTTP Server on http://(null):8081
NanoMQ Broker is started successfully!
```

This CMOS seeding is **deliberately qemu-only**.  The sibling ESP32-S3 demo
([../nanomq_zephyr_esp32s3](../nanomq_zephyr_esp32s3/)) has no RTC at all
and seeds the same clock over SNTP instead.  Do not "fix" the difference by
enabling SNTP here: its auto-init path runs from `SYS_INIT`, i.e. *before*
the CMOS seed in `main()`, so CMOS would simply overwrite the SNTP result —
extra boot latency, no effect.  Rationale in PORTING_ZEPHYR.md §22-4.

The guest broker listens on `10.0.2.15:1883` (static IP set in
[prj.conf](prj.conf)); SLIRP forwards host `tcp:1883` to it.  Pick a
different `hostfwd` port (e.g. `11883`) if 1883 is taken on the host.

**Clear the previous instance before relaunching.**  A leftover qemu keeps
1883/8081/8083 bound and the next launch dies with

```
qemu-system-i386: ... Could not set up host forwarding rule 'tcp:127.0.0.1:8083-:8083'
```

`-t run` is the usual source of one: stopping it does not necessarily take
the qemu it spawned with it.  Kill by port rather than by name — a
`pkill -f "qemu-system-i386"` matches its own command line:

```sh
ss -ltnp | grep -E ':(1883|8081|8083)' | grep -oP 'pid=\K[0-9]+' | sort -u | xargs -r kill
```

A rebuild must be followed by a relaunch.

### Where to run the clients

qemu and the SLIRP forwards run on this machine, so every client runs here
too and reaches the broker through the forwarded ports:

| Client | Address |
|---|---|
| `mosquitto_sub` / `mosquitto_pub`, `accept.sh` | `127.0.0.1:1883` |
| `mqtt_accept.py`, `hook_receiver.py` | `127.0.0.1:1883`, `127.0.0.1:18080` |
| REST `curl` | `http://127.0.0.1:8081` |
| MQTT over WebSocket (paho `transport="websockets"`, path `/mqtt`) | `ws://127.0.0.1:8083/mqtt` |
| `function_test.py` (whole suite) | manages qemu itself; pass `--addr 127.0.0.1` to reuse one you started |

## Acceptance

Mosquitto clients against the forwarded port:

```sh
./accept.sh 127.0.0.1 1883
```

Covers QoS0/1/2 pub/sub, retained messages, will messages (client
SIGKILLed — note mosquitto rejects `-k < 5`), MQTT v5 pub/sub with
user-properties and the response-topic/correlation-data roundtrip.
Expect `RESULT: pass=7 fail=0`.

Notes from bring-up that are easy to trip on again:

* mosquitto `-k` (keepalive) minimum is **5** — `-k 2` makes the client
  exit immediately without connecting.
* A SIGKILLed client's will is only published when the broker sees the
  socket close; `kill -9` the client itself, not a `timeout` wrapper
  around it.

## Extended scenarios (session / keepalive / $SYS / REST / webhook)

The acceptance script above covers the protocol surface; the scenarios
below (verification record: `PORTING_ZEPHYR.md` §9-4/6/7/10) need packet
control the mosquitto CLI does not give you (clean=0 without auto-reconnect,
MQTT 5 session-expiry, arbitrary keepalive), so they are driven by
[`mqtt_accept.py`](mqtt_accept.py) — a stdlib-only raw-socket MQTT 3.1.1/5
client with machine-friendly `CONNACK/SUBACK/MSG/MATCH/EXIT` output.  It is
stdlib-only, so it runs anywhere python3 does:

```sh
python3 demo/nanomq_zephyr_qemu_x86/mqtt_accept.py 127.0.0.1 1883 ...
```

or `cd demo/nanomq_zephyr_qemu_x86` first and use the shorter
`python3 mqtt_accept.py ...` forms below:

```sh
# persistent session, MQTT 5, 30 s session-expiry: reconnect within the
# window and the offline QoS1 message is delivered (session_present=1)
python3 mqtt_accept.py 127.0.0.1 1883 sub --proto 5 --clean 0 --expiry 30 \
    --topic v5/offline --qos 1 --expect v5-offline --hold 25
# keepalive timeout: a silent client with --keepalive 2 is kicked after
# ~5.6 s (1.5 x keepalive + the 1 s qos_duration tick); watch the broker
# log or REST for the disconnect
python3 mqtt_accept.py 127.0.0.1 1883 connect --keepalive 2 --hold 30
# $SYS: subscribe from a second client to see the online/offline pair
python3 mqtt_accept.py 127.0.0.1 1883 expect --topic '$SYS/brokers/client_status/#' \
    --expect online --expect offline --hold 20
```

These need the demo's default build flags (`CONFIG_BROKER_REST_API`,
`CONFIG_BROKER_WEBHOOK`, `CONFIG_BROKER_LOG_DEBUG`); the REST and webhook
switches were added on top of the original demo to make the §9-4 path
exercisable (Kconfig options wired to main.c overrides, see
[Kconfig](Kconfig)).  The broker also overrides `qos_duration` to 1 s
(conf default 10 s) so keepalive/session-expiry checks tick promptly.

REST is served on `tcp:8081` (the second of the three SLIRP hostfwd entries
in [prj.conf](prj.conf))
behind **Basic auth**, default `admin`/`public` (set in `main.c`; same
credentials as `etc/nanomq.conf` and the upstream docs).  Note this is
base64 over plain HTTP, not encryption — TLS is not in the Zephyr NanoNNG
build — so keep it off untrusted networks.  curl exists on the outer host
only — use the container IP (see the table in "Run"):

```sh
curl -s -u admin:public http://<container-ip>:8081/api/v4/clients  # key is "data"
```

Override the credentials for the suite with `--rest-user`/`--rest-pass`.

Webhook is **off by default** here too (the two `CONFIG_BROKER_WEBHOOK*`
lines in [prj.conf](prj.conf) are commented out).  The `CLIENT_CONNACK` rule
fires on every client connect, so leaving the forwarder on with no receiver
listening costs a failed HTTP attempt plus two log lines per connect — that
measurably perturbs the suite's timing-sensitive subtests
(PORTING_ZEPHYR.md §22-6).  Turn it on only when you want to exercise it:

```sh
# uncomment CONFIG_BROKER_WEBHOOK / CONFIG_BROKER_WEBHOOK_URL in prj.conf,
# or keep prj.conf pristine and use an overlay:
west build -b qemu_x86 -d build/nanomq_zephyr_qemu_x86 demo/nanomq_zephyr_qemu_x86 -- \
    -DEXTRA_CONF_FILE=webhook.conf      # holding the same two lines
```

The URL matters, not the `BROKER_WEBHOOK` bool: main.c enables the forwarder
only when it is non-empty, so an empty URL is how the demo keeps it off.
Events are POSTed to the QEMU-host alias `10.0.2.2` — the machine running
qemu itself — so the receiver runs **on that machine** (no container
round-trip).  To watch events by hand, start it before publishing to
`hook/#`:

```sh
python3 demo/nanomq_zephyr_qemu_x86/hook_receiver.py --port 18080 --out /tmp/webhook.log
```

Stop it again before running the suite: the `webhook_smoke` group starts its
own receiver and needs port 18080 to itself, and it will refuse to run if
something is already listening there (the broker's target URL is a build-time
setting, so the port cannot be moved out of the way).

One event per connect (`client_connack` — clientid, proto_ver, keepalive)
and one per `hook/#` publish (`message_publish` — ts, topic, qos, payload):

```
{"proto_ver": 4, "keepalive": 30, "conn_ack": "success", "username": "undefined", "clientid": "zf-webhook-pub", "action": "client_connack"}
{"ts": 1789117395540, "topic": "hook/webhook", "retain": false, "qos": 1, "action": "message_publish", "from_username": "undefined", "from_client_id": "zf-webhook-pub", "payload": "zf-webhook-1789117396-0"}
```

Re-run it end to end with:

```sh
python3 demo/nanomq_zephyr_qemu_x86/function_test.py --group webhook_smoke --webhook \
    --no-manage --addr 127.0.0.1
```

`--webhook` tells the suite the broker has the forwarder compiled in; it
then starts the receiver itself and asserts both events arrive.  Without the
flag the group reports SKIP (the broker cannot be asked: the REST
`/configuration/webhook` route has no handler, and the "Hook service
started" banner is a DEBUG-level line the board builds do not emit).

## Functional test suite (`function_test.py`)

[`function_test.py`](function_test.py) is the host-side end-to-end suite for
this demo: it starts qemu itself (the same command as "Run" above, fresh
serial log, waits for the broker banner), runs the groups below, and stops
the broker again.  It is the Zephyr counterpart of
`.github/scripts/test.py`, which cannot run here — that runner needs a host
nanomq binary with TLS/WS listeners and drives host-only tooling
(mosquitto CLI, TLS, auth).

Run it from the repo root on the outer host:

```sh
python3 demo/nanomq_zephyr_qemu_x86/function_test.py                  # all groups
python3 demo/nanomq_zephyr_qemu_x86/function_test.py --group ws_v5 -v # one group, show output
python3 demo/nanomq_zephyr_qemu_x86/function_test.py --no-manage --addr 127.0.0.1  # broker already up
python3 demo/nanomq_zephyr_qemu_x86/function_test.py --list           # groups + timeouts
```

| Group | What it drives | Driver |
|---|---|---|
| `mqtt_v311` | sessions, retain, v4/v5 interop | CI `mqtt_test.py` |
| `mqtt_v5` | session expiry, user properties, `$share`, topic alias | CI `mqtt_test_v5.py` |
| `rest_get` | REST GET surface on :8081 — 7 routes, plus `/configuration/websocket` mirroring the runtime WS conf | self-written |
| `ws_v311` | MQTT 3.1.1 over `nmq-ws://` on :8083 | CI `ws_test.py` |
| `ws_v5` | MQTT 5 over WS — properties, topic alias, session expiry | CI `ws_v5_test.py` |
| `webhook_smoke` | `hook_receiver.py` receives `client_connack` + `message_publish` — needs `--webhook`, else SKIP | self-written |
| `capacity` | 12 concurrent CONNECTs + a QoS1 echo — regression for the connection-pool limit above | self-written |
| `ws_abort` | 60 handshake-then-close ws connections, then a real MQTT-over-WS session — guards the accept-path leak (PORTING_ZEPHYR.md §22-5) | self-written |
| `survival` | scaled-down `attack.py` load/session churn + post-churn echo probe | [`survival_test.py`](survival_test.py) |

How the CI modules are reused without touching them: every group runs in its
own subprocess (`--worker`), and the wrapper injects the broker address
through each module's own seam — `g_addr`/`g_port`/`g_url` for the mqtt
modules, a wrapped `Test.init` for `ws_test.py`, and
`paho.mqtt.client.Client.connect` for `ws_v5_test.py` (which hardcodes
`localhost:8083`).  The address reaches the subprocess via `ZF_ADDR`.

Notes from bring-up:

* The `.github/scripts/ws_v5_test.py` copy this tree carried was stale: it
  set `MaximumPacketSize` (a CONNECT-only property) on the PUBLISH
  properties, which paho 2.x rejects in the client thread — every v5
  publisher died before it connected.  The file here is now upstream
  master's version, which also bounds its waits instead of sleeping blindly.
* The ws groups get one extra attempt by default (`--retry-ws`):
  `ws_v5_test.py` uses fixed sleeps tuned for a host broker, and SLIRP
  latency can make the first pass flaky.  Real jitter is recorded in
  `PORTING_ZEPHYR.md` §9-13, not papered over.
* `survival_test.py` scales `attack.py`'s constants down (30 s, 2 flood
  publishers, 8 noise clients, 2-node share groups): the point is broker
  liveness under churn on qemu, not throughput.  Host-side scale is a crash
  amplifier — SLIRP forwards roughly 9 msg/s per connection.
* Exit status: `0` all groups pass, `1` at least one failed, `2` structural
  failure (qemu/module prerequisites).  A failing group prints its last 40
  output lines plus the serial-log tail.

Verification record: `PORTING_ZEPHYR.md` §9-13.

## Performance notes (qemu/SLIRP)

Best-effort numbers (see PORTING_ZEPHYR.md §9-10 for the record):

* QoS0 one-way forwarding reaches ~1.1-1.4 k msg/s with zero loss.
* Request/response exchanges (QoS1 PUBACK, PINGREQ, SUBACK) cost a flat
  ~110 ms each — Zephyr's TCP delayed-ACK (`ACK_DELAY = K_MSEC(100)`)
  holds the ACK for ~100 ms on small segments.  This is a stack
  characteristic, not a broker defect; QoS0 one-way throughput is
  unaffected.
* With `CONFIG_BROKER_LOG_DEBUG=y` the serial console becomes the
  bottleneck (~380 log lines/s) and throughput drops to ~150-250 msg/s;
  measure on a non-DEBUG build.
* Connection capacity is a **configuration** limit, not a network one.
  Zephyr's defaults are sized for a sensor node: `CONFIG_NET_MAX_CONTEXTS=6`
  (one context per socket) and `CONFIG_NET_MAX_CONN=8` leave only ~4 slots
  once the three listeners (1883 + 8081 + 8083) exist.  When the pool is exhausted
  Zephyr's TCP answers the next SYN with **RST** (`tcp.c` `tcp_conn_new()`:
  `net_context_get()` fails → `net_tcp_reply_rst()`), which a client reports
  as `Error: The connection was lost.` / "Connection reset by peer".
  [prj.conf](prj.conf) raises both pools to 32 (plus the zvfs fd table and
  the nng pollq's `poll()` event budget).  Measured before → after: 6
  concurrent MQTT connects 2/6 → 6/6; 20 back-to-back connects at 50 ms
  spacing 9/20 → 20/20; the `.github/scripts` v5 suite (`mqtt_test_v5.py`)
  0/7 → 3/3 consecutive full passes.

  A second, unrelated pool bites load tests: Zephyr allocates pthread
  **rwlocks** from a fixed pool and nanolib takes one per topic-tree node
  (`dbtree_node_new`/`dbtree_node_free`, `nanolib/mqtt_db.c` — paired, so
  the live count tracks distinct subscribed topics).  The default 32 is
  enough for the listeners but not for a flood over many topics: the
  survival group reached `panic: pthread_rwlock_init: pool exhausted` at
  ~30 topics, which aborts the guest (clients then see "Connection
  refused").  [prj.conf](prj.conf) sets `CONFIG_MAX_PTHREAD_RWLOCK_COUNT=256`.

SLIRP is a proxy network: absolute numbers need re-measuring on real
hardware and a real network.
