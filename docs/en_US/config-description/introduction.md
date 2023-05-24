# Configuration

The configuration files of NanoMQ Broker is HOCON（Human-Optimized Config Object Notation）.It is ideal for configuration data storage that is easy for humans to read and write. You can find these configuration files in the etc directory. Start from v0.14, for the sake of consistensy with EMQX 5.0, NanoMQ adapt to new HOCON style configuration.

| File                    | Description                            |
| ----------------------- | -------------------------------------- |
| etc/nanomq.conf         | NanoMQ Configuration File              |
| etc/nanomq_gateway.conf | NanoMQ Gateway File (for `nanomq_cli`) |

> Visit the old version of Config: [ Configuration (v0.13)](./v013.md)

## Syntax

In config file the values can be notated as JSON like objects, such as

```bash
websocket {
     enable=false
     bind="0.0.0.0:8083/mqtt"
}
```

Another equivalent representation is flat, such as

```bash
websocket.enable = false
websocket.bind="0.0.0.0:8083/mqtt"
```

This flat format is almost backward compatible (the so called 'cuttlefish' format).

It is not fully compatible because the often HOCON requires strings to be quoted,
while cuttlefish treats all characters to the right of the `=` mark as the value.

e.g. cuttlefish: cuttlefish：`websocket.bind = 0.0.0.0:8083/mqtt`，HOCON：`websocket.bind = "0.0.0.0:8083/mqtt"`.

### Config Overlay Rules

HOCON objects are overlaid, in general:

- Within one file, objects defined 'later' recursively override objects defined 'earlier'
- When layered, 'later' (higher layer) objects override objects defined 'earlier' (lower layer)

Below are more detailed rules.

For example, in below config, the last line `debug` overwrites `error` for
console log handler's `level` config, but leaving `to` unchanged.

```bash
log {
    to=[file,console]
    level=error
}

## ... more configs ...

log.level=debug
```
