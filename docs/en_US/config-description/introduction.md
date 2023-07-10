# Configuration

NanoMQ configuration files come in two versions: the Classic KV version and the HOCON version. The HOCON version is a new configuration format introduced in version 0.14. The KV version is the original configuration file format of NanoMQ, which will be retained and compatible with older users for the long term (although some new features will only support the new HOCON configuration format).

## HOCON

NanoMQ's default configuration file format is HOCON. HOCON (Human-Optimized Config Object Notation) is a superset of JSON, making it ideal for storing configuration data in a human-readable format. You can find these configuration files in the `etc` directory. Peripheral functions such as authentication/gateways can use separate configuration files (specified by the `include` method). The main configuration files include:

| Configuration File              | Description                                      |
| ------------------------------- | ------------------------------------------------ |
| etc/nanomq.conf                 | Main NanoMQ configuration file                   |
| etc/nanomq_pwd.conf             | NanoMQ username and password auth config         |
| etc/nanomq_acl.conf             | NanoMQ ACL access control auth config            |
| etc/nanomq_vsomeip_gateway.conf | NanoMQ SOME/IP gateway config (for `nanomq_cli`) |
| etc/nanomq_dds_gateway.conf     | NanoMQ DDS gateway config (for `nanomq_cli`)     |
| etc/nanomq_bridge.conf          | NanoMQ bridge config (for `nanomq_cli`)          |
| etc/nanomq_zmq_gateway.conf     | NanoMQ ZeroMQ config (for `nanomq_cli`)          |

The below sections are based on the HOCON configuration format. 

## Syntax

In the configuration file the values can be notated as JSON-like objects, such as

```bash
log {
    dir = "/tmp"
    file = "nanomq.log"
}
```

Another equivalent representation is flat, such as

```bash
log.dir = "/tmp"
log.file = "nanomq.log"
```

This flat format is almost backward compatible (the so called 'cuttlefish' format).

It is not fully compatible because HOCON requires strings to be quoted, while cuttlefish treats all characters to the right of the `=` mark as the value.

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
