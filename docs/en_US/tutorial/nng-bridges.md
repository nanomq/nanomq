# NNG Bridge Configuration and Testing

This section explains how to configure and verify `bridges.nng.pub` and `bridges.nng.sub` based on the current `etc/nanomq.conf`. All commands in this document were validated against the build artifacts in this repository.

For parameter-level details, see [NNG Bridging](../config-description/nng_bridges.md).

## Prerequisites

Before running the tests, make sure the following requirements are met:

1. The project has already been built from the repository root.
2. The `nngcat` executable is available at `build/nng/src/tools/nngcat/nngcat`.
3. If you want to test with Mangos `macat` instead of `nngcat`, make sure `macat` is available in your environment.
4. The `nanomq_cli` executable is available at `build/nanomq_cli/nanomq_cli`.
5. NanoMQ is started with `etc/nanomq.conf`, and both `bridges.nng.pub.t1` and `bridges.nng.sub.t2` are enabled.

If NanoMQ is not running yet, start it from the `build` directory:

```bash
./nanomq/nanomq start --conf ../etc/nanomq.conf
```

The tests in this document use the following socket addresses:

- `bridges.nng.pub.t1.pub_url = "ipc:///tmp/nng_pub.ipc"`
- `bridges.nng.sub.t2.sub_url = "ipc:///tmp/nng_sub.ipc"`

---

## Configure and Test `bridges.nng.pub`

The direction of `bridges.nng.pub` is: **MQTT -> NanoMQ -> NNG**.

### Configuration

In the current `etc/nanomq.conf`, `bridges.nng.pub.t1` is configured as follows:

```hcl
# MQTT(local_topic) -> NanoMQ -> NNG(remote_topic)
bridges.nng.pub.t1 {

  # NNG pub socket URL.
  # The address of the NNG pub0 protocol server to publish to.
  #
  # Value: String
  # Example: tcp://127.0.0.1:9900
  #          ipc:///tmp/nng_pub.ipc
  #          inproc://nng_pub_inproc (Use for Inter-process communication)
  pub_url = "ipc:///tmp/nng_pub.ipc"

  # The ClientId of this NNG bridge publisher.
  # Default random string.
  #
  # Value: String
  clientid = "nng_proxy"

  # Topics that need to be forwarded to NNG.
  # This defines mappings between local MQTT topics and remote NNG topics.
  #
  # Value: Array of objects
  forwards = [
    {
      # Local MQTT topic filter to subscribe to.
      # Messages matching this filter are forwarded.
      # Supports MQTT wildcards (# and +).
      #
      # Value: String
      local_topic = "mqtt/local/#"

      # Remote NNG topic to publish to.
      # NNG message format:
      # "remote_topic + nng_delimiter + payload"
      # If remote_topic is empty, it is treated as local_topic.
      #
      # Value: String
      remote_topic = "nng/remote"

      # Delimiter between remote_topic and payload in NNG message.
      # Default delimiter is "/".
      # Example with ":" -> "remote_topic:payload".
      #
      # Value: String
      nng_delimiter = ":"

      # QoS level for MQTT messages from local_topic.
      # Value: 0 | 1 | 2
      qos = 1
    },
    {
      # Local MQTT topic filter to subscribe to.
      #
      # Value: String
      local_topic = "mqtt/ekuiper"

      # Remote NNG topic to publish to.
      #
      # Value: String
      remote_topic = "nng/ekuiper"

      # Delimiter between remote_topic and payload in NNG message.
      #
      # Value: String
      nng_delimiter = ":"
    }
  ]
}
```

This configuration means:

- NanoMQ listens on `ipc:///tmp/nng_pub.ipc` with an NNG `pub0` socket.
- External NNG `sub0` clients connect to this address to receive forwarded messages.
- When an MQTT client publishes to a topic matching `mqtt/local/#`, NanoMQ prepends the configured `remote_topic` to the original payload and sends the raw NNG message in `remote_topic + nng_delimiter + payload` format (default delimiter is `/`).
- If `remote_topic` is omitted or set to an empty string in a forwarding rule, NanoMQ treats `remote_topic` as `local_topic` for message construction.

### Test Procedure

Run the following commands from the `build` directory.

**1. Start the NNG subscriber**

Start an `nngcat` client and subscribe to the `nng/remote` topic:

```bash
./nng/src/tools/nngcat/nngcat --sub0 --dial ipc:///tmp/nng_pub.ipc --subscribe "nng/remote" --raw
```

Equivalent `macat` command:

```bash
macat --sub --connect ipc:///tmp/nng_pub.ipc --subscribe "nng/remote" --raw
```

The `--raw` option is used here so you can inspect the exact raw NNG message emitted by NanoMQ.

**2. Publish an MQTT message**

In another terminal, run:

```bash
./nanomq_cli/nanomq_cli pub -t "mqtt/local/123" -m "hello" -q 1
```

This topic matches `local_topic = "mqtt/local/#"`, so it triggers the first forwarding rule of `bridges.nng.pub.t1`.

**3. Check the result**

The `nngcat` terminal receives the following raw message:

```text
nng/remote:hello
```

This shows the bridge behavior clearly:

- MQTT topic: `mqtt/local/123`
- MQTT payload: `hello`
- NNG prefix: `nng/remote`
- Configured delimiter: `:`
- Final raw message sent to the NNG peer: `nng/remote:hello`

In other words, `bridges.nng.pub` does not forward the original MQTT topic `mqtt/local/123` to the NNG peer. The NNG peer sees a raw message composed of `remote_topic` and payload.

---

## Configure and Test `bridges.nng.sub`

The direction of `bridges.nng.sub` is: **NNG -> NanoMQ -> MQTT**.

### Configuration

In the current `etc/nanomq.conf`, `bridges.nng.sub.t2` is configured as follows:

```hcl
# NNG(remote_topic) -> NanoMQ -> MQTT(local_topic)
bridges.nng.sub.t2 {

  # NNG sub socket URL.
  # The address of the NNG sub0 protocol server to subscribe to.
  #
  # Value: String
  # Example: tcp://127.0.0.1:9901
  #          ipc:///tmp/nng_sub.ipc
  #          inproc://nng_sub_inproc (Use for Inter-process communication)
  sub_url = "ipc:///tmp/nng_sub.ipc"

  # The ClientId of this NNG bridge subscriber.
  # Default random string.
  #
  # Value: String
  clientid = "nng_proxy_2"

  # Subscription topics from remote NNG server.
  # This defines mappings between remote NNG topics and local MQTT topics.
  #
  # Value: Array of objects
  subscription = [
    {
      # Remote NNG topic to subscribe to.
      # Topic extraction rules:
      # 1) If nng_delimiter is not set or is "/":
      #    extracted topic is matched against configured remote_topic,
      #    and the matched suffix (the part after matched prefix)
      #    becomes payload.
      # 2) If nng_delimiter is set to non-"/" (e.g. ":"):
      #    extracted topic extends from remote_topic prefix to delimiter,
      #    and the part after delimiter becomes payload.
      #
      # Value: String
      remote_topic = "test/123"

      # Local MQTT topic to publish to.
      # If local_topic is empty, local_topic is treated as remote_topic.
      #
      # Value: String
      local_topic = "test/forward"

      # Delimiter between remote_topic and payload in incoming NNG message.
      # Default delimiter is "/".
      #
      # Value: String
      nng_delimiter = ":"

      # QoS level for MQTT messages published to local_topic.
      # Value: 0 | 1 | 2
      qos = 1
    },
    {
      # Remote NNG topic to subscribe to.
      #
      # Value: String
      remote_topic = "ekuiper"

      # Local MQTT topic to publish to.
      #
      # Value: String
      local_topic = "ekuiper/forward"

      # Delimiter between remote_topic and payload in incoming NNG message.
      #
      # Value: String
      nng_delimiter = ":"

      # QoS level for MQTT messages published to local_topic.
      # Value: 0 | 1 | 2
      qos = 2
    }
  ]
}
```

This configuration means:

- NanoMQ listens on `ipc:///tmp/nng_sub.ipc` with an NNG `sub0` socket.
- External NNG `pub0` clients connect to this address and push raw NNG messages into NanoMQ.
- Topic extraction depends on `nng_delimiter`:
  - When `nng_delimiter = "/"`: NanoMQ matches the extracted topic against configured `remote_topic`, and the suffix after the match becomes payload. For `remote_topic="test/123"` and message `"test/123/hello world"`, extracted topic is `"test/123"` and payload is `"hello world"`.
  - When `nng_delimiter = ":"`: NanoMQ extracts topic from the prefix to the delimiter. For `remote_topic="test/123"`, `nng_delimiter=":"` and message `"test/123:hello nanomq"`, extracted topic is `"test/123"` and payload is `"hello nanomq"`.
- The MQTT topic used by local subscribers is `test/forward`, not `test/123` (the local_topic is where the message is published).

### Test Procedure

Run the following commands from the `build` directory.

**1. Start the MQTT subscriber**

Start a `nanomq_cli` subscriber on the mapped local MQTT topic:

```bash
./nanomq_cli/nanomq_cli sub -t "test/forward"
```

Note that this subscribes to the `local_topic`, not the `remote_topic`.

**2. Send a message from the NNG side**

In another terminal, run:

```bash
./nng/src/tools/nngcat/nngcat --pub0 --dial ipc:///tmp/nng_sub.ipc --data "test/123:hello nanomq"
```

Equivalent `macat` command:

```bash
macat --pub --connect ipc:///tmp/nng_sub.ipc --data "test/123:hello nanomq"
```

Because the message starts with the `test/123:` prefix, it matches the first subscription rule. NanoMQ strips the prefix and publishes only `hello nanomq` as the MQTT payload.

**3. Check the result**

The `nanomq_cli sub` terminal receives:

```text
test/forward: hello nanomq
HEX : 68656c6c6f206e616e6f6d71
```

This confirms the bridge behavior:

- Raw NNG message: `test/123:hello nanomq`
- Matched `remote_topic`: `test/123`
- MQTT topic published by NanoMQ: `test/forward`
- MQTT payload: `hello nanomq`

The key points for testing `bridges.nng.sub` are:

- The MQTT subscriber must subscribe to `local_topic`.
- The NNG publisher must send a message with the `remote_topic + nng_delimiter` prefix (default `remote_topic/`), which NanoMQ strips during conversion.

---

## Troubleshooting

If your result does not match the behavior above, check the following items first:

1. Confirm that NanoMQ was started with `etc/nanomq.conf`.
2. Confirm that the IPC endpoints for `pub_url` and `sub_url` are not occupied by another process.
3. Confirm that the `bridges.nng.pub.t1` and `bridges.nng.sub.t2` nodes exist and have valid `pub_url`/`sub_url` and rule items configured.
4. For `bridges.nng.pub`, confirm that the MQTT publish topic matches `mqtt/local/#`.
5. For `bridges.nng.sub`, confirm that the NNG message starts with `remote_topic + nng_delimiter` (default `/`) and that the MQTT subscriber is listening on the mapped `local_topic`.

If you need more detail about field meanings and bridge data flow, refer back to [NNG Bridging](../config-description/nng_bridges.md).
