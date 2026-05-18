
# NNG Pub/Sub Bridging

NanoMQ supports data bridging with NNG (Next Generation Scalability Protocols) `pub0`/`sub0` protocols, leveraging its underlying NanoNNG engine. This is particularly useful in edge computing scenarios where you need to interface standard MQTT with high-throughput NNG-based internal message buses.

NNG bridging is divided into two directions: **NNG Pub Bridge** (forwarding MQTT messages to NNG) and **NNG Sub Bridge** (receiving NNG messages and publishing them as MQTT).

## NNG Pub Bridge (`bridges.nng.pub`)

The NNG Pub Bridge is responsible for forwarding MQTT messages from local topics to a remote NNG `pub0` socket.

* **Data Flow**: MQTT PUBLISH → NNG `pub0` message.
* **Workflow**: MQTT Client publishes to `local_topic` → Bridge subscribes and extracts the payload → Payload is prefixed with `remote_topic + nng_delimiter` (default `/`) → Sent to NNG pub socket.

### **Configuration Example**

```hcl
bridges.nng.pub.t1 {

    # NNG pub socket URL.
    # The address of the NNG pub0 protocol server to publish to.
    #
    # Value: String
    # Example: tcp://127.0.0.1:9900
    #          ipc:///tmp/nng_pub.ipc
    #          inproc://nng_pub_inproc (Use for Inter-process communication)
    pub_url = "tcp://localhost:9900"

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
            local_topic = "nng/#"

            # Remote NNG topic to publish to.
            # NNG message format:
            # "remote_topic + nng_delimiter + payload"
            # If remote_topic is empty, it is treated as local_topic.
            #
            # Value: String
            remote_topic = "remote/nng"

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
            local_topic = "ekuiper/"
            # Example of fallback behavior:
            # when remote_topic is empty, remote_topic = local_topic.
            remote_topic = ""
            nng_delimiter = "/"
        }
    ]
}
```

### **Parameters**

* `bridges.nng.pub.<name>`: Defines an NNG Pub bridge instance, where `<name>` is a unique identifier (e.g., `t1`).
* `pub_url`: The address on which NanoMQ listens with its NNG `pub0` socket. **External NNG sub clients connect to this address** to receive messages. Supports various transports such as `tcp://127.0.0.1:9900`, `ipc:///tmp/nng_pub.ipc` or `inproc://inproc_thr`.
* `clientid`: Identifier for this bridge publisher within the local NanoMQ broker.
* `forwards`: Array of mapping rules between local MQTT topics and remote NNG topics.
    * `local_topic`: The local MQTT topic filter to subscribe to. Supports wildcards (`#` and `+`).
    * `remote_topic`: The topic prefix prepended to the payload when sending to the NNG side. The constructed NNG message format is: `"remote_topic + nng_delimiter + payload"`. If `remote_topic` is omitted or set to an empty string, it is treated as `local_topic`.
    * `nng_delimiter`: Delimiter inserted between `remote_topic` and payload when building NNG messages. Default: `/`. Example: `:` produces `remote_topic:payload`.
    * `qos`: QoS level used for the internal subscription to `local_topic`. Value: `0` | `1` | `2`.

---

## NNG Sub Bridge (`bridges.nng.sub`)

The NNG Sub Bridge subscribes to topics on a remote NNG `sub0` socket and forwards received messages as MQTT publications to a local topic.

* **Data Flow**: NNG `sub0` message → MQTT PUBLISH.
* **Workflow**: NNG pub socket sends message with prefix → Bridge matches `remote_topic + nng_delimiter` (default `/`) → Forwards remainder of message as MQTT payload to `local_topic`.

### **Configuration Example**

```hcl
bridges.nng.sub.t2 {

    # NNG sub socket URL.
    # The address of the NNG sub0 protocol server to subscribe to.
    #
    # Value: String
    # Example: tcp://127.0.0.1:9901
    #          ipc:///tmp/nng_sub.ipc
    #          inproc://nng_sub_inproc (Use for Inter-process communication)
    sub_url = "tcp://localhost:9901"

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
            #    Example: remote_topic="nng/pub", nng_delimiter="/",
            #    msg="nng/pub/123/hello" -> extracted topic="nng/pub",
            #    payload="123/hello".
            # 2) If nng_delimiter is set to non-"/" (e.g. ":"):
            #    extracted topic extends from remote_topic prefix to delimiter,
            #    and the part after delimiter becomes payload.
            #    Example: remote_topic="nng/pub", nng_delimiter=":",
            #    msg="nng/pub/123/1234:payload" ->
            #    extracted topic="nng/pub/123/1234", payload="payload".
            #
            # Value: String
            remote_topic = "nng"

            # Delimiter between remote_topic and payload in incoming NNG message.
            # Default delimiter is "/".
            #
            # Value: String
            nng_delimiter = "/"

            # Local MQTT topic to publish to.
            # If local_topic is empty, local_topic is treated as remote_topic.
            #
            # Value: String
            local_topic = "local/nng"

            # QoS level for MQTT messages published to local_topic.
            # Value: 0 | 1 | 2
            qos = 1
        },
        {
            remote_topic = "ekuiper"
            nng_delimiter = ":"
            local_topic = "local/ekuiper"
        }
    ]
}
```

### **Parameters**

* `bridges.nng.sub.<name>`: Defines an NNG Sub bridge instance, where `<name>` is a unique identifier (e.g., `t2`).
* `sub_url`: The address on which NanoMQ listens with its NNG `sub0` socket. **External NNG pub clients connect to this address** to push messages. Supports TCP and IPC transports, e.g., `tcp://localhost:9901`, `ipc:///tmp/nng_sub.ipc` or `inproc://inproc_thr`.
* `clientid`: Identifier for this bridge subscriber within the local NanoMQ broker.
* `subscription`: Array of mapping rules between remote NNG topics and local MQTT topics.
    * `remote_topic`: The NNG topic prefix to subscribe to. Topic extraction rules:
      - If `nng_delimiter` is not set or is `/`: extracted topic is matched against configured `remote_topic`, and the matched suffix (the part after matched prefix) becomes payload. Example: `remote_topic="nng/pub"`, `nng_delimiter="/"`, message `"nng/pub/123/hello"` → extracted topic=`"nng/pub"`, payload=`"123/hello"`.
      - If `nng_delimiter` is set to non-`/` (e.g. `":"`): extracted topic extends from `remote_topic` prefix to delimiter, and the part after delimiter becomes payload. Example: `remote_topic="nng/pub"`, `nng_delimiter=":"`, message `"nng/pub/123/1234:payload"` → extracted topic=`"nng/pub/123/1234"`, payload=`"payload"`.
    * `nng_delimiter`: Delimiter used when matching `remote_topic` and splitting payload from incoming NNG messages. Default: `/`.
    * `local_topic`: The local MQTT topic to which the forwarded message will be published. If `local_topic` is omitted or set to an empty string, it is treated as `remote_topic`.
    * `qos`: QoS level used when publishing the message to the local broker. Value: `0` | `1` | `2`.
