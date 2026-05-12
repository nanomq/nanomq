
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
    # Enable or disable this bridge
    enable = true
    
    # NNG pub socket URL
    pub_url = "tcp://localhost:9900"
    
    # The ClientId of this NNG bridge publisher
    clientid = "nng_proxy"
    
    # Topics that need to be forwarded to NNG
    forwards = [
        {
            local_topic = "nng/#"
            remote_topic = "remote/nng"
            nng_delimiter = ":"
            qos = 1
        },
        {
            local_topic = "ekuiper/"
            remote_topic = "remote/ekuiper"
            nng_delimiter = ":"
        }
    ]
}
```

### **Parameters**

* `bridges.nng.pub.<name>`: Defines an NNG Pub bridge instance, where `<name>` is a unique identifier (e.g., `t1`).
* `enable`: Whether to enable this bridge. Value: `true` | `false`. Default: `false`.
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
    # Enable or disable this bridge
    enable = true
    
    # NNG sub socket URL
    sub_url = "tcp://localhost:9901"
    
    # The ClientId of this NNG bridge subscriber
    clientid = "nng_proxy_2"
    
    # Subscription topics from remote NNG server
    subscription = [
        {
            remote_topic = "nng"
            nng_delimiter = "/"
            local_topic = "local/nng"
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
* `enable`: Whether to enable this bridge. Value: `true` | `false`. Default: `false`.
* `sub_url`: The address on which NanoMQ listens with its NNG `sub0` socket. **External NNG pub clients connect to this address** to push messages. Supports TCP and IPC transports, e.g., `tcp://localhost:9901`, `ipc:///tmp/nng_sub.ipc` or `inproc://inproc_thr`.
* `clientid`: Identifier for this bridge subscriber within the local NanoMQ broker.
* `subscription`: Array of mapping rules between remote NNG topics and local MQTT topics.
    * `remote_topic`: The NNG topic prefix to subscribe to. The adapter uses prefix matching; if a message starts with `remote_topic + nng_delimiter`, the content after the prefix is treated as the payload.
    * `nng_delimiter`: Delimiter used when matching `remote_topic` and splitting payload from incoming NNG messages. Default: `/`.
    * `local_topic`: The local MQTT topic to which the forwarded message will be published.
    * `qos`: QoS level used when publishing the message to the local broker. Value: `0` | `1` | `2`.