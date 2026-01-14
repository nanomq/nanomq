# MQTT over QUIC Bridge – Product Overview


## 1. Introduction to QUIC & MQTT over QUIC

QUIC (Quick UDP Internet Connections) is a modern transport protocol standardized by the IETF. It runs over UDP and integrates encryption and multiplexing by design. Compared to traditional TCP+TLS, QUIC offers:

- Faster connection establishment with 0-RTT/1-RTT handshakes.
- Stream-based multiplexing without head-of-line blocking.
- More flexible congestion control and timeout behavior, especially under high packet loss and long RTT.

With MQTT over QUIC bridging, a NanoMQ edge node can connect to a cloud MQTT broker (such as EMQX 5.x) using QUIC as the transport layer, achieving faster, more stable and bandwidth-efficient cloud–edge messaging.


## 2. Capability Overview

MQTT over QUIC bridging provides:

- A QUIC-based MQTT data bridge between edge and cloud.
- QUIC performance benefits without upgrading existing device-side MQTT SDKs.
- Support for both MQTT v3.1.1 and MQTT v5.
- Fine-grained control over QUIC connection behavior (timeouts, keepalive, congestion control).
- QoS 1/2 priority over QoS 0 traffic under congestion.
- QUIC/TCP hybrid bridging with automatic fallback to TCP/TLS.


## 3. Typical Use Cases

### 3.1 Legacy Devices without MQTT over QUIC

Many deployed devices still speak MQTT over TCP and are difficult to upgrade:

1. Devices connect to NanoMQ over MQTT/TCP at the edge.
2. NanoMQ bridges to the cloud over MQTT over QUIC.

This lets you benefit from QUIC on the cloud–edge link without touching the device firmware.

### 3.2 Weak Network, High Latency or High Packet Loss

Examples include:

- Cross-region public networks (cross-country or cross-operator).
- Mobile networks (4G/5G, in-vehicle networks).
- Satellite links with high latency and packet loss.

In such environments, QUIC’s fast reconnection, multi-stream capability and advanced congestion control can significantly improve end-to-end latency stability and connectivity.

### 3.3 Prioritizing High-Value Business Data

On a bandwidth-constrained link that carries both bulk telemetry and critical business data, enabling QoS 1/2 priority ensures that alarms and control commands are delivered ahead of QoS 0 telemetry when buffers are congested.

### 3.4 Gradual Adoption of QUIC

If you are unsure about QUIC support in your current environment, you can start with hybrid bridging:

- Prefer QUIC when possible.
- Automatically fall back to TCP/TLS when QUIC is unavailable or unstable.

This strategy allows you to gradually adopt QUIC in production without sacrificing reliability.


## 4. Enabling MQTT over QUIC

### 4.1 Build with QUIC Enabled

By default, NanoMQ binaries may not include QUIC support. To use MQTT over QUIC bridging, build NanoMQ from source with QUIC enabled:

```bash
git clone https://github.com/emqx/nanomq.git
cd nanomq
git submodule update --init --recursive

mkdir build && cd build

# Enable QUIC bridging
cmake -G Ninja -DNNG_ENABLE_QUIC=ON ..
ninja install
```

To build msquic as a static library, you can add:

```bash
cmake -G Ninja -DNNG_ENABLE_QUIC=ON -DQUIC_BUILD_SHARED=OFF ..
```

### 4.2 HOCON Configuration

NanoMQ uses a HOCON-style configuration file `nanomq.conf`. To configure MQTT over QUIC bridging:

1. Define a `bridges.mqtt.<name>` block to create a bridge client.
2. Set `server` to a `mqtt-quic://host:port` URL.
3. Configure basic MQTT bridge parameters (protocol version, credentials, forwards/subscriptions).
4. Configure `quic_*` options to tune QUIC behavior.


## 5. Configuration Options

### 5.1 Basic MQTT Bridge Parameters

These options are shared across TCP, TLS and QUIC bridges; only the most relevant ones are listed:

- **`bridges.mqtt.<name>.server`**  
  - Description: Target MQTT broker URL for bridging.  
  - Examples:  
    - `mqtt-tcp://127.0.0.1:1883` (MQTT over TCP)  
    - `tls+mqtt-tcp://127.0.0.1:8883` (MQTT over TLS)  
    - `mqtt-quic://54.75.171.11:14567` (MQTT over QUIC)  

- **`bridges.mqtt.<name>.proto_ver`**  
  - Description: MQTT protocol version used by the bridge client.  
  - Values: `5` (MQTT v5), `4` (MQTT v3.1.1), `3` (MQTT v3.1).  

- **`bridges.mqtt.<name>.clientid`**  
  - Description: ClientId used by the bridge. If omitted, a random ID will be generated.

- **`bridges.mqtt.<name>.keepalive`**  
  - Description: MQTT protocol-level keepalive interval.  
  - Note: Different from QUIC-level `quic_keepalive`.

- **`bridges.mqtt.<name>.username` / `password`**  
  - Description: Credentials for authenticating with the upstream broker.

- **`bridges.mqtt.<name>.forwards`**  
  - Description: Rules describing which local topics should be forwarded to the upstream broker.  
  - Each entry can configure:  
    - `local_topic`: Local topic filter (supports wildcards).  
    - `remote_topic`: Remote topic used when forwarding.  
    - Optional `qos`, `retain`, `prefix`, `suffix`, etc.

- **`bridges.mqtt.<name>.subscription`**  
  - Description: Rules describing which upstream topics are subscribed and republished locally.  
  - Each entry can configure:  
    - `remote_topic`: Topic to subscribe on the upstream broker.  
    - `local_topic`: Local topic used when republishing.  
    - `qos`, plus optional `retain_as_published`, `retain_handling`.

Whenever `server` uses the `mqtt-quic://` prefix, all these semantics run on top of QUIC.

### 5.2 QUIC-Specific Options

The following options appear under `bridges.mqtt.<name>` and only apply when `server` is a `mqtt-quic://` URL.

#### 5.2.1 Timeouts & Keepalive

- **`quic_keepalive`**  
  - Type: Duration (e.g. `120s`)  
  - Purpose: Interval for sending QUIC-level keepalive probes.  
  - Default: `120s`.

- **`quic_idle_timeout`**  
  - Type: Duration (e.g. `120s`, `0s`)  
  - Purpose: Maximum idle time before the QUIC connection is closed.  
  - Special: `0` disables this timeout.  
  - Default: `120s`.

- **`quic_discon_timeout`**  
  - Type: Duration (e.g. `20s`)  
  - Purpose: Maximum time to wait for an ACK before declaring a path dead and disconnecting.  
  - Default: `20s`.

- **`quic_handshake_timeout`**  
  - Type: Duration (e.g. `60s`)  
  - Purpose: Maximum time allowed for a full QUIC handshake.  
  - Default: `60s`.

#### 5.2.2 Congestion & RTT-Related Options

- **`quic_send_idle_timeout`**  
  - Type: Duration (e.g. `2s`, `60s`)  
  - Purpose: Reset congestion control after being idle for this period to re-estimate the network.  
  - Default: `60s`.

- **`quic_initial_rtt_ms`**  
  - Type: Duration in milliseconds (e.g. `800ms`)  
  - Purpose: Initial RTT estimate before real RTT measurements are available.  
  - Default: `800ms`.

- **`quic_max_ack_delay_ms`**  
  - Type: Duration in milliseconds (e.g. `100ms`)  
  - Purpose: Maximum delay between receiving data and sending an ACK.  
  - Default: `100ms`.

#### 5.2.3 Multiplexing & QoS Priority

- **`quic_multi_stream`**  
  - Type: Boolean (`true` / `false`)  
  - Purpose: Enable or disable QUIC multi-stream bridging:  
    - `true`: Different topics/subscriptions can be mapped to different streams.  
    - `false`: Single-stream mode.  
  - Default: `false`.

- **`quic_qos_priority`**  
  - Type: Boolean (`true` / `false`)  
  - Purpose: Prioritize QoS 1/2 messages over QoS 0 when the link or buffers are congested.  
  - Default: `true`.

#### 5.2.4 0-RTT Fast Reconnect

- **`quic_0rtt`**  
  - Type: Boolean (`true` / `false`)  
  - Purpose: Enable QUIC 0-RTT so that application data can be sent during reconnection without waiting for a full handshake.  


## 6. QUIC/TCP Hybrid Bridging

To combine the performance of QUIC with the robustness of TCP/TLS, you can use hybrid bridging:

- **`hybrid_bridging`**  
  - Type: Boolean (`true` / `false`)  
  - Purpose: Enable or disable hybrid bridging mode.

- **`hybrid_servers`**  
  - Type: Array of strings  
  - Example:
    ```hcl
    hybrid_servers = [
      "mqtt-quic://127.0.0.1:14567",
      "mqtt-tcp://127.0.0.1:1883"
    ]
    ```  
  - Purpose: Define candidate URLs, usually with a QUIC URL first and TCP/TLS URLs as fallbacks.

In production, a “QUIC-first with TCP fallback” strategy is recommended to gradually adopt QUIC while preserving reliability.


## 7. Configuration Examples

### 7.1 Single MQTT over QUIC Bridge

```hcl
bridges.mqtt.emqx_quic {
  server    = "mqtt-quic://your_server_address:14567"
  proto_ver = 4
  clientid  = "bridge_client"
  username  = "emqx"
  password  = "emqx123"
  keepalive = "60s"

  # QUIC-specific options
  quic_keepalive         = "120s"
  quic_idle_timeout      = "120s"
  quic_discon_timeout    = "20s"
  quic_handshake_timeout = "60s"
  quic_send_idle_timeout = "2s"
  quic_initial_rtt_ms    = "800ms"
  quic_max_ack_delay_ms  = "100ms"
  quic_multi_stream      = false
  quic_qos_priority      = true
  quic_0rtt              = true
  hybrid_bridging        = false

  forwards = [
    { remote_topic = "fwd/topic1", local_topic = "topic1", qos = 1 },
    { remote_topic = "fwd/topic2", local_topic = "topic2", qos = 2 }
  ]

  subscription = [
    { remote_topic = "cmd/topic1", local_topic = "topic3", qos = 1 },
    { remote_topic = "cmd/topic2", local_topic = "topic4", qos = 2 }
  ]

  max_parallel_processes = 2
  max_send_queue_len     = 32
  max_recv_queue_len     = 128
}
```

### 7.2 QUIC/TCP Hybrid Bridge

```hcl
bridges.mqtt.emqx_hybrid {
  server    = "mqtt-quic://your_server_address:14567"
  proto_ver = 5

  # Hybrid bridging: prefer QUIC, fall back to TCP
  hybrid_bridging = true
  hybrid_servers  = [
    "mqtt-quic://your_server_address:14567",
    "mqtt-tcp://your_server_address:1883"
  ]

  quic_keepalive      = "120s"
  quic_idle_timeout   = "120s"
  quic_discon_timeout = "20s"
  quic_0rtt           = true
  quic_qos_priority   = true
}
```


## 8. Validating with the Command-Line Tool

NanoMQ ships with a `nanomq_cli` tool that makes it easy to validate MQTT over QUIC.

### 8.1 Subscribe over QUIC

```bash
./nanomq_cli sub --quic \
  -h remote.broker.address \
  -p 14567 \
  -t "forward1/#" \
  -q 2
```

### 8.2 Publish over QUIC

```bash
./nanomq_cli pub --quic \
  -h remote.broker.address \
  -p 14567 \
  -t "recv/topic1" \
  -m "cmd_msg" \
  -q 2 \
  -u emqx \
  -P emqx123
```

If messages are successfully published and received across the QUIC link, your MQTT over QUIC bridge has been set up correctly.

