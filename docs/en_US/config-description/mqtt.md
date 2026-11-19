# MQTT Messaging

MQTT Messaging configuration allows you to specify settings for the MQTT protocol used by your NanoMQ broker.

## **Example Configuration**

```hcl
mqtt = {
  max_packet_size = 1KB       # Maximum packet size NanoMQ can accept and send, 1B~260MB.
  max_mqueue_len = 2048       # Maximum length of the in-flight window queue
  retry_interval = 10s        # Retry interval for QoS 1/2 message delivering
  keepalive_multiplier = 1.25 # Multiplier for MQTT keepalive timeout. 
  property_size = 32          # Maximum size for a MQTT user property.
}
```

## **Configuration Items**

| Configuration Item     | Description                                                  | Value Range      |
| ---------------------- | ------------------------------------------------------------ | ---------------- |
| `max_packet_size`      | Specifies the maximum size of a packet that NanoMQ can accept and send | 1 Byte to 260 MB |
| `max_mqueue_len`       | Specifies the maximum length of the in-flight window queue. <br /><br />**Note**: This item may affect the system performance and memory consumption, please set it with caution. | 1 ~ infinity     |
| `retry_interval`       | Specifies the retry interval for outbound QoS 1/2 message delivery when an acknowledgment is not received. Increasing this value on high-latency or lossy links helps reduce unnecessary retransmissions and duplicate deliveries. | 1 ~ infinity     |
| `keepalive_multiplier` | Specifies the multiplier for the MQTT keepalive timeout. The broker will disconnect the client if there's no activity for `Keepalive * backoff` time. | Float > 0.5      |
| `property_size`        | Specifies the maximum size for an MQTT user property.        | 1 ~ infinity     |

::: tip

All of these MQTT configurations in NanoMQ support hot upgrading. This means that any changes made to these settings will take effect immediately after you save the configuration file, without the need to restart the NanoMQ broker. 

:::

## QoS 2 Trade-offs and Best Practices

::: warning Use QoS 1 with Application-Level Idempotency Instead of QoS 2

1. **Inherent Limitations of MQTT QoS 2**: Due to the Two Generals' Problem in distributed networks, the four-step MQTT QoS 2 handshake (`PUBLISH` / `PUBREC` / `PUBREL` / `PUBCOMP`) only operates on a single hop and cannot guarantee true end-to-end "exactly-once" business execution (for example, if a subscriber crashes or disconnects after executing a side effect but before sending `PUBCOMP`). Critical workloads still require application-level idempotency (such as deduplicating by message payload ID or sequence number).
2. **NanoMQ Architectural Trade-off**: To preserve a minimal memory footprint and lock-free forwarding hot path on resource-constrained edge hardware, NanoMQ does not maintain inbound `awaiting PUBREL` deduplication state (`max_awaiting_rel` and `await_rel_timeout` are not active). If a publisher retransmits a QoS 2 `PUBLISH` with the same Packet ID before receiving `PUBREC`, NanoMQ forwards it again rather than allocating per-connection state tables.
3. **Recommendations**:
   - **Avoid QoS 2**: Use **QoS 1 combined with idempotent consumers** for lower latency, higher throughput, and reliable end-to-end semantics.
   - **Tune Retry Intervals to Reduce Duplicates**: Where legacy clients require QoS 2 (or QoS 1), increase `mqtt.retry_interval` (e.g., from `10s` to `30s` or higher based on link RTT) and configure a correspondingly larger retransmission timeout on publishing clients to prevent premature retransmissions during transient network jitter.

:::

## Upcoming Features

More configuration items will be supported in upcoming releases, please stay tuned. 

- ​    `max_inflight_window`
- ​    `max_awaiting_rel`
- ​    `await_rel_timeout`

