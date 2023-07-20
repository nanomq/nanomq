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
| `retry_interval`       | Specifies the retry interval for QoS 1/2 message delivering  | 1 ~ infinity     |
| `keepalive_multiplier` | Specifies the multiplier for the MQTT keepalive timeout. The broker will disconnect the client if there's no activity for `Keepalive * backoff` time. | Float > 0.5      |
| `property_size`        | Specifies the maximum size for an MQTT user property.        | 1 ~ infinity     |

::: tip

All of these MQTT configurations in NanoMQ support hot upgrading. This means that any changes made to these settings will take effect immediately after you save the configuration file, without the need to restart the NanoMQ broker. 

:::

## Upcoming Features

More configuration items will be supported in upcoming releases, please stay tuned. 

- ​    `max_inflight_window`
- ​    `max_awaiting_rel`
- ​    `await_rel_timeout`

