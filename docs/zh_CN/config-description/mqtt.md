# MQTT 消息服务

本节包括与 MQTT 协议相关的一些配置项。

## **配置示例**

```hcl
mqtt = {
  max_packet_size = 1KB       # NanoMQ 可接收和发送的最大包大小。
  max_mqueue_len = 2048       # 等待确认窗口队列的最大长度。
  retry_interval = 10s        # QoS 1/2 消息投递的重试间隔。
  keepalive_multiplier = 1.25 # MQTT keepalive 超时的乘数。 
  property_size = 32          # MQTT 用户最大属性长度。
}
```

## **配置项**

| 配置项     | 说明                                                  | 取值范围      |
| ---------------------- | ------------------------------------------------------------ | ---------------- |
| `max_packet_size`      | NanoMQ 可接收和发送的最大包大小。 | 1B~260MB |
| `max_mqueue_len`       | 等待确认窗口队列的最大长度。 <br /><br />**注意**：该项配置可能会影响系统性能和内存消耗，请谨慎设置。 | 1 ~ infinity     |
| `retry_interval`       | QoS 1/2 消息投递的重试间隔。 | 1 ~ infinity     |
| `keepalive_multiplier` | 指定 MQTT keepalive 超时的乘数。如果 `Keepalive * backoff` 时间内没有任何活动，NanoMQ 将断开客户端连接。 | 浮点数 > 0.5      |
| `property_size`        | 最大属性长度。 | 1 ~ infinity     |

::: tip

以上 MQTT 相关配置均支持热升级，保存配置文件即生效，无需重启 NanoMQ。

:::

## 功能预告

接下来，NanoMQ 将支持更多配置项，敬请期待：

- ​    `max_inflight_window`
- ​    `max_awaiting_rel`
- ​    `await_rel_timeout`

