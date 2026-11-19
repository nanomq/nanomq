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
| `retry_interval`       | Broker 向订阅端投递 QoS 1/2 消息未收到确认时的重传间隔。在弱网或高延迟场景下，适当调大该值可减少不必要的重传及重复投递概率。 | 1 ~ infinity     |
| `keepalive_multiplier` | 指定 MQTT keepalive 超时的乘数。如果 `Keepalive * backoff` 时间内没有任何活动，NanoMQ 将断开客户端连接。 | 浮点数 > 0.5      |
| `property_size`        | 最大属性长度。 | 1 ~ infinity     |

::: tip

以上 MQTT 相关配置均支持热升级，保存配置文件即生效，无需重启 NanoMQ。

:::

## QoS 2 设计取舍与使用建议

::: warning 建议优先使用 QoS 1 + 业务层幂等替代 QoS 2

1. **MQTT QoS 2 的协议局限性**：在分布式系统中，受限于网络不可靠性与两军问题（Two Generals' Problem），MQTT QoS 2 的四步握手（`PUBLISH` / `PUBREC` / `PUBREL` / `PUBCOMP`）仅作用于单跳传输链路，无法保证应用层业务动作在端到端真实“有且仅有一次”执行（例如订阅端在完成业务处理后、回发 `PUBCOMP` 前发生断网或崩溃，重连后仍可能引发状态不一致）。因此，对数据一致性敏感的业务始终需要在消费端实现幂等去重（如基于消息唯一 ID 或业务流水号）。
2. **NanoMQ 的轻量化架构取舍**：为面向边缘计算场景保持极低的内存占用与无锁转发热路径，NanoMQ 在入站方向不维护 `awaiting PUBREL` 去重状态表（`max_awaiting_rel` 与 `await_rel_timeout` 暂未启用）。当发布端在未收到 `PUBREC` 时重传同 `Packet ID` 的 QoS 2 报文，Broker 会将其作为常规消息再次转发。
3. **推荐实践**：
   - **避免使用 QoS 2**：在绝大多数物联网场景下，推荐使用 **QoS 1 + 消费端幂等** 替代 QoS 2，既能避免多轮握手的网络延迟与状态开销，又能提供可靠的端到端语义。
   - **调整重传间隔降低重复概率**：若因存量终端限制必须使用 QoS 2（或 QoS 1），建议根据实际网络 RTT 适当调大 `mqtt.retry_interval`（例如从默认的 `10s` 调整为 `30s` 或更高），同时适当放宽发布端 SDK 的 ACK 重传超时时间，避免网络瞬时抖动触发重复发包。

:::

## 功能预告

接下来，NanoMQ 将支持更多配置项，敬请期待：

- ​    `max_inflight_window`
- ​    `max_awaiting_rel`
- ​    `await_rel_timeout`

