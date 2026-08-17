# 批量重发快速参考 (Batch Resend Quick Reference)

## 什么是批量重发？

批量重发是一个优化功能，允许 NanoMQ 高效地同时重新发送多个缓存的 QoS 1 和 QoS 2 消息，而不是逐条重发消息。这在高消息速率或频繁网络断开时特别能提升性能。

## 如何启用

```hocon
listeners.tcp {
    bind = "0.0.0.0:1883"
    
    mqtt {
        batch_resend = true  # 启用批量重发模式
        qos_duration = 10    # 重试间隔，单位秒（默认：10）
    }
}
```

## 关键点

| 特性 | 描述 |
|------|------|
| **何时生效** | 仅当 `batch_resend = true` 且收到 QoS 消息的 PUBACK/PUBCOMP 时 |
| **消息类型** | 仅限 QoS 1（至少一次）和 QoS 2（恰好一次） |
| **缓存位置** | nano_qos_db（SQLite 或内存哈希表） |
| **热更新支持** | 是 - 无需重启 broker，可通过 IPC 命令启用/禁用 |

## 配置选项

### `batch_resend` (boolean)
- 默认值：false
- 设置为 true 以启用批量重发模式
- 为 true 时，多个缓存的 QoS 消息会一起分批重新发送而不是单独处理

### `qos_duration` (integer, 秒)
- 默认值：10
- 控制重试间隔和定时器循环频率
- 消息在没有确认的情况下超时时间为 `qos_duration * 1250ms`

## 适用场景

**应该启用 batch_resend：**
- 有高消息吞吐量需求时
- 网络不稳定且经常断开连接时
- 在资源受限的硬件上运行时（边缘设备）
- 与其他 broker 或系统进行桥接且连接可能间歇性中断时

**保持禁用状态：**
- 网络条件稳定可预测时
- 需要立即重试失败的消息时
- 内存使用是主要考虑因素时

## 热更新命令

```bash
# 无需重启即可启用批量重发
echo "set mqtt.batch_resend=true" > /var/run/nanomq/ipc.sock

# 无需重启即可调整重试间隔  
echo "set mqtt.qos_duration=20" > /var/run/nanomq/ipc.sock
```

## 监控

启用调试日志以查看批量重发活动：

```hocon
log {
    level = debug
}
```

查找这些日志消息：
- `INFO: resending qos msg id X to pipe Y` - 正在从缓存重发消息

## 相关文档

- [完整的批量重发指南](./batch_resend.md) - 详细解释工作原理
- [MQTT QoS 文档](https://docs.nanomq.io/) - 了解 MQTT 消息传递保证
