# QoS 消息批量重发 (Batch Resend)

## 概述

NanoMQ 引入了**批量重发**功能，用于高效地重新发送在本地 nano_qos_db 中缓存的 MQTT QoS 1（至少一次）和 QoS 2（恰好一次）消息。此功能通过在检测到网络问题或客户端断开连接时允许批量重发消息来优化消息传递效率。

## 背景说明

MQTT QoS 级别确保可靠的消息传输：
- **QoS 0**：至多一次 - 最佳努力，无需确认
- **QoS 1**：至少一次 - 需要 PUBACK 确认
- **QoS 2**：恰好一次 - 需要 PUBLISH/PUBREC/PUBREL/PUBCOMP 四次握手

当 QoS 消息传输失败（由于网络问题、客户端断开等）时，NanoMQ 会将消息缓存在 `nano_qos_db` 中并重试发送。传统方法是在检测到确认未收到时逐个重试消息，这在高负载或频繁断开的情况下效率较低。

## 批量重发的工作原理

### 传统的单条消息重试机制（启用前）

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  Client A   │   │    Broker   │   │  Client B   │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │
       │ QoS1 PUBLISH    │                 │
       │────────────────►│                 │
       │                 │ Cache in DB      │
       │                 │◄─────────────────│
       │                 │ PUBACK           │
       │                 │──────────────────│
```

当单个消息需要重试时，每个消息通过 QoS 管道单独处理：
1. 定时器触发每管道路由器的重试（基于 `qos_duration`）
2. 从 `nano_qos_db` 逐个获取消息
3. 设置重复标志后发送给客户端

### 批量重发模式（启用后）

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  Client A   │   │    Broker   │   │  Client B   │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │
       │ QoS1 PUBLISH    │                 │
       │────────────────►│                 │
       │                 │ Cache in DB      │
       │                 │◄─────────────────│
       │                 │ PUBACK           │
       │                 │──────────────────│

┌─────────────────────────────────────────────────────┐
│                  Batch Resend                        │
├─────────────────────────────────────────────────────┤
│ 当 batch_resend = true 且收到 PUBACK 时：             │
│ 1. Broker 查询 nano_qos_db 获取所有待处理消息         │
│    (get_one() 迭代缓存中的所有消息)                 │
│ 2. 所有符合条件的消息被排队进行批量重发              │
│ 3. 每条消息获得自己的 packet_id 并设置 DUP 标志       │
│ 4. 只在管道空闲时发送（避免内容争用）                │
└─────────────────────────────────────────────────────┘
```

### 关键算法组件

1. **配置检查**：批量重发仅在 broker 配置中 `batch_resend = true` 时激活

2. **触发点**：
   - 收到 PUBACK/PUBCOMP（QoS 1/2 确认）时
   - QoS 定时器间隔过期 (`qos_duration * 1000ms`)

3. **消息检索机制** (`tcptran_pipe_getopt`):
   ```c
   // 迭代所有缓存的消息
   while (1) {
       msg = nni_qos_db_get_one(is_sqlite, qos_db, pipe_id, &pid);
       
       if (msg == NULL) break;  // 没有更多消息
       
       // 检查过期条件：
       // 1. 消息因 MESSAGE_EXPIRY_INTERVAL 属性而过期
       // 2. 重试超时超过 (qos_duration * 1250ms)
       
       if (!expired && !timeout_exceeded) {
           req->msg = msg;
           return 0;  // 返回第一条符合条件的消息
       }
   }
   ```

4. **重复标志**：所有重发消息通过 `nano_msg_set_dup()` 设置 DUP 标志

5. **管道同步**：仅在管道不繁忙时发送 (`!p->busy`)，避免内容争用

6. **消息清理**：
   - 过期的消息从缓存中删除
   - 成功确认的消息由 QoS DB 自动清理

## 配置方法

### 启用批量重发

在 broker 配置文件中添加或修改以下内容：

```hocon
listeners.tcp {
    bind = "0.0.0.0:1883"
    
    mqtt {
        # 控制 QoS 消息的重传行为
        batch_resend = true
        
        # 单个 QoS 消息的重试间隔（秒）
        qos_duration = 10
    }
}
```

### 配置参数说明

| 参数 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `batch_resend` | boolean | false | 启用批量重发模式。为 true 时，多个缓存的 QoS 消息会一起重新发送而不是单独处理。 |
| `qos_duration` | integer (秒) | 10 | 每个管道路由器的单个 QoS 消息重试间隔。也控制 QoS 缓存清理循环的定时器间隔。 |

### 热更新支持

两个参数都支持**热更新** - 您可以无需重启 NanoMQ 就修改这些配置：

```bash
# 示例使用 IPC 命令行
echo "set mqtt.batch_resend=true" > /var/run/nanomq/ipc.sock
echo "set mqtt.qos_duration=20" > /var/run/nanomq/ipc.sock
```

## 适用场景

### 批量重发模式特别适用的情况

1. **高消息速率**：当大量 QoS 消息同时在传输中时，批量重发减少了多次定时器触发和独立查找的开销。

2. **频繁断开连接**：在网络不稳定的条件下客户端经常断开时，批量重发可以更高效地清除多个过期的缓存消息。

3. **资源受限系统**：通过批处理操作而不是为每个消息单独通过 QoS 管道进行处理来降低 CPU 使用率。

4. **桥接场景**：特别是当与其他 broker 或系统进行桥接且连接可能间歇性中断时很有用。

### 权衡与注意事项

| 方面 | 单条消息重试 (batch_resend=false) | 批量重发 (batch_resend=true) |
|------|----------------------------------|-----------------------------|
| 内存使用 | 较低（逐个处理消息） | 较高（多个消息在管道中持有） |
| CPU 开销 | 每条消息较高（每条消息的定时器 + 查找） | 整体较低（批处理操作） |
| 延迟 | 可预测，立即重试 | 轻微延迟等待批量组装完成 |
| 网络效率 | 可能发送单个 PUBLISH 包的突发流 | 更有效的包批处理 |
| 复杂性 | 简单的失败隔离 | 复杂的状态追踪 |

## 实现细节

### 代码位置

批量重发功能在 MQTT broker 传输层中实现：

1. **`nng/src/sp/protocol/mqtt/nmq_mqtt.c`**: 
   - CMD_PUBACK 处理器（第 1215 行）- 收到 PUBACK 时触发批量重发
   - 使用 `batch_resend` 标志确定是否处于批处理模式

2. **`nng/src/sp/transport/mqtt/broker_tcp.c`**:
   - `tcptran_pipe_getopt()` 函数（第 1630-1704 行）- 从 QoS DB 检索消息用于重发
   - 实现了消息选择和过期的逻辑

3. **消息存储** (`nng/src/sp/transport/mqtt/broker_tcp.c`):
   - 第 1082-1110 行：消息存储在 `nano_qos_db` 中，使用 (pipe_id, packet_id) 作为键索引
   - 第 1093-1110 行处理重复检测和缓存管理

### 数据结构

```c
// QoS 消息检索的请求结构
typedef struct {
    uint16_t packet_id;      // MQTT 包 ID
    nni_msg *msg;            // NNG 消息指针
} nmq_req;
```

### 缓存管理

`nano_qos_db` 使用 SQLite（当启用时）或内存哈希表：
- **SQLite 模式**：消息作为带有 pipe_id 和 packet_id 索引的行存储
- **哈希表模式**：用于更快访问的内存查找
- 最大缓存大小受 `qos_duration * 1250ms` 超时控制

### 消息过期逻辑

消息可以通过两种方式从缓存中删除：

1. **MESSAGE_EXPIRY_INTERVAL 属性** (MQTT v5):
   - 如果消息有此属性，检查 `(当前时间 > 发布时间 + 过期间隔)`
   - 过期的消息会自动删除

2. **重试超时**:
   - 在收到确认前经过 `qos_duration * 1250ms` 后返回进行重发尝试
   - 此超时时限防止无限期缓存

## 使用示例

### 基本配置

```hocon
mqtt {
    batch_resend = true
    qos_duration = 15
}
```

此配置启用批量重发，重试间隔为 15 秒。

### 带 SQLite 持久化存储的配置

用于跨 broker 重启时持久化消息：

```hocon
mqtt {
    sqlite {
        enable = true
        user_path = "/var/lib/nanomq"
        db_name = "mqtt.db"
    }
    
    batch_resend = true
    qos_duration = 10
}
```

### 桥接模式下的批量重发配置

当与其他 broker 进行桥接时：

```hocon
bridges.bridge_to_another_broker {
    remote_url = "tcp://broker.example.com:1883"
    
    mqtt {
        batch_resend = true  # 高效处理桥接断开连接
        qos_duration = 5     # 更快的桥接连接重试间隔
    }
}
```

## 监控与调试

### 日志消息

当启用批量重发时，您会看到类似这样的日志：

```
INFO: resending qos msg id X to pipe Y
```

这表示正在从缓存中重新发送 QoS 消息。

### 性能指标

要监控批量重发的效果：

1. **检查 `nano_qos_db` 大小**：随着消息被确认或过期，该值应减小
2. **监控重试率**：在稳定条件下启用 batch_resend=true 时重试率应降低
3. **CPU 利用率**：消息风暴期间 CPU 使用率可能略有增加，但整体效率更好

### 故障排除

如果您没有看到预期的行为：

1. **验证配置**：必须将 `batch_resend` 设置为 true 才能生效
2. **检查管道繁忙状态**：如果管道正在处理其他工作，消息不会重发
3. **审查过期设置**：MESSAGE_EXPIRY_INTERVAL 可能导致消息在重试前就过期
4. **日志级别**：设置 log_level=debug 以查看详细的 QoS 缓存操作信息

## 相关功能

- **[QoS Duration](https://docs.nanomq.io/)**: 控制消息重试和缓存清理的时间间隔
- **[SQLite 持久化存储](https://docs.nanomq.io/)**: 支持 broker 重启时保存消息
- **[消息过期属性](https://docs.nanomq.io/)**: MQTT v5 的每个消息 TTL

## 未来改进计划

潜在的增强功能可能包括：

1. **可配置的批量大小**: 允许指定每批的最大消息数而不是全部一次性发送
2. **优先级队列**: 在批次中优先处理更高优先级的缓存消息
3. **自适应批处理**: 根据网络条件动态调整批处理方式
4. **批处理统计信息**: 暴露关于批处理操作的指标用于可观测性

## 参考资料

- [MQTT QoS 规范](https://docs.oasis-open.org/mqtt/mqtt/v1.2/os/mqtt-v1.2-os.html#_Toc39875206)
- [NanoMQ MQTT Broker 文档](./index.md)
- `nng/src/supplemental/mqtt/mqtt_qos_db_api.h`（NNG QoS 数据库 API）
