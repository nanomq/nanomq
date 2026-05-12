# NNG 数据桥接 (NNG Bridging)

NanoMQ 借助其底层的 NanoNNG 通信引擎，不仅支持标准的 MQTT 协议桥接，还支持与 NNG (Next Generation Scalability Protocols) 的 `pub0`/`sub0` 协议进行数据桥接。这种桥接方式非常适合边缘计算场景下，将标准的 MQTT 协议与轻量级、高吞吐的内部 IPC/TCP NNG 消息总线打通。

NNG 数据桥接主要分为两个方向：**NNG Pub 桥接**（将 MQTT 消息转发给 NNG）和 **NNG Sub 桥接**（将 NNG 消息引入并作为 MQTT 消息发布）。

## NNG Pub 桥接 (`bridges.nng.pub`)

NNG Pub 桥接负责将 NanoMQ 本地的 MQTT 消息转换为 NNG `pub0` 协议消息，并向外部的 NNG 节点发送。

* **数据流向**：MQTT PUBLISH -> NNG `pub0` 消息。
* **工作流**：MQTT 客户端发布消息到指定的 `local_topic` -> 桥接模块在本地订阅该主题并拦截消息 -> 从 MQTT 报文中提取有效载荷（Payload）-> 将配置的 `remote_topic` 作为前缀拼接到 Payload 前 -> 通过 NanoNNG 底层的 `pub0` Socket 发送给对端。

### **配置示例**

```hcl
bridges.nng.pub.t1 {
    # 是否启用此 NNG 桥接
    enable = true
    
    # NNG pub0 Socket URL
    pub_url = "tcp://localhost:9900"
    
    # 桥接的本地 Client ID
    clientid = "nng_proxy"
    
    # 需要转发到 NNG 端的主题映射数组
    forwards = [
        {
            # 本地订阅的 MQTT 主题（支持通配符）
            local_topic = "nng/#"
            # 转发至 NNG 时的前缀主题
            remote_topic = "remote/nng"
            # 本地订阅的 QoS 级别
            qos = 1
        },
        {
            local_topic = "ekuiper/"
            remote_topic = "remote/ekuiper"
            qos = 1
        }
    ]
}
```

### **配置项**

* `bridges.nng.pub.<name>`：定义一个 NNG Pub 桥接实例，`<name>` 为自定义标识符（例如 `t1`）。
* `enable`：指定是否启用此桥接实例。可选值：`true` | `false`，默认为 `false`。
* `pub_url`：NanoMQ 在此地址上启动 NNG `pub0` Socket 并监听（listen），**外部 NNG sub 端主动连接**到该地址以接收消息。支持多种传输协议，例如 `tcp://127.0.0.1:9900` 、本地进程间通信 `ipc:///tmp/nng_pub.ipc`或进程内线程间通信 `inproc://inproc_thr`。
* `clientid`：用于本地 MQTT 代理中标识此桥接发布者的 Client ID。
* `forwards`：定义本地 MQTT 主题到远端 NNG 主题的映射关系规则数组。
  * `local_topic`：本地 MQTT 主题过滤器。凡是发布到匹配该主题的消息都将被桥接模块捕获并转发。支持 MQTT 标准通配符（如 `#` 和 `+`）。
  * `remote_topic`：转发给 NNG 对端时附加的主题前缀。在 NanoNNG 的底层实现中，构造的 NNG 消息格式为 `"remote_topic/payload"`（以 `/` 分隔主题与有效载荷）。若此字段留空，NanoMQ 将以原始 MQTT 主题作为 NNG 消息的前缀。
  * `qos`：桥接模块在本地订阅 `local_topic` 时使用的 QoS 级别。可选值：`0` | `1` | `2`。

---

## NNG Sub 桥接 (`bridges.nng.sub`)

NNG Sub 桥接负责监听外部 NNG 节点发布的 `pub0` 消息，根据前缀将其过滤，并转换为标准的 MQTT 消息在 NanoMQ 内部代理上发布。

* **数据流向**：NNG `sub0` 消息 -> MQTT PUBLISH。
* **工作流**：NNG pub Socket 发送携带主题前缀的字节流 -> NanoMQ 桥接模块通过 NanoNNG `sub0` Socket 接收消息 -> 使用配置的 `remote_topic` 进行前缀匹配截取 -> 提取后续的有效载荷并将其作为 MQTT 消息发布到对应的 `local_topic` 上。

### **配置示例**

```hcl
bridges.nng.sub.t2 {
    # 是否启用此 NNG 桥接
    enable = true
    
    # NNG sub0 Socket URL
    sub_url = "tcp://localhost:9901"
    
    # 桥接的本地 Client ID
    clientid = "nng_proxy_2"
    
    # 需要从 NNG 端接收的主题映射数组
    subscription = [
        {
            # 用于匹配 NNG 消息的前缀
            remote_topic = "nng"
            # 转换为 MQTT 消息后的目标主题
            local_topic = "local/nng"
            # 发布为 MQTT 消息时的 QoS
            qos = 1
        },
        {
            remote_topic = "ekuiper"
            local_topic = "local/ekuiper"
            qos = 1
        }
    ]
}
```

### **配置项**

* `bridges.nng.sub.<name>`：定义一个 NNG Sub 桥接实例，`<name>` 为自定义标识符（例如 `t2`）。
* `enable`：指定是否启用此桥接实例。可选值：`true` | `false`，默认为 `false`。
* `sub_url`：NanoMQ 在此地址上启动 NNG `sub0` Socket 并监听（listen），**外部 NNG pub 端主动连接**到该地址以推送消息。同样支持 TCP 和 IPC 传输，例如 `tcp://localhost:9901`、 `ipc:///tmp/nng_sub.ipc`或进程内线程间通信 `inproc://inproc_thr`。
* `clientid`：用于本地 MQTT 代理中标识此桥接订阅者的 Client ID。
* `subscription`：定义远端 NNG 主题前缀到本地 MQTT 主题的映射关系规则数组。来源于匹配 `remote_topic` 的 NNG 消息将发布至 `local_topic`。
  * `remote_topic`：配置底层 NNG Socket 的主题过滤前缀。只有以 `"remote_topic/"` 或该配置前缀开头的 NNG 消息字节流才会被接收，前缀之后的内容将被当作 MQTT 消息的主体 Payload 处理。
  * `local_topic`：指定该过滤后的数据将被发布到 NanoMQ 的哪一个本地 MQTT 主题上。
  * `qos`：指定转换并发布为本地 MQTT 消息时所采用的 QoS 等级。可选值：`0` | `1` | `2`。
