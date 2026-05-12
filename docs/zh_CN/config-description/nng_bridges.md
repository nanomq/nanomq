# NNG 数据桥接 (NNG Bridging)

NanoMQ 借助其底层的 NanoNNG 通信引擎，不仅支持标准的 MQTT 协议桥接，还支持与 NNG (Next Generation Scalability Protocols) 的 `pub0`/`sub0` 协议进行数据桥接。这种桥接方式非常适合边缘计算场景下，将标准的 MQTT 协议与轻量级、高吞吐的内部 IPC/TCP NNG 消息总线打通。

NNG 数据桥接主要分为两个方向：**NNG Pub 桥接**（将 MQTT 消息转发给 NNG）和 **NNG Sub 桥接**（将 NNG 消息引入并作为 MQTT 消息发布）。

## NNG Pub 桥接 (`bridges.nng.pub`)

NNG Pub 桥接负责将 NanoMQ 本地的 MQTT 消息转换为 NNG `pub0` 协议消息，并向外部的 NNG 节点发送。

* **数据流向**：MQTT PUBLISH -> NNG `pub0` 消息。
* **工作流**：MQTT 客户端发布消息到指定的 `local_topic` -> 桥接模块在本地订阅该主题并拦截消息 -> 从 MQTT 报文中提取有效载荷（Payload）-> 将配置的 `remote_topic + nng_delimiter`（默认 `/`）拼接到 Payload 前 -> 通过 NanoNNG 底层的 `pub0` Socket 发送给对端。

### **配置示例**

```hcl
bridges.nng.pub.t1 {
    # # 是否启用此 NNG 桥接。
    # #
    # # Value: true | false
    # # Default: false
    enable = true

    # # NNG pub0 Socket URL。
    # # NNG pub0 协议服务端地址。
    # #
    # # Value: String
    # # Example: tcp://127.0.0.1:9900
    # #          ipc:///tmp/nng_pub.ipc
    # #          inproc://nng_pub_inproc (用于进程内通信)
    pub_url = "tcp://localhost:9900"

    # # 桥接的本地 Client ID。
    # # 默认随机字符串。
    # #
    # # Value: String
    clientid = "nng_proxy"

    # # 需要转发到 NNG 端的主题映射数组。
    # # 定义本地 MQTT 主题与远端 NNG 主题的映射关系。
    # #
    # # Value: Array of objects
    forwards = [
        {
            # # 本地 MQTT 订阅主题过滤器。
            # # 匹配该过滤器的消息将被转发。
            # # 支持 MQTT 通配符（# 和 +）。
            # #
            # # Value: String
            local_topic = "nng/#"

            # # 转发至 NNG 时的前缀主题。
            # # NNG 消息格式为：
            # # "remote_topic + nng_delimiter + payload"。
            # # 若 remote_topic 为空字符串，remote_topic 等同于 local_topic。
            # #
            # # Value: String
            remote_topic = "remote/nng"

            # # NNG 消息中 remote_topic 与 payload 的分隔符。
            # # 默认分隔符为 "/"。
            # # 例如设置为 ":" 时格式为 "remote_topic:payload"。
            # #
            # # Value: String
            nng_delimiter = ":"

            # # 本地订阅 local_topic 时使用的 QoS。
            # # Value: 0 | 1 | 2
            qos = 1
        },
        {
            local_topic = "ekuiper/"
            # # 回退示例：
            # # remote_topic 为空时，remote_topic = local_topic。
            remote_topic = ""
            nng_delimiter = "/"
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
    * `remote_topic`：转发给 NNG 对端时附加的主题前缀。在 NanoNNG 的底层实现中，构造的 NNG 消息格式为 `"remote_topic + nng_delimiter + payload"`。若此字段未填写或为空字符串，`remote_topic` 等同于 `local_topic`。
    * `nng_delimiter`：NNG 消息中 `remote_topic` 与 payload 之间的分隔符。默认值为 `/`，例如设置为 `:` 时消息格式为 `remote_topic:payload`。
  * `qos`：桥接模块在本地订阅 `local_topic` 时使用的 QoS 级别。可选值：`0` | `1` | `2`。

---

## NNG Sub 桥接 (`bridges.nng.sub`)

NNG Sub 桥接负责监听外部 NNG 节点发布的 `pub0` 消息，根据前缀将其过滤，并转换为标准的 MQTT 消息在 NanoMQ 内部代理上发布。

* **数据流向**：NNG `sub0` 消息 -> MQTT PUBLISH。
* **工作流**：NNG pub Socket 发送携带主题前缀的字节流 -> NanoMQ 桥接模块通过 NanoNNG `sub0` Socket 接收消息 -> 使用配置的 `remote_topic + nng_delimiter`（默认 `/`）进行前缀匹配截取 -> 提取后续的有效载荷并将其作为 MQTT 消息发布到对应的 `local_topic` 上。

### **配置示例**

```hcl
bridges.nng.sub.t2 {
    # # 是否启用此 NNG 桥接。
    # #
    # # Value: true | false
    # # Default: false
    enable = true

    # # NNG sub0 Socket URL。
    # # NNG sub0 协议服务端地址。
    # #
    # # Value: String
    # # Example: tcp://127.0.0.1:9901
    # #          ipc:///tmp/nng_sub.ipc
    # #          inproc://nng_sub_inproc (用于进程内通信)
    sub_url = "tcp://localhost:9901"

    # # 桥接的本地 Client ID。
    # # 默认随机字符串。
    # #
    # # Value: String
    clientid = "nng_proxy_2"

    # # 需要从 NNG 端接收的主题映射数组。
    # # 定义远端 NNG 主题与本地 MQTT 主题的映射关系。
    # #
    # # Value: Array of objects
    subscription = [
        {
            # # 远端 NNG 订阅主题前缀。
            # # Topic 提取规则：
            # # 1) nng_delimiter 未设置或为 "/" 时：
            # #    提取的 topic 与 remote_topic 匹配，匹配后的后缀作为 payload。
            # #    例：remote_topic="nng/pub"，nng_delimiter="/"，
            # #    msg="nng/pub/123/hello" -> 提取 topic="nng/pub"，payload="123/hello"。
            # # 2) nng_delimiter 为非 "/"（例如 ":"）时：
            # #    提取的 topic 从 remote_topic 前缀延伸到分隔符，分隔符后为 payload。
            # #    例：remote_topic="nng/pub"，nng_delimiter=":"，
            # #    msg="nng/pub/123/1234:payload" ->
            # #    提取 topic="nng/pub/123/1234"，payload="payload"。
            # #
            # # Value: String
            remote_topic = "nng"

            # # NNG 入站消息中 topic 与 payload 的分隔符。
            # # 默认分隔符为 "/"。
            # #
            # # Value: String
            nng_delimiter = "/"

            # # 转换后发布到本地 Broker 的 MQTT 主题。
            # # 若 local_topic 为空字符串，local_topic 等同于 remote_topic。
            # #
            # # Value: String
            local_topic = "local/nng"

            # # 发布为 MQTT 消息时使用的 QoS。
            # # Value: 0 | 1 | 2
            qos = 1
        },
        {
            remote_topic = "ekuiper"
            nng_delimiter = ":"
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
    * `remote_topic`: 配置底层 NNG Socket 的主题过滤前缀。Topic 提取规则如下：
      - 当 `nng_delimiter` 未设置或为 `/` 时：提取的 topic 与配置的 `remote_topic` 进行匹配，匹配成功后的后缀部分（超出前缀的部分）作为 payload。例：`remote_topic="nng/pub"`，`nng_delimiter="/"`，消息 `"nng/pub/123/hello"` → 提取的 topic=`"nng/pub"`，payload=`"123/hello"`。
      - 当 `nng_delimiter` 设置为非 `/`（如 `":"`）时：提取的 topic 从 `remote_topic` 前缀延伸到分隔符位置，分隔符之后的部分作为 payload。例：`remote_topic="nng/pub"`，`nng_delimiter=":"` ，消息 `"nng/pub/123/1234:payload"` → 提取的 topic=`"nng/pub/123/1234"`，payload=`"payload"`。
    * `nng_delimiter`：匹配和拆分 NNG 入站消息时使用的分隔符。默认值为 `/`。
  * `local_topic`：指定该过滤后的数据将被发布到 NanoMQ 的哪一个本地 MQTT 主题上。若此字段未填写或为空字符串，`local_topic` 等同于 `remote_topic`。
  * `qos`：指定转换并发布为本地 MQTT 消息时所采用的 QoS 等级。可选值：`0` | `1` | `2`。
