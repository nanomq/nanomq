# 数据桥接

桥接是一种连接多个 MQTT 消息中间件的策略，其特性与集群模式显著不同。在桥接模式下，节点之间不进行主题树或路由表的复制操作。桥接模式的核心职能包括：

- 根据预定的规则，将消息转发至指定的桥接节点；
- 对桥接节点上的特定主题进行订阅，并在接收到消息后在本地节点或集群内进行传递和转发。

## MQTT over TCP 桥接

本节将介绍 MQTT over TCP 数据桥接相关的配置参数。

### **配置示例**

```hcl
bridges.mqtt.emqx1 = {
  server = "mqtt-tcp://127.0.0.1:1883"    # MQTT 服务器地址
  proto_ver = 4                           # MQTT 协议版本
  clientid = "bridge_client"              # 桥接的客户端 ID
  keepalive = "60s"                       # 桥接的保活间隔时间（s）
  clean_start = false                     # 清除会话
  username = "username"                   # 桥接用户名
  password = "passwd"                     # 桥接密码
  will = {                                # 遗嘱消息相关配置
  	topic = "will_topic"                  # Will 主题
  	qos = 1                               # Will QoS
  	retain = false                        # 是否应保留遗嘱消息
  	payload = "will_message"              # Will payload
  	properties = {                        # Will 消息属性
    	payload_format_indicator = 0
    	message_expiry_interval = 0
    	content_type = ""
    	response_topic = ""
    	correlation_data = ""
    	will_delay_interval = 0
    	user_property = {
      	key1 = "value1"
      	key2 = "value2"
    	}
  	}
  }
  ssl = {                                 # SSL 配置
    key_password = "yourpass"             # SSL 密钥密码
    keyfile = "/etc/certs/key.pem"        # SSL 密钥文件
    certfile = "/etc/certs/cert.pem"      # SSL 证书文件
    cacertfile = "/etc/certs/cacert.pem"  # SSL CA 证书文件
  }
  
  forwards = [                            # 要转发到远端 MQTT 服务器的主题
    {
      remote_topic = "fwd/topic1"
      local_topic = "topic1"
    },
    {
      remote_topic = "fwd/topic2"
      local_topic = "topic2"
    }
  ]     
  subscription = [                        # 要从远端 MQTT 服务器订阅的主题
    {
      remote_topic = "cmd/topic1"
      local_topic = "topic3"
      qos = 1
      retain = 2                          # 重载标志位
    },
    {
      remote_topic = "cmd/topic2"
      local_topic = "topic4"
      qos = 2
    }
  ]
  max_parallel_processes = 2              # 最大并行进程数
  max_send_queue_len = 32                 # 消息发送队列的最大长度
  max_recv_queue_len = 128                # 消息接收队列的最大长度
}
```

通过以上配置，NanoMQ 可以建立到远端 MQTT 服务器到 MQTT over TCP 桥接，并激活遗嘱消息和 SSL 加密通讯。

### **配置项**

- bridges.mqtt.\<name>：桥接名称。
- `server`：桥接目标 Broker 的地址 URL。示例：
  - MQTT over TCP 桥接：`mqtt-tcp://127.0.0.1:1883`
  - 经 SSL 加密的 MQTT over TCP 桥接：`tls+mqtt-tcp://127.0.0.1:8883`
  - MQTT over QUIC 桥接：`mqtt-quic://54.75.171.11:14567`
- `proto_ver`：指定 MQTT 协议版本：可选值：
  - `5`：MQTT v5
  - `4`：MQTT v3.1.1
  - `3`： MQTT v3.1
- `clientid`：桥接客户端 ID，默认 NULL 为自动生成随机 ID。
- `keepalive`：保活间隔时间。
- `clean_start`：清除会话。注意：有些 IoT 平台会要求该项设为 `false`。
- `username`：登录用户名。
- `password`：登录密码。
- `ssl`：SSL/TLS 相关配置项：
  - `key_password`：TLS 私钥密码。
  - `keyfile`：TLS 私钥数据。
  - `certfile`：TLS Cert 证书数据。
  - `cacertfile`：TLS CA 证书数据。
- `forwards`：转发到远端 MQTT 服务器的主题数组，应包括消息主题（`remote_topic`）、（`local_topic`）和 QoS （`qos`）。
  - `suffix`：将为远程主题添加后缀字符串（如果 remote_topic 为空，则添加到原始主题）
  - `prefix`：将为远程主题添加前缀字符串（如果 remote_topic 为空，则添加到原始主题）
- `subscription`：这是一个需要从远程 MQTT 服务器订阅的主题对象数组。每个对象定义一个主题及其对应的 QoS 级别（请注意，如果配置了多个重叠规则，则只有第一个规则生效）。除`forwards`中各项外，还包括以下几项：
  - `remote_topic`：用于订阅远程代理的主题过滤器。
  - `local_topic`：用于主题反射，如果您想要使用原始方式，只需保留 `local_topic=""` 即可，以便在远程代理发送的消息中保留原始主题。

  ::: tip
  
  `subscription`部分的`local_topic` 与`forwards`部分的工作方式不同。为了简化管理本地和远程主题关系（社区中经常提及的功能），自 0.23.7 版本起，引入了主题重新映射功能，该功能允许使用通配符删除或替换主题的部分内容。具体来说，通配符在此处充当字符串搜索锚点，以便用户保留匹配的部分。
  例如：
  `remote_topic = "+/nanomq/#"`
  `local_topic = "#"`
  如果下发消息来自主题`cmd/nanomq/hello/world`，则您将收到一条主题为`hello/world`的消息。

  :::

  - `retain`：重载标志位。
  - `retain_as_publish`：MQTTV5可选特性，Retain As Published。
  - `retain_handling`：MQTTV5可选特性，Retain Handling。
- `max_parallel_processes`：接客户端并发数。
- `max_send_queue_len`：最大发送队列长度。
- `max_recv_queue_len`：最大接收队列长度。

### **MQTT 5** 

如果选择使用 MQTT 5.0 协议（`proto_ver = 5`），NanoMQ 还支持以下配置项：

**连接相关：**

| 配置项                                         | 说明                                                  | 取值范围                     |
| ---------------------------------------------- | ------------------------------------------------------------ | -------------------------------- |
| `conn_property.maximum_packet_size`            | 最大报文长度 | 1 - 4294967295                   |
| `conn_properties.receive_maximum`              | QoS 1 和 QoS 2 消息的最大接收数量，仅在当前连接下有效。<br />如未配置，将使用默认值 65535。 <!--to be confirmed--> | 1 - 65535                        |
| `conn_properties.topic_alias_maximum`          | 主题别名最大长度 | 0 - 65535                        |
| `conn_properties.request_problem_information`  | 请求问题信息： <br /><br />- 如设为 0，服务器仅可在 PUBLISH、CONNACK 或 DISCONNECT 包中插入问题信息。如违反该规则，客户端则将断开连接并返回协议错误信息。 <!--to be confirmed--><br /><br />-  如设为 1，则不限制包的类型。 | 0 或 1                           |
| `conn_properties.request_response_information` | 请求响应信息： <br /><br />- 如设为 0，服务器禁止返回响应信息。 <!--to be confirmed--><br /><br />-  如设为 1，服务器可以在 CONNACK 包中返回响应信息。 | 0 或 1                           |
| `conn_properties.session_expiry_interval`      | 会话过期间隔：<br /><br />- 如设为 0，会话将在网络连接关闭后结束。<br /><br />- 如设为 4294967295 (UINT_MAX)，会话则永不过期。 | 0 - 4294967295                   |
| `conn_properties.user_property`                | 用户属性键值对。 | Map[key(String) - value(String)] |

**订阅相关**

| 配置项            | 说明             | 取值范围                       |
| ------------------------------ | ----------------------- | --------------------------------- |
| `sub_properties.identifier`    | 订阅标识符 | 1 ~ 268,435,455                   |
| `sub_properties.user_property` | 用户属性     | Map[key(String) - value(String)]* |

### **遗嘱消息 （Will Message）**

遗嘱消息是 MQTT 为那些可能出现**意外断线**的设备提供的将 **遗嘱** 优雅地发送给第三方的能力，意外断线包括但不限于：

- 因网络故障或网络波动，设备在保持连接周期内未能通讯，连接被服务端关闭
- 设备意外掉电
- 设备尝试进行不被允许的操作而被服务端关闭连接，例如订阅自身权限以外的主题等

相关配置项包括：

- `will.topic`：指定应发布遗嘱消息的主题。

- `will.payload`：指定遗嘱消息的有效 Payload，通常连接断开的通知消息。
- `will.qos`：遗嘱消息的 QoS 等级。可以是 0（最多一次）、1（至少一次）或 2（恰好一次）。
- `will.retain`：指定是否应保留遗嘱消息。如设置为 `true`，NanoMQ 则将存储遗嘱消息，并发给后续的订阅者。
- `will.properties`：
  - `payload_format_indicator`：指定遗嘱消息的 Payload 格式。可选值：0 或 1。0 表示未指定的字节流，1表示 UTF-8 字符串。
  - `message_expiry_interval`：指定遗嘱消息的保留时间段（单位：秒）。如未配置，消息将永不过期。
  - `content_type`：指定遗嘱消息 Payload 的内容类型，用于解释 Payload 中包含的数据。
  - `response_topic`：指定遗嘱消息的响应主题。其他客户端可以使用此主题发送对遗嘱消息的响应。
  - `correlation_data`：指定用于将响应与遗嘱消息相关联的二进制数据。
  - `will_delay_interval`：指定客户端非正常断开连接与代理发布遗嘱消息之间的延迟。单位：秒。注意：默认值 0 表示没有延迟。
  - `user_property`：用户定义键值对，用户可按照 `key1 = value1 `格式发送其他自定义数据。

## MQTT over QUIC 桥接

本节将介绍 MQTT over QUIC 数据桥接相关的配置参数。QUIC 最初由 Google 开发，后来被互联网工程任务组（IETF）采纳为全球标准。它是一种新的传输协议，提供更快的连接建立速度。通过 MQTT over QUIC 数据桥接，我们可以充分发挥 QUIC 协议在 IoT 场景中的优势。

### **配置示例**

```hcl
bridges.mqtt.emqx1 = {
  server = "mqtt-quic://127.0.0.1:14567"  # MQTT 服务器地址
  proto_ver = 4                           # MQTT 协议版本
  clientid = "bridge_client"              # 桥接的客户端 ID
  keepalive = "60s"                       # 桥接的保活间隔时间（s）
  clean_start = false                     # 清除会话
  username = "username"                   # 桥接用户名
  password = "passwd"                     # 桥接密码
  quic_keepalive = "120s"                 # 使用 QUIC 桥接的 ping 间隔
  quic_idle_timeout = "120s"              # 使用 QUIC 桥接的连接最大过期时间
  quic_discon_timeout = "20s"             # QUIC 桥接等待连接 ACK 最大时间
  quic_handshake_timeout = "60s"          # QUIC 握手最大超时时间
  quic_send_idle_timeout = "2s"           # QUIC 传输层重置拥塞控制算法的等待超时时间
  quic_initial_rtt_ms = "800ms"           # 初始 RTT 估计时间
  quic_max_ack_delay_ms = "100ms"         # 发送 ACK 之前接收数据后等待时长
  hybrid_bridging = false                 # 混合桥接模式开关
  quic_multi_stream = false               # 多流传输开关
  quic_qos_priority = true                # 高优先级发送 QOS 1 或 2 的消息
  quic_0rtt = true                        # 0RTT 开关，用于快速重新建立连接
  forwards = [                            # 要转发到远端 MQTT 服务器的主题
    {
      remote_topic = "fwd/topic1"
      local_topic = "topic1"
      qos = 1
    },
    {
      remote_topic = "fwd/topic2"
      local_topic = "topic2"
      qos = 2
    }
  ]     
  subscription = [                        # 要从远端 MQTT 服务器订阅的主题
    {
      remote_topic = "cmd/topic1"
      local_topic = "topic3"
      qos = 1
    },
    {
      remote_topic = "cmd/topic2"
      local_topic = "topic4"
      qos = 2
    }
  ]
  max_parallel_processes = 2              # 最大并行进程数
  max_send_queue_len = 32                 # 消息发送队列的最大长度
  max_recv_queue_len = 128                # 消息接收队列的最大长度
}
```

#### **配置项**

本部分重点介绍 MQTT over QUIC 桥接相关的配置项，其他配置项可参考 [MQTT over TCP 桥接](#mqtt-over-tcp-桥接)。

- Server：桥接的 MQTT 服务器地址，例如 `mqtt-quic://54.75.171.11:14567`
- `quic_keepalive`：QUIC 传输层保活时间，缺省为 120 秒。
- `quic_idle_timeout`：QUIC 连接最大过期时间，超时后，连接将被断开。0 表示永不超时，缺省为 120 秒。
- `quic_discon_timeout`：QUIC 等待连接 ACK 最大时间 ，缺省为 `20s`。
- `quic_handshake_timeout`：QUIC 握手最大超时时间，缺省为 60 秒。
- `quic_send_idle_timeout`：传输层重置拥塞控制算法的等待超时时间，缺省为 60 秒。
- `quic_initial_rtt_ms`：初始 RTT 估计时间，单位：ms，缺省为 800 ms。
- `quic_max_ack_delay_ms`：发送 ACK 之前接收数据后等待时长，缺省为 100 ms。
- `hybrid_bridging`：确认是否开启混合桥接模式；缺省为 `false`。
- `hybrid_servers`：确认混合桥接URLs；缺省为 `[]`。
- `quic_multi_stream`：确认是否开始多流传输，本功能目前正在进一步验证中，不建议开启。缺省为 `false`。
- `quic_qos_priority`：确认高优先级发送 QOS 1 或 2 的消息，QoS 0 消息的优先级不变。缺省为 `true`。
 - `quic_0rtt`：确认是否开启 0RTT QUIC 协议特性，用于快速重新建立连接。缺省为 `true`。

::: tip

MQTT over QUIC  桥接暂不支持 SSL 相关配置。

:::

## 配置多个 MQTT 桥接及缓存

您可在 `nanomq.conf` 配置文件中设置多个数据桥接，不同的桥接通过名称进行区分。此外，`cache` 相关配置项作为一个独立的组件工作，支持被多个组件引用。例如，您需要在多个桥接中实现消息缓存，可按照如下示例进行配置。

### **配置示例**

```hcl
## 第一个桥接客户端
bridges.mqtt.emqx1 {
  retry_qos_0 = false
  ......
}

## 第二个桥接客户端
bridges.mqtt.emqx2 {
  retry_qos_0 = true
  ......
}

## 缓存设置
bridges.mqtt.cache {
    disk_cache_size = 102400   # 缓存的最大消息限制
    mounted_file_path="/tmp/"  # 挂载的文件路径
    flush_mem_threshold = 100  # 刷新消息到闪存的阈值
    resend_interval = 5000     # 故障恢复后消息的重发间隔
}
```

### **配置项**

- `retry_qos_0`：指定 MQTT 桥接中可以缓存的消息的QoS。False 表示不缓存 QoS 0。
- `disk_cache_size`：指定 MQTT 桥接中可以缓存的消息的最大数量。0 表示不生效。
- `mounted_file_path`：指定 MQTT 桥接缓存文件的挂载路径。
- `flush_mem_threshold`：指定刷新消息到缓存文件的阈值。当消息数量达到阈值时，就会被刷新到缓存文件中。
- `resend_interval`：指定在故障恢复后消息的重发间隔，单位：毫秒。注意：该配置项与是否触发消息重发无关。

::: tip

NanoMQ 的缓存功能依赖于 SQLite 的配置，关于配置项的详细说明，见 [SQLite](broker.md#cache)。

:::

## AWS IoT Core 桥接

本部分介绍了与 NanoMQ AWS IoT Core 桥接相关的配置项。AWS IoT Core 是在欧美广泛使用的公有云 IoT 服务之一。但由于其与标准 MQTT 协议多有不同，且不支持 QoS 2 消息，因此许多使用标准 MQTT SDK 的客户端设备无法无缝兼容。NanoMQ 现已内置 AWS IoT Core 桥接功能，帮助用户解决兼容性问题。

### **配置示例**

```hcl
bridges.aws.c1 = {
  server = "127.0.0.1:8883"             # AWS IoT Core 服务器地址
  proto_ver = 4                         # MQTT 协议版本
  clientid = "aws_bridge_client"        # 桥接的客户端 ID
  keepalive = "60s"                     # 桥接的保活间隔时间（s）
  clean_start = true                    # 清除会话
  forwards = [                          # 要转发到远端 AWS IoT Core 的主题
    {
      remote_topic = "fwd/topic1"
      local_topic = "topic1"
    },
    {
      remote_topic = "fwd/topic2"
      local_topic = "topic2"
    }
  ]     
  subscription = [                      # 要从 AWS IoT Core 订阅的主题
    {
      remote_topic = "cmd/topic1"
      local_topic = "topic3"
      qos = 1
    },
    {
      remote_topic = "cmd/topic2"
      local_topic = "topic4"
      qos = 2
    }
  ]
  max_parallel_processes = 2            # 最大并行进程数
}
```

### **配置项**

- `server`：指定 AWS IoT Core 服务器的地址（主机:端口），例如，“127.0.0.1:8883”。
- `proto_ver`：指定桥接使用的 MQTT 协议版本，可选值 4（MQTT v3.1.1）和 5（MQTT v5）。
- `clientid`：指定桥接到 AWS IoT Core 的客户端 ID。默认值为随机字符串。
- `keepalive`：指定向 AWS IoT Core 发送保活消息的间隔。默认是 60 秒。
- `clean_start`：指定是否清除会话。注意：有些 IoT 平台要求高选项设为 true。
- `username` 和 `password`：桥接的登录用户名和密码。
- `ssl`：SSL/TLS 相关配置：
  - `key_password`：TLS 私钥密码。
  - `keyfile`：TLS 私钥数据。
  - `certfile`：TLS Cert 证书数据。
  - `cacertfile`：TLS CA 证书数据。
- `forwards`：要转发到 AWS IoT Core 的 Topic 数组。
- `subscription`：要从 AWS IoT Core 订阅的主题，每组配置应包含消息主题和对应的 QoS 等级。
- `max_parallel_processes`：最大并行进程数。
