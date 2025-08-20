# MQTT over TCP 桥接

MQTT over TCP 桥接是一种使用传输控制协议（TCP）作为底层通信协议的 MQTT 桥接方式。这种桥接方式利用了 TCP 的可靠传输特性，确保了 MQTT 消息在跨网络或跨代理通信时的完整性和准确性。通过优化的配置和管理，MQTT over TCP 桥接可以灵活地应对各种网络环境和应用场景，是实现物联网（IoT）设备间通信的重要工具。NanoMQ 现已支持通过 MQTT over TCP 桥接连接至 [EMQX 企业级 MQTT 物联网接入平台](https://www.emqx.com/zh/products/emqx)。

## 配置 MQTT over TCP 桥接

NanoMQ 已内置对 MQTT over TCP 桥接的支持，因此当您通过各种方式[安装 NanoMQ](../installation/introduction.md) 后，即可直接通过配置文件配置并启用 MQTT over TCP 桥接。

这里将使用 EMQ 提供的[免费公共桥接 broker.emqx.io:1883](https://www.emqx.com/en/mqtt/public-mqtt5-broker) 来构建 MQTT over TCP 数据桥接。

:::: tabs type:card

::: tab Hocon 配置格式

希望使用 HOCON 配置格式的用户，可参考以下格式，将配置写入 `nanomq.conf`文件，相关设置将在 NanoMQ 重启后生效。

- 完整的配置项列表，可参考[配置说明 - v019](../config-description/bridges.md)

- NanoMQ 0.14 ~ 0.18 版本用户，可参考 [配置说明 - v0.14](../config-description/v014.md)

```bash
bridges.mqtt.name {
	## TCP URL 格式:  mqtt-tcp://host:port
	## TLS URL 格式:  tls+mqtt-tcp://host:port
	## QUIC URL 格式: mqtt-quic://host:port
	server = "mqtt-tcp://broker.emqx.io:1883"
	## MQTT 协议版本 （ 4 ｜ 5 ）
	proto_ver = 4
	# username = admin
	# password = public
	clean_start = true
	keepalive = 60s
	## 如果通过 TLS 桥接将下面的代码取消注释
	## ssl {
	## 	keyfile = "/etc/certs/key.pem"
	## 	certfile = "/etc/certs/cert.pem"
	## 	cacertfile = "/etc/certs/cacert.pem"
	## }
	forwards = [
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

	subscription = [
		{
			remote_topic = "recv/topic1"
			local_topic = "topic3"
			qos = 1
		},
		{
			remote_topic = "recv/topic2"
			local_topic = "topic4"
			qos = 2
		}
	]
	max_parallel_processes = 2 
	max_send_queue_len = 1024
	max_recv_queue_len = 1024
}
```

:::

::: tab 经典 KV 配置格式

希望使用 KV 配置格式的用户，可参考以下格式，将配置写入 `nanomq_old.conf `文件，相关设置将在 NanoMQ 重启后生效。

完整的配置项列表，可参考[经典 KV 格式配置说明](../config-description/v013.md)

```bash
bridge.mqtt.emqx.bridge_mode=true
bridge.mqtt.emqx.address=mqtt-tcp://your_server_address:port
bridge.mqtt.emqx.proto_ver=4
bridge.mqtt.emqx.clientid=bridge_client
bridge.mqtt.emqx.clean_start=false
bridge.mqtt.emqx.forwards.1.remote_topic=fwd/topic1
bridge.mqtt.emqx.forwards.1.local_topic=topic1
bridge.mqtt.emqx.subscription.1.remote_topic=cmd/topic1
bridge.mqtt.emqx.subscription.1.local_topic=topic1
bridge.mqtt.emqx.subscription.1.qos=1
bridge.mqtt.emqx.parallel=2
bridge.mqtt.emqx.max_send_queue_len=32
bridge.mqtt.emqx.max_recv_queue_len=128
```

:::

::::


**重点配置项**：

- 远端 broker 地址：`bridges.mqtt.name.server`
- 转发远端 Topic 数组（支持 MQTT 通配符）： `bridges.mqtt.name.forwards`
- 订阅远端 Topic 数组（支持 MQTT 通配符）：  `bridges.mqtt.name.subscription`

具体配置参数请参考桥接 [Hocon 版本配置](../config-description/bridges.md) 或 [旧版本配置](../config-description/v013.md) (*不推荐*)

如使用 Hocon 版本配置项且 NanoMQ 版本在 0.19 及以上，除将相关配置直接写入  `nanomq.conf ` 中外，您也可单独为桥接定义一份配置文件，如 `nanomq_bridge.conf` ，然后通过 HOCON 的 `include` 语法在 `nanomq.conf` 中引用此文件：

示例：

```shell
include "path/to/nanomq_bridge.conf" 
```

如需查看运行过程中更多日志数据，可以在配置文件中设置日志等级 `log.level`

:::: tabs type:card

::: tab 通过 URL 前缀选择桥接传输层

NanoMQ 已经解耦了协议和传输层设计。使用 `mqtt-tcp` 或 `mqtt-quic` 作为 URL 前缀，以表示使用 TCP 或 QUIC 作为 MQTT 的传输层。
支持以下传输层选择：
```
	mqtt-tcp://127.0.0.1:xxxx
	tls+mqtt-tcp://127.0.0.1:xxxx
	mqtt-quic://127.0.0.1:xxxx
```
:::

::: tab 动态主题映射

它允许您在转发/订阅本地和远程代理之间的消息时动态转换主题，例如剥离前缀、更改主题层次结构的部分内容或保留特定段。这在桥接设置中管理主题关系时特别有用，确保消息能够正确路由，而无需手动重新配置。通过设置 `remote_topic` 和 `local_topic` 双向主题映射功能主题重映射使用 MQTT 通配符（` ` 表示单级匹配，`#` 表示多级匹配）作为模式来匹配和操作来自远程代理的传入主题。这些通配符充当锚点，以确定在映射到原始主题时要保留、剥离或替换主题的哪些部分。

**` `**: 精确匹配主题层级中的一个级别（例如，一个单词或片段）。
**`#`**: 匹配零个或多个层级，但必须在主题过滤器的末尾（`#` 仅在主题末尾有效）.

以桥接中的下行订阅消息为例：
当来自远程Broker的主题的消息到达并与配置的 `remote_topic` 进行模式匹配时，NanoMQ 通过替换匹配的部分将其重新映射到 `local_topic`。如果远程主题为 `system/nanomq/start`，且配置使用通配符去掉 `system/nanomq`，增加前缀 `cmd/` 和后缀 `remote`，则本地主题变为 `cmd/start/remote`。在桥接部分的 HOCON 格式配置（通常为 `nanomq.conf`）中的示例配置如下：

```
bridges.mqtt.mybridge {
  ...
  subscription = [
    {
      remote_topic = "+/nanomq/#"  # Matches topics starting with any single level, followed by "/nanomq/", and any remaining 
      local_topic = "#"            # Remaps by preserving only the parts after the matched substring
	  prefix = "cmd"
	  suffix = "remote"
    }
  ]
}
```

后缀/前缀在通配符过滤后生效。
相同的语法也适用于转发，这有助于以灵活的方式管理桥接主题，以在边缘和云之间构建统一命名空间（UNS）。
:::

::: tab 透明桥接

通过设置 `transparent = true` 开启透明桥接功能。

```
bridges.mqtt.mybridge {
  ...
  transparent = true
}
```

透明桥接将会将所有本地客户端的订阅/取消订阅包传递到远程桥接目标。这提供了一种简单的方法，可以在开始服务之前不指定桥接主题的情况下使用桥接。

:::

::: tab 混合桥接

混合桥接允许用户在配置中设置远程桥接服务器列表。然后它将在每次重连时逐个尝试这一系列的桥接目标。

```
bridges.mqtt.mybridge {
  ...
  hybrid_bridging = true
  hybrid_servers = ["mqtt-quic://127.0.0.1:14567", "mqtt-tcp://127.0.0.1:1883", "tls+mqtt-tcp://127.0.0.1:1883", "mqtt-tcp://127.0.0.1:1884"]
}
```
通过将不同传输方式的目标URL候选项混合桥接，实现当 QUIC 连接不被运营商接受时自动从QUIC到TCP/TLS的回退也是可行的。
:::

::: tab 网络接口绑定

在企业级应用中，通常会将流量分配到不同的网络接口。通过在 `nanomq.conf` 中设置 `bind_interface`，用户可以指定桥接流量的去向，并轻松管理带宽。

```
bridges.mqtt.mybridge {
  ...
	tcp {
	# # allows fine tuning of TCP options.
	# Interface binding: only send packet to specific interface
	 	bind_interface = wlan0

	# # nodelay: equals to `nodelay` from POSIX standard
	#	     but also serves as the switch of a fail interface binding action
	#	     `true` keeps retrying. `false` ignore fales, skip this time.
		nodelay = false
	}
}
```

`no_delay` 选项定义了绑定失败的行为。如果有严格的接口绑定规则，请记得将其设置为 `true`，以避免自动回退到系统的默认路由。
:::

::: tab 上行消息缓存

在实际生产场景中，网络条件差是常见的，这会导致消息重传和流量拥堵，最终导致消息丢失和断连。调整桥接缓存配置可以让用户从不同角度控制桥接通道的行为，例如缓存限制和中止超时。

```
bridges.mqtt.emqx1 {
  ......
  keepalive = 30s           # 连接的超时断开时间。
  max_send_queue_len = 512  # 设置飞行窗口大小，直接影响网络阻塞时的缓存消息数量，使用TCP 桥接时对QoS 0/1/2 均生效。
  resend_interval = 5000    # 重发间隔（毫秒），如果没有其他操作阻塞，它将在每5秒重试一次QoS。重试时间应至少为保活的1/2或1/4。
  resend_wait = 3000  # resend_wait 是发布后重新发送消息的等待时间。如果您不希望出现重复的 QoS 消息，请将其设置得比 keepalive 时间更长。
  cancel_timeout  = 10000 	# 在取消确认操作之前设置一个最大超时时间。基本上，这也是你为每个QoS消息留出的时间窗口。(cancel_timeout - resend_wait) / resend_wait > 1：至少重试一次。
}
```
有关更详细的配置，请参阅 `config-description` 部分。
:::

::::

## 启动 NanoMQ 

启动 NanoMQ 时使用`--conf` 指定配置文件路径（若配置文件已放置于系统路径 `/etc/nanomq.conf` 则无需在命令行指定）

:::: tabs type:card

::: tab Hocon 配置格式

```bash
$ nanomq start --conf nanomq.conf
```

:::

::: tab KV 配置格式

```bash
$ nanomq start --old_conf nanomq.conf
```

:::

::::

## 测试桥接

本节将通过 [MQTTX 客户端工具](https://mqttx.app/)来测试新建的 MQTT 数据桥接，我们将新建 2 个连接，分别连接到 NanoMQ 和 MQTT 数据桥接，用于验证 NanoMQ 和数据桥接的消息收发服务。

**连接到 NanoMQ**

![Connect to NanoMQ](./assets/connect-nanomq.png)

**连接到数据桥接**

![Connect to Public Broker](./assets/connect-public-broker.png)

**验证 NanoMQ 到数据桥接的消息服务**

在连接数据桥接的客户端 `MQTTbridge` 中，订阅 `forward1/#` 主题。

在连接 NanoMQ 的客户端 `NanoMQTest` 中，向 `forward1/#` 主题发送消息 ，如 `Hello from NanoMQ` 。

可以看到，消息被成功转发到 MQTT 数据桥接。

<img src="./assets/hellofromnano.png" alt="message from nanomq" style="zoom:50%;" />

**验证数据桥接到  NanoMQ 的消息服务**

在连接 NanoMQ 的客户端 `NanoMQTest` 中，订阅 `recv/topic1` 主题。

在连接数据桥接的客户端 `MQTTbridge` 中，向 `recv/topic1` 主题发布信息，例如：`Hello from broker.emqx.io`。

验证是否收到了从 broker.emqx.io 发布的消息。

![message from broker](./assets/hellofrombroker.png)



