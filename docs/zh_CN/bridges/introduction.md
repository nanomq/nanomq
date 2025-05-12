# MQTT 数据桥接

桥接是一种连接多个 MQTT 消息中间件的策略，其特性与集群模式显著不同。在桥接模式下，节点之间不进行主题树或路由表的复制操作。桥接模式的核心职能包括：

- 根据预定的规则，将消息转发至指定的桥接节点；
- 对桥接节点上的特定主题进行订阅，并在接收到消息后在本地节点或集群内进行传递和转发。

作为一种高效的网络协议，桥接模式极大地提高了 MQTT 消息传递的灵活性和可扩展性，因此在物联网通信中扮发挥着重要的作用。NanoMQ 现支持创建 MQTT over TCP 桥接、 MQTT over QUIC 桥接和 AWS IoT Core 桥接，进一步增强了跨网络通信的便捷性和效率。

## [特殊桥接功能]
NanoMQ的桥接功能旨在提供云边数据总线，能够扮演本地数据代理网关角色来完成无缝数据同步。根据开源和商业用户的长期反馈，NanoMQ 的数据桥接功能具有以下

### [透明桥接]

```bash
bridges.mqtt.name {
......
	# # The transparent proxy flag of the bridging client
	# #
	# # Value: boolean
	# # Default: false
	# #
	# # NOTE: This option gonna proxy Sub/UnSub action
	# # of all local client to this bridging connection as well 
	transparent = true
}
```

在NanoMQ中，透明桥接指的是这样一个功能：本地（连接到NanoMQ的）MQTT客户端的订阅主题被桥接模块识别，并自动与远程 MQTT Broker 同步（将订阅/取消订阅数据包转发到远程 MQTT Broker）。这确保了远程 Broker 了解本地客户端所订阅的主题，从而实现从远程代理到边缘客户端的无缝消息转发，而无需手动配置主题，因此使得更容易管理分散的 NanoMQ实例之间的分布式主题。

### [上行 QoS 覆盖]
```bash
bridges.mqtt.name {
......
	forwards = [
		{
			remote_topic = "fwd/topic1"
			local_topic = "topic1"
			qos = 1
		}
	]
}
```
在 forward node 中增加 qos 配置来指定匹配到该条规则而上传的 Publish 消息的 QoS 等级， 会覆盖原有消息的 QoS。
### [桥接主题覆盖和动态匹配前后缀]

为了能够更灵活的定义边缘主题，建立云边一体化的统一数据空间（UNS），NanoMQ 提供了桥接主题覆盖和前后缀功能。用户可以在 Forward 和 Subscription 的多个 node 中增加前后缀信息来修改上下行消息的桥接主题，便于复杂网络拓扑下的主题管理，避免不同边缘设备之间的主题冲突。
以 Forward 为例：
```bash
bridges.mqtt.emqx {
......
	forwards = [
		{
			remote_topic = "fwd/topic1"
			local_topic = "topic1"
			qos = 2
      suffix = "/forward/rule1"
      prefix = "emqx/"
		}
		{
			remote_topic = ""
			local_topic = "#"
			qos = 2
      suffix = "/forward/rule2"
      prefix = "nanomq/"
		}
	]
}
```

每个 forwarding node 都会单独匹配并执行。例如，有一条本地的发到主题：“topic1” 的消息，由于该条消息同时匹配了两条上行桥接规则。
第一条规则会先根据配置的 remote_topic 覆盖掉原有主题，之后添加前后缀，所以远端桥接目标会在主题：“emqx/fwd/topic1/forward/rule1” 收到该条消息。 
第二条规则由于 remote_topic 留空，故保留原有主题并添加前后缀，所以远端桥接目标会在主题：“nanomq/topic1/forward/rule2” 收到该条消息。 

对于下行的订阅消息，前后缀和主题覆盖功能在收到消息后生效。本地客户端将收到经过前后缀修改和主题覆写后的消息。
但由于 MQTT 协议的局限性，若订阅可多个重复主题或重叠主题（通配符），消息的前后缀和主题覆写将只对第一个规则生效。

```bash
bridges.mqtt.name {
......
	subscription = [
		{
			remote_topic = "cmd/topic1"
			local_topic = "topic3"
			qos = 1
      suffix = "/sub/rule1"
      prefix = "emqx/"
		},
		{
			remote_topic = "cmd/#"
			local_topic = ""
			qos = 2
      suffix = "/forward/rule2"
      prefix = "nanomq/"
		}
	]
......
}
```

例如按上文的配置方式，收到来自远端的桥接目标的 “cmd/topic1” 主题的消息后，会总是命中第一条规则，将在本地的 “emqx/topic3/sub/rule1” 主题投递两次该条消息。而第二条规则将无法命中，因为每条消息都是各自独立的，且无法根据 Publish 消息的内容和桥接订阅规则相匹配。
所以请尽量不要配置互相重叠的桥接订阅主题。、

## [MQTT over TCP 桥接](./tcp-bridge.md)
本节将介绍 MQTT over TCP 数据桥接相关的配置参数，并将包含一个典型的 `nanomq.conf` 文件配置。本节还将介绍如何通过指定的配置文件运行 NanoMQ 以及如何对桥接进行测试。

## [MQTT over QUIC 桥接](./quic-bridge.md)
针对较难集成 MQTT over TCP 数据桥接的场景，NanoMQ 创新性地引入了 MQTT over QUIC 数据桥接。QUIC 最初由 Google 开发，后来被互联网工程任务组（IETF）采纳为全球标准。它是一种新的传输协议，提供更快的连接建立速度。通过 MQTT over QUIC 数据桥接，我们可以充分发挥 QUIC 协议在 IoT 场景中的优势。

### [QUIC QoS 优先传输]

当使用 QUIC 桥接时，可以通过如下配置开启 QoS 1/2 消息相对于 QoS 0 消息的优先。

```bash
bridges.mqtt.emqx {
......
	# # qos_priority: send QoS 1/2 msg in high priority
	# # QoS 0 messages remain the same
	# # Value: true/false
	# # Default: true
	quic_qos_priority = true
......
}
```
NanoMQ 根据 QUIC 的特性，实现了在网络拥塞状态下的 QoS 消息优先传输，当缓冲队列因为弱网或带宽有限而拥塞的话，QoS 1/2的消息将得到更优先的传输。帮助用户将更宝贵的带宽留给更重要的数据。

### [QUIC/TCP 混合桥接自适应切换]

```bash
bridges.mqtt.emqx {
......
	# # Hybrid bridging: enable or disable the hybrid bridging mode
	# # Value: True/False
	# # Default: False
	hybrid_bridging = true

	# # Hybrid servers
	# # When hybrid mode is enabled and the connection to server is
	# # disconnected. Bridge will switch to hybrid_servers in roundrobin.
	# # Value: Array
	# # Default: []
	hybrid_servers = ["mqtt-quic://127.1:14567", "mqtt-tcp://127.1:1883"]
......
}
```
为了让用户更放心的使用 MQTT over QUIC 功能，特地制作了 QUIC/TCP 桥接的自适应混合切换。当 QUIC 连接不成功的时候，支持自动切换回传统的 TCP 桥接。

## [AWS IoT Core 桥接](./aws-iot-core-bridge.md)

[AWS IoT Core](https://docs.aws.amazon.com/zh_cn/iot/latest/developerguide/protocols.html) 是在欧美广泛使用的公有云 IoT 服务之一。但由于其与标准 MQTT 协议多有不同，且不支持 QoS 2 消息，因此许多使用标准 MQTT SDK 的客户端设备无法无缝兼容。NanoMQ 现已内置 AWS IoT Core 桥接功能，帮助用户解决兼容性问题。
AWS IoT Core 数据桥接与其他特殊/高级桥接功能并不兼容，仅提供标准 MQTT 的双向数据通道。
