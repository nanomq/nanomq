# MQTT Data Bridges

Bridging is a way to connect multiple MQTT brokers. Unlike swarms, topic trees, and routing tables are not replicated between nodes operating in bridge mode.

- Forward the message to the bridge node according to the rules;
- Subscribe to the topic from the bridge node, and forward the message to this node/group after collecting the message.

This section introduces MQTT over TCP bridge, MQTT over QUIC bridge, and AWS IoT Core Bridge. 

## Adavanced bridging features
NanoMQ's bridging function is designed to provide an edge-cloud databus that can act as a local data proxy gateway to complete seamless data synchronization. Based on long-term feedback from open-source and commercial users, NanoMQ’s advanced data-bridging capabilities have the following:

### Transparent bridging

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
In NanoMQ, transparent bridging refers to the feature where subscription topics from local MQTT clients (connected to the NanoMQ edge broker) are awared by bridging module and automatically synchronized with a remote MQTT broker (forwarding Subscribe/Unsubscribe packets to remote broker). This ensures that the remote broker is aware of the topics that local clients are subscribed to, enabling seamless message forwarding from the remote broker to the edge clients without manual topic configuration, therefore make it easier to manage distributed topics across dispersed instances of NanoMQ.

### Uplink QoS overwrite

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

By adding the "QoS" parameter to the forward node in the configuration, you can specify the QoS level of the uploaded Publish message. Matching this rule will overwrite the QoS of the original message.

### Topic overwrite & Suffix/Prefix

To define edge topics more flexibly and establish a cloud-edge integrated unified data space (UNS), NanoMQ provides bridging topic overwritten and prefix/suffix functions. Users can add prefix/suffix information to multiple nodes of Forward and Subscription to modify the bridging topics of uplink and downlink messages, which facilitates topic management under complex network topologies and avoids topic conflicts between different edge devices.

Taking Forward node as an example：

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

Each forwarding node that matches will be executed individually. For example, there is a local message sent to topic: "topic1", this message matches two upstream bridging rules at the same time.
The first rule will firstly overwrite the original topic according to the configured remote_topic, and then add the prefix and suffix as well, so the remote bridge target will receive the message in the topic: "emqx/fwd/topic1/forward/rule1". 
In the second rule, because remote_topic is left blank, the original topic is retained and the prefix and suffix are added, so the remote bridge target will receive the message in the topic: "nanomq/topic1/forward/rule2".

For downstream subscription messages, the prefix, prefix, and topic override functions take effect after the message is received. The local client will receive the message with the prefix and suffix modified and the topic overwritten.
However, due to the limitations of the MQTT protocol, if you subscribe to multiple repeating topics or overlapping topics (wildcards), the message's prefix and topic override will only take effect on the first rule.

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

For example, according to the configuration method above, after receiving a message from the "cmd/topic1" topic of the remote bridge target, the first rule will always be hit, and will deliver msg to "emqx/topic3/sub/rule1" twice. 
The second rule will fail to hit because each message is independent and we cannot match the bridge subscription rule based on the content of the Publish message.
Please try not to configure overlapping bridge subscription topics. 

## [MQTT over TCP Bridging](./tcp-bridge.md)

This section provides an in-depth guide to configuring MQTT over TCP bridging, explaining the primary configuration parameters and demonstrating a typical `nanomq.conf` file setup. It also introduces how to run NanoMQ with a specified configuration file and test bridging to ensure its successful implementation.

## [MQTT over QUIC Bridging](./quic-bridge.md)

In cases where integration with MQTT over TCP bridging is hard to implement, NanoMQ has innovatively introduced a new protocol, MQTT over QUIC. QUIC, initially developed by Google, was later adopted as a worldwide standard by the Internet Engineering Task Force (IETF). With MQTT over QUIC bridging, you can take full advantage of the QUIC protocol's benefits in IoT scenarios. 

### QUIC QoS Priority

When using QUIC bridging, you can enable the priority of QoS 1/2 messages relative to QoS 0 messages through the following configuration.

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
Based on the characteristics of QUIC, NanoMQ implements priority transmission of QoS messages under network congestion. When the buffer queue is congested due to weak network or limited bandwidth, QoS 1/2 messages will be transmitted with higher priority. Help users save more valuable bandwidth for more important data.

### QUIC/TCP hybrid bridging

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
In order to allow users to use the MQTT over QUIC function with more easily, adaptive hybrid switching of QUIC/TCP bridging has been specially produced. When the QUIC connection fails, it will automatically switch back to traditional TCP bridging.


## [AWS IoT Core Bridging](./aws-iot-core-bridge.md)

[AWS IoT Core](https://docs.aws.amazon.com/zh_cn/iot/latest/developerguide/protocols.html) is one of the widely used public cloud IoT services in Europe and the United States.  However, because it is not fully aligned with the standard MQTT protocol and does not support QoS 2 messages, standard MQTT SDKs are not seamlessly compatible. AWS IoT Core bridging is now built into NanoMQ to help users address compatibility issues. AWS IoT Core Data Bridge is not compatible with other special/advanced bridging features and only provides a bidirectional data channel for standard MQTT.
