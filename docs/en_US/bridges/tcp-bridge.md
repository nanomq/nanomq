# MQTT over TCP Bridge

MQTT over TCP Bridging serves as a reliable communication strategy, leveraging the trustworthiness of the Transmission Control Protocol (TCP) to ensure the accuracy and integrity of MQTT messages during cross-network or cross-proxy communications. With the flexibility to adapt to various network environments and application scenarios, it plays a pivotal role in facilitating communication between Internet of Things (IoT) devices. 

NanoMQ now supports MQTT over TCP bridging, enabling connections to the [EMQX Enterprise MQTT IoT Access Platform](https://www.emqx.com/products/emqx).

## Configure MQTT over TCP Bridge

NanoMQ comes with built-in support for MQTT over TCP bridging. Thus, after [installing NanoMQ](../installation/introduction.md) through any given method, you can immediately configure and enable MQTT over TCP bridging via the configuration file.

This section utilizes EMQ's [free public bridge broker.emqx.io:1883](https://www.emqx.com/en/mqtt/public-mqtt5-broker) to establish MQTT over TCP data bridging. Insert the following content (in HOCON format) into the configuration file:

:::: tabs type:card

::: tab HOCON

Users wishing to use the HOCON configuration format can refer to the following structure and write their configurations into the `nanomq.conf` file. The relevant settings will take effect after NanoMQ is restarted.

- For a complete list of configuration options, refer to [Configuration Description](../config-description/bridges.md)
- For users of NanoMQ versions 0.14 ~ 0.18, please refer to [Configuration Description - v0.14](../config-description/v014.md)

```bash
bridges.mqtt.name {
	## TCP URL format:  mqtt-tcp://host:port
	## TLS URL format:  tls+mqtt-tcp://host:port
	## QUIC URL format: mqtt-quic://host:port
	server = "mqtt-tcp://broker.emqx.io:1883"
	## MQTT protocol version（4 ｜ 5）
	proto_ver = 4
	# username = admin
	# password = public
	clean_start = true
	keepalive = 60s
	## Uncomment if you need TLS
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
			remote_topic = "cmd/topic3"
			local_topic = "topic3"
			qos = 1
		},
		{
			remote_topic = "cmd/topic4"
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

::: tab KV format

Users wishing to use the KV configuration format can refer to the following structure and write their configurations into the `nanomq_old.conf` file. The relevant settings will take effect after NanoMQ is restarted.

- For a complete list of configuration options, refer to [Configuration Description - v013](../config-description/v013.md)

```bash
bridge.mqtt.emqx.bridge_mode=true
bridge.mqtt.emqx.address=mqtt-tcp://your_server_address:port
bridge.mqtt.emqx.proto_ver=4
bridge.mqtt.emqx.clientid=bridge_client
bridge.mqtt.emqx.clean_start=false
bridge.mqtt.emqx.parallel=2
bridge.mqtt.emqx.forwards.1.remote_topic=fwd/topic1
bridge.mqtt.emqx.forwards.1.local_topic=topic1
bridge.mqtt.emqx.subscription.1.remote_topic=cmd/topic1
bridge.mqtt.emqx.subscription.1.local_topic=topic1
bridge.mqtt.emqx.max_send_queue_len=32
bridge.mqtt.emqx.max_recv_queue_len=128
```

:::

::::

:::: tabs type:card

::: tab Pick transport with URL settings

NanoMQ has a decoupled protocol & transport layering design.
Using `mqtt-tcp` or `mqtt-quic` as the URL prefix to signify the use of TCP or QUIC as the transport layer for MQTT.
All supported URL prefixes are as follows
```
	mqtt-tcp://127.0.0.1:xxxx
	tls+mqtt-tcp://127.0.0.1:xxxx
	mqtt-quic://127.0.0.1:xxxx
```
:::

::: tab Topic Mapping/Remapping

It allows you to dynamically transform topics when forwarding/subscribing messages between local and remote brokers, such as stripping prefixes, replacing parts of the topic hierarchy, or preserving specific segments. This is particularly useful for managing topic relationships in bridged setups, ensuring messages are routed correctly without manual reconfiguration.
By setting `remote_topic` & `local_topic`  bidirectional Topic mapping feature 

Topic remapping uses MQTT wildcards (`+` for single-level matching and `#` for multi-level matching) as patterns to match and manipulate incoming topics from a remote broker. These wildcards act as anchors to identify which parts of the topic to keep, strip, or replace when mapping to original topic.

**`+`**: Matches exactly one level in the topic hierarchy (e.g., a single word or segment).
**`#`**: Matches zero or more levels but must be at the end of the topic filter.(only valid at the end of topic)

Take a subscription as an example:
When a message arrives from a remote topic that matches the configured `remote_topic` pattern, NanoMQ remaps it to the `local_topic` by substituting the matched parts.
If the remote topic is `system/nanomq/start` and the configuration uses wildcards to strip `system/nanomq`, adding prefix `cmd/` and suffix `remote`, the local topic becomes `cmd/start/remote`. Example config in HOCON-format config (typically `nanomq.conf`) under the bridges section is:
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

Suffix/Preffix takes effect after wildcard filtering.
The same syntax applies to forwarding as well, which helps manage bridging topics in a flexible way to build an UNS (Unified Namespace) across edge and cloud.
:::

::: tab Transparent bridging

Enable transparent bridging by setting `transparent = true` in config

```
bridges.mqtt.mybridge {
  ...
  transparent = true
}
```

The transparent bridging will convey all subscribe/unsubscribe packets from all local clients to the remote bridging target. This provides a simple way to use bridging without specifying the bridging topic before starting service.
:::

::: tab Hybrid bridging

Hybrid bridging allows users to set a list of remote bridging servers in the config. Then it will try the series of bridging targets one by one each time of reconnects.

```
bridges.mqtt.mybridge {
  ...
  hybrid_bridging = true
  hybrid_servers = ["mqtt-quic://127.0.0.1:14567", "mqtt-tcp://127.0.0.1:1883", "tls+mqtt-tcp://127.0.0.1:1883", "mqtt-tcp://127.0.0.1:1884"]
}
```
By mixing bridging target URL candidates with different transports, the auto fallback from QUIC to TCP/TLS is also feasible.

:::

::: tab Interface binding

At enterprise level application, it is common to assign traffic to different networking interfaces. By setting `bind_interface` in `nanomq.conf`, users could specify where the bridging traffic goes and manage bandwidth easily.

```
bridges.mqtt.mybridge {
  ...
	tcp {
	# # allows fine tuning of TCP options.
	# Interface binding: only send packet to specific interface
	 	bind_interface = wlan0

	# # nodelay: equals to `nodelay` from POSIX standard
	#	     but also serves as the switch of a fail interface binding action
	#	     `true` keeps retrying. `false` ignores failed binding, skip this time.
		nodelay = false
	}
}
```

The `no_delay` option defines the behaviour of binding failure. Remember to set to `true` if there is strict rules on interface binding, so that it will not fall back to the default routes of the system.
:::

::: tab Upwards bridging message cache

Poor networking conditions are common in real production scenarios, which cause message retransmision and traffic congestion, eventually leading to message loss and disconnection. Tuning of bridging cache config allows the user to control the behaviour of the bridging channel in different perspectives, such as caching limits and abort timeout.

```
bridges.mqtt.emqx1 {
  ......
  keepalive = 30s           # Taking 30s keepalive as context
  max_send_queue_len = 512  # Give inflight window enough space for caching msg
  resend_interval = 5000    # Resend interval (ms), it will retry QoS every 5s 
                            # if there is no other action blocking.
                            # retry time shall be at least 1/2 or 1/4 of keepalive
  resend_wait = 3000  # resend_wait is the waiting time for resending the messages
                      # after it is publiushed. Please set it longer than 
                      # keepalive if you don't want duplicated QoS msg.
  cancel_timeout  = 10000 	# set a max timeout time before canceling the ack   
                            # action. Basically, this is also the time window you # spare to each QoS msg. 
                            # (cancel_timeout - resend_wait) / resend_wait > 1 : retry at least once.
}
```

For more detailed config, please refer to `config-description` section.
:::

::::

**Key Configuration Items**

- Remote broker address: `bridges.mqtt.name.server`
- Array of remote topics to forward (supporting MQTT wildcard): `bridges.mqtt.name.forwards`
- Array of remote topics to subscribe to (supporting MQTT wildcard): `bridges.mqtt.name.subscription`

If using Hocon version configuration items and NanoMQ version >= 0.19, you can either directly write the related configurations into `nanomq.conf`, or create a separate configuration file for bridging, such as `nanomq_bridge.conf`, and use HOCON's `include` syntax to reference this file in `nanomq.conf`:

Example:

```bash
include "path/to/nanomq_bridge.conf" 
```

To view more log data during runtime, you can set the log level `log.level` in the configuration file.

## Start NanoMQ

When launching NanoMQ, use the `--conf` command line option to specify the path to the configuration file (If the configuration file is already located in the system path `/etc/nanomq.conf`, there's no need to specify it in the command line).

:::: tabs type:card

::: tab Hocon Configuration Format

```bash
$ nanomq start --conf nanomq.conf
```

:::

::: tab Old Configuration Format

```bash
$ nanomq start --old_conf nanomq.conf
```

:::

::::

::: tip

If you enabled SQLite feature, NanoMQ will automatically flush cached messages into disk when network is disconnected. NanoMQ will resend cached messages once bridging connection is restored. But each cached message will be resent in a certain interval to avoid bandwidth exhaustion.

:::

## Test the Bridge

This section will guide you in testing the newly established MQTT data bridge using the [MQTTX Client Tool](https://mqttx.app/). We will create two connections, one to NanoMQ and the other to the MQTT data bridge, to verify the message sending and receiving services of both NanoMQ and the data bridge.

**Client connecting NanoMQ**

![Connect to NanoMQ](./assets/connect-nanomq.png)

**Client connecting MQTT bridge**

![Connect to Public Broker](./assets/connect-public-broker.png)

**Verify messages are forwarded from NanoMQ to MQTT bridge**

On your client connecting the MQTT bridge, `MQTTbridge` in this example, subscribe to the `fwd/#` topic.

On your client connecting NanoMQ, `NanoMQTest` in this example, publish a message to the `topic1` topic, for example, `Hello from NanoMQ`

Verify that you received the message that was published from the local broker.

<img src="./assets/hellofromnano.png" alt="message from nanomq" style="zoom:50%;" />

**Verify subscribed messages are received by NanoMQ from MQTT bridge**

On your client connecting NanoMQ, `NanoMQTest` in this example, subscribe to the `topic3` topic.

On your client connecting the MQTT bridge, `MQTTbridge` in this example, publish a message to the `cmd/topic3` topic, for example, `Hello from broker.emqx.io`

Verify that you received the message that was published from broker.emqx.io.

![message from broker](./assets/hellofrombroker.png)

If you're interested in evaluating the performance of MQTT over QUIC bridging, you can conduct a benchmark test. Please refer to the guide available at [Toolkit - Bench](../toolkit/bench.md) for detailed instructions.
