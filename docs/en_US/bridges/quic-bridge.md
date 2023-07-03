# MQTT over QUIC Bridge

NanoMQ has supported MQTT over QUIC bridging, users can use QUIC as the transport layer of the MQTT protocol to establish a bridge with the EMQX 5.0 message service for data synchronization. This provides a shortcut for end-user devices that cannot integrate or find a suitable MQTT over QUIC SDK, as well as embedded devices that are difficult to modify the firmware, to take advantage of the advantages of the QUIC protocol in IoT scenarios. 

With the cloud-edge integrated message architecture of EMQX+NanoMQ, users can complete the data collection and synchronization needs across spatiotemporal regions in general IoT scenarios quickly with low costs.

**Feature list：**

- Multiple streams
- Hybird bridging
- High priority for QoS (1|2) message
- Initail RTT（Round Trip Time）estimate time
- *Reset congestion control after being idle*
- TLS verify peer

## Enable MQTT over QUIC

By default, the QUIC module in NanoMQ is deactivated. If you wish to utilize MQTT over QUIC bridging, you need to install NanoMQ via [build options](../installation/build-options.md) and enable the QUIC module during the process.

```bash
$ git clone https://github.com/emqx/nanomq.git
$ cd nanomq 
$ git submodule update --init --recursive
$ mkdir build && cd build
$ cmake -G Ninja -DNNG_ENABLE_QUIC=ON ..
$ sudo ninja install
```

::: tip

For macOS users, you can complie with `make`:

```bash
$ git clone https://github.com/emqx/nanomq.git
$ cd nanomq 
$ git submodule update --init --recursive
$ mkdir build && cd build
$ cmake -DNNG_ENABLE_QUIC=ON ..
$ make
```

:::

### Configure MQTT over QUIC

### Prerequisites

Before setting up MQTT over QUIC bridging, you should install EMQX 5.0, which provides the MQTT over QUIC messaging services. For instructions on enabling QUIC bridging in EMQX, refer to the [EMQX - MQTT over QUIC tutorial](https://docs.emqx.com/zh/enterprise/v5.0/mqtt-over-quic/getting-started.html).

### Bridge Configuration

Once the QUIC module is enabled, you need to configure the MQTT over QUIC bridging feature and related topics in the `nanomq.conf` file. The following configuration file, for example, defines the server address for MQTT over QUIC bridging, connection credentials, connection parameters, message forwarding rules, subscription topics, and queue length.

```bash
bridges.mqtt.name {
	## TCP URL format:  mqtt-tcp://host:port
	## TLS URL format:  tls+mqtt-tcp://host:port
	## QUIC URL format: mqtt-quic://host:port
	server = "mqtt-quic://iot-platform.cloud:14567"
	proto_ver = 4
	username = emqx
	password = emqx123
	clean_start = true
	keepalive = 60s
	forwards = ["forward1/#","forward2/#"]
	quic_keepalive = 120s
	quic_idle_timeout = 120s
	quic_discon_timeout = 20s
	quic_handshake_timeout = 60s
	hybrid_bridging = false
	subscription = [
		{
			topic = "recv/topic1"
			qos = 1
		},
		{
			topic = "recv/topic2"
			qos = 2
		}
	]
	max_parallel_processes = 2 
	max_send_queue_len = 1024
	max_recv_queue_len = 1024
}
```

::: tip 

Using `mqtt-quic` as the URL prefix indicates the use of QUIC as the transport layer for MQTT.

:::

**Key Configuration Items**

- Remote broker address: `bridges.mqtt.name.server`
- Array of Topics to forward to remote (supports MQTT wildcard): bridges.mqtt.name.forwards`
- Array of Topics to subscribe from remote (supports MQTT wildcard): bridges.mqtt.name.subscription`

**QUIC-Specific Configurations**

- Switch for hybrid bridging mode: bridges.mqtt.name.hybrid_bridging`
- Switch for multi-stream bridging: `bridges.mqtt.name.multi_stream`

For detailed configuration parameters, please refer to [Hocon version configuration](../config-description/v014.md) or [Old version configuration](../config-description/v013.md) (*Not Recommended*).

If you choose to use Hocon version configuration items, apart from writing the related configurations directly into `nanomq.conf`, you can also define a separate configuration file for bridging, such as `nanomq_bridge.conf`. You can then include this file in `nanomq.conf` using HOCON's `include` syntax.

Example:

```shell
include "path/to/nanomq_bridge.conf" 
```

To get detailed log data during operation, you can set the log level `log.level` in the configuration file.

## Start NanoMQ

In the installation directory of NanoMQ, execute the following command to launch NanoMQ:

:::: tabs type:card

::: tab Hocon

```bash
$ nanomq start --conf nanomq.conf
```

:::

::: tab Old version

```bash
$ nanomq start --old_conf nanomq.conf
```

:::

::::

## Test the Bridge

This section uses NanoMQ's built-in client tool to test the newly built MQTT over QUIC bridge. Two connections will be created to connect to NanoMQ and the MQTT over QUIC data bridge respectively, to verify the messaging service.

### Test Message Forwarding

1. Subscribe to the message topic for the remote EMQX Broker:

   Subscribe to the forwarding topic "`forward1/#`" for **EMQX** to receive data forwarded by **NanoMQ**.

   Open a new command line window, navigate to the `nanomq_cli` folder under the `build` folder, and execute the following command to subscribe:

   ```bash
   ## -h {host} 
   ## -p {port number, if unspecified, will use 1883 for MQTT or 14567 for QUIC connection}
   ## -t {topic}
   ## --quic {enable quic}
   ## --q {message QoS, values: 0, 1, 2}
   ## --m {message payload}
   ## -u {username} 
   ## -P {password}
   $ ./nanomq_cli sub --quic -h "remote.broker.address" -t "forward1/#" -q 2
   ```

2. Open another command line window and publish a message to the **NanoMQ** Broker with the topic "`forward1/msg`":

   ```bash
   ./nanomq_cli pub -h "local.broker.address" -t "forward1/msg" -m "forward_msg" -q 2
   ```

3. Go back to the first command line window, you will see the message forwarded by the NanoMQ Broker, for example:

   ```bash
   quic_msg_recv_cb: forward1/#: forward_msg
   ```

### Test Message Receiving

1. Subscribe to the message topic for the local NanoMQ Broker:

   Subscribe to the topic `cmd/topic1` for **NanoMQ** to receive data published by **EMQX**:

   In the second command line window, navigate to the `nanomq_cli` folder under the `build` folder, and execute the following command to subscribe:

   ```bash
   ./nanomq_cli sub -h "local.broker.address" -t "recv/topic1" -q 2
   ```

2. In the first command line window, publish a message to the remote **EMQX** Broker with the topic "`cmd/topic1`":

   ```bash
   $ ./nanomq_cli pub --quic -h "remote.broker.address" -t "recv/topic1" -m "cmd_msg" -q 2 -u emqx -P emqx123
   ```

3. Go back to the second command line window, you will see the message sent by the remote **EMQX** Broker, for example:

   ```bash
   quic_msg_recv_cb: recv/topic1: cmd_msg
   ```

## QUIC Multi-Stream Bridging

One of the significant advantages of the QUIC protocol over TCP is that it solves the problem of head-of-line blocking. This advantage relies on the multi-stream feature of a single QUIC connection. To address situations like network congestion or network jitter, NanoMQ and EMQX 5.0 have jointly designed and introduced the Mutli-stream QUIC protocol standard for improved message transmission experience.

![NanoMQ multi-stream](./assets/multi-stream.png)

### Enable Multi-Stream Bridging

To use multi-stream bridging, you simply need to activate the corresponding configuration option:

:::: tabs type:card

::: tab Hocon

```bash
quic_multi_stream = false
quic_qos_priority=true
```

:::

::: tab old version

```bash
## multi-stream: enable or disable the multi-stream bridging mode
## Value: true/false
## Default: false
bridge.mqtt.emqx.quic_multi_stream=false

## Value: true/false
## Default: true
bridge.mqtt.emqx.quic_qos_priority=true
```

:::

::::

NanoMQ will then create topics for specific Pub/Sub topics. You can check the effectiveness of this function in the log, for example, when subscribing to the `nanomq/1` topic, a data stream will be automatically created:

```bash
quic_ack_cb: Quic bridge client subscribe to topic (QoS 1)nanomq/1.
mqtt_sub_stream: topic nanomq/1 qos 1
bridge client is connected!
quic_pipe_open: [strm][0x618000020080] Starting...
quic_pipe_open: [strm][0x618000020080] Done...
quic_strm_cb: quic_strm_cb triggered! 0
decode_pub_message: topic: [$SYS/brokers/connected], qos: 0
mqtt_sub_stream: create new pipe 0x61c000020080 for topic nanomq/1
quic_strm_cb: QUIC_STREAM_EVENT_START_COMPLETE [0x618000020080] ID: 4 Status: 0
```

Afterward, NanoMQ will automatically route the data packets to different streams based on the topic for transmission. Through internal testing conducted in a simulated weak network environment with 2s latency and 40% packet loss, a significant reduction in latency proportional to the number of streams was observed. 

