# MQTT over QUIC Bridge

NanoMQ has supported MQTT over QUIC bridging, users can use QUIC as the transport layer of the MQTT protocol to establish a bridge with the EMQX 5.0 message service for data synchronization. This provides a shortcut for end-user devices that cannot integrate or find a suitable MQTT over QUIC SDK, as well as embedded devices that are difficult to modify the firmware, to take advantage of the advantages of the QUIC protocol in IoT scenarios.With the cloud-edge integrated message architecture of EMQX+NanoMQ, users can complete the data collection and synchronization needs across spatiotemporal regions in general IoT scenarios quickly with low costs.

Features：

- Multiple stream
- Hybird bridging
- High priority for qos (1|2) message
- Initail RTT（Round Trip Time）estimate time
- *Reset congestion control after being idle*
- TLS verify peer

## Start MQTT over QUIC bridging

### Building

The QUIC modle of NanoMQ is disabled by default, enable it with cmake option `-DNNG_ENABLE_QUIC=ON`.

```bash
$ git clone https://github.com/emqx/nanomq.git
$ cd nanomq 
$ git submodule update --init --recursive
$ mkdir build && cd build
$ cmake -G Ninja -DNNG_ENABLE_QUIC=ON ..
$ sudo ninja install
```



### QUIC Bridging Configuration

After building nanomq, it's necessary to enable and configurate MQTT over Quic bridging. Set url prefix as `mqtt-quic` means use QUIC transport layer.

For specific configuration parameters, please refer to [Hocon version](../config-description/v014.md) or [Old version](../config-description/v013.md)(*Deprecated*), the following configuration example is in Hocon format.

Key configuration parameters:

- Remote broker address: `bridges.mqtt.name.connector.server`
- Forward topic array(Support MQTT Wildcard):  `bridges.mqtt.name.forwards`
- Subscribe topic array(Support MQTT Wildcard):   `bridges.mqtt.name.subscription`

For QUIC:

- Hybrid bridge mode：`bridges.mqtt.name.hybrid_bridging`
- Multiple stream mode: `bridges.mqtt.name.multi_stream`

The bridge configuration part of `nanomq.conf`:

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

It's  available to print more log  by setting `log.level` in the configuration file if needed.

### Running

Start NanoMQ：

Hocon format:

```bash
$ nanomq start --conf nanomq.conf
```

Old version format (*Deprecated*):

```bash
$ nanomq start --old_conf nanomq.conf
```



### Test bridging

To verify that bridging has succeeded, simply send data to the bridging's upstream and downstream topics, or use quic client included in nanomq_cli to verify communication with EMQX 5.0.

#### Forwarding messge 

1. Subscribe topic from EMQX broker:

   Subscribe forward topic `forward1/#` from EMQX, then will be received the messages from `NanoMQ`;

   Subscribe in the 1st terminal:

   ```bash
   ## -h {remote host} 
   ## -p {remote port}
   ## --quic {enable quic}
   ## -u {username} 
   ## -P {password}
   $ nanomq_cli sub --quic -h "iot-platform.cloud" -p 14567 -t  "forward1/#" -u emqx -P emqx123
   forward1/msg: forward_msg
   ```

2. Publish message to the topic of local nanomq broker: 

   Publish message to NanoMQ broker with topic `forward1/msg` :

   Publish in the 2nd terminal: 

   ```bash
   $ nanomq_cli pub -t  "forward1/msg"  -m "forward_msg"
   ```

#### Subscribing message

1. Subscribe local topic from NanoMQ broker:

   Subscribe topic `cmd/topic1` from NanoMQ, then it will be received message from EMQX.

   Subscribe in the 3rd terminal: 

   ```bash
   $ nanomq_cli sub -t "recv/topic1"
   recv/topic1: cmd_msg
   ```

2. Publish message to remote EMQX broker with topic `cmd/topic1`:

   Publish in the 4th terminal:

   ```bash
   $ nanomq_cli pub --quic -h "iot-platform.cloud" -p 14567 -t  "recv/topic1" -m "cmd_msg" -u emqx -P emqx123
   ```

   



