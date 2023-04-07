# MQTT over TCP Bridge

Bridging is a way to connect multiple MQTT broker. Unlike swarms, topic trees and routing tables are not replicated between nodes operating in bridge mode.

- Forward the message to the bridge node according to the rules;
- Subscribe to the topic from the bridge node, and forward the message in this node/group after collecting the message.

## Configuring

For specific configuration parameters, please refer to [configuration](../config-description/v014.md) the following configuration example is in Hocon format.

Key configuration parameters:

- Enable bridge mode: `bridges.mqtt.nodes[].enable`

- Remote broker address: `bridges.mqtt.nodes[].connector.server`
- Forward topic array:  `bridges.mqtt.nodes[].forwards`
- Subscribe topic arrary:   `bridges.mqtt.nodes[].subscription`

The bridge configuration part of `nanomq.conf`:


```bash
bridges.mqtt {
	nodes = [ 
		{
			## Bridging Node Name
			name = emqx
			## Enable bridging
			enable = true
			connector {
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
				ssl {
					enable = false
					keyfile = "/etc/certs/key.pem"
					certfile = "/etc/certs/cert.pem"
					cacertfile = "/etc/certs/cacert.pem"
				}
			}
			forwards = ["forward1/#","forward2/#"]
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
			congestion_control = cubic
			parallel = 2
			max_send_queue_len = 1024
			max_recv_queue_len = 1024
		}
	]
}
```

It's  available to print more log  by setting `log.level` in the configuration file if needed.

## Running

Start NanoMQ with `--conf` to specify the configuration file path (if the configuration file is placed in the system path `/etc/nanomq.conf`, no need to specify on the command line)


```bash
$ nanomq start --conf nanomq.conf
```

## Test bridging

To verify that bridging has succeeded, simply send data to the bridging's upstream and downstream topics, or use mqtt client included in nanomq_cli to verify communication with EMQX 5.0.

### Forwarding messge 


1.Subscribe topic from EMQX broker：

  Subscribe forward topic `forward1/#` from EMQX, then will be received the messages from `NanoMQ`;

   Subscribe in the 1st terminal:

   ```bash
   $ nanomq_cli sub --url "mqtt-tcp://broker.emqx.io:1883" -t  "forward1/#"
   forward1/msg: forward_msg
   ```

2. Publish message to the topic of local nanomq broker: 

   Publish message to NanoMQ broker with topic `forward1/msg` :

   Publish in the 2nd terminal: 

   ```bash
   $ nanomq_cli pub -t  "forward1/msg"  -m "forward_msg"
   ```

### Subscribing message

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
   $ nanomq_cli pub --url "mqtt-tcp://broker.emqx.io:1883" -t  "recv/topic1" -m "cmd_msg"
   ```

   





