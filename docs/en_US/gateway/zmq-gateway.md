# ZMQ Gateway

[**ZeroMQ**](https://en.wikipedia.org/wiki/ZeroMQ) (also spelled **ØMQ**, **0MQ,** or **ZMQ**) is an asynchronous messaging library, aimed at use in distributed or concurrent applications. It provides a message queue, but unlike message-oriented middleware, a ZeroMQ system can run without a dedicated message broker; the zero in the name is for zero brokers.

NanoMQ supports data transmission and routing for ZeroMQ message queues through its ZMQ gateway.

## Enable ZMQ Gateway

You can enable the ZMQ gateway feature during the compilation process using the `-DBUILD_ZMQ_GATEWAY=ON` switch. For further details on the compilation, refer to [this guide on installing NanoMQ via compilation](../installation/build-options.md).

Example command:

```bash
cmake -G Ninja -DBUILD_ZMQ_GATEWAY=ON ..
ninja
```

After the compilation is complete, you can navigate to the build -> nanomq_cli directory, and execute the `nanomq` command to verify if the ZMQ gateway is correctly installed:

```bash
$ ./nanomq_cli nanomq
available applications:
   * broker
   * pub
   * sub
   * conn
   * nngproxy
   * nngcat
   * gateway
   
NanoMQ  Edge Computing Kit & Messaging bus v0.6.8-3
Copyright 2023 EMQX Edge Team
```
Then run the command `nanomq gateway` or `nanomq gateway --help` and you will get:

```
Usage: nanomq_cli gateway [--conf <path>]

  --conf <path>  The path of a specified nanomq configuration file 
```
The output indicates that you should first specify a configuration file for this gateway.

### Configure the ZMQ Gateway
The configuration file `etc/nanomq_zmq_gateway.conf` allows you to specify the topics and service addresses for bridging.

Suppose you aim to build a powerful gateway that connects a local NanoMQ Broker, ZeroMQ client, and a remote MQTT broker ([broker.emqx.io:1883](https://www.emqx.com/zh/mqtt/public-mqtt5-broker)). In this case, you can use the following configuration file to facilitate cross-protocol and cross-network message transmission under the `sub` and `pub` topics:

```bash
##====================================================================
## Configuration for MQTT ZeroMQ Gateway
##====================================================================

## MQTT Broker address: host:port .
##
## Value: String
## Example: mqtt-tcp://127.0.0.1:1883
gateway.mqtt.address=mqtt-tcp://broker.emqx.io:1883

## ZeroMQ Subscribe address: host:port .
##
## Value: String
## Example: tcp://127.0.0.1:5560
gateway.zmq.sub.address=tcp://127.0.0.1:5560

## ZeroMQ Publish address: host:port .
##
## Value: String
## Example: tcp://127.0.0.1:5559
gateway.zmq.pub.address=tcp://127.0.0.1:5559

## ZeroMQ subscription prefix
##
## Value: String
## Example: sub_prefix
## gateway.zmq.sub_pre=sub_prefix

## ZeroMQ publish prefix
##
## Value: String
## Example: pub_prefix
## gateway.zmq.sub_pre=pub_prefix

## Need to subscribe to remote broker topics
##
## Value: String
gateway.mqtt.subscription.topic=topic/sub

## Protocol version of the mqtt client.
##
## Value: Enum
## - 5: mqttv5
## - 4: mqttv4
## - 3: mqttv3
gateway.mqtt.proto_ver=4

## Ping interval of a down mqtt client.
##
## Value: Duration
## Default: 10 seconds
gateway.mqtt.keepalive=60

## The Clean start flag of mqtt client.
##
## Value: boolean
## Default: true
##
## NOTE: Some IoT platforms require clean_start
##       must be set to 'true'
gateway.mqtt.clean_start=true

## The username for mqtt client.
##
## Value: String
gateway.mqtt.username=username

## The password for mqtt client.
##
## Value: String
gateway.mqtt.password=passwd

## Topics that need to be forward to IoTHUB
##
## Value: String
## Example: topic1/pub
gateway.mqtt.forward=topic/pub

## Need to subscribe to remote broker topics
##
## Value: String
gateway.mqtt.subscription=topic/sub

## parallel
## Handle a specified maximum number of outstanding requests
##
## Value: 1-infinity
gateway.mqtt.parallel=2
```
Configure file description can find [here](../config-description/v019.md).

## Test ZMQ Gateway

After setting up the configuration, use the following commands to start the NanoMQ Broker, ZMQ server, and ZMQ gateway. This will enable the message transmission between the ZMQ server and the MQTT Broker:

```bash
$ nanomq start
$ {your.zmq.server}
$ nanomq_cli gateway --conf path/to/nanomq_gateway.conf
```



