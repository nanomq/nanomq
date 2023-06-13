# ZMQ GATEWAY

## Compile
Gateway tool isn't built by default, you can enable it via -DBUILD_ZMQ_GATEWAY=ON.

```
cmake -G Ninja -DBUILD_ZMQ_GATEWAY=ON ..
ninja
```
Now we run command `nanomq` will get output below:
```
available applications:
   * broker
   * pub
   * sub
   * conn
   * nngproxy
   * nngcat
   * gateway

```
It's show that gateway is ok now. 

## Run
Run command `nanomq gateway` or `nanomq gateway --help` will get:
```
Usage: nanomq_cli gateway [--conf <path>]

  --conf <path>  The path of a specified nanomq configuration file 
```
The output indicate that gateway need a configure file.

### Confiure file
Here is a configure file template.
```
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
Configure file description can find [here](./config-description/v014.md).

Launch broker and zmq server, then launch nanomq gateway 
```
$ nanomq start
$ your zmq server
$ nanomq_cli gateway --conf path/to/nanomq_gateway.conf
```
Gateway will transfer data between zmq and mqtt broker.

