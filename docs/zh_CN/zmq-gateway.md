# ZMQ GATEWAY

## 编译
Gateway 默认情况是不编译的，可以通过 -DBUILD_ZMQ_GATEWAY=ON 选项设置使 gateway 编译。

```
cmake -G Ninja -DBUILD_ZMQ_GATEWAY=ON ..
ninja
```
现在执行命令 `nanomq` 可以看到以下输出:
```
available applications:
   * broker
   * pub
   * sub
   * conn
   * nngproxy
   * nngcat
   * gateway

NanoMQ  Edge Computing Kit & Messaging bus v0.6.8-3
Copyright 2022 EMQ X Edge Team
```
以上输出显示 gateway 目前已经可用。 

## 运行
运行命令 `nanomq gateway` 或者 `nanomq gateway --help` 可看到一下输出:
```
Usage: nanomq_cli gateway [--conf <path>]

  --conf <path>  The path of a specified nanomq configuration file 
```
输出显示运行 gateway 需要指定配置文件

### 配置文件
下面是配置文件模版
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
配置文集的[详细描述](./config-description/v014.md).

启动 broker 和 zmq 的服务器, 启动 gateway: 
```
$ nanomq start
$ your zmq server
$ nanomq_cli gateway --conf path/to/nanomq_gateway.conf
```
现在 gateway 将会在 zmq 服务器和 mqtt broker 之间做数据交换。

