# ZMQ 网关

**ZeroMQ**（也写作 **ØMQ**，**0MQ **或 **ZMQ **)是一个为可伸缩的分布式或并发应用程序设计的高性能异步消息库，是一种高性能、低延迟的消息传递机制。与面向消息的中间件不同，ZeroMQ 的运行不需要专门的消息代理。

NanoMQ 通过 ZMQ 网关实现了对 ZeroMQ 消息队列的数据传输与路由。

启用 

## 启用 ZMQ 网关

请通过 `-DBUILD_ZMQ_GATEWAY=ON` 选项启用 ZMQ 网关编译，参考[编译方式安装 NanoMQ](https://github.com/emqx/nanomq/installation/build-options.md)。

示例代码如下：

```bash
cmake -G Ninja -DBUILD_ZMQ_GATEWAY=ON ..
ninja
```
编译完成后，可进入 build -> nanomq_cli 文件夹，执行命令 `nanomq` 确认 ZMQ 网关是否正确安装：
```bash
$ ./nanomq_cli nanomq
available tools:
   * broker
   * pub
   * sub
   * conn
   * nngproxy
   * nngcat
   * gateway

NanoMQ  Edge Computing Kit & Messaging bus v0.6.8-3
Copyright 2022 EMQX Edge Team
```
运行命令 `nanomq gateway` 或者 `nanomq gateway --help` 可看到以下输出：

```
Usage: nanomq_cli gateway [--conf <path>]

  --conf <path>  The path of a specified nanomq configuration file 
```

即我们需要首先为该网关指定相关配置文件。

## 配置 ZMQ 网关

通过 `etc/nanomq_zmq_gateway.conf` 配置文件来设置桥接的主题和请求服务地址。

例如，我们可以通过如下配置文件构建一个连接本地 NanoMQ Broker、ZeroMQ 客户端和远端 MQTT broker （[broker.emqx.io:1883](https://www.emqx.com/zh/mqtt/public-mqtt5-broker)）的强大网关，实现对  `sub` 和 `pub` 主题下跨协议和跨网络的消息传递：

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
配置文集的[详细描述](../config-description/v019.md)。

更多关于 ZMQ 网关配置项的解释，可以参考[配置参数文件](../config-description/v014.md)。

## 测试 ZMQ 网关

配置完成后，您可通过如下命令启动 NanoMQ Broker、ZMQ 服务器 和 ZMQ 网关，实现 ZMQ 服务器和 MQTT Broker 之间的消息传递：

```bash
$ nanomq start
$ {your.zmq.server}
$ nanomq_cli gateway --conf path/to/nanomq_gateway.conf
```
