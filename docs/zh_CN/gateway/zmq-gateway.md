# ZMQ 网关

**ZeroMQ**（也写作 **ØMQ**，**0MQ **或 **ZMQ **)是一个为可伸缩的分布式或并发应用程序设计的高性能异步消息库，是一种高性能、低延迟的消息传递机制。与面向消息的中间件不同，ZeroMQ 的运行不需要专门的消息代理。

NanoMQ 通过 ZMQ 网关实现了对 ZeroMQ 消息队列的数据传输与路由。

启用 

## 启用 ZMQ 网关

如希望启用 ZMQ 网关，请通过[编译方式安装 NanoMQ](../installation/build-options.md)，并通过 `-DBUILD_ZMQ_GATEWAY=ON` 选项启用 ZMQ 网关编译，示例代码如下：

```bash
cmake -G Ninja -DBUILD_ZMQ_GATEWAY=ON ..
ninja
```
编译完成后，可进入 build -> nanomq_cli 文件夹，执行命令 `nanomq_cli` 确认 ZMQ 网关是否正确安装：
```bash
$ ./nanomq_cli
nanomq_cli { pub | sub | conn | nngproxy | nngcat | zmq_gateway } [--help]

available tools:
   * pub
   * sub
   * conn
   * nngproxy
   * nngcat
   * zmq_gateway

Copyright 2022 EMQ Edge Computing Team
```
运行命令 `./nanomq_cli zmq_gateway --help` 可看到以下输出：

```
Usage: nanomq_cli zmq_gateway [--conf <path>]

  --conf <path>  The path of a specified nanomq configuration file 
```

即我们需要首先为该网关指定相关配置文件。

## 配置 ZMQ 网关

通过 `etc/nanomq_zmq_gateway.conf` 配置文件来设置桥接的主题和请求服务地址。

例如，我们可以通过如下配置文件构建一个连接本地 ZeroMQ 服务端和远端 MQTT broker （[broker.emqx.io:1883](https://www.emqx.com/zh/mqtt/public-mqtt5-broker)）的强大网关，实现对  `sub` 和 `pub` 主题下跨协议和跨网络的消息传递：

```bash
##====================================================================
## Configuration for MQTT ZeroMQ Gateway
##====================================================================

gateway.mqtt {
    ## MQTT Broker address: host:port .
    ##
    ## Value: String
    ## Example: mqtt-tcp://127.0.0.1:1883
    address="mqtt-tcp://broker.emqx.io:1883"
    ## Need to subscribe to remote broker topics
    ##
    ## Value: String
    sub_topic="topic/sub"
    ## Protocol version of the mqtt client.
    ##
    ## Value: Enum
    ## - 5: mqttv5
    ## - 4: mqttv4
    ## - 3: mqttv3
    proto_ver=4
    ## Ping interval of a down mqtt client.
    ##
    ## Value: Duration
    ## Default: 10 seconds
    keepalive=60
    ## The Clean start flag of mqtt client.
    ##
    ## Value: boolean
    ## Default: true
    ##
    ## NOTE: Some IoT platforms require clean_start
    ##       must be set to 'true'
    clean_start=true
    ## The username for mqtt client.
    ##
    ## Value: String
    username="username"
    ## The password for mqtt client.
    ##
    ## Value: String
    password="passwd"
    ## Topics that need to be forward to IoTHUB
    ##
    ## Value: String
    ## Example: topic1/pub
    forward="topic/pub"
    ## parallel
    ## Handle a specified maximum number of outstanding requests
    ##
    ## Value: 1-infinity
    parallel=2
}
gateway.zmq {
    ## ZeroMQ Subscribe address: host:port .
    ##
    ## Value: String
    ## Example: tcp://127.0.0.1:5560
    sub_address="tcp://127.0.0.1:5560"
    ## ZeroMQ Publish address: host:port .
    ##
    ## Value: String
    ## Example: tcp://127.0.0.1:5559
    pub_address="tcp://127.0.0.1:5559"
    ## ZeroMQ subscription prefix
    ##
    ## Value: String
    ## Example: sub_prefix
    sub_pre="sub_prefix"
    ## ZeroMQ publish prefix
    ##
    ## Value: String
    ## Example: pub_prefix
    pub_pre="pub_prefix"
}
```
配置文集的[详细描述](../config-description/v019.md)。

## 测试 ZMQ 网关

配置完成后，您可通过如下命令启动 NanoMQ Broker、ZMQ 服务器 和 ZMQ 网关，实现 ZMQ 服务器和 MQTT Broker 之间的消息传递：

```bash
$ nanomq start
$ {your.zmq.server}
$ nanomq_cli zmq_gateway --conf path/to/nanomq_zmq_gateway.conf
```
