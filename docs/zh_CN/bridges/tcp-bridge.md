# MQTT over TCP 桥接

MQTT over TCP 桥接是一种使用传输控制协议（TCP）作为底层通信协议的 MQTT 桥接方式。这种桥接方式利用了 TCP 的可靠传输特性，确保了 MQTT 消息在跨网络或跨代理通信时的完整性和准确性。通过优化的配置和管理，MQTT over TCP 桥接可以灵活地应对各种网络环境和应用场景，是实现物联网（IoT）设备间通信的重要工具。NanoMQ 现已支持通过 MQTT over TCP 桥接连接至 [EMQX 企业级 MQTT 物联网接入平台](https://www.emqx.com/zh/products/emqx)。

## 配置 MQTT over TCP 桥接

NanoMQ 已内置对 MQTT over TCP 桥接的支持，因此当您通过各种方式[安装 NanoMQ](../installation/introduction.md) 后，即可直接通过配置文件配置并启用 MQTT over TCP 桥接。

这里将使用 EMQ 提供的[免费公共桥接 broker.emqx.io:1883](https://www.emqx.com/en/mqtt/public-mqtt5-broker) 来构建 MQTT over TCP 数据桥接。在配置文件 `etc/nanomq.conf` 中贴入如下内容（HOCON 格式）：

```bash
bridges.mqtt.name {
	## TCP URL 格式:  mqtt-tcp://host:port
	## TLS URL 格式:  tls+mqtt-tcp://host:port
	## QUIC URL 格式: mqtt-quic://host:port
	server = "mqtt-tcp://broker.emqx.io:1883"
	## MQTT 协议版本 （ 4 ｜ 5 ）
	proto_ver = 4
	# username = admin
	# password = public
	clean_start = true
	keepalive = 60s
	## 如果通过 TLS 桥接将下面的代码取消注释
	## ssl {
	## 	keyfile = "/etc/certs/key.pem"
	## 	certfile = "/etc/certs/cert.pem"
	## 	cacertfile = "/etc/certs/cacert.pem"
	## }
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
	max_parallel_processes = 2 
	max_send_queue_len = 1024
	max_recv_queue_len = 1024
}
```

::: tip 

使用 `mqtt-tcp` 作为 URL 前缀即是采用 TCP 作为 MQTT 的传输层。

:::

重点配置项：

- 远端 broker 地址：`bridges.mqtt.name.server`
- 转发远端 Topic 数组（支持 MQTT 通配符）： `bridges.mqtt.name.forwards`
- 订阅远端 Topic 数组（支持 MQTT 通配符）：  `bridges.mqtt.name.subscription`

具体配置参数请参考桥接 [Hocon 版本配置](../config-description/v018.md) 或 [旧版本配置](../config-description/v013.md) (*不推荐*)

如使用 Hocon 版本配置项，除将相关配置直接写入  `nanomq.conf ` 中外，您也可单独为桥接定义一份配置文件，如 `nanomq_bridge.conf` ，然后通过 HOCON 的 `include` 语法在 `nanomq.conf` 中引用此文件：

示例：

```shell
include "path/to/nanomq_bridge.conf" 
```

如需查看运行过程中更多日志数据，可以在配置文件中设置日志等级 `log.level`

## 启动 NanoMQ 

启动 NanoMQ 时使用`--conf` 指定配置文件路径（若配置文件已放置于系统路径 `/etc/nanomq.conf` 则无需在命令行指定）

:::: tabs type:card

::: tab Hocon 格式配置

```bash
$ nanomq start --conf nanomq.conf
```

:::

::: tab 旧版本配置

```bash
$ nanomq start --old_conf nanomq.conf
```

:::

::::

## 测试桥接

本节将通过 [MQTTX 客户端工具](https://mqttx.app/)来测试新建的 MQTT 数据桥接，我们将新建 2 个连接，分别连接到 NanoMQ 和 MQTT 数据桥接，用于验证 NanoMQ 和数据桥接的消息收发服务。

**连接到 NanoMQ**

![Connect to NanoMQ](./assets/connect-nanomq.png)

**连接到数据桥接**

![Connect to Public Broker](./assets/connect-public-broker.png)

**验证 NanoMQ 到数据桥接的消息服务**

在连接数据桥接的客户端 `MQTTbridge` 中，订阅 `forward1/#` 主题。

在连接 NanoMQ 的客户端 `NanoMQTest` 中，向 `forward1/#` 主题发送消息 ，如 `Hello from NanoMQ` 。

可以看到，消息被成功转发到 MQTT 数据桥接。

<img src="./assets/hellofromnano.png" alt="message from nanomq" style="zoom:50%;" />

**验证数据桥接到  NanoMQ 的消息服务**

在连接 NanoMQ 的客户端 `NanoMQTest` 中，订阅 `recv/topic1` 主题。

在连接数据桥接的客户端 `MQTTbridge` 中，向 `recv/topic1` 主题发布信息，例如：`Hello from broker.emqx.io`。

验证是否收到了从 broker.emqx.io 发布的消息。

![message from broker](./assets/hellofrombroker.png)



