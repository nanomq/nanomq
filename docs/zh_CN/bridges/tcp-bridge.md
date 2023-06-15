# NanoMQ 桥接到 EMQX

桥接是一种连接多个 MQTT 消息中间件的方式。不同于集群，工作在桥接模式下的节点之间不会复制主题树和路由表。桥接模式所做的是：

- 按照规则把消息转发至桥接节点； 
- 从桥接节点订阅主题，并在收到消息后在本节点/集群中转发该消息。

## 配置

需在配置`nanomq.conf`文件中进行配置

具体配置参数请参考桥接[配置](../config-description/v014.md),  以下配置示例为 Hocon 格式配置:

重点配置项：

- 远端 broker 地址: `bridges.mqtt.name.server`
- 转发远端 Topic 数组(支持 MQTT 通配符):  `bridges.mqtt.name.forwards`
- 订阅远端 Topic 数组(支持 MQTT 通配符):   `bridges.mqtt.name.subscription`

nanomq.conf 桥接配置部分

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

这里你也可以使用 HOCON 的 `include` 语法，将桥接的配置放到单独的配置文件里 
`nanomq_bridge.conf` 然后在 nanomq.conf 加入下面的语句
```shell
include "path/to/nanomq_bridge.conf" 
```

如需查看运行过程中更多日志数据，可以在配置文件中设置日志等级 `log.level`

## 运行

启动 NanoMQ 时使用`--conf` 指定配置文件路径（若配置文件已放置于系统路径`/etc/nanomq.conf` 则无需在命令行指定）

```bash
$ nanomq start --conf nanomq.conf
```

## 验证桥接

验证桥接是否成功，只需往桥接的上下行主题发送数据即可，也可以使用 NanoMQ 自带的 nanomq_cli 工具中的 QUIC 客户端来与 EMQX 5.0 测试验证。

### 测试消息转发

使用 nanomq 自带客户端工具测试桥接消息的收发。

1. 订阅远端 EMQX Broker 的主题：

   从**EMQX**订阅转发的主题 “`forward1/#`”, 该主题将接收到从**NanoMQ**上转发的数据：

   在第 1 个终端上执行订阅:

   ```bash
   $ nanomq_cli sub -h "broker.emqx.io" -t  "forward1/#"
   forward1/msg: forward_msg
   ```

2. 发布消息到本地 NanoMQ Broker 主题:

   发布消息到 NanoMQ Broker ，主题为 “`forward1/msg`”：

   在第 2 个终端上执行消息发布:

   ```bash
   $ nanomq_cli pub -t  "forward1/msg"  -m "forward_msg"
   ```

### 测试消息接收

1. 订阅本地**NanoMQ** Broker 的主题：

   从**NanoMQ**订阅主题 “`cmd/topic1`”, 该主题将接收到**EMQX**上发布的数据：

   在第 3 个终端上执行订阅:

   ```bash
   $ nanomq_cli sub -t "recv/topic1"
   recv/topic1: cmd_msg
   ```

2. 发布消息到远端**EMQX** Broker 主题“`cmd/topic1`”：

   在第 4 个终端上执行消息发布:

   ```bash
   $ nanomq_cli pub -h "broker.emqx.io" -t  "recv/topic1" -m "cmd_msg"
   ```

   





