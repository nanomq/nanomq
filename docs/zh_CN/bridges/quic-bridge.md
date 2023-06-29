# MQTT over QUIC 桥接

NanoMQ 已支持 MQTT over QUIC 桥接，用户可以使用 QUIC 作为 MQTT 协议的传输层来与 EMQX 5.0 消息服务建立桥接进行数据同步，从而为无法集成或找到合适的 MQTT over QUIC SDK 的端侧设备和难以修改固件的嵌入式设备提供在 IoT 场景利用 QUIC 协议优势的捷径。依靠 EMQX+NanoMQ 的云边一体化的消息架构，用户能够快速且低成本的在泛物联网场景中完成跨时空地域的数据采集和同步需求。

支持特性：

- 多流传输 
- 混合桥接模式 
- 设置 QoS 消息更高的优先传输级别
- 初始的 RTT （ Round Trip Time ） 预测值设置
- 重置 QUIC 传输层拥塞控制检测的最大空闲时间
- TLS 双向认证

## 启用 MQTT over QUIC 桥接

NanoMQ 的 QUIC 模组处于默认关闭状态，如希望使用 MQTT over QUIC 桥接，请通过[编译方式安装 NanoMQ](../installation/build-options.md)，并在编译时启用 QUIC 模组：

```bash
$ git clone https://github.com/emqx/nanomq.git
$ cd nanomq 
## 使用国内网络拉取 submodule 可能耗时较久
$ git submodule update --init --recursive
$ mkdir build && cd build
## 默认编译`msquic`为动态库，如需设置编译目标为静态库则添加 cmake 编译选项 `-DQUIC_BUILD_SHARED=OFF`
$ cmake -G Ninja -DNNG_ENABLE_QUIC=ON ..
$ sudo ninja install
```

::: tip

对于 macOS 系统，可通过 `make` 进行编译，代码如下：

```bash
$ git clone https://github.com/emqx/nanomq.git
$ cd nanomq 
$ git submodule update --init --recursive
$ mkdir build && cd build
$ cmake -DNNG_ENABLE_QUIC=ON ..
$ make
```

:::

### 配置 MQTT over QUIC 桥接

### 前置准备

配置 MQTT over QUIC 桥接前，应先安装 EMQX 5.0 来提供消息服务，有关如何在 EMQX 中启用 QUIC 桥接，可参考 [EMQX - MQTT over QUIC 教程](https://docs.emqx.com/zh/enterprise/v5.0/mqtt-over-quic/getting-started.html)。

### 配置桥接 

启动 QUIC 模组后，您需要在 `nanomq.conf ` 文件中配置 MQTT over QUIC 桥接功能和对应的主题，例如，在下面的配置文件中，我们定义了 MQTT over QUIC 桥接的服务器地址、连接凭证、连接参数、消息转发规则、订阅主题和队列长度等内容：

```bash
bridges.mqtt.name {
	## TCP URL 格式:  mqtt-tcp://host:port
	## TLS URL 格式:  tls+mqtt-tcp://host:port
	## QUIC URL 格式: mqtt-quic://host:port
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

使用 `mqtt-quic` 作为 URL 前缀即是采用 QUIC 作为 MQTT 的传输层，

:::

**关键配置项：**

- 远端 broker 地址: `bridges.mqtt.name.server`
- 转发远端 Topic 数组（支持 MQTT 通配符）:  `bridges.mqtt.name.forwards`
- 订阅远端 Topic 数组（支持 MQTT 通配符）: `bridges.mqtt.name.subscription`

**QUIC 专用配置项**

- 混合桥接模式开关：`bridges.mqtt.name.hybrid_bridging`
- 多流桥接开关: `bridges.mqtt.name.multi_stream`


具体配置参数请参考桥接 [Hocon 版本配置](../config-description/v014.md) 或 [旧版本配置](../config-description/v013.md) (*不推荐*)

如使用 Hocon 版本配置项，除将相关配置直接写入  `nanomq.conf ` 中外，您也可单独为桥接定义一份配置文件，如 `nanomq_bridge.conf` ，然后通过 HOCON 的 `include` 语法在 `nanomq.conf` 中引用此文件：

示例：

```shell
include "path/to/nanomq_bridge.conf" 
```

如需查看运行过程中更多日志数据，可以在配置文件中设置日志等级 `log.level`

## 启动 NanoMQ

在 NanoMQ 的安装目录，运行以下命令启动 NanoMQ

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

本节将通过 NanoMQ 自带的客户端工具测试测试新建的 MQTT over QUIC 桥接，我们将新建 2 个连接，分别连接到 NanoMQ 和 MQTT over QUIC 数据桥接，用于验证 NanoMQ 和数据桥接的消息收发服务。

### 测试消息转发

1. 为远端 EMQX Broker 订阅消息主题：

   为 **EMQX** 订阅转发主题 “`forward1/#`”，用于接收由 **NanoMQ **转发的数据：

   新建一个命令行窗口，前往 build 文件夹下的 nanomq_cli 文件夹，执行以下命令进行订阅：

   ```bash
   ## -h {远端 host} 
   ## -p {端口号，如不指定将使用默认端口号 1883（MQTT）或 14567（QUIC）}
   ## -t {主题名称}
   ## --quic {开启 quic}
   ## --q {消息 QoS，可选值 0、1、2}
   ## --m {消息 payload}
   ## -u {用户名} 
   ## -P {密码}
   $ ./nanomq_cli sub --quic -h "your.host.address"  -t "forward1/#" -q 2 -u emqx -P emqx123
   ```

2. 新建一个命令行窗口，发布消息到 **NanoMQ** Broker，主题为 “`forward1/msg`”：

   ```bash
   $ ./nanomq_cli pub --quic -h "your.host.address"  -t "nanomq/1" -m "forward_msg" -q 2
   ```

3. 返回第一个命令行窗口，可以看到由 NanoMQ Broker 转发到消息，例如：

   ```bash
   quic_msg_recv_cb: forward1/#: forward_msg
   ```

### 测试消息接收

1. 为本地 NanoMQ Broker 订阅消息主题：

   为 **NanoMQ** 订阅主题 “`cmd/topic1`”，用于接收 **EMQX** 发布的数据：

   新建第三个命令行窗口，前往 build 文件夹下的 nanomq_cli 文件夹，执行以下命令进行订阅：

   ```bash
   $ ./nanomq_cli sub --quic -h "your.host.address"  -t "recv/topic1" -q 2
   ```
   
2. 新建第四个命令行窗口，发布消息到远端 **EMQX** Broker，主题为 “`cmd/topic1`”：

   ```bash
   $ ./nanomq_cli pub --quic -h "your.host.address"  -t "recv/topic1" -m "cmd_msg" -q 2 -u emqx -P emqx123
   ```
   
3. 返回第三个命令行窗口，将能看到远端 **EMQX** Broker 发送的消息，例如：

   ```bash
   quic_msg_recv_cb: recv/topic1: cmd_msg
   ```

## QUIC 多流桥接

QUIC 协议相较于 TCP 的一大优势在于解决了队首阻塞的问题，但这是依赖于 QUIC 的单链接多 Stream 特性的。针对网络拥塞或者网络抖动等情况，NanoMQ 和 EMQX 5.0 一起设计和引入了 Mutli-stream QUIC 协议标准，以提供更好消息传输体验。

![NanoMQ 多流桥接](./assets/multi-stream.png)

目前多流桥接将 Stream 分为以下两种类型

- **控制流：**对于每个 MQTT over QUIC 连接，首次建立时必须先建立此 Stream，所有 MQTT 控制信令如 CONNECT/PINGREQ/PINGRESP 都默认在此流上传输。连接以控制流作为探测当前网络环境和连接健康度的唯一指标，控制流断开将导致连接重连。但用户也可以选择在控制流上传输 PUBLISH 包。
- **数据流：**桥接客户端每次进行 PUBLISH 和 SUBSCRIBE 操作都会根据使用的主题创建一个对应的数据流。此流由订阅或发布行为开启，服务端与客户端都会标识记录 PUBLISH 和 SUBSCRIBE 包中 Topic 和 此 Stream 的对应关系。所有发布到此 Topic 的数据都会被定向到此数据流。有别于控制流，数据流断开不会导致连接断开，而是下次自动重建。

### 启用多流桥接

如希望使用多流桥接，只需打开对应的配置选项：

:::: tabs type:card

::: tab Hocon 格式配置

```bash
quic_multi_stream = false
quic_qos_priority=true
```

:::

::: tab 旧版本配置

```bash
## multi-stream: enable or disable the multi-stream bridging mode
## Value: true/false
## Default: false
bridge.mqtt.emqx.quic_multi_stream=false

## 在流中是否赋予Qos消息高传输优先级
## 针对每个流单独生效，非主题优先级
## Value: true/false
## Default: true
bridge.mqtt.emqx.quic_qos_priority=true
```

:::

::::

之后根据用户 Pub/Sub 的具体主题会建立对应的 Stream，可以在 log 中检查功能是否生效，如订阅 nanomq/1 主题就会自动创建一个 data stream：

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

之后 NanoMQ 就会自动根据 Topic 将数据包导流至不同的 Stream 发送。经过内部测试，在使用模拟 2s 延迟和 40% 丢包的弱网环境时，能够得到 stream 数量倍数的延时降低。
