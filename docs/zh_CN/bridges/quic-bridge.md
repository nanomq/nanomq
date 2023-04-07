# MQTT over QUIC桥接

NanoMQ已支持MQTT over QUIC桥接，用户可以使用 QUIC 作为 MQTT 协议的传输层来与 EMQX 5.0 消息服务建立桥接进行数据同步，从而为无法集成或找到合适的 MQTT over QUIC SDK 的端侧设备和难以修改固件的嵌入式设备提供在 IoT 场景利用 QUIC 协议优势的捷径。依靠 EMQX+NanoMQ 的云边一体化的消息架构，用户能够快速且低成本的在泛物联网场景中完成跨时空地域的数据采集和同步需求。

支持特性：

- 多流传输 
- 混合桥接模式 
- 设置QoS 消息更高的优先传输级别
- 初始的 RTT（Round Trip Time） 预测值设置
- 重置 QUIC 传输层拥塞控制检测的最大空闲时间
- TLS双向认证

## 启用 MQTT over QUIC 桥接

### 编译

NanoMQ 的 QUIC 模组处于默认关闭状态，需通过编译选项打开后安装使用，完整的下载和编译安装命令可以参考:

```bash
$ git clone https://github.com/emqx/nanomq.git
$ cd nanomq 
## 使用国内网络拉取submodule可能耗时较久
$ git submodule update --init --recursive
$ mkdir build && cd build
## 默认编译`msquic`为动态库，如需设置编译目标为静态库则添加cmake编译选项 `-DQUIC_BUILD_SHARED=OFF`
$ cmake -G Ninja -DNNG_ENABLE_QUIC=ON ..
$ sudo ninja install
```



### QUIC桥接配置

开启 QUIC 桥接功能的 NanoMQ 编译安装完成后, 需在配置`nanomq.conf`文件中进行配置MQTT over QUIC 桥接功能和对应的主题，使用 `mqtt-quic` 作为 URL 前缀即是采用 QUIC 作为 MQTT 的传输层；

具体配置参数请参考桥接[Hocon版本配置](../config-description/v014.md) 或 [旧版本配置](../config-description/v013.md) (*不推荐*), 以下配置示例为Hocon格式配置:

重点配置项：

- 桥接功能启用: `bridges.mqtt.nodes[].enable`

- 远端broker地址: `bridges.mqtt.nodes[].connector.server`
- 转发远端Topic数组(支持MQTT 通配符):  `bridges.mqtt.nodes[].forwards`
- 订阅远端Topic数组(支持MQTT 通配符):   `bridges.mqtt.nodes[].subscription`

QUIC专用配置:

- 混合桥接模式开关：`bridges.mqtt.nodes[].hybrid_bridging`
- 多流桥接开关: `bridges.mqtt.nodes[].multi_stream`



nanomq.conf的桥接配置部分:

```bash
bridges.mqtt {
	nodes = [ 
		{
			name = emqx
			enable = true
			connector {
				## TCP URL格式:  mqtt-tcp://host:port
				## TLS URL格式:  tls+mqtt-tcp://host:port
				## QUIC URL格式: mqtt-quic://host:port
				server = "mqtt-quic://iot-platform.cloud:14567"
				proto_ver = 4
				username = emqx
				password = emqx123
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
			quic_keepalive = 120s
			quic_idle_timeout = 120s
			quic_discon_timeout = 20s
			quic_handshake_timeout = 60s
			hybrid_bridging = false
			congestion_control = cubic
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
      parallel = 2
      max_send_queue_len = 1024
      max_recv_queue_len = 1024
		}
	]
}
```

如需查看运行过程中更多日志数据，可以在配置文件中设置日志等级 `log.level`

### 运行

然后启动 NanoMQ 即可：

Hocon格式配置

```bash
$ nanomq start --conf nanomq.conf
```

旧版本配置

```bash
$ nanomq start --old_conf nanomq.conf
```



### 验证桥接

验证桥接是否成功，只需往桥接的上下行主题发送数据即可，也可以使用 NanoMQ 自带的 nanomq_cli 工具中的 QUIC 客户端来与 EMQX 5.0 测试验证。

#### 测试消息转发

使用nanomq自带客户端工具测试桥接消息的收发。

1. 订阅远端EMQX Broker的主题：

   从**EMQX**订阅转发的主题 “`forward1/#`”, 该主题将接收到从**NanoMQ**上转发的数据：

   在第1个终端上执行订阅:

   ```bash
   ## --url {远端broker} 
   ## -u {用户名} 
   ## -p {密码}
   $ nanomq_cli sub --url "mqtt-quic://iot-platform.cloud:14567" -t  "forward1/#" -u emqx -p emqx123
   forward1/msg: forward_msg
   ```

2. 发布消息到本地**NanoMQ** Broker主题:

   发布消息到**NanoMQ** Broker，主题为 “`forward1/msg`”：

   在第2个终端上执行消息发布:

   ```bash
   $ nanomq_cli pub -t  "forward1/msg"  -m "forward_msg"
   ```

#### 测试消息接收

1. 订阅本地NanoMQ Broker的主题：

   从**NanoMQ**订阅主题 “`cmd/topic1`”, 该主题将接收到**EMQX**上发布的数据：

   在第3个终端上执行订阅:

   ```bash
   $ nanomq_cli sub -t "recv/topic1"
   recv/topic1: cmd_msg
   ```

2. 发布消息到远端**EMQX** Broker主题“`cmd/topic1`”：

   在第4个终端上执行消息发布:

   ```bash
   $ nanomq_cli pub --url "mqtt-quic://iot-platform.cloud:14567" -t  "recv/topic1" -m "cmd_msg" -u emqx -p emqx123
   ```

   



