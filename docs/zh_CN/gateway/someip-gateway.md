# SOME/IP 网关

由德国宝马公司开发的 SOME/IP（**Scalable service-Oriented MiddlewarE over IP**），是一种面向服务的车载以太网通信协议，并支持服务导向架构（SOA）。有别于传统车载总线，按照 SOME/IP 协议，发送方只会在网络中至少存在一个接收方、且需要相关数据时，才会发送数据，因此能极大提升网络带宽的利用率。

在软件定义汽车的趋势下，SOME/IP 在处理来自车内各种来源数据方面表现出高效和安全的特性。它既能与传统的 TSP 平台对接，还能联系 ADAS 等新一代应用服务完成计算卸载转移。

NanoMQ 现已通过 SOME/IP Gateway 支持基于 AUTOSAR 标准的 SOME-IP 数据通信方式，可以部署在车内中央网关中完成汇聚和与 TSP 平台的对接工作，并通过MQTT over QUIC/TCP + TLS 加密连接保证网关的安全性。

<img src="./assets/someip-solution.png" alt="SOME/IP + MQTT 共同应用场景" style="zoom:50%;" />

## 前置准备

NanoMQ 的 SOME/IP Gateway 功能依赖于 [vSOMEIP](https://github.com/COVESA/vsomeip)，运行以下命令安装 vSOMEIP。

::: 有关 vSOMEIP 的安装依赖项，可参考 [vsomeip - GitHub 页面](https://github.com/COVESA/vsomeip) 

```shell
git clone https://github.com/COVESA/vsomeip.git
cd vsomeip
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=$YOUR_PATH
make -j8
make install
```

### 编译例程服务

1. 编译 vSOMEIP 中的 `hello_world_service` 例程服务，稍后我们将通过该例程测试 NanoMQ 的 SOME/IP 网关。

```shell
cd vsomeip/examples/hello_world
mkdir build
cd build
cmake ..
make -j8
```
2. 准备notify-sample例程，为SOME/IP sub event的测试做准备

- 修改vsomeip notify-sample的service-id等信息

```shell
diff --git a/examples/sample-ids.hpp b/examples/sample-ids.hpp
index 6d31131..078df71 100644
--- a/examples/sample-ids.hpp
+++ b/examples/sample-ids.hpp
@@ -6,9 +6,9 @@
 #ifndef VSOMEIP_EXAMPLES_SAMPLE_IDS_HPP
 #define VSOMEIP_EXAMPLES_SAMPLE_IDS_HPP
 
-#define SAMPLE_SERVICE_ID       0x1234
-#define SAMPLE_INSTANCE_ID      0x5678
-#define SAMPLE_METHOD_ID        0x0421
+#define SAMPLE_SERVICE_ID       0x1111
+#define SAMPLE_INSTANCE_ID      0x2222
+#define SAMPLE_METHOD_ID        0x3333
 
 #define SAMPLE_EVENT_ID         0x8778
 #define SAMPLE_GET_METHOD_ID    0x0001
```

- 编译vsomeip 中的 notify-sample
```
$ cd vsomeip/build/examples
$ make -j8
```

## 启用 SOME/IP 协议转换功能

通过以下命令在编译阶段为 NanoMQ 开启 SOME/IP 协议转换功能:

```shell
cmake -G Ninja -DBUILD_VSOMEIP_GATEWAY=ON ..
ninja
```

编译完成后，可进入 build -> nanomq_cli 文件夹，执行命令 `nanomq_cli` 确认网关是否正确安装：

```bash
$ ./nanomq_cli
nanomq_cli { pub | sub | conn | nngproxy | nngcat | vsomeip_gateway } [--help]

available tools:
   * pub
   * sub
   * conn
   * nngproxy
   * nngcat
   * vsomeip_gateway

Copyright 2022 EMQ Edge Computing Team
```

运行命令 `nanomq_cli vsomeip_gateway --help` 可看到以下输出：

```
Usage: nanomq_cli vsomeip_gateway [--conf <path>]

  --conf <path>  The path of a specified nanomq_vsomeip_gateway.conf file
```

即我们需要首先为该网关指定相关配置文件。

## 配置 SOME/IP 网关

通过 `etc/nanomq_vsomeip_gateway.conf` 配置文件来设置桥接的主题和需要请求的 SOME/IP 服务地址。

例如，您希望将从 SOME/IP 服务接收到的数据转发至本地 MQTT Broker 的 `topic/pub` 主题，同时将通过主题 `topic/sub` 收到的 MQTT 消息转发至 SOME/IP 服务，可通过如下配置实现：

```bash
gateway.mqtt {
    address = "mqtt-tcp://localhost:1883"
    sub_topic = "topic/sub" # message from mqtt
    sub_qos = 0
    proto_ver = 4
    keepalive = 60
    clean_start = true
    username = "username"
    password = "passwd"
    clientid = "vsomeip_gateway"
    forward = "topic/pub" # message to mqtt
    parallel = 2
}

gateway.vsomeip {
    service_id = "0x1111"
    service_instance_id = "0x2222"
    service_method_id = "0x3333"
    service_event_id = "0x8778"
    service_eventgroup_id = "0x4465"
    # conf_path = "/etc/vsomeip.json"
}

```

如果你希望通过 HTTP API 动态更新配置或者控制网关的重启或停止，可以通过将以下配置加入到 `nanomq_vsomeip_gateway.conf` 中，启动 HTTP 服务：

```bash
# #============================================================
# # Http server
# #============================================================
http_server {
	# # http server port
	# #
	# # Value: 0 - 65535
	port = 8082
	# # parallel for http server
	# # Handle a specified maximum number of outstanding requests
	# #
	# # Value: 1-infinity
	parallel = 2
	# # username
	# #
    # # Basic authorization 
    # #
	# # Value: String
	username = admin
	# # password
	# #
    # # Basic authorization
    # #
	# # Value: String
	password = public
}
```
## HTTP API
HTTP API 提供了如下几个接口：
- 获取配置文件：
```shell
$ curl --basic -u admin:public 'http://127.0.0.1:8082/api/v4/proxy/configuration/someip' --output nanomq_vsomeip_gateway.conf
```
- 更新配置文件：
```shell
$ curl --basic -u admin:public 'http://127.0.0.1:8082/api/v4/proxy/configuration/someip' --header 'Content-Type: text/plain'  --data-binary '@nanomq_vsomeip_gateway.conf'
```
- 停止网关：
```shell
$ curl --basic -u admin:public 'http://127.0.0.1:8082/api/v4/proxy/ctrl/stop' \
--header 'Content-Type: application/json' \
--data '{
    "req": 10,
    "action": "stop",
    "seq": 1234
}'
```
- 重启网关：
```shell
$ curl --basic -u admin:public 'http://127.0.0.1:8082/api/v4/proxy/ctrl/restart' \
--header 'Content-Type: application/json' \
--data '{
    "req": 10,
    "action": "restart",
    "seq": 1234
}'
```



## 测试 SOME/IP 网关

1. 使用上面编译好的 `hello_world_service` 作为 SOME/IP 的服务端，并通过
SOME/IP gateway 与 NanoMQ 对接。

::: tip

该服务可以更换成其他 SOME/IP 兼容的服务。

:::

通过以下命令启动  `hello_world_service` ：

``` shell
$ ldconfig
$ ./hello_world_service // 启动 SOME/IP Server
$ nanomq start // 启动 NanoMQ MQTT Broker
$ ./nanomq_cli vsomeip_gateway --conf path/to/nanomq_vsomeip_gateway.conf // 启动 SOME/IP proxy
```
配置好 SOME/IP 网关之后，当您通过 MQTT 客户端向 `topic/sub` 主题发送一条消息时，SOME/IP 网关会将这条消息转发给预先指定的 SOME/IP 服务，即 `hello_world_service`；SOME/IP 服务接收到消息后会产生一个回应，并通过 SOME/IP 网关将回应消息转发到 `topic/pub` 主题，订阅该主题的客户端即可收到相应回复消息。

运行如图：
![img](./assets/hello_service.png)
![img](./assets/nanomq_someip_gateway.png)
![img](./assets/someip_gateway.png)
![img](./assets/pub_sub.png)

2. 测试SOME/IP sub event功能
- 运行nanomq SOME/IP 网关
```shell
$ ./nanomq_cli vsomeip_gateway --conf=../etc/nanomq_vsomeip_gateway.conf
Start http server listener: http://0.0.0.0:8082/api/v4/proxy                                                                                             [3/3039]
2023-10-11 11:33:27.331499 [info] Parsed vsomeip configuration in 0ms                                                                                            
2023-10-11 11 :33:27.331709 [info] Configuration module loaded.                                                                                                   
2023-10-11 11:33:27.331741 [info] Initializing vsomeip (3.3.8) application "".                                                                                   
2023-10-11 11:33:27.332751 [info] Instantiating routing manager [Host].
2023-10-11 11:33:27.333824 [info] create_routing_root: Routing root @ /tmp/vsomeip-0
2023-10-11 11:33:27.334535 [info] Service Discovery enabled. Trying to load module.
2023-10-11 11:33:27.337933 [info] Service Discovery module loaded.
2023-10-11 11:33:27.338445 [info] Application(unnamed, 0100) is initialized (11, 100).
2023-10-11 11:33:27.338846 [info] REGISTER EVENT(0100): [1111.2222.8778:is_provider=false]
2023-10-11 11:33:27.338991 [info] SUBSCRIBE(0100): [1111.2222.4465:ffff:0]
2023-10-11 11:33:27.339122 [info] notify_one_unlocked: Notifying 1111.2222.8778 to client 100 failed. Event payload not set!
2023-10-11 11:33:27.339296 [info] Starting vsomeip application "" (0100) using 2 threads I/O nice 255
2023-10-11 11:33:27.340355 [info] Client [0100] routes unicast:127.0.0.1, netmask:255.255.255.0
2023-10-11 11:33:27.340443 [info] shutdown thread id from application: 0100 () is: 7fd859fdd640 TID: 313601
2023-10-11 11:33:27.340371 [info] main dispatch thread id from application: 0100 () is: 7fd85a7de640 TID: 313600
2023-10-11 11:33:27.342756 [info] Watchdog is disabled!
2023-10-11 11:33:27.344507 [info] connect_cb: connected!
2023-10-11 11:33:27.344764 [info] io thread id from application: 0100 () is: 7fd86bad0b80 TID: 313566
2023-10-11 11:33:27.344807 [info] topic: topic/sub
2023-10-11 11:33:27.344528 [info] REQUEST(0100): [1111.2222:255.4294967295]
2023-10-11 11:33:27.346067 [info] Recv message: '' from ''
2023-10-11 11:33:27.344800 [info] io thread id from application: 0100 () is: 7fd858fdb640 TID: 313603
2023-10-11 11:33:27.347251 [info] vSomeIP 3.3.8 | (default)
2023-10-11 11:33:27.347239 [info] create_local_server: Listening @ /tmp/vsomeip-100
2023-10-11 11:33:27.347933 [info] Network interface "lo" state changed: up
2023-10-11 11:33:29.981305 [info] Application/Client 0101 is registering.
2023-10-11 11:33:29.981761 [info] Client [100] is connecting to [101] at /tmp/vsomeip-101
2023-10-11 11:33:29.982757 [info] REGISTERED_ACK(0101)
2023-10-11 11:33:29.982877 [info] OFFER(0101): [1111.2222:0.0] (true)
2023-10-11 11:33:29.982948 [info] Port configuration missing for [1111.2222]. Service is internal.
2023-10-11 11:33:29.983767 [info] SUBSCRIBE ACK(0101): [1111.2222.4465.ffff]
2023-10-11 11:33:29.985027 [info] Send publish: '' to 'topic/pub'
2023-10-11 11:33:30.991436 [info] Send publish: '' to 'topic/pub'
2023-10-11 11:33:31.996741 [info] Send publish: '' to 'topic/pub'
2023-10-11 11:33:32.000175 [info] Send publish: '' to 'topic/pub'
2023-10-11 11:33:33.006548 [info] Send publish: '' to 'topic/pub'
2023-10-11 11:33:34.009595 [info] Send publish: '' to 'topic/pub'
2023-10-11 11:33:35.014565 [info] Send publish: '' to 'topic/pub'
2023-10-11 11:33:36.019592 [info] Send publish: '' to 'topic/pub'
2023-10-11 11:33:37.350110 [info] vSomeIP 3.3.8 | (default)
2023-10-11 11:33:37.025566 [info] Send publish: '' to 'topic/pub'
2023-10-11 11:33:38.020287 [info] Send publish: '' to 'topic/pub'
2023-10-11 11:33:39.007535 [info] STOP OFFER(0101): [1111.2222:0.0] (true)
^C2023-10-11 11:33:44.494770 [info] RELEASE(0100): [1111.2222]
```

- 运行notify-sample
```shell
$ ./notify-sample
2023-10-11 11:11:30.705967 [info] Parsed vsomeip configuration in 0ms
2023-10-11 11:11:30.706632 [info] Configuration module loaded.
2023-10-11 11:11:30.706724 [info] Initializing vsomeip (3.3.8) application "".
2023-10-11 11:11:30.706990 [info] Instantiating routing manager [Proxy].
2023-10-11 11:11:30.707191 [info] Client [ffff] is connecting to [0] at /tmp/vsomeip-0
2023-10-11 11:11:30.707414 [info] Application(unnamed, ffff) is initialized (11, 100).
2023-10-11 11:11:30.707528 [info] offer_event: Event [1111.2222.8778] uses configured cycle time 0ms
2023-10-11 11:11:30.707828 [info] Starting vsomeip application "" (ffff) using 2 threads I/O nice 255
2023-10-11 11:11:30.709944 [info] io thread id from application: ffff () is: 7f7918b08b80 TID: 312699
Setting event (Length=1).
2023-10-11 11:11:30.710052 [info] main dispatch thread id from application: ffff () is: 7f7916ffd640 TID: 312702
2023-10-11 11:11:30.710180 [info] shutdown thread id from application: ffff () is: 7f79167fc640 TID: 312703
2023-10-11 11:11:30.710269 [info] io thread id from application: ffff () is: 7f7915ffb640 TID: 312704
2023-10-11 11:11:30.713151 [info] create_local_server: Listening @ /tmp/vsomeip-101
2023-10-11 11:11:30.713436 [info] Client 101 () successfully connected to routing  ~> registering..
2023-10-11 11:11:30.713521 [info] Registering to routing manager @ vsomeip-0
2023-10-11 11:11:30.716261 [info] Application/Client 101 () is registered.
Application  is registered.
2023-10-11 11:11:30.720445 [info] Client [101] is connecting to [100] at /tmp/vsomeip-100
2023-10-11 11:11:30.721525 [info] SUBSCRIBE(0100): [1111.2222.4465:ffff:0]
Setting event (Length=2).
Setting event (Length=3).
Setting event (Length=4).
Setting event (Length=5).
Setting event (Length=6).
Setting event (Length=7).
Setting event (Length=8).
Setting event (Length=9).
Setting event (Length=1).
...
```

目前，NanoMQ 的 SOME/IP 网关仅支持透明传输（透传）服务，即原始数据经过 SOME/IP 网关后不会有任何的改变或处理，我们后续计划根据用户所使用的数据序列化和反序列化格式工具，比如 IDL 或 FIDL，提供更多高级功能，比如自动代码生成和数据序列化，敬请期待。

