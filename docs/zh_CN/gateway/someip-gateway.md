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

编译 vSOMEIP 中的 hello_world_service 例程服务，稍后我们将通过该例程测试 NanoMQ 的SOME/IP 网关。

```shell
cd vsomeip/examples/hello_world
mkdir build
cd build
cmake ..
make -j8
```

## 启用 SOME/IP 协议转换功能

通过以下命令在编译阶段为 NanoMQ 开启 SOME/IP 协议转换功能:

```shell
cmake -G Ninja -DBUILD_VSOMEIP_GATEWAY=ON ..
ninja
```

## 配置 SOME/IP 网关

开始使用前，首先通过 `etc/nanomq_vsomeip_gateway.conf` 配置文件来设置桥接的主题和需要请求的 SOME/IP 服务地址。

例如，您希望将从 SOME/IP 服务接收到的数据转发至本地 MQTT Broker 的 topic/pub 主题，同时将通过主题 topic/sub 收到的 MQTT 消息转发至 SOME/IP 服务，可通过如下配置实现：

```apacheconf
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
    # conf_path = "/etc/vsomeip.json"
}

http_server {
	enable = false
	port = 8082
	parallel = 2
	username = admin
	password = public
}
```

这个示例中定义了两个 SOME/IP 服务，分别对应 MQTT 主题 `someip/1234/5678/9ABC` 和 `someip/1111/2222/3333`。

- 当接收到来自指定 `service_id`，`service_instance_id` 和 `service_method_id` 的消息后，SOME/IP 网关会自动将其转换为 MQTT 消息，并发布到相应的主题上。
- 当 SOME/IP 网关从 MQTT 主题接收到消息时，也会自动将其转换为 SOME/IP 格式，并发送给指定的SOME/IP 服务。

## 测试 SOME/IP 网关

本节将通过 vSOMEIP 项目提供的例程服务 `hello_world_service` 来连接和转发的 SOME/IP 服务，并通过
SOME/IP gateway 与 NanoMQ 对接。

::: tip

有关如何安装启动此示例服务请参考 VSOMEIP 项目文档，该服务也可以更换成其他 SOME/IP 兼容的服务。

:::

通过以下命令启动  `hello_world_service` ：

``` shell
ldconfig
./hello_world_service // 启动 SOME/IP Server
nanomq start // 启动 NanoMQ MQTT Broker
./nanomq_cli vsomeip_gateway --conf ../etc/nanomq_vsomeip_gateway.conf // 启动 SOME/IP proxy
```
配置好 SOME/IP 网关之后，当您通过 MQTT 客户端向 `topic/pub` 主题发送一条消息时，SOME/IP 网关会将这条消息转发给预先指定的 SOME/IP 服务，即 `hello_world_service`；SOME/IP 服务接收到消息后会产生一个回应，并通过 SOME/IP 网关将回应消息转发到 `topic/sub` 主题，订阅该主题的客户端即可收到相应回复消息。

运行如图：
![img](./assets/hello_service.png)
![img](./assets/nanomq_someip_gateway.png)
![img](./assets/someip_gateway.png)
![img](./assets/pub_sub.png)

目前，NanoMQ 的 SOME/IP 网关仅支持透明传输（透传）服务，即原始数据经过 SOME/IP 网关后不会有任何的改变或处理，我们后续计划根据用户所使用的数据序列化和反序列化格式工具，比如 IDL 或 FIDL，提供更多高级功能，比如自动代码生成和数据序列化，敬请期待。

