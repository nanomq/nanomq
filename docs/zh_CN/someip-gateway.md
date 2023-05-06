# SOME/IP GATEWAY

## 依赖

目前 someip-gateway 功能依赖于 [vsomeip](https://github.com/COVESA/vsomeip)。

### 安装 vsomeip
请参照 [vsomeip](https://github.com/COVESA/vsomeip) 安装指定依赖，以下假定已安装相关依赖。

```shell
git clone https://github.com/COVESA/vsomeip.git
cd vsomeip
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=$YOUR_PATH
make -j8
make install
```

### 编译 hello_world_service

```shell
cd vsomeip/examples/hello_world
mkdir build
cd build
cmake ..
make -j8
```

## 编译

通过以下命令在编译阶段为 NanoMQ 开启 SOME/IP 协议转换功能:

```shell
cmake -G Ninja -DBUILD_VSOMEIP_GATEWAY=ON ..
ninja
```

## 运行
开始使用前，首先通过 `etc/nanomq_vsomeip_gateway.conf` 独立配置文件来设置桥接的主题和需要请求的 SOME/IP 服务地址。例如此处配置将从 SOME/IP 服务接收到的数据转发至本地 MQTT Broker 的 topic/pub 主题，将从主题 topic/sub 收到的 MQTT 消息转发至 SOME/IP 服务。

```apacheconf
##====================================================================
# # Configuration for MQTT VSOMEIP Gateway
# #====================================================================
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

# #============================================================
# # Http server
# #============================================================
http_server {
	# # allow http server
	# #
	# # Value: true | false
	enable = false
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

以 VSOMEIP 项目提供的例程服务 `hello_world_service` 为需要连接和转发的 SOME/IP 服务，启动
SOME/IP gateway 将 NanoMQ 和其对接。(如何安装启动此示例服务请参考 VSOMEIP 项目文档，该服务也可以更换成其他SOME/IP 兼容的服务)
``` shell
ldconfig
./hello_world_service // 启动 SOME/IP Server
nanomq start // 启动 NanoMQ MQTT Broker
nanomq cli vsomeip gateway--conf /etc/nanomq_vsomeip_gateway.conf// 启动 SOME/IP proxy
```
之后在 topic/pub 主题发消息就能在对应的 topic/sub 收到 hello_world_service 回复的消息。

运行如图：
![img](./images/hello_service.png)
![img](./images/nanomq_someip_gateway.png)
![img](./images/someip_gateway.png)
![img](./images/pub_sub.png)

目前还只能提供透传服务，后续会根据用户使用的数据序列化/版序列化格式工具，如 IDL/FIDL 提供类似于 DDS Proxy Gateway 一样的自动代码生成+序列化功能。
