# 网关

本节介绍如何使用配置文件配置多协议网关，包括 ZMQ 网关、SOME/IP 网关和 DDS 网关。

启用网关配置之前，应首先通过源代码方式编译构建 NanoMQ，具体参考如下页面：

- [ZMQ 网关](../gateway/zmq-gateway.md)
- [SOME/IP 网关](../gateway/someip-gateway.md)
- [DDS 网关](../gateway/dds.md)

此外，NanoMQ 已为每个网关建立独立的配置文件，您可将相关配置写入对应的文件即可：

- `nanomq_zmq_gateway.conf`：ZeroMQ 网关
- `nanomq_vsomeip_gateway.conf`：SomeIP 网关
- `nanomq_dds_gateway.conf`：DDS 网关

配置完成后，可在 `nanomq_cli` 工具中通过以下命令启用网关，注意：请把`<path>`替换为真实配置文件的路径。

```hcl
nanomq_cli zmq_gateway --conf <path>
```

## ZMQ 网关

NanoMQ 支持通过其 ZMQ 网关进行 ZeroMQ 消息队列的数据传输和路由。

### **配置示例**

```hcl
gateway.mqtt {
    address = "mqtt-tcp://broker.emqx.io:1883"  # MQTT Broker 地址
    sub_topic = "topic/sub"                     # 从 broker 订阅的主题
    proto_ver = 4                               # MQTT 协议版本
    keepalive = 60                              # 保活间隔时间（s）
    clean_start = true                          # 清除会话。
    username = "username"                       # MQTT 客户端用户名
    password = "passwd"                         # MQTT 客户端密码
    forward = "topic/pub"                       # 待转发到 IoTHUB 的主题
    parallel = 2                                # 可处理的最大并发请求数
}

gateway.zmq {
    sub_address = "tcp://127.0.0.1:5560"        # ZeroMQ 订阅地址
    pub_address = "tcp://127.0.0.1:5559"        # ZeroMQ 发布地址
    sub_pre = "sub_prefix"                      # ZeroMQ 订阅前缀
    pub_pre = "pub_prefix"                      # ZeroMQ 发布前缀
}

http_server {
    port = 8082  																# HTTP 服务器端口
    parallel = 2  															# 可处理的最大并发请求数
    username = "admin" 												  # Basic 授权用户名
    password = "public"  												# Basic 授权密码
}
```

### 配置项

#### gateway.mqtt

- `address`：MQTT Broker 的地址，格式："mqtt-tcp://host:port"。
- `sub_topic`：网关应从 MQTT broker 订阅的主题。
- `proto_ver`：MQTT 协议版本。可选值： 3（MQTT v3.1）、4（MQTT v3.1.1） 和 5（MQTT v5）。
- `keepalive`：保活间隔时间，单位：秒。
- `clean_start`：清除会话。注意：有些 IoT 平台会要求该项设为 `false`。
- `username`：登录用户名。
- `password`：登录密码。
- `forward`：转发到远端 IoTHUB 服务器的主题。
- `parallel`：最大并行进程数。

#### gateway.zmq

- `sub_address`：ZeroMQ 订阅地址，格式："tcp://host:port"。
- `pub_address`：ZeroMQ 发布地址：格式： "tcp://host:port"。
- `sub_pre`：ZeroMQ 订阅的前缀。
- `pub_pre`： ZeroMQ 发布的前缀。

### http_server (可选)

如果你希望通过 HTTP API 动态更新配置或者控制网关的重启或停止，可以通过将以下配置启动 HTTP 服务：

- `port`：HTTP 服务器的端口号。取值范围：0 ～ 65535。
- `parallel`：HTTP 服务器可以处理的最大并发请求数。
- `username`：访问 HTTP 服务器时的基础授权用户名。
- `password`：访问 HTTP 服务器时的基础授权密码。



## SOME/IP 网关

NanoMQ 支持通过其 SOME/IP 网关进行 SOME/IP 消息队列的数据传输和路由。

### **配置示例**

```hcl
gateway.mqtt {
    address = "mqtt-tcp://localhost:1885"    # MQTT Broker 地址
    sub_topic = "topic/sub"             # 要订阅的主题
    sub_qos = 0                         # 要订阅的 QoS 等级
    proto_ver = 4                       # MQTT 协议版本
    keepalive = 60                      # 保活间隔时间（s）
    clean_start = true  								# 清除会话。
    username = "username"  							# MQTT 客户端用户名
    password = "passwd"  								# MQTT password
    clientid = "vsomeip_gateway"    		# MQTT 客户端密码
    forward = "topic/pub"  							# 待转发到 VSOMEIP 的主题
    parallel = 2                        # 可处理的最大并发请求数
}

gateway.vsomeip {
    service_id = "0x1111"               # VSOMEIP 服务 ID
    service_instance_id = "0x2222"      # VSOMEIP 实例 ID
    service_method_id = "0x3333"        # VSOMEIP 方法 ID
    conf_path = "/etc/vsomeip.json"     # 配置文件路径
}

http_server {
    port = 8082  																# HTTP 服务器端口
    parallel = 2  															# 可处理的最大并发请求数
    username = "admin" 												  # Basic 授权用户名
    password = "public"  												# Basic 授权密码
}
```



### **配置项**

::: tip

HTTP 服务器部分的配置与 ZMQ 网关相同，可参考 [ZMQ 网关 - HTTP 服务器](#http_server-可选)。

:::

### gateway.mqtt

- `address`：MQTT Broker 的地址。
- `sub_topic`：MQTT 客户端应订阅的主题。
- `sub_qos`：订阅的 QoS 等级。
- `proto_ver`：MQTT 协议版本。
- `keepalive`：保活间隔时间，单位：秒。
- `clean_start`：清除会话。
- `username`：登录用户名。
- `password`：登录密码。
- `clientid`：Client ID。
- `forward`：要转发到 SOME/IP 网关的主题。
- `parallel`：最大并行进程数。

#### gateway.vsomeip <!-- @jaylin the vsomeip in the configuration file may need to be renamed-->

- `service_id`：指定 VSOMEIP 服务的服务 ID。
- `service_instance_id`：指定 VSOMEIP 服务的实例 ID。
- `service_method_id`：指定 VSOMEIP 服务的方法 ID。
- `conf_path`：指定 SOMEIP 配置文件的路径。

## DDS 网关

NanoMQ 自 v0.16 版本引入了基于 Cyclone DDS 开发的 DDS Proxy 插件，此插件能够完成将 DDS 消息转换为 MQTT 消息并桥接上云，支持用户将 DDS 的数据通过 NanoMQ 来完成跨域传输并通过 MQTT 和云端互通。

### **配置示例**

```hcl
forward_rules = {
    dds_to_mqtt = {
        from_dds = "MQTTCMD/topic1"  				# DDS 主题
        to_mqtt = "DDS/topic1"     					# MQTT 主题
        struct_name = "idl_struct1"  				# 主题的结构体名称
    }
    
    mqtt_to_dds = {
        from_mqtt = "DDSCMD/topic1"  				# MQTT 主题
        to_dds = "MQTT/topic1"       				# DDS 主题
        struct_name = "idl_struct2"  				# 主题的结构体名称
    }
}

dds {
    domain_id = 0                    				# DDS domain ID
    
    shared_memory = {
        enable = false               				# 启用共享内存传输
        log_level = info             				# 共享内存传输的日志级别
    }
}

mqtt {
    connector {
        server = "mqtt-tcp://127.0.0.1:1883"  # MQTT Broker 地址
        proto_ver = 4   											# MQTT 协议版本
        keepalive = 60s 											# 保活间隔时间（s）
        clean_start = true  									# 清除会话。
        username = "username"  								# MQTT 用户名
        password = "passwd"  									# MQTT 密码
        
  	ssl = {                                  # SSL 配置
   		 key_password = "yourpass"             # SSL 密钥密码
   		 keyfile = "/etc/certs/key.pem"        # SSL 密钥文件
    	 certfile = "/etc/certs/cert.pem"      # SSL 证书文件
    	 cacertfile = "/etc/certs/cacert.pem"  # SSL CA 证书文件
  }
    }
}

http_server {
    port = 8082  																# HTTP 服务器端口
    parallel = 2  															# 可处理的最大并发请求数
    username = "admin" 												  # Basic 授权用户名
    password = "public"  												# Basic 授权密码
}
```

### **配置项**

::: tip

HTTP 服务器部分的配置与 ZMQ 网关相同，可参考 [ZMQ 网关 - HTTP 服务器](#http_server-可选)。

:::

#### forward_rules

- `dds_to_mqtt`：指定从 DDS 到 MQTT 的转发规则。
  - `from_dds`：指定要订阅的 DDS 主题。
  - `to_mqtt`：指定要发布的 MQTT 主题。
  - `struct_name`：指定主题的结构体名称。
- `mqtt_to_dds`：指定从 MQTT 到 DDS 的转发规则。
  - `from_mqtt`：指定要订阅的 MQTT 主题。
  - `to_dds`：指定要发布的 DDS 主题。
  - `struct_name`：指定主题的结构体名称。

**DDS 配置**

- `domain_id`：指定 DDS 网络的 Domain ID。
- `shared_memory`：共享内存相关设置：
  - `enable`：是否启用共享内存传输。
  - `log_level`：共享内存传输的日志级别。

**MQTT 连接配置**

- `server`：MQTT Broker 的地址。
- `proto_ver`：MQTT 协议版本。
- `keepalive`：保活间隔时间。
- `clean_start`：清除会话。
- `username`：登录用户名。
- `password`：登录密码。
- `ssl`：SSL 相关配置： 
  - `key_password`：TLS 私钥密码。
  - `keyfile`：TLS 私钥数据。
  - `certfile`：TLS Cert 证书数据。
  - `cacertfile`：TLS CA 证书数据。
