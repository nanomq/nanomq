# DDS

​      Data Distribution Service 数据分发服务，是新一代分布式实时通信中间件协议，采用发布/订阅体系架构，强调以数据为中心，提供丰富的QoS服务质量策略，以保障数据进行实时、高效、灵活地分发，可满足各种分布式实时通信应用需求。

​      DDS可以将数据从一个应用程序传递到另一个应用程序，以支持高性能、可靠性和实时性能。DDS可以实现发布/订阅模式，允许发布者发布数据，订阅者订阅数据，以及发布者和订阅者之间的双向通信。DDS可以支持多种类型的数据，包括文本、图像、视频、音频等，可以支持多种类型的协议，包括TCP/IP、UDP、HTTP等，可以支持多种类型的网络，包括局域网、广域网等。

​      [Cyclone DDS](https://cyclonedds.io/)是一款基于OMG（Object Management Group）DDS规范的开源的DDS实现，用于发布/订阅消息的实时系统。它是一款开源的软件，支持多种编程语言，可以在多种操作系统平台上运行，提供了一个可靠的发布订阅框架，可以让开发者实现可靠的数据交换。它还支持多种QoS（质量服务），可以让开发者根据自己的需求来配置QoS，以满足不同的业务需求。

## DDS to MQTT Proxy

​      基于Cyclone DDS实现的NanoMQ_CLI DDS PROXY负责将指定Topic的MQTT和DDS消息相互转发到对方。

<img src="./images/dds-mqtt.png" style="zoom: 67%;" />


## 安装DDS库

### Iceoryx

不需iceoryx可跳过本步骤

```bash
$ git clone https://github.com/eclipse-iceoryx/iceoryx.git
$ cd iceoryx
$ git checkout release_2.0
$ mkdir build && cd build
$ cmake -G Ninja -DCMAKE_INSTALL_PREFIX={USER_LIBRARY_PATH} ../iceoryx_meta
$ ninja
$ sudo ninja install
```

### CycloneDDS

```bash
$ git clone https://github.com/eclipse-cyclonedds/cyclonedds.git
$ cd cyclonedds
$ mkdir build && cd build
$ cmake -G Ninja -DCMAKE_INSTALL_PREFIX={DDS_LIBRARY_PATH} -DCMAKE_PREFIX_PATH={DDS_LIBRARY_PATH} -DBUILD_EXAMPLES=ON ..
$ ninja 
$ sudo ninja install
```

DDS_LIBRARY_PATH 为用户指定安装DDS库的路径



## DDS Proxy on NanoMQ_CLI 

### 编译安装IDL代码生成器 idl-serial-code-gen

编译`IDL`代码生成器`idl-serial` 

```bash
$ git clone https://github.com/nanomq/idl-serial.git
$ cd idl-serial
$ mkdir build && cd build
$ cmake -G Ninja -DCMAKE_INSTALL_PREFIX={DDS_LIBRARY_PATH} ..
$ ninja 
$ sudo ninja install
```

编译完成生成可执行文件 `idl-serial-code-gen`

### 编译NanoMQ与DDS Proxy

1. 通过cmake参数`IDL_FILE_PATH`指定`idl`文件路径 (不指定则默认为 工程路径下的 `etc/idl/dds_type.idl`)

```
$ git clone https://github.com/emqx/nanomq.git $ cd nanomq $ mkdir build && cd build $ cmake -G Ninja -DIDL_FILE_PATH={IDL_PATH} -DCMAKE_PREFIX_PATH={DDS_LIBRARY_PATH} -DBUILD_DDS_PROXY=ON .. $ ninja  $ sudo ninja install
```

1. 执行以下命令查看是否已编译 `dds`

```
$ ./nanomq_cli/nanomq_cli  nanomq_cli { pub | sub | conn | nngproxy | nngcat | dds } [--help] available tools:   * pub   * sub   * conn   * nngproxy   * nngcat   * dds Copyright 2022 EMQ Edge Computing Team
```



### 配置

#### 配置DDS Proxy

##### 重点配置项:

###### DDS订阅与MQTT发布

- DDS订阅Topic

- -  `forward_rules.dds_to_mqtt.from_dds = "MQTTCMD/topic1"`

- MQTT发布Topic

- - `forward_rules.dds_to_mqtt.to_mqtt = "DDS/topic1"`

- 指定接收的DDS结构体名称

- - `forward_rules.dds_to_mqtt.struct_name = "remote_control_result_t"`

###### MQTT订阅与DDS发布

- MQTT订阅Topic

- -  `forward_rules.dds_to_mqtt.from_dds = "DDSCMD/topic1"`

- DDS发布Topic

- - `forward_rules.dds_to_mqtt.to_mqtt = "MQTT/topic1"`

- 指定发布的DDS结构体名称

- - `forward_rules.dds_to_mqtt.struct_name = "remote_control_req_t"`



```bash
## 转发规则配置
forward_rules = {
	  ## DDS to MQTT
    dds_to_mqtt = {
        from_dds = "MQTTCMD/topic1"
        to_mqtt = "DDS/topic1"
        struct_name = "remote_control_result_t"
    }
    ## MQTT to DDS
    mqtt_to_dds = {
        from_mqtt = "DDSCMD/topic1"
        to_dds = "MQTT/topic1"
        struct_name = "remote_control_req_t"
    }
}

## DDS 配置参数
dds {
    # # dds domain id
    # # default: 0
    # # Value: uint32
    domain_id = 0
    
    shared_memory = {
        # # Enable shared memory transport.
        # # Iceoryx is required if enable shared memory transport.
        # #
        # # Default: false
        # # Value:  boolean
        enable = false
        
        # # controls the output of the iceoryx runtime and can be set to, in order of decreasing output:
        # # log level: verbose, debug, info, warn, error, fatal, off
        # # Default:  info
        # # Value: enum
        log_level = info
    }
}

## MQTT 配置参数
mqtt {
	connector {
        # # Bridge address: host:port .
        # #
        # # Value: String
        # # Example: mqtt-tcp://127.0.0.1:1883
        # #          tls+mqtt-tcp://127.0.0.1:8883
        server = "mqtt-tcp://127.0.0.1:1883"
        
        # # Protocol version of the bridge.
        # #
        # # Value: Enum
        # # - 5: mqttv5
        # # - 4: mqttv311
        # # - 3: mqttv31
        proto_ver = 4
        # # The ClientId of a remote bridge.
        # # Default random string.
        # #
        # # Value: String
        # clientid="bridge_client"
        
        # # Ping: interval of a downward bridge.
        # #
        # # Value: Duration
        # # Default: 10 seconds
        keepalive = 60s
        # # The Clean start flag of a remote bridge.
        # #
        # # Value: boolean
        # # Default: false
        # #
        # # NOTE: Some IoT platforms require clean_start
        # #       must be set to 'true'
        clean_start = false
        # # The username for a remote bridge.
        # #
        # # Value: String
        username = username
        # # The password for a remote bridge.
        # #
        # # Value: String
        password = passwd
        
        ssl {
            # # enable ssl
            # # 
            # # Value: true | false
            enable = false
            # # Ssl key password
            # # String containing the user's password. Only used if the private keyfile
            # # is password-protected.
            # #
            # # Value: String
            key_password = "yourpass"
            # # Ssl keyfile
            # # Path of the file containing the client's private key.
            # #
            # # Value: File
            keyfile = "/etc/certs/key.pem"
            # # Ssl cert file
            # # Path of the file containing the client certificate.
            # #
            # # Value: File
            certfile = "/etc/certs/cert.pem"
            # # Ssl ca cert file
            # # Path of the file containing the server's root CA certificate.  
            # # 
            # # This certificate is used to identify the AWS IoT server and is publicly
            # # available.
            # #
            # # Value: File
            cacertfile = "/etc/certs/cacert.pem"
        }
    }
}
```



### 测试

1. 启动MQTT Broker

```bash
$ nanomq start
```

或

```bash
$ emqx start
```

2. 启动DDS Proxy

```bash
$ ./nanomq_cli dds proxy --conf nanomq_dds_gateway.conf
```

3. 启动MQTT客户端订阅主题 `DDS/topic1`

```bash
$ ./nanomq_cli sub --url "mqtt-tcp://127.0.0.1:1883" -t "DDS/topic1"
```

4. 启动DDS客户端, 指定结构体名称`remote_control_result_t`并发布消息(*命令行参数为JSON格式*)到DDS主题 `MQTTCMD/topic1`

```bash
$ ./nanomq_cli dds pub -t "MQTTCMD/topic1" --struct "remote_control_result_t"  -m '{
  "req_result_code": 1,
  "req_token": [1,2,3,4,5,6],
  "req_result_msg": [7,8,9,10,11],
  "req_id": [12,13,14],
  "req_token_len": 6,
  "req_id_len": 3
}'
```

5. 启动DDS客户端订阅DDS主题 `MQTT/topic1`并指定接收的结构体名称`remote_control_req_t`

```bash
$ ./nanomq_cli dds sub -t "MQTT/topic1" --struct "remote_control_req_t"
```

6. 启动MQTT客户端发布消息(*JSON*)到MQTT主题 `DDSCMD/topic1`

```bash
$ ./nanomq_cli pub --url "mqtt-tcp://127.0.0.1:1883" -t "DDSCMD/topic1" -m '{ 
  "req": 1,         
  "req_id": [15,16],
  "req_id_len": 2
 }'
```