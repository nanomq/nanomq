# NanoMQ Toolkit

NanoMQ 有丰富的工具集，其中包括 broker、 bench、 conn、 pub、 sub client。接下来将一一进行介绍。

## broker

NanoMQ 是一款用在物联网平台边缘端的超轻量 MQTT Broker。

| Parameter       | abbreviation | Optional value | Default value            | Description                                                  |
| --------------- | ------------ | -------------- | ------------------------ | ------------------------------------------------------------ |
| --url           | -            | -              | nmq-tcp://127.0.0.1:1883 | 指定监听的 url: 'nmq-tcp://host:port', 'tls+nmq-tcp://host:port' or 'nmq-ws://host:port/path' or 'nmq-wss://host:port/path' |
| --conf          | -            | -              | -                        | NanoMQ 配置文件路径                                          |
| --bridge        | -            | -              | -                        | 桥接配置文件路径                                             |
| --auth          | -            | -              | -                        | 认证配置文件路径                                             |
| --http          | -            | true false     | false                    | Http 服务开关                                                |
| --port          | -p           | -              | 8081                     | Http 服务端口设置                                            |
| --tq_thread     | -t           | -              | -                        | Taskq 线程数量设置，最小为1， 最大为256                      |
| --max_tq_thread | -T           | -              | -                        | Taskq 最大线程数量设置，最小为1， 最大为256                  |
| --parallel      | -n           | -              | -                        | 可以处理的最大外部请求数                                     |
| --property_size | -s           | -              | -                        | MQTT 用户属性的最大数量                                      |
| --msq_len       | -S           | -              | -                        | 重发消息的最大数量                                           |
| --qos_duration  | -D           | -              | -                        | Qos 定时器时间间隔                                           |
| --daemon        | -d           | true false     | false                    | Daemon 模式运行 NanoMQ                                       |
| --cacert        | -            | -              | -                        | PEM 编码 CA 证书路径                                         |
| --cert          | -E           | -              | -                        | 用户证书路径                                                 |
| --key           | -            | -              | -                        | PEM 编码用户私钥路径                                         |
| --keypass       | -            | -              | -                        | 用户密钥。在私钥受密钥保护的情况下使用。                     |
| --verify        | -            | true false     | false                    | 设置对端证书验证                                             |
| --fail          | -            | true false     | false                    | 客户端证书验证操作使能位。如果设置为true，客户端无证书时拒绝连接 |

例如，我们在 url nmq-tcp://localhost:1884 上启动 NanoMQ 监听 MQTT 消息，在 url nmq-ws://localhost:8085 上启动 websocket 消息，在端口 30000 上启用 http 服务器。

```bash
$ nanomq broker start --url nmq-tcp://localhost:1884 --url nmq-ws://localhost:8085 --http -p 30000
```

## bench

Bench 是使用 NanoSDK 编写的简洁强大的 MQTT 协议性能测试工具。

### Compile 

**注意**：bench 工具默认不构建，您可以通过`-DBUILD_BENCH=ON` 启用它。

```bash
$ cmake -G Ninja -DBUILD_BENCH=ON ..
$ Ninja
```

编译完成后，会生成一个名为“nanomq”的可执行文件。执行以下命令确认可以正常使用：

```bash
$ nanomq
available applications:
   * broker
   * pub
   * sub
   * conn
   * bench
   * nngcat

EMQX Edge Computing Kit v0.6.0-3
Copyright 2022 EMQX Edge Team
```

```bash
$ nanomq bench start
Usage: nanomq bench start { pub | sub | conn } [--help]
```

以上内容的输出证明`bench`已经被正确编译。

### 使用

`bench` 有三个子命令：

1. `pub`：用于创建大量客户端来执行发布消息的操作。
2. `sub`：用于创建大量客户端订阅主题和接收消息。
3. `conn`：用于创建大量连接。

### 发布

执行 `nanomq bench start pub --help` 时，您将获得可用的参数输出。

| Parameter         | abbreviation | Optional value | Default value  | Description               |
| ----------------- | ------------ | -------------- | -------------- | ------------------------- |
| --host            | -h           | -              | localhost      | 服务端地址                |
| --port            | -p           | -              | 1883           | 服务端端口                |
| --version         | -V           | 3 4 5          | 5              | MQTT 协议版本             |
| --count           | -c           | -              | 200            | 客户端数量                |
| --interval        | -i           | -              | 10             | 创建客户端的时间间隔 (ms) |
| --interval_of_msg | -I           | -              | 1000           | 发布消息时间间隔          |
| --username        | -u           | -              | None; optional | 客户端用户名              |
| --password        | -P           | -              | None; optional | 客户端密码                |
| --topic           | -t           | -              | None; required | 发布主题                  |
| --size            | -s           | -              | 256            | 消息负载的大小            |
| --qos             | -q           | -              | 0              | Qos 服务级别              |
| --retain          | -r           | true false     | false          | 保留消息标示位            |
| --keepalive       | -k           | -              | 300            | 保活时间                  |
| --clean           | -C           | true false     | true           | 清理会话标示位            |
| --ssl             | -S           | true false     | false          | SSL 使能位                |
| --certfile        | -            | -              | None           | 客户端 SSL 证书           |
| --keyfile         | -            | -              | None           | 客户端私钥                |
| --ws              | -            | true false     | false          | 是为建立 websocket 连接   |

例如，我们启动 10 个连接，每秒向主题 t 发送 100 条 Qos0 消息，其中每个消息负载的大小为 16 字节：

```bash
$ nanomq bench start pub -t t -h nanomq-server -s 16 -q 0 -c 10 -I 10
```

### 订阅

执行 `nanomq bench start sub --help` 以获取此子命令的所有可用参数。它们的解释已包含在上表中，此处不再赘述。

例如，我们启动 500 个连接，每个连接使用 Qos0 订阅 `t` 主题：

```bash
$ nanomq bench start sub -t t -h nanomq-server -c 500
```

### 连接

执行 `nanomq bench start conn --help` 以获取此子命令的所有可用参数。它们的解释已包含在上表中，此处不再赘述。

例如，我们启动 1000 个连接：

```bash
$ nanomq bench start conn -h nano-server -c 1000
```

### SSL 连接

`bench` 支持建立安全的 SSL 连接和执行测试。

单向认证

```bash
$ nanomq bench start sub -c 100 -i 10 -t bench -p 8883 -S
$ nanomq bench start pub -c 100 -I 10 -t bench -p 8883 -s 256 -S
```

双向认证

```bash
$ nanomq bench start sub -c 100 -i 10 -t bench -p 8883 --certfile path/to/client-cert.pem --keyfile path/to/client-key.pem
$ nanomq bench start pub -c 100 -i 10 -t bench -s 256 -p 8883 --certfile path/to/client-cert.pem --keyfile path/to/client-key.pem
```

## client

目前客户端支持 MQTT 版本 3.1/3.1.1。

### Pub

执行 `nanomq pub --help` 时，您将获得可用的参数输出。

| Parameter       | abbreviation | Optional value | Default value             | Description          |
| --------------- | ------------ | -------------- | ------------------------- | -------------------- |
| --url           | -            | -              | mqtt-tcp://127.0.0.1:1883 | 连接到服务端的 url   |
| --version       | -V           | 3 4 5          | 4                         | MQTT 协议版本        |
| --parallel      | -n           | -              | 1                         | 客户端并行数         |
| --verbose       | -v           | -              | disable                   | 是否详细输出         |
| --user          | -u           | -              | None; optional            | 客户端用户名         |
| --password      | -P           | -              | None; optional            | 客户端密码           |
| --topic         | -t           | -              | None; required            | 发布的主题           |
| --msg           | -m           | -              | None; required            | 发布的消息           |
| --qos           | -q           | -              | 0                         | Qos 级别             |
| --retain        | -r           | true false     | false                     | 保留标识位           |
| --keepalive     | -k           | -              | 300                       | 保活时间             |
| --count         | -C           | -              | 1                         | 客户端数量           |
| --clean_session | -c           | true false     | true                      | 会话清除             |
| --ssl           | -s           | true false     | false                     | SSL 使能位           |
| --cacert        | -            | -              | None                      | SSL 证书             |
| --cert          | -E           | -              | None                      | 证书路径             |
| --key           | -            | true false     | false                     | 私钥路径             |
| --keypass       | -            | -              | None                      | 私钥密码             |
| --interval      | -i           | -              | 10                        | 创建客户端间隔（ms） |
| --identifier    | -I           | -              | random                    | 客户端订阅标识符     |
| --limit         | -L           | -              | 1                         | 最大发布消息刷量     |
| --will-qos      | -            | -              | 0                         | 遗愿消息的 qos 级别  |
| --will-msg      | -            | -              | None                      | 遗愿消息             |
| --will-topic    | -            | -              | None                      | 遗愿消息主题         |
| --will-retain   | -            | true false     | false                     | 遗愿消息保留标示位   |

例如，我们使用用户名 nano 启动 1 个客户端，并向主题 `t` 发送 100 条 Qos2 消息测试。

```bash
$ nanomq pub start -t t -h nanomq-server -q 2 -u nano -L 100 -m test
```

### Sub

执行 `nanomq sub start --help` 以获取该命令的所有可用参数。它们的解释已包含在上表中，此处不再赘述。

例如，我们使用用户名 nano 启动 1 个客户端，并从主题 `t` 设置 Qos1。

```bash
$ nanomq sub start -t t -h nanomq-server -q 1
```

### Conn

执行 `nanomq conn start --help` 以获取该命令的所有可用参数。它们的解释已包含在上表中，此处不再赘述。

例如，我们使用用户名 nano 启动 1 个客户端并设置 Qos1 。

```bash
$ nanomq conn start -h nanomq-server -q 1
```

