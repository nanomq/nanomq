# NanoMQ Toolkit

NanoMQ 有丰富的工具集，其中包括 broker、 bench、 conn、 pub、 sub client。接下来将一一进行介绍。

## broker

NanoMQ 是一款用在物联网平台边缘端的超轻量 MQTT Broker。

| Parameter       | abbreviation | Optional value                         | Default value            | Description                                                  |
| --------------- | ------------ | -------------------------------------- | ------------------------ | ------------------------------------------------------------ |
| --url           | -            | -                                      | nmq-tcp://127.0.0.1:1883 | 指定监听的 url: 'nmq-tcp://host:port', 'tls+nmq-tcp://host:port' or 'nmq-ws://host:port/path' or 'nmq-wss://host:port/path' |
| --conf          | -            | -                                      | -                        | NanoMQ 配置文件路径                                          |
| --http          | -            | true false                             | false                    | Http 服务开关                                                |
| --port          | -p           | -                                      | 8081                     | Http 服务端口设置                                            |
| --tq_thread     | -t           | -                                      | -                        | Taskq 线程数量设置，最小为1， 最大为256                      |
| --max_tq_thread | -T           | -                                      | -                        | Taskq 最大线程数量设置，最小为1， 最大为256                  |
| --parallel      | -n           | -                                      | -                        | 可以处理的最大外部请求数                                     |
| --property_size | -s           | -                                      | -                        | MQTT 用户属性的最大数量                                      |
| --msq_len       | -S           | -                                      | -                        | 重发消息的最大数量                                           |
| --qos_duration  | -D           | -                                      | -                        | Qos 定时器时间间隔                                           |
| --daemon        | -d           | true false                             | false                    | Daemon 模式运行 NanoMQ                                       |
| --cacert        | -            | -                                      | -                        | PEM 编码 CA 证书路径                                         |
| --cert          | -E           | -                                      | -                        | 用户证书路径                                                 |
| --key           | -            | -                                      | -                        | PEM 编码用户私钥路径                                         |
| --keypass       | -            | -                                      | -                        | 用户密钥。在私钥受密钥保护的情况下使用。                     |
| --verify        | -            | true false                             | false                    | 设置对端证书验证                                             |
| --fail          | -            | true false                             | false                    | 客户端证书验证操作使能位。如果设置为true，客户端无证书时拒绝连接 |
| --log_level     | -            | trace, debug, info, warn, error, fatal | warn                     | 日志等级                                                     |
| --log_file      | -            | -                                      | -                        | 日志文件输出路径                                             |
| --log_stdout    | -            | true, false                            | true                     | 日志输出到控制台                                             |
| --log_syslog    | -            | true, false                            | false                    | 日志输出到Syslog (默认只支持兼容 POSIX 的系统)                       |

例如，我们在 url nmq-tcp://localhost:1884 上启动 NanoMQ 监听 MQTT 消息，在 url nmq-ws://localhost:8085 上启动 websocket 消息，在端口 30000 上启用 http 服务器。

```bash
$ nanomq start --url nmq-tcp://localhost:1884 --url nmq-ws://localhost:8085 --http -p 30000
```

nanomq命令行支持多个日志类型输出，例如以下同时启用三种输出类型, 并设置日志等级为debug：

```bash
$ nanomq start --log_level=debug --log_file=nanomq.log  --log_stdout=true --log_syslog=true
```

或启动时指定配置文件:

```bash
$ nanomq start --conf <config_file>
```



## NanoMQ Client

NanoMQ 的客户端工具在 `nanomq_cli` 中。目前客户端完整支持MQTT3.1.1，部分支持MQTT5.0 。

### Pub

执行 `nanomq_cli pub --help` 时，您将获得可用的参数输出。

| Parameter       | abbreviation | Optional value | Default value             | Description          |
| --------------- | ------------ | -------------- | ------------------------- | -------------------- |
| --host          | -h           | -              | Defaults to localhost.    | 远端 IP.  |
| --port          | -p           | -              | Defaults to 1883 TCP MQTT, 8883 for MQTT over TLS, 14567 for MQTT over QUIC | 远端端口.                                   |
| --quic          | -            | -              | Defaults to false. |  QUIC 传输选项            |
| --version       | -V           | 4 5          | 4                         | MQTT 协议版本        |
| --parallel      | -n           | -              | 1                         | 客户端并行数         |
| --verbose       | -v           | -              | disable                   | 是否详细输出         |
| --user          | -u           | -              | None; optional            | 客户端用户名         |
| --password      | -P           | -              | None; optional            | 客户端密码           |
| --topic         | -t           | -              | None; required            | 发布的主题           |
| --msg           | -m           | -              | None; required            | 发布的消息           |
| --qos           | -q           | -              | Publish: *0*<br>Subscribe: *1* | Qos 级别       |
| --retain        | -r           | true false     | false                     | 保留标识位           |
| --keepalive     | -k           | -              | 300                       | 保活时间             |
| --count         | -C           | -              | 1                         | 客户端数量           |
| --clean_session | -c           | true false     | true                      | 会话清除             |
| --ssl           | -s           | true false     | false                     | SSL 使能位           |
| --cafile        | -            | -              | None                      | SSL 证书             |
| --cert          | -E           | -              | None                      | 证书路径             |
| --key           | -            | true false     | false                     | 私钥路径             |
| --keypass       | -            | -              | None                      | 私钥密码             |
| --interval      | -I           | -              | 10                        | 创建客户端间隔（ms） |
| --identifier    | -i           | -              | random                    | 客户端订阅标识符     |
| --limit         | -L           | -              | 1                         | 最大发布消息刷量     |
| --stdin-line    | -l           | -              | false                     | 发送从 stdin 读取的消息，将单独的行拆分为单独的消息|
| --will-qos      | -            | -              | 0                         | 遗愿消息的 qos 级别  |
| --will-msg      | -            | -              | None                      | 遗愿消息             |
| --will-topic    | -            | -              | None                      | 遗愿消息主题         |
| --will-retain   | -            | true false     | false                     | 遗愿消息保留标示位   |

例如，我们使用用户名 nano 启动 1 个客户端，并向主题 `t` 发送 100 条 Qos2 消息测试。

```bash
$ nanomq_cli pub -t "topic" -q 2 -u nano -L 100 -m test -h broker.emqx.io -p 1883t
```

### Sub

执行 `nanomq_cli sub --help` 以获取该命令的所有可用参数。它们的解释已包含在上表中，此处不再赘述。

例如，我们使用用户名 nano 启动 1 个客户端，并从主题 `t` 设置 Qos1。

```bash
$ nanomq_cli sub -t t -q 1 -h broker.emqx.io -p 1883 
```

### Conn

执行 `nanomq_cli conn --help` 以获取该命令的所有可用参数。它们的解释已包含在上表中，此处不再赘述。

例如，我们使用用户名 nano 启动 1 个客户端并设置 Qos1 。

```bash
$ nanomq_cli conn -q 1 -h broker.emqx.io -p 1883
```

### Rule

执行 `nanomq_cli rules --help` 以获取该命令的所有可用参数。

#### rules create

创建一个新的规则。参数:

- *`<sql>`*: 规则 SQL
- *`<actions>`*: JSON 格式的动作列表

使用举例:
```bash
## 创建一个 sqlite 落盘规则，存储所有发送到 'abc' 主题的消息内容
$ nanomq_cli rules --create --sql 'SELECT * FROM "abc"' --actions '[{"name":"sqlite", "params": {"table": "test01"}}]'

{"rawsql":"SELECT * FROM \"abc\"","id":4,"enabled":true}

```

#### rules list

列出当前所有的规则:
```bash
$ nanomq_cli rules --list

{"rawsql":"SELECT payload.x.y as y, payload.z as z FROM \"#\" WHERE y > 10 and z != 'str'","id":1,"enabled":true}
{"rawsql":"SELECT * FROM \"abc\"","id":2,"enabled":true}
{"rawsql":"SELECT payload, qos FROM \"#\" WHERE qos > 0","id":3,"enabled":true}
{"rawsql":"SELECT * FROM \"abc\"","id":4,"enabled":true}

```
#### rules show

查询规则:
```bash
## 查询 RuleID 为 '1' 的规则
$ nanomq_cli rules --show --id 1

{"rawsql":"SELECT payload.x.y as y, payload.z as z FROM \"#\" WHERE y > 10 and z != 'str'","id":1,"enabled":true}
```
#### rules delete

删除规则:
```bash
## 删除 RuleID 为 'rule:1' 的规则
$ nanomq_cli rules --delete --id 1

{"code":0}
```



## Bench

Bench 是使用 NanoSDK 编写的简洁强大的 MQTT 协议性能测试工具。

### Compile 

**注意**：bench 工具默认不构建，您可以通过`-DBUILD_BENCH=ON` 启用它。

```bash
$ cmake -G Ninja -DBUILD_BENCH=ON ..
$ Ninja
```

编译完成后，会生成一个名为“nanomq”的可执行文件。执行以下命令确认可以正常使用：

```bash
$ nanomq_cli 
available tools:
   * pub
   * sub
   * conn
   * bench
   * nngproxy
   * nngcat
   * dds

Copyright 2022 EMQ Edge Computing Team
```

```bash
$ nanomq_cli bench
Usage: nanomq_cli bench { pub | sub | conn } [--help]
```

以上内容的输出证明`bench`已经被正确编译。

### 使用

`bench` 有三个子命令：

1. `pub`：用于创建大量客户端来执行发布消息的操作。
2. `sub`：用于创建大量客户端订阅主题和接收消息。
3. `conn`：用于创建大量连接。

### 发布

执行 `nanomq_cli bench pub --help` 时，您将获得可用的参数输出。

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
$ nanomq_cli bench pub -t t -h nanomq-server -s 16 -q 0 -c 10 -I 10
```

### 订阅

执行 `nanomq_cli bench sub --help` 以获取此子命令的所有可用参数。它们的解释已包含在上表中，此处不再赘述。

例如，我们启动 500 个连接，每个连接使用 Qos0 订阅 `t` 主题：

```bash
$ nanomq_cli bench sub -t t -h nanomq-server -c 500
```

### 连接

执行 `nanomq_cli bench conn --help` 以获取此子命令的所有可用参数。它们的解释已包含在上表中，此处不再赘述。

例如，我们启动 1000 个连接：

```bash
$ nanomq_cli bench conn -h nano-server -c 1000
```

### SSL 连接

`bench` 支持建立安全的 SSL 连接和执行测试。

单向认证

```bash
$ nanomq_cli bench sub -c 100 -i 10 -t bench -p 8883 -S
$ nanomq_cli bench pub -c 100 -I 10 -t bench -p 8883 -s 256 -S
```

双向认证

```bash
$ nanomq_cli bench sub -c 100 -i 10 -t bench -p 8883 --certfile path/to/client-cert.pem --keyfile path/to/client-key.pem
$ nanomq_cli bench pub -c 100 -i 10 -t bench -s 256 -p 8883 --certfile path/to/client-cert.pem --keyfile path/to/client-key.pem
```

