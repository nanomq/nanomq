# 使用命令行

## broker

NanoMQ 是一款用在物联网平台边缘端的超轻量 MQTT Broker 。

| Parameter       | abbreviation | Optional value                         | Default value            | Description                                                  |
| --------------- | ------------ | -------------------------------------- | ------------------------ | ------------------------------------------------------------ |
| --url           | -            | -                                      | nmq-tcp://127.0.0.1:1883 | 指定监听的 url: 'nmq-tcp://host:port', 'tls+nmq-tcp://host:port' or 'nmq-ws://host:port/path' or 'nmq-wss://host:port/path' |
| --conf          | -            | -                                      | -                        | NanoMQ 配置文件路径                                          |
| --http          | -            | true false                             | false                    | Http 服务开关                                                |
| --port          | -p           | -                                      | 8081                     | Http 服务端口设置                                            |
| --tq_thread     | -t           | -                                      | -                        | Taskq 线程数量设置，最小为 1 ， 最大为 256                      |
| --max_tq_thread | -T           | -                                      | -                        | Taskq 最大线程数量设置，最小为 1 ， 最大为 256                  |
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
| --fail          | -            | true false                             | false                    | 客户端证书验证操作使能位。如果设置为 true ，客户端无证书时拒绝连接 |
| --log_level     | -            | trace, debug, info, warn, error, fatal | warn                     | 日志等级                                                     |
| --log_file      | -            | -                                      | -                        | 日志文件输出路径                                             |
| --log_stdout    | -            | true, false                            | true                     | 日志输出到控制台                                             |
| --log_syslog    | -            | true, false                            | false                    | 日志输出到 Syslog (默认只支持 Linux 系统)                       |

例如，我们在 url nmq-tcp://localhost:1884 上启动 NanoMQ 监听 MQTT 消息，在 url nmq-ws://localhost:8085 上启动 websocket 消息，在端口 30000 上启用 http 服务器。

```bash
$ nanomq start --url nmq-tcp://localhost:1884 --url nmq-ws://localhost:8085 --http -p 30000
```

nanomq 命令行支持多个日志类型输出，例如以下同时启用三种输出类型, 并设置日志等级为 debug ：

```bash
$ nanomq start --log_level=debug --log_file=nanomq.log  --log_stdout=true --log_syslog=true
```

或启动时指定配置文件:

```bash
$ nanomq start --conf <config_file>
```



## Client

目前客户端完整支持 MQTT3.1.1 ，部分支持 MQTT5.0 。

### Pub

执行 `nanomq pub --help` 时，您将获得可用的参数输出。

| Parameter       | abbreviation | Optional value                                               | Default value                  | Description          |
| --------------- | ------------ | ------------------------------------------------------------ | ------------------------------ | -------------------- |
| --url           | -            | mqtt-tcp://host:port<br/>tls+mqtt-tcp://host:port<br/>mqtt-quic://host<br/> | mqtt-tcp://127.0.0.1:1883      | 连接到服务端的 url   |
| --version       | -V           | 4 5                                                          | 4                              | MQTT 协议版本        |
| --parallel      | -n           | -                                                            | 1                              | 客户端并行数         |
| --verbose       | -v           | -                                                            | disable                        | 是否详细输出         |
| --user          | -u           | -                                                            | None; optional                 | 客户端用户名         |
| --password      | -P           | -                                                            | None; optional                 | 客户端密码           |
| --topic         | -t           | -                                                            | None; required                 | 发布的主题           |
| --msg           | -m           | -                                                            | None; required                 | 发布的消息           |
| --qos           | -q           | -                                                            | Publish: *0*<br>Subscribe: *1* | Qos 级别             |
| --retain        | -r           | true false                                                   | false                          | 保留标识位           |
| --keepalive     | -k           | -                                                            | 300                            | 保活时间             |
| --count         | -C           | -                                                            | 1                              | 客户端数量           |
| --clean_session | -c           | true false                                                   | true                           | 会话清除             |
| --ssl           | -s           | true false                                                   | false                          | SSL 使能位           |
| --cacert        | -            | -                                                            | None                           | SSL 证书             |
| --cert          | -E           | -                                                            | None                           | 证书路径             |
| --key           | -            | true false                                                   | false                          | 私钥路径             |
| --keypass       | -            | -                                                            | None                           | 私钥密码             |
| --interval      | -i           | -                                                            | 10                             | 创建客户端间隔（ ms ） |
| --identifier    | -I           | -                                                            | random                         | 客户端订阅标识符     |
| --limit         | -L           | -                                                            | 1                              | 最大发布消息刷量     |
| --will-qos      | -            | -                                                            | 0                              | 遗愿消息的 qos 级别  |
| --will-msg      | -            | -                                                            | None                           | 遗愿消息             |
| --will-topic    | -            | -                                                            | None                           | 遗愿消息主题         |
| --will-retain   | -            | true false                                                   | false                          | 遗愿消息保留标示位   |

例如，我们使用用户名 nano 启动 1 个客户端，并向主题 `t` 发送 100 条 Qos2 消息测试。

```bash
$ nanomq_cli pub -t t --url "mqtt-tcp://broker.emqx.io:1883" -q 2 -u nano -L 100 -m test
```

### Sub

执行 `nanomq_cli sub --help` 以获取该命令的所有可用参数。它们的解释已包含在上表中，此处不再赘述。

例如，我们使用用户名 nano 启动 1 个客户端，并从主题 `t` 设置 Qos1 。

```bash
$ nanomq_cli sub -t t --url "mqtt-tcp://broker.emqx.io:1883" -q 1
```

### Conn

执行 `nanomq_cli conn --help` 以获取该命令的所有可用参数。它们的解释已包含在上表中，此处不再赘述。

例如，我们使用用户名 nano 启动 1 个客户端并设置 Qos1 。

```bash
$ nanomq_cli conn --url "mqtt-tcp://broker.emqx.io:1883" -q 1
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



## 