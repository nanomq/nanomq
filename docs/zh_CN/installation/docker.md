# Docker 部署指南

本节将指导您使用官方 Docker 镜像快速安装和运行 NanoMQ，以及 Docker 部署模式下如何加载自定义配置。我们将以最新版的 NanoMQ 为例进行说明，如希望体验其他版本，可前往 [NanoMQ 下载页面](https://www.emqx.com/zh/try?product=nanomq)。

## 拉取 Docker 镜像

NanoMQ 目前提供了三个 Docker 部署版本，功能差异见下表：<!-- this should be checked before the final release-->

| 功能                 | NanoMQ 基础版（默认） | NanoMQ Slim 版 | NanoMQ 完整版 |
| -------------------- | --------------------- | -------------- | ------------- |
| MQTT Broker 功能     | ✅                     | ✅              | ✅             |
| TLS/SSL              | ❌                     | ✅              | ✅             |
| SQLite               | ❌                     | ✅              | ✅             |
| 规则引擎             | ❌                     | ❌              | ✅             |
| MQTT over TCP 桥接   | ✅                     | ✅              | ✅             |
| MQTT over QUIC 桥接  | ❌                     | ❌              | ✅             |
| AWS 桥接 *           | ❌                     | ❌              | ❌             |
| ZMQ 网关             | ❌                     | ❌              | ✅             |
| SOME/IP 网关         | ❌                     | ❌              | ❌             |
| DDS 网关             | ❌                     | ❌              | ❌             |
| Bench 基准测试工具集 | ❌                     | ❌              | ✅             |

[^*]: Docker 部署中暂不支持 AWS 桥接，如希望使用 AWS 桥接，请通过[源码编译安装](./build-options.md)。

您可根据需要选择要拉取的 Docker 镜像，如`latest`，此时将拉取最新的基础版镜像：

```bash
docker pull emqx/nanomq:latest
```

如希望拉取指定版本 Slim 或者完整版镜像，还应指定版本号：

如

```bash
docker pull emqx/nanomq:0.18.2-slim
```

或完整版

```bash
docker pull emqx/nanomq:0.18.2-full
```

有关 NanoMQ 官方镜像的更多信息，请查看 [Docker Hub - nanomq](https://hub.docker.com/r/emqx/nanomq)。

## 通过 Docker 运行 NanoMQ

运行以下命令启动 NanoMQ：

```bash
docker run -d --name nanomq -p 1883:1883 -p 8083:8083 -p 8883:8883 emqx/nanomq:latest
```

## 加载自定义配置

NanoMQ 也支持通过配置文件或环境变量加载自定义配置。

### 通过配置文件加载

如希望通过配置文件启动 NanoMQ：

- 在 Docker 容器中修改 `/etc/nanomq.conf`

- 将本机已修改的配置文件通过 docker cp 命令拷贝到容器中 `/etc/nanomq.conf`路径：

   `docker cp nanomq.conf nanomq:/etc/nanomq.conf`

以下为 MQTT 桥接配置示例，更多关于 NanoMQ 的配置项说明，可参考 [配置说明](../config-description/introduction.md)：

```bash
bridges.mqtt.name {
	server = "mqtt-tcp://broker.emqx.io:1883"
	proto_ver = 4
	clean_start = true
	keepalive = 60s
	forwards = [
		{
			remote_topic = "fwd/topic1"
			local_topic = "topic1"
		}
		{
			remote_topic = "fwd/topic2"
			local_topic = "topic2"
		}
	]
	subscription = [
		{
			remote_topic = "cmd/topic1"
			local_topic = "topic3"
			qos = 1
		},
		{
			remote_topic = "cmd/topic2"
			local_topic = "topic4"
			qos = 2
		}
	]
	max_parallel_processes = 2 
	max_send_queue_len = 1024
	max_recv_queue_len = 1024
}
```

完成配置文件的更新后，可运行以下命令启动 NanoMQ：

```
docker run -d -p 1883:1883 -v {YOU LOCAL PATH}: /etc \
            --name nanomq  emqx/nanomq:latest
```

### 通过环境变量加载

NanoMQ 也支持通过环境变量自定义配置，支持的环境变量列表如下：

| 变量名                          | 数据类型 | 描述                                                         |
| ------------------------------- | -------- | ------------------------------------------------------------ |
| NANOMQ_BROKER_URL               | String   | `nmq-tcp://host:port`<br /> `tls+nmq-tcp://host:port`        |
| NANOMQ_DAEMON                   | Boolean  | 后台启动（默认：False）                                      |
| NANOMQ_NUM_TASKQ_THREAD         | Integer  | 任务线程数  (范围：0 ~ 256)                                  |
| NANOMQ_MAX_TASKQ_THREAD         | Integer  | 最大任务线程数 (范围：0 ~ 256)                               |
| NANOMQ_PARALLEL                 | Long     | 并行数                                                       |
| NANOMQ_PROPERTY_SIZE            | Integer  | 最大属性长度                                                 |
| NANOMQ_MSQ_LEN                  | Integer  | 队列长度                                                     |
| NANOMQ_QOS_DURATION             | Integer  | QoS 消息定时间隔时间                                         |
| NANOMQ_ALLOW_ANONYMOUS          | Boolean  | 允许匿名登录（默认：True）                                   |
| NANOMQ_WEBSOCKET_ENABLE         | Boolean  | 启动 WebSocket 监听（默认：True）                            |
| NANOMQ_WEBSOCKET_URL            | String   | `nmq-ws://host:port/path` 								  |
| NANOMQ_WEBSOCKET_TLS_URL        | String   | `nmq-wss://host:port/path` 							   |
| NANOMQ_HTTP_SERVER_ENABLE       | Boolean  | 启动 HTTP 服务监听（默认：False）                            |
| NANOMQ_HTTP_SERVER_PORT         | Integer  | HTTP 服务端监听端口（默认：8081）                            |
| NANOMQ_HTTP_SERVER_USERNAME     | String   | 访问 HTTP 服务的用户名                                       |
| NANOMQ_HTTP_SERVER_PASSWORD     | String   | 访问 HTTP 服务的密码                                         |
| NANOMQ_TLS_ENABLE               | Boolean  | 启动 TLS 监听（默认：False）                                 |
| NANOMQ_TLS_URL                  | String   | 'tls+nmq-tcp://host:port'.                                   |
| NANOMQ_TLS_CA_CERT_PATH         | String   | TLS CA 证书数据                                              |
| NANOMQ_TLS_CERT_PATH            | String   | TLS Cert 证书数据                                            |
| NANOMQ_TLS_KEY_PATH             | String   | TLS 私钥数据                                                 |
| NANOMQ_TLS_KEY_PASSWORD         | String   | TLS 私钥密码                                                 |
| NANOMQ_TLS_VERIFY_PEER          | Boolean  | 验证客户端证书 (默认：False）                                |
| NANOMQ_TLS_FAIL_IF_NO_PEER_CERT | Boolean  | 拒绝无证书连接，与 tls.verify_peer 配合使用（默认：False）   |
| NANOMQ_LOG_TO                   | String   | 日志输出类型数组，使用竖线 `|` 分隔多种类型<br />支持文件，控制台，Syslog输出，对应参数:<br />file, console, syslog |
| NANOMQ_LOG_LEVEL                | String   | 日志等级：trace, debug, info, warn, error, fatal             |
| NANOMQ_LOG_DIR                  | String   | 日志文件存储路径（输出文件时生效）                           |
| NANOMQ_LOG_FILE                 | String   | 日志文件名（输出文件时生效）                                 |
| NANOMQ_LOG_ROTATION_SIZE        | String   | 每个日志文件的最大占用空间<br />单位：`KB| MB | GB`<br />默认：`10MB` |
| NANOMQ_LOG_ROTATION_COUNT       | Integer  | 轮换的最大日志文件数<br /> 默认： `5`                        |
| NANOMQ_CONF_PATH                | String   | NanoMQ 配置文件路径（默认: `/etc/nanomq.conf`）              |

**示例：通过环境变量指定配置文件路径**

```bash
docker run -d -p 1883:1883 -e NANOMQ_CONF_PATH="/usr/local/etc/nanomq.conf" \
            [-v {LOCAL PATH}:{CONTAINER PATH}] \
            --name nanomq emqx/nanomq:0.14.0-slim
```

## 性能调优

为了获取更优异的性能表现，您可在配置文件  `nanomq.conf`  中调整以下配置项的设置：

| 配置项                  | 类型    | 描述                                                         |
| ----------------------- | ------- | ------------------------------------------------------------ |
| system.num_taskq_thread | Long    | 使用的 taskq 线程数，推荐设为 CPU 核数。                     |
| system.max_taskq_thread | Long    | 可使用的最大 taskq 线程数，推荐设为 CPU 核数。               |
| system.parallel         | Long    | 并行处理数，推荐设为 CPU 核数的两倍。                        |
| mqtt.session.msq_len    | Integer | 用于重发消息的 Inflight 窗口/队列长度。如内存允许，推荐设为最大值：65535。 |

**示例**

比如在一个 4 核操作系统中，可进行如下设置，更新将在重启 NanoMQ 后生效。

```bash
system.num_taskq_thread = 4
system.max_taskq_thread = 4
system.parallel = 8
mqtt.session.msq_len = 65535
```

