# Docker部署

本章节将指导您使用官方 Docker 镜像快速安装和运行 EMQX，并提供Docker部署的配置方法。



## 通过Docker运行NanoMQ

本节主要介绍如何通过 Docker 镜像安装最新版本的 EMQX，如希望体验其他版本，可以前往 [NanoMQ 下载页面](https://www.emqx.com/zh/try?product=nanomq)。

1. 运行以下命令获取 Docker 镜像：

```bash
docker pull emqx/nanomq:lastest
```

2. 运行以下命令启动 Docker 容器

```bash
docker run -d --name nanomq -p 1883:1883 -p 8083:8083 -p 8883:8883 emqx/nanomq:latest
```

有关 NanoMQ 官方镜像的更多信息，请查看 [Docker Hub - nanomq](https://hub.docker.com/r/emqx/nanomq)

### 配置

Docker容器中修改配置文件可使用以下几种方式:

- 在Docker容器中修改`/etc/nanomq.conf`来达到修改配置参数的目的, 可参考[配置说明](./config-description/v014.md) ;

- 将本机已修改的配置文件通过docker cp命令拷贝到容器中 `/etc/nanomq.conf`路径:  `docker cp nanomq.conf nanomq:/etc/nanomq.conf`

- 通过环境变量修改配置参数, 例如: 

```bash
docker run -d -p 1883:1883 -p 8883:8883 \
           -e NANOMQ_BROKER_URL="nmq-tcp://0.0.0.0:1883" \
           -e NANOMQ_TLS_ENABLE=true \
           -e NANOMQ_TLS_URL="tls+nmq-tcp://0.0.0.0:8883" \
           --name nanomq emqx/nanomq
```

> 具体参数描述见下表

#### NanoMQ 环境变量

| 变量名                          | 数据类型 | 描述                                                      |
| ------------------------------- | -------- | --------------------------------------------------------- |
| NANOMQ_BROKER_URL               | String   | 'nmq-tcp://host:port', 'tls+nmq-tcp://host:port'          |
| NANOMQ_DAEMON                   | Boolean  | 后台启动（_默认 false _）                                 |
| NANOMQ_NUM_TASKQ_THREAD         | Integer  | 任务线程数  (设置范围: 0 ~ 256).                          |
| NANOMQ_MAX_TASKQ_THREAD         | Integer  | 最大任务线程数 (设置范围: 0 ~ 256).                       |
| NANOMQ_PARALLEL                 | Long     | 并行数.                                                   |
| NANOMQ_PROPERTY_SIZE            | Integer  | 最大属性长度.                                             |
| NANOMQ_MSQ_LEN                  | Integer  | 队列长度.                                                 |
| NANOMQ_QOS_DURATION             | Integer  | QOS消息定时间隔时间.                                      |
| NANOMQ_ALLOW_ANONYMOUS          | Boolean  | 允许匿名登录 (默认: true).                                |
| NANOMQ_WEBSOCKET_ENABLE         | Boolean  | 启动websocket监听（_默认true_）.                          |
| NANOMQ_WEBSOCKET_URL            | String   | 'nmq-ws://host:port/path', 'nmq-wss://host:port/path'     |
| NANOMQ_HTTP_SERVER_ENABLE       | Boolean  | 启动Http服务监听（_默认false_).                           |
| NANOMQ_HTTP_SERVER_PORT         | Integer  | Http服务端监听端口 (默认: 8081).                          |
| NANOMQ_HTTP_SERVER_USERNAME     | String   | 访问Http服务用户名.                                       |
| NANOMQ_HTTP_SERVER_PASSWORD     | String   | 访问Http服务密码.                                         |
| NANOMQ_TLS_ENABLE               | Boolean  | 启动TLS监听（_默认false_) .                               |
| NANOMQ_TLS_URL                  | String   | 'tls+nmq-tcp://host:port'.                                |
| NANOMQ_TLS_CA_CERT_PATH         | String   | TLS CA证书数据。                                          |
| NANOMQ_TLS_CERT_PATH            | String   | TLS Cert证书数据。                                        |
| NANOMQ_TLS_KEY_PATH             | String   | TLS私钥数据.                                              |
| NANOMQ_TLS_KEY_PASSWORD         | String   | TLS私钥密码.                                              |
| NANOMQ_TLS_VERIFY_PEER          | Boolean  | 验证客户端证书(*默认false*).                              |
| NANOMQ_TLS_FAIL_IF_NO_PEER_CERT | Boolean  | 拒绝无证书连接，与 tls.verify_peer 配合使用(*默认false*). |
| NANOMQ_LOG_TO                   | String   | 日志输出类型数组，使用竖线`|`分隔多种类型<br>支持文件，控制台，Syslog输出，对应参数:<br>file, console, syslog |
| NANOMQ_LOG_LEVEL                | String   | 日志等级：trace, debug, info, warn, error, fatal |
| NANOMQ_LOG_DIR                  | String   | 日志文件存储路径 (输出文件时生效) |
| NANOMQ_LOG_FILE                 | String   | 日志文件名(输出文件时生效) |
| NANOMQ_LOG_ROTATION_SIZE        | String   | 每个日志文件的最大占用空间;<br>支持单位: `KB| MB | GB`;<br> 默认:`10MB` |
| NANOMQ_LOG_ROTATION_COUNT       | Integer  | 轮换的最大日志文件数;<br> 默认: `5` |
| NANOMQ_CONF_PATH                | String   | NanoMQ配置文件路径 (*默认: `/etc/nanomq.conf`*).          |