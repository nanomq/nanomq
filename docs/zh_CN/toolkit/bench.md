# Bench

Bench 是使用 NanoSDK 编写的简洁强大的 MQTT 协议性能测试工具。

## Compile 

**注意**： bench 工具默认不构建，您可以通过`-DBUILD_BENCH=ON` 启用它。

```bash
$ cmake -G Ninja -DBUILD_BENCH=ON ..
$ Ninja
```

编译完成后，会生成一个名为“ nanomq_cli ”的可执行文件。执行以下命令确认可以正常使用：

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

## 使用

`bench` 有三个子命令：

1. `pub`：用于创建大量客户端来执行发布消息的操作。
2. `sub`：用于创建大量客户端订阅主题和接收消息。
3. `conn`：用于创建大量连接。

## 发布

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

## 订阅

执行 `nanomq_cli bench sub --help` 以获取此子命令的所有可用参数。它们的解释已包含在上表中，此处不再赘述。

例如，我们启动 500 个连接，每个连接使用 Qos0 订阅 `t` 主题：

```bash
$ nanomq_cli bench sub -t t -h nanomq-server -c 500
```

## 连接

执行 `nanomq_cli bench conn --help` 以获取此子命令的所有可用参数。它们的解释已包含在上表中，此处不再赘述。

例如，我们启动 1000 个连接：

```bash
$ nanomq_cli bench conn -h nano-server -c 1000
```

## SSL 连接

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

# nftp

nftp 是基于MQTT的轻量级文件传输工具。

## Compile 

**注意**： nftp 工具默认不构建，您可以通过`-DBUILD_NFTP=ON` 启用它。

```bash
$ cmake -G Ninja -DBUILD_NFTP=ON ..
$ Ninja
```

编译完成后，会生成一个名为“ nanomq_cli ”的可执行文件。执行以下命令确认可以正常使用：

```bash
$ nanomq_cli 
available tools:
   * pub
   * sub
   * conn
   * bench
   * nngproxy
   * nngcat
   * nftp

Copyright 2022 EMQ Edge Computing Team
```

```bash
$ nanomq_cli nftp
Usage: nanomq_cli nftp { send | recv } [<opts>]
```

以上内容的输出证明`nftp`已经被正确编译。

## 使用

`nftp` 有两个子命令：

1. `send`：用于传输文件。
2. `recv`：用于接受文件。

先在接收端，启动nftp接收客户端。再在发送端，启动nftp发送客户端。具体用法参见下面内容。

## 参数

执行 `nanomq_cli nftp --help` 时，您将获得可用的参数输出。

| Parameter         | abbreviation | Optional value | Default value     | Description               |
| ----------------- | ------------ | -------------- | ----------------- | ------------------------- |
| --url             | -            | -              | localhost         | Broker地址                |
| --file            | -f           | -              | None; required    | 文件路径                  |
| --dir             | -d           | -              | current directory | 接收文件目录               |

## 发送

执行 `nanomq_cli nftp send --help` 以获取此子命令的所有可用参数。

例如，我们发送`/tmp/aaa/filename.c`文件：

```bash
$ nanomq_cli nftp send --file /tmp/aaa/filename.c
```

## 接收

执行 `nanomq_cli nftp recv --help` 以获取此子命令的所有可用参数。

例如，我们启动接收，并将收到的文件保存到`/tmp/`目录下：

```bash
$ nanomq_cli nftp recv -dir /tmp/
```

