# NFTP

nftp 是基于MQTT的轻量级文件传输工具。

## 编译 

**注意**： nftp 工具默认不构建，您可以通过`-DBUILD_NFTP=ON` 启用它。

```bash
$ mkdir build && cd build
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

