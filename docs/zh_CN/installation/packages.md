# Linux

针对 Linux 用户，NanoMQ 目前提供四种部署版本，您可从下表中了解各版本的功能差异：

| 功能               | NanoMQ 基础版 | NanoMQ **SQLite版** | **NanoMQ MsQuic版** | NanoMQ完整版 |
| ------------------ | ------------- | ------------------- | ------------------- | ------------ |
| MQTT Broker功能    | ✅             | ✅                   | ✅                   | ✅            |
| TLS/SSL            | ✅              | ✅                   | ✅                   | ✅            |
| SQLite             | ❌             | ✅                   | ❌                   | ✅            |
| 规则引擎            | ❌             | ❌                   | ✅                   | ✅            |
| MQTT over TCP桥接  | ✅             | ✅                   | ✅                   | ✅            |
| MQTT over TLS桥接  | ✅             | ✅                   | ✅                   | ✅            |
| MQTT over QUIC桥接 | ❌             | ❌                   | ✅                   | ✅            |
| AWS桥接 *          | ❌             | ❌                   | ❌                   | ❌            |
| ZMQ网关            | ❌             | ❌                   | ❌                   | ✅            |
| SOME/IP网关        | ❌             | ❌                   | ❌                   | ❌            |
| DDS网关            | ❌             | ❌                   | ❌                   | ❌            |
| Bench基准测试工具  | ❌             | ❌                   | ✅                   | ✅            |

[^*]: Docker 部署中暂不支持 AWS 桥接，如希望使用 AWS 桥接，请通过[源码编译安装](./build-options.md)。

您可根据具体业务需求，选择适合的 NanoMQ 安装版本，并在安装命令中将 `nanomq` 替换为相应的版本代码：

- SQLite 版的NanoMQ：`nanomq-sqlite`
- MsQuic 版的NanoMQ：`nanomq-msquic`
- NanoMQ 完整版：`nanomq-full`

## 安装 NanoMQ

**使用 Apt/Yum 源安装**

| 操作系统                                 | 安装方法 |
| ---------------------------------------- | -------- |
| 基于 Debian 的发行版，如 Ubuntu          | Apt      |
| 基于 Red Hat的 发行版，如 CentOS，Fedora | Yum      |

**使用包安装**

| 架构        | Debian 包 (.deb) | RPM 包 (.rpm) |
| ----------- | ---------------- | ------------- |
| **amd64**   | 是               | 否            |
| **arm64**   | 是               | 是            |
| **riscv64** | 是               | 是            |
| **mips**    | 是               | 是            |
| **armhf**   | 是               | 是            |
| **armel**   | 是               | 是            |
| **X86_64**  | 否               | 是            |

## 使用 Apt 源安装

NanoMQ 支持使用 Apt 源安装，为用户提供了一种便捷可靠的方式来管理 NanoMQ 的安装和更新。以下是如何使用 Apt 源安装 NanoMQ 的方法：

1. 下载 NanoMQ 仓库：

   ```bash
   curl -s https://assets.emqx.com/scripts/install-nanomq-deb.sh | sudo bash
   ```

2. 安装 NanoMQ：

   ```bash
   sudo apt-get install nanomq
   ```

3. 启动 NanoMQ：

   ```bash
   nanomq start  
   ```

## 使用 Yum 源安装

对于基于 Red Hat 的发行版，如 CentOS，Fedora，NanoMQ 也支持使用 Yum 源安装。以下是如何使用 Yum 源安装NanoMQ的方法：

1. 下载 NanoMQ 仓库：

   ```bash
   curl -s https://assets.emqx.com/scripts/install-nanomq-rpm.sh | sudo bash
   ```

2. 安装 NanoMQ：

   ```bash
   sudo yum install -y nanomq
   ```

3. 启动 NanoMQ：

   ```bash
   nanomq start  
   ```

## 使用包安装

本节以在 arm64 架构下安装 v0.18.2 为例，更多安装选项，您可以参考 [NanoMQ 下载](https://nanomq.io/downloads?os=Linux)页面。

1. 下载 [anomq-0.18.2-linux-x86_64.rpm](https://www.emqx.com/zh/downloads/nanomq/0.18.2/nanomq-0.18.2-linux-x86_64.rpm).

   ```bash
   wget https://www.emqx.com/en/downloads/nanomq/0.18.2/nanomq-0.18.2-linux-arm64.deb
   ```

2. 安装 NanoMQ

   ```bash
   sudo apt install ./nanomq-0.18.2-linux-arm64.deb
   ```

3. 运行 NanoMQ

   ```bash
   nanomq start
   ```

## 使用 AUR 安装

AUR（Arch 用户仓库）是针对基于 Arch 的 Linux 发行版用户的由社区驱动的仓库。它包含名为 PKGBUILD 的包描述，它可让你使用 makepkg 从源代码编译软件包，然后通过 pacman（Arch Linux 中的软件包管理器）安装。NanoMQ 支持通过 AUR 安装。


- 安装基础版

  ```bash
  yay -S nanomq
  ```

- 安装 SQLite 版

  ```bash
  yay -S nanomq-sqlite
  ```

- 安装 MsQuic 版

  ```bash
  yay -S nanomq-msquic
  ```

- 安装完整版

  ```bash
  yay -S nanomq-full
  ```

## 安装包内容

二进制安装包内容有：
| 文件目录     | 作用                 |
| ----------- | ------------------- |
| **/etc**    | 所有的 NanoMQ 配置文件 |
| **/usr/local/bin**   |   NanoMQ 的可执行文件   |
| **/usr/local/lib**   | NanoMQ 内部的静态和动态库文件               |

