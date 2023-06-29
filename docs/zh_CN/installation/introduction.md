# 安装

本节介绍了如何通过各种方法安装 NanoMQ，比如通过 Docker 安装，通过安装包安装，或通过源码编译安装。

**[通过 Docker 安装](./docker.md)**

本节主要介绍了如何通过 Docker 安装和运行 NanoMQ，以及通过配置文件或环境变量进行配置。 

**[通过安装包安装](./packages.md)**

NanoMQ 目前提供以下安装包：

| 安装包           | 描述                                                         |
| ---------------- | ------------------------------------------------------------ |
| AUR (Arch Linux) | Arch Linux 用户可通过 AUR 源安装 NanoMQ，目前支持安装 NanoMQ 基本版、sqlite 版、msquic 版和完整版。 |
| deb 一键安装     | Ubuntu 用户可通过 deb 包一键安装 NanoMQ。                    |
| deb 手动安装     | Ubuntu 用户也可将官方的 EMQX NanoMQ 软件库添加到源列表中，并使用 apt-get 手动安装 NanoMQ。 |
| rpm 一键安装     | CentOS 可通过 rpm 包一键安装。                               |
| rpm 手动安装     | CentOS 用户也可将官方的 EMQX NanoMQ 软件库添加到 yum 配置中，并使用 yum 手动安装 NanoMQ。 |

**[ 通过源代码编译安装](./build-options.md)**

NanoMQ 同样支持基于从源代码编译和安装，本节同时提供了编译参数列表，以便更好地满足用户的需求。