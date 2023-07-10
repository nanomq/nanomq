# 源码编译安装

作为一款用于物联网边缘的超轻量级 MQTT 消息服务器，NanoMQ 支持在各种边缘平台运行，例如支持 x86_64 和 ARM 等架构。

## 前置准备

正式安装前，请先安装以下依赖项：

- 支持 C99 标准的编译环境
- Git
- [CMake](https://www.cmake.org/)：3.13 或以上

## 源码编译

在 NanoMQ 的安装目录，运行以下命令进行编译：
*Ninja非必须，可以使用传统 Make 命令编译*

:::: tabs type:card

::: tab 通过 Ninja 编译（推荐）

```bash
git clone https://github.com/emqx/nanomq.git
cd nanomq
git submodule update --init --recursive
mkdir build && cd build
cmake -G Ninja ..
ninja
```
:::
::: tab 通过 make 编译

```bash
git clone https://github.com/emqx/nanomq.git 
cd nanomq
git submodule update --init --recursive
mkdir build && cd build
cmake .. 
make
```

:::

::::

编译完成后，您将在命令行窗口看到类似提示：

 ```bash
[495/495] Linking CXX executable nng/tests/cplusplus_pair
 ```

## 启动 NanoMQ

编译完成后，您可在 `build` -> `NanoMQ` 找到相关可执行文件。

运行以下命令启动 NanoMQ：

```bash
./nanomq start
```

成功启动后，您可在命令行窗口看到以下提示：

```bash
NanoMQ Broker is started successfully!
```

## 更多编译选项

除常见设置（如 `CMAKE_BUILD_TYPE`）外，你还可通过 CMake 配置更多高级功能，如启用 [MQTT over QUIC](../bridges/quic-bridge) 数据桥接或 [ZMQ 网关](../gateway/zmq-gateway)，一些常见的编译选项参见下表：

| 编译选项                 | 说明                                                         |
| ------------------------ | ------------------------------------------------------------ |
| `-DNNG_ENABLE_QUIC=ON`   | 启用 QUIC 桥接                                               |
| `-DENABLE_AWS_BRIDGE=ON` | 启用 AWS IoT Core 桥接<br />注意：AWS IoT Core 桥接与 MQTT over QUIC 桥接暂不兼容，请选择启用一种桥接。 |
| `-DNNG_ENABLE_TLS=ON`    | 编译启用 TLS，依赖项：[mbedTLS](https://tls.mbed.org/)       |
| `-DBUILD_CLIENT=OFF`     | 停用客户端套件，包括 pub、sub 、conn                         |
| `-DBUILD_ZMQ_GATEWAY=ON` | 启用 ZeroMQ 网关                                             |
| `-DBUILD_DDS_PROXY=ON`   | 启用 DDS Proxy，包括 proxy、sub、pub                         |
| `-DBUILD_VSOMEIP_GATEWAY`| 开启 vsomeip gateway                                        |
| `-DBUILD_NNG_PROXY`      | 开启 nng proxy                                              |
| `-DBUILD_BENCH=ON`       | 编译启用 MQTT Bench                                          |
| `-DENABLE_JWT=ON`        | 编译启用 HTTP Server 所需的 JWT 依赖项                       |
| `-DNNG_ENABLE_SQLITE=ON` | 支持 SQLite                                                  |
| `-DBUILD_STATIC_LIB=ON`  | 作为静态库编译                                               |
| `-DBUILD_SHARED_LIBS=ON` | 作为共享库编译                                               |
| `-DDEBUG=ON`             | 启用调试标志                                                 |
| `-DASAN=ON`              | 启用 Sanitizer                                               |
| `-DNOLOG=1`              | 关闭 Log 系统，提高性能                                |
| `-DDEBUG_TRACE=ON`       | 启用 ptrace，用于进程跟踪和检查                              |
| `-DENABLE_RULE_ENGINE=ON`| 启用规则引擎                                           |
| `-DENABLE_MYSQL=ON`      | 启用 MySQL                                                 |
| `-DENABLE_ACL`           | 启用 ACL                                                   |
| `-DENABLE_SYSLOG`        | 启用 syslog                                                |
| `-DNANOMQ_TESTS`         | 启用 NanoMQ 单元测试                                     |


### MQTT over QUIC 数据桥接

依赖项：libmsquic

NanoMQ 支持通过 MQTT over QUIC 协议与 EMQX 5 进行桥接。

由于兼容性问题，目前尚未发布支持 QUIC 的二进制包。如希望使用 MQTT over QUIC，应通过编译方式安装 NanoMQ，命令如下：

```bash
cmake -G Ninja -DNNG_ENABLE_QUIC=ON ..
ninja
```

### TLS

依赖项: [mbedTLS](https://tls.mbed.org/)

默认情况下，TLS 为未启用状态。如希望启用，可在编译阶段通过 `-DNNG_ENABLE_TLS=ON` 启用。

`Ninja`：

```bash
cmake -G Ninja -DNNG_ENABLE_TLS=ON ..
```

`make`：

```bash
cmake -DNNG_ENABLE_TLS=ON ..
```

::: tip

关于 TLS 的详细配置参数，可参考配置文件  `etc/nanomq_example.conf`

:::

### 客户端管理

NanoMQ 会在构建时默认安装客户端工具（pub、sub 、conn）。如希望禁用客户端工具，可通过 `-DBUILD_CLIENT=OFF` 实现：

```bash
cmake -G Ninja -DBUILD_CLIENT=OFF ..
ninja
```

### 网关工具

默认情况下，网关为未启用状态。如希望启用，如 ZMQ 网关，可通过 `-DBUILD_ZMQ_GATEWAY=ON` 实现：

```
cmake -G Ninja -DBUILD_ZMQ_GATEWAY=ON ..
ninja
```

### Benchmark 基准测试工具 

默认情况下，Benchmark 为未启用状态。如希望启用，可通过 `-DBUILD_BENCH=ON` 实现：

```
cmake -G Ninja -DBUILD_BENCH=ON ..
ninja
```

### JWT 依赖

HTTP Server 的  JWT 依赖默认未启用。如希望启用，可通过 `-DENABLE_JWT=ON` 实现：

```
cmake -G Ninja -DENABLE_JWT=ON ..
ninja
```

### SQLite 支持

NanoMQ 支持通过 SQLite3 实现消息的持久化，该功能默认未启用。如希望启用，可通过 `-DNNG_ENABLE_SQLITE=ON` 实现：

```
cmake -G Ninja -DNNG_ENABLE_SQLITE=ON ..
ninja
```

### 静态库

如通过以静态库的方式编译 NanoMQ，可通过 `-DBUILD_STATIC_LIB=ON` 实现：

```
cmake -G Ninja -DBUILD_STATIC_LIB=ON ..
ninja libnano
```

### 共享库

如通过以共享库的方式编译 NanoMQ，可通过  `-DBUILD_SHARED_LIBS=ON` 实现：

```
cmake -G Ninja -DBUILD_SHARED_LIBS=ON ..
ninja
```

### NanoNNG 依赖

NanoNNG 是含 MQTT 支持的 NNG 仓库分支，由 NanoMQ 自行维护，可单独编译：

```
cd nng/build
cmake -G Ninja ..
ninja
```

## 性能调优

NanoMQ 提供了多种性能调优方式，您可根据需求进行选择。

## 参数设置

**线程数量限制**

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNNG_RESOLV_CONCURRENCY=1                                														 -DNNG_NUM_TASKQ_THREADS=5 -DNNG_MAX_TASKQ_THREADS=5 ..
```

**调试**：NanoMQ 提供调试功能，启用后，将按照 Syslog 标准记录所有线程信息。您可选择禁用/启用该功能。

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=1  ..
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=0  ..
```

**MQTT 客户端**：MQTT 客户端默认启用，您可通过 `-DBUILD_CLIENT=OFF` 禁用。

```bash
# Disable client
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DBUILD_CLIENT=OFF ..
# Enable client
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DBUILD_CLIENT=ON ..
```

**消息队列**：mqueue 消息队列默认启用，但 macOS 系统中暂不支持，您可通过 `-DMQ=0` 禁用。

```sh
# Enable MQ
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=1  ..
# Disable MQ
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=0  ..
```

### 系统调优

::: tip

运行以下命令前，请根据实际场景替换 `{size}`、 `{PARALLEL}` 字段。

:::

为 MQTT 数据包设置**固定头**加**可变头**最大长度，默认为 64 字节：

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_PACKET_SIZE={size} ..
```

为 MQTT 数据包设置**固定头**最大长度，默认为 5 字节：

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_HEADER_SIZE={size} ..
```

为 MQTT 数据包设置**属性**最大长度，默认为 32 字节：

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_PROPERTY_SIZE={size} ..
```

为 QOS > 0的消息设置队列长度，默认为 64：

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_QOS_LEN={size} ..
```

设置重发消息的队列长度，默认为 64：

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_MSQ_LEN={size} ..
```


设置逻辑并发数限制，默认为 32，使用 -DPARALLEL 指定：

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DPARALLEL={PARALLEL} ..
```

