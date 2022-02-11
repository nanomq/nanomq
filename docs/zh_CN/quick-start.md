# 快速开始

## 编译和安装

编译 NanoMQ 需要支持 C99 和 C++ 11 标准的编译环境和高于 3.13 的 [CMake](https://cmake.org/) 版本。

你需要通过以下步骤来编译和安装 NanoMQ：

```bash
$ mkdir build
$ cd build
$ cmake -G Ninja ..
$ sudo ninja install
```

或者你可以不用 ninja 来编译：

```bash
$ mkdir build 
$ cd build
$ cmake .. 
$ make
```

可增加cmake编译参数`NNG_ENABLE_TLS`来支持**TLS**连接:
>需提前安装 [mbedTLS](https://tls.mbed.org).
```bash
cmake -G Ninja -DNNG_ENABLE_TLS=ON ..
```
或者
```bash
cmake -DNNG_ENABLE_TLS=ON ..
```
> 查看配置文件 `nanomq.conf` 了解更多TLS相关配置参数.

## 编译依赖

请注意，NanoMQ 依赖于 nanolib 和 nng

两个依赖项都可以独立编译

```bash
$PROJECT_PATH/nanomq/nng/build$ cmake -G Ninja ..
$PROJECT_PATH/nanomq/nng/build$ ninja install
```

独立编译 nanolib：

```bash
$PROJECT_PATH/nanolib/build$ cmake -G Ninja ..
$PROJECT_PATH/nanolib/build$ ninja install
```



## 启动 MQTT Broker

```bash
nanomq broker start &
```

目前，NanoMQ 只支持 MQTT 3.1.1，部分支持 MQTT 5.0。



## 使用MQTT Client

```bash
# Publish
nanomq pub  start --url <url> -t <topic> -m <message> [--help]

# Subscribe
nanomq sub  start --url <url> -t <topic> [--help]

# Connect*
nanomq conn start --url <url> [--help]
```



## 测试 POSIX 消息队列

```bash
nanomq mq start/stop
```
