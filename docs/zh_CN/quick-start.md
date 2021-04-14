# 快速开始

## 编译和安装

编译 NanoMQ 需要支持 C99 和 C++ 11 标准的编译环境和高于 3.13 的 [CMake](https://cmake.org/) 版本。

你需要通过以下步骤来编译和安装 NanoMQ：

`$PROJECT_PATH/nanomq$ mkdir build & cd build`

`$PROJECT_PATH/nanomq/build$ cmake -G Ninja ..`

`$PROJECT_PATH/nanomq/build$ sudo ninja install`

或者你可以不用 ninja 来编译：

`$PROJECT_PATH/nanomq$ mkdir build ; cd build; cmake .. ; make`

## 编译依赖

请注意，NanoMQ 依赖于 nanolib 和 ng ( nanonng 为 MQTT )

两个依赖项都可以独立编译

`$PROJECT_PATH/nanomq/nng/build$ cmake -G Ninja ..`
`$PROJECT_PATH/nanomq/nng/build$ ninja install`

独立编译 nanolib：

`$PROJECT_PATH/nanolib/build$ cmake -G Ninja ..`
`$PROJECT_PATH/nanolib/build$ ninja install`

## 启动 MQTT Broker

```sh
nanomq broker start 'tcp://localhost:1883' &
```

目前，NanoMQ 只支持 MQTT 3.1.1，部分支持 MQTT 5.0。

## 测试 POSIX 消息队列

```sh
nanomq broker mq start/stop
```
