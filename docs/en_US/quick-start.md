# QuickStart

## Compile & Install

To build NanoMQ, you will need a C99 & C++11 compatible compiler and [CMake](https://www.cmake.org/) version 3.13 or newer.

Basically, you need to compile and install NanoMQ by following steps :

`$PROJECT_PATH/nanomq$ mkdir build & cd build`

`$PROJECT_PATH/nanomq/build$ cmake -G Ninja ..`

`$PROJECT_PATH/nanomq/build$ sudo ninja install`

Or you can compile it without ninja:

`$PROJECT_PATH/nanomq$ mkdir build ; cd build; cmake .. ; make`

## Compile dependency

Please be aware that NanoMQ depends on nanolib & nng(nanonng for MQTT)

both dependencies can be compiled independently

`$PROJECT_PATH/nanomq/nng/build$ cmake -G Ninja ..`
`$PROJECT_PATH/nanomq/nng/build$ ninja install`

compile nanolib independently:

`$PROJECT_PATH/nanolib/build$ cmake -G Ninja ..`
`$PROJECT_PATH/nanolib/build$ ninja install`

## Start MQTT Broker

```sh
nanomq broker start 'tcp://localhost:1883' &
```

Currently, NanoMQ only supports MQTT 3.1.1, partially supports MQTT 5.0

## test POSIX message Queue

```sh
nanomq broker mq start/stop
```
