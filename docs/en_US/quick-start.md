# QuickStart



## Compile & Install

To build NanoMQ, you will need a C99 & C++11 compatible compiler and [CMake](https://www.cmake.org/) version 3.13 or newer.

Basically, you need to compile and install NanoMQ by following steps :

```bash
$ mkdir build
$ cd build
$ cmake -G Ninja ..
$ sudo ninja install
```

Or you can compile it without ninja:

```bash
$ mkdir build 
$ cd build
$ cmake .. 
$ make
```



## Compile dependency

Please be aware that NanoMQ depends on nanolib & nng

both dependencies can be compiled independently

```bash
$PROJECT_PATH/nanomq/nng/build$ cmake -G Ninja ..
$PROJECT_PATH/nanomq/nng/build$ ninja install
```

compile nanolib independently:

```bash
$PROJECT_PATH/nanolib/build$ cmake -G Ninja ..
$PROJECT_PATH/nanolib/build$ ninja install
```



## Start MQTT Broker

```bash
nanomq broker start &
```

Currently, NanoMQ only supports MQTT 3.1.1, partially supports MQTT 5.0



## MQTT Client

```bash
# Publish
nanomq pub  start --url <url> -t <topic> -m <message> [--help]

# Subscribe
nanomq sub  start --url <url> -t <topic> [--help]

# Connect*
nanomq conn start --url <url> [--help]
```



## Test POSIX message Queue

```sh
nanomq mq start/stop
```
