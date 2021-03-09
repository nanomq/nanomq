# NanoMQ

Nano MQTT Broker
A light-weight and Blazing-fast MQTT Broker for IoT Edge platform.
NanoMQ is base on NNG's asynchronous I/O threading model. With an extension of MQTT support in the protocol layer and reworked transport layer. Plus an enhanced asynchronous IO mechanism to maximize the throughout capacity.



## Features

1. Cost-effective on embedded platform.
2. Fully base on native POSIX. High Compatibility.
3. Pure C/C++ implementation. High portability.
4. Fully asynchronous I/O and multi-threading. 
5. Good support for SMP.
6. Low latency & High handling capacity.



## QuickStart

1. Compile & Install

To build NanoMQ, you will need a C99 & C++11 compatible compiler and [CMake](http://www.cmake.org/) version 3.13 or newer.

Basically, you need to compile and install NanoMQ by following steps :

`$PROJECT_PATH/nanomq$ mkdir build & cd build`

`$PROJECT_PATH/nanomq/build$ cmake -G Ninja ..` 

`$PROJECT_PATH/nanomq/build$ sudo ninja install`

Or you can compile it without ninja:

`$PROJECT_PATH/nanomq$ mkdir build ; cd build; cmake .. ; make`

2. Compile dependency

Please be aware that NanoMQ depends on nanolib & nng(nanonng for MQTT)

both dependencies can be compiled independently

`$PROJECT_PATH/nanomq/nng/build$ cmake -G Ninja ..` 
`$PROJECT_PATH/nanomq/nng/build$ ninja install`

compile nanolib independently:

`$PROJECT_PATH/nanolib/build$ cmake -G Ninja ..`
`$PROJECT_PATH/nanolib/build$ ninja install`


## Configuration

NanoMQ provides several options for optimizing performance according to your system.

### Configure method

NanoMQ can start with contents of configure file named `config.cmake.in`.

`$PROJECT_PATH/nanomq/build$ cmake -DCFG_METHOD=FILE_CONFIG ..`

Of course, NanoMQ can start with cmake-gui or cmake with arguments.

`$PROJECT_PATH/nanomq/build$ cmake -DCFG_METHOD=CMAKE_CONFIG ..`

### Arguments

limiting the number of threads:

```
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNNG_RESOLV_CONCURRENCY=1 -DNNG_NUM_TASKQ_THREADS=5 -DNNG_MAX_TASKQ_THREADS=5 ..
```

For debugging, NanoMQ has a debugging system that logs all information from all threads. Which is aligned with Syslog standard.
And you can disable/enable it by:

```
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=1  ..
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=0  ..
```

Message queue support:

For macos, mqueue is not support, you can set -DMQ=0 to disable it. It is enabled by default.

```
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=1  ..
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=0  ..
```

System tunning parameters:

set max size of fixed header + variable header for MQTT packet , default is 64 bytes
```
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_PACKET_SIZE=set ..
```

set max fixed header size for MQTT packet, default is 5.
```
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_HEADER_SIZE=set ..
```

set max property size for MQTT packet, default is 32
```
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_PROPERTY_SIZE=set ..
```

set queue length for QoS message, default is 64
```
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_QOS_LEN=set ..
```

set queue length for resending message, default is 64
```
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_MSQ_LEN=set ..
```

set nano qos timer, default is 30 seconds
```
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_QOS_TIMER=set ..
```

set logical concurrency limitation by *-DPARALLEL*, default is 32
```
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DPARALLEL=32 ..
```
For more information about these parameters, please refer to the project's Wiki

## Usage

#Start MQTT Broker

`nanomq broker start 'tcp://localhost:1883' &`

Currently, NanoMQ only supports MQTT 3.1.1, partially supports MQTT 5.0

#test POSIX message Queue

`nanomq broker mq start/stop`

## Communities

You can join us on the Slack channel:

#nanomq: general usage

#nanomq-dev : for MQTT lover & developer

#nanomq-nng : for users & nng project.

More communities on GitHub, Slack, Reddit, Twitter, Gitter, Discord are coming soon.

## Authors


The EMQ X team.
