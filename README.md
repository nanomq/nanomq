# NanoMQ

Nano MQTT Broker

A light-weight and Blazing-fast MQTT 5.0 Broker for IoT Edge platform.



## Features

1. Cost-effective on embedded platform.
2. Fully base on native POSIX. High Compatibility.
3. Pure C/C++ implementation. High portability.
4. Fully asynchronous I/O and multi-threading. 
5. Good support for SMP.
6. Low latency & High handling capacity.



## QuickStart

1. Compile & Install

NanoMQ is base on NNG's asynchronous I/O threading model. With rewriting the TCP/SP part with self-added protocol: nano_tcp.

To build this whole project, you will need a C99 compatible & C++11 compiler and [CMake](http://www.cmake.org/) version 3.13 or newer.

Basically you just need to simply compile and install nanomq by:

$PROJECT_PATH/nanomq$ mkdir build & cd build

$PROJECT_PATH/nanomq/build$ cmake -G Ninja .. 

$PROJECT_PATH/nanomq/build$ sudo ninja install

or you can limit threads by
cmake -G Ninja -DNNG_RESOLV_CONCURRENCY=1 -DNNG_NUM_TASKQ_THREADS=5 -DNNG_MAX_TASKQ_THREADS=5  ..

Please be aware that nanomq depends on nanolib & nng (MQTT ver)

both dependencies can be complied independently

$PROJECT_PATH/nanomq/nng/build$ cmake -G Ninja .. 
$PROJECT_PATH/nanomq/nng/build$ ninja install

compile nanolib independently:
$PROJECT_PATH/nanolib/build$ cmake -G Ninja ..
$PROJECT_PATH/nanolib/build$ ninja install

In short future, We will  implement a way to let nanomq support MQTT without damaging NNG's SP support.
Also rewrite CMake and MakeFile so that user can easily choose which ver of nng to base on.

TODO:

more features coming

===============================================

2. Usage:

#ongoing MQTT Broker
sudo ./nanomq broker start 'tcp://localhost:1883' &

#test POSIX message Queue
sudo ./nanomq broker mq start/stop  

## Communties

You can Join us on Slack channel:

#nanomq: general usage

#nanomq-dev : for MQTT lover & developer

#nanomq-nng : for users & nng project.



More communities on github, slack, reddit, twitter, gitter, discord are coming soon.

## Authors

The EMQ X team.