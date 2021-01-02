# NanoMQ

Nano MQTT Broker
A light-weight and Blazing-fast MQTT Broker for IoT Edge platform.



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
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DNNG_RESOLV_CONCURRENCY=1 -DNNG_NUM_TASKQ_THREADS=5 -DNNG_MAX_TASKQ_THREADS=5  ..
or you can print log by

cmake -DNOLOG=0

Please be aware that nanomq depends on nanolib & nng (MQTT ver)

both dependencies can be complied independently

$PROJECT_PATH/nanomq/nng/build$ cmake -G Ninja .. 
$PROJECT_PATH/nanomq/nng/build$ ninja install

compile nanolib independently:
$PROJECT_PATH/nanolib/build$ cmake -G Ninja ..
$PROJECT_PATH/nanolib/build$ ninja install

Currently, NanoMQ only supports basic MQTT 3.1.1 Pub/Sub with Qos 0.
In short future, We will release a roadmap, and next version of NanoMQ with full MQTT 5.0 support. 
Also, in order to let NanoMQ be compatible with NNG library and SP, implementing a subsystem to let nanomq support MQTT without damaging NNG's SP support.
Rewriting CMake and MakeFile so that users can easily choose which ver of nng to base on.

===============================================

2. Usage:

#ongoing MQTT Broker
sudo ./nanomq broker start 'tcp://localhost:1883' &

#test POSIX message Queue
sudo ./nanomq broker mq start/stop

===============================================

3. Debug:

For Support & Debug, NanoMQ has a Debugging system which logs all information from all threads. It is enabled by default.
And you can disable/enable it by:

```
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DNOLOG=1  ..
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DNOLOG=0  ..
```

4. Mqueue support:

For macos, mqueue is not support, you can set -DMQ=0 to disable it. It is enabled by default.
```
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DMQ=1  ..
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DMQ=0  ..
```
5. More parameter support:
For macos, mqueue is not support, you can set -DMQ=0 to disable it. It is enabled by default.
```
set max emq packet size, default is 512
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DEMQ_PACKET_SIZE=set ..

set max emq header size, default is 5
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DEMQ_HEADER_SIZE=set ..

set emq property size, default is 32
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DEMQ_PROPERTY_SIZE=set ..

set nano qos length, default is 64
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DNANO_QOS_LEN=set ..

set nano msq length, default is 64
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DNANO_MSQ_LEN=set ..

set nano qos timer, default is 30
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DDNANO_QOS_TIMER=set ..

set nano publish client, default is 256
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DNANO_PUB_CLIENT=set ..
```
## Communties

You can Join us on Slack channel:

#nanomq: general usage

#nanomq-dev : for MQTT lover & developer

#nanomq-nng : for users & nng project.

More communities on github, slack, reddit, twitter, gitter, discord are coming soon.

## Authors


The EMQ X team.
