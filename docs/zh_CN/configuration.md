# Configuration

NanoMQ provides several options for optimizing performance according to your system.

## Configure method

NanoMQ can start with contents of configure file named `config.cmake.in`.

`$PROJECT_PATH/nanomq/build$ cmake -DCFG_METHOD=FILE_CONFIG ..`

Of course, NanoMQ can start with cmake-gui or cmake with arguments.

`$PROJECT_PATH/nanomq/build$ cmake -DCFG_METHOD=CMAKE_CONFIG ..`

## Arguments

limiting the number of threads:

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNNG_RESOLV_CONCURRENCY=1 -DNNG_NUM_TASKQ_THREADS=5 -DNNG_MAX_TASKQ_THREADS=5 ..
```

For debugging, NanoMQ has a debugging system that logs all information from all threads. Which is aligned with Syslog standard.
And you can disable/enable it by:

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=1  ..
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=0  ..
```

Message queue support:

For macos, mqueue is not support, you can set -DMQ=0 to disable it. It is enabled by default.

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=1  ..
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=0  ..
```

System tunning parameters:

set max size of fixed header + variable header for MQTT packet , default is 64 bytes

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_PACKET_SIZE=set ..
```

set max fixed header size for MQTT packet, default is 5.

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_HEADER_SIZE=set ..
```

set max property size for MQTT packet, default is 32

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_PROPERTY_SIZE=set ..
```

set queue length for QoS message, default is 64

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_QOS_LEN=set ..
```

set queue length for resending message, default is 64

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_MSQ_LEN=set ..
```

set nano qos timer, default is 30 seconds

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_QOS_TIMER=set ..
```

set logical concurrency limitation by *-DPARALLEL*, default is 32

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DPARALLEL=32 ..
```

For more information about these parameters, please refer to the project's Wiki
