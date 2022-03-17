# Build Options

NanoMQ provides several options for optimizing performance according to your system.



## Configure method

NanoMQ can start with contents of configure file named `config.cmake.in`.

```bash
$PROJECT_PATH/nanomq/build$ cmake -DCFG_METHOD=FILE_CONFIG ..
```

Of course, NanoMQ can start with cmake-gui or cmake with arguments.

```bash
$PROJECT_PATH/nanomq/build$ cmake -DCFG_METHOD=CMAKE_CONFIG ..
```



## Arguments

Limiting the number of threads:

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNNG_RESOLV_CONCURRENCY=1                                														 -DNNG_NUM_TASKQ_THREADS=5 -DNNG_MAX_TASKQ_THREADS=5 ..
```

For debugging, NanoMQ has a debugging system that logs all information from all threads. Which is aligned with Syslog standard.
And you can disable/enable it by:

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=1  ..
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=0  ..
```

MQTT client support: 

MQTT client is enabled by default，it can be disabled with -DBUILD_CLIENT=OFF:

```bash
# Disable client
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DBUILD_CLIENT=OFF ..
# Enable client
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DBUILD_CLIENT=ON ..
```

Message queue support:

For macos, mqueue is not support, you can set -DMQ=0 to disable it. It is enabled by default.

```sh
# Enable MQ
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=1  ..
# Disable MQ
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=0  ..
```

System tunning parameters:

Set max size of fixed header + variable header for MQTT packet , default is 64 bytes:

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_PACKET_SIZE={size} ..
```

Set max fixed header size for MQTT packet, default is 5:

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_HEADER_SIZE={size} ..
```

Set max property size for MQTT packet, default is 32:

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_PROPERTY_SIZE={size} ..
```

Set queue length for QoS message, default is 64:

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_QOS_LEN={size} ..
```

Set queue length for resending message, default is 64:

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_MSQ_LEN={size} ..
```


Set logical concurrency limitation by -DPARALLEL, default is 32:

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DPARALLEL={PARALLEL} ..
```

For more information about these parameters, please refer to the project's Wiki.

