# Build Options

NanoMQ provides several options for optimizing performance according to your system.



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

**System tunning parameters:**

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

**Note (optional) build NanoMQ with QUIC bridging feature** This enable NanoMQ bridging with EMQX 5.0 via MQTT over QUIC protocol

  ``` bash
  cmake -G Ninja -DNNG_ENABLE_QUIC=ON ..
  ninja
  ```
  Attention: MQTT over QUIC bridging requires libmsquic preinstalled, for now we do not release formal binary package with QUIC support due to compatability.

**Note (optional): TLS is disabled by default**. If you want to build with TLS support you will also need [mbedTLS](https://tls.mbed.org). After installing [mbedTLS](https://tls.mbed.org), you can enable it by `-DNNG_ENABLE_TLS=ON`.

```bash
cmake -G Ninja -DNNG_ENABLE_TLS=ON ..
ninja
```

**Note (optional): client ( pub / sub / conn ) is built by default**, you can disable it via `-DBUILD_CLIENT=OFF`.

  ``` bash
  cmake -G Ninja -DBUILD_CLIENT=OFF ..
  ninja
  ```
**Note (optional): gateway tool isn't built by default**, you can enable it via `-DBUILD_ZMQ_GATEWAY=ON`.

  ``` bash
  cmake -G Ninja -DBUILD_ZMQ_GATEWAY=ON ..
  ninja
  ```

**Note (optional): bench tool isn't built by default**, you can enable it via `-DBUILD_BENCH=ON`.

  ``` bash
  cmake -G Ninja -DBUILD_BENCH=ON ..
  ninja
  ```

**Note (optional): JWT dependency (for http server) isn't built by default**, you can enable it via `-DENABLE_JWT=ON`.

  ``` bash
  cmake -G Ninja -DENABLE_JWT=ON ..
  ninja
  ```

**Note (optional): SQLite3 (for message persistence) isn't built by default**, you can enable it via `-DNNG_ENABLE_SQLITE=ON`.

  ``` bash
  cmake -G Ninja -DNNG_ENABLE_SQLITE=ON ..
  ninja
  ```

**Note (optional): nanomq as a static lib isn't built by default**, you can enable it via `-DBUILD_STATIC_LIB=ON`.
```bash
cmake -G Ninja -DBUILD_STATIC_LIB=ON ..
ninja libnano
```
**Note (optional): nanomq as a shared lib isn't built by default**, you can enable it via `-DBUILD_SHARED_LIBS=ON`.
```bash
cmake -G Ninja -DBUILD_SHARED_LIBS=ON ..
ninja
```

**Note (optional): nanonng are dependency of NanoMQ that can be compiled independently**.

To compile nanonng (*nanonng is the fork of nng repository with MQTT support*):

```bash
cd nng/build
cmake -G Ninja ..
ninja
```


