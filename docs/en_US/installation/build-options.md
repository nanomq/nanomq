# Build from Source Code

NanoMQ is dedicated to providing a powerful messaging hub that can be used on various edge platforms. The tool can be run on different architectures like x86_64 and ARM, requiring only minor migration efforts.

## Prerequisites

Before you begin, ensure you have the following installed:

- A C99-compatible compiler
- Git
- [CMake](https://www.cmake.org/): 3.13 or later

## Compile from the Source Code

1. Navigate to the directory where you want to clone and build NanoMQ.

2. Choose your compilation method, either `Ninja` (recommended) or `make`.

   :::: tabs type:card

   ::: tab Compile with Ninja

   ```bash
   git clone https://github.com/emqx/nanomq.git
   cd nanomq
   git submodule update --init --recursive
   mkdir build && cd build
   cmake -G Ninja ..
   ninja
   ```
   :::
   ::: tab Compile with make

   ```bash
   git clone https://github.com/emqx/nanomq.git 
   cd nanomq
   git submodule update --init --recursive
   mkdir build && cd build
   cmake .. 
   make
   ```

   :::

   ::::

Wait until the terminal indicates that all required modules are compiled. For example, you should see something like:

 ```bash
 [495/495] Linking CXX executable nng/tests/cplusplus_pair
 ```

## Start NanoMQ

Once compiled, you can start NanoMQ by following the steps below:

1. Navigate to the `nanomq` directory within the `build` directory, where the `nanomq` executable file is located.

2. Run the command below to start NanoMQ

   ```bash
   ./nanomq start
   ```

A successful start of NanoMQ is indicated by the terminal message:

```bash
NanoMQ Broker is started successfully!
```



## Advanced Compilation Options

Apart from common settings like `CMAKE_BUILD_TYPE`, you can specify additional configurations for NanoMQ using CMake. This allows you to enable features such as an [MQTT over QUIC](../bridges/quic-bridge) data bridge or a [ZMQ gateway](../gateway/zmq-gateway). See the table below for a list of commonly used build options.

| Build Option             | Description                                                  |
| ------------------------ | ------------------------------------------------------------ |
| `-DNNG_ENABLE_QUIC=ON`   | Enables the QUIC bridging feature in NanoMQ.                 |
| `-DENABLE_AWS_BRIDGE=ON` | Enables the AWS IoT Core bridging feature. <br />**Note**: This feature is not compatible with MQTT over QUIC bridging. Users can operate only one type of bridging at a time. |
| `-DNNG_ENABLE_TLS=ON`    | Builds NanoMQ with TLS support. Dependency: [mbedTLS](https://tls.mbed.org/). |
| `-DBUILD_CLIENT=OFF`     | Disables the client suite, including pub, sub, and conn.     |
| `-DBUILD_ZMQ_GATEWAY=ON` | Builds with ZeroMQ gateway tool.                             |
| `-DBUILD_DDS_PROXY=ON`   | Builds with DDS proxy (proxy, sub, pub).                     |
| `-DBUILD_VSOMEIP_GATEWAY`| Build vsomeip gateway                                        |
| `-DBUILD_NNG_PROXY`      | Build nng proxy                                              |
| `-DBUILD_BENCH=ON`       | Builds with MQTT bench.                                      |
| `-DENABLE_JWT=ON`        | Builds JWT dependency for the HTTP server.                   |
| `-DNNG_ENABLE_SQLITE=ON` | Builds with SQLite support.                                  |
| `-DBUILD_STATIC_LIB=ON`  | Builds as a static library.                                  |
| `-DBUILD_SHARED_LIBS=ON` | Builds as a shared library.                                  |
| `-DDEBUG=ON`             | Enables the debug flag.                                      |
| `-DASAN=ON`              | Enables sanitizer.                                           |
| `-DNOLOG=1`              | Disable the log system to improve system performance         |
| `-DDEBUG_TRACE=ON`       | Enables ptrace, allowing process tracing and inspection.     |
| `-DENABLE_RULE_ENGINE=ON`| Enable rule engine                                           |
| `-DENABLE_MYSQL=ON`      | Enable MySQL                                                 |
| `-DENABLE_ACL`           | Enable ACL                                                   |
| `-DENABLE_SYSLOG`        | Enable syslog                                                |
| `-DNANOMQ_TESTS`         | Enable nanomq unit tests                                     |

### MQTT over QUIC Data Bridge

NanoMQ supports bridging with EMQX 5.0 via MQTT over QUIC protocol. This feature requires libmsquic preinstalled. Note that as of now, we do not release a formal binary package with QUIC support due to compatibility issues. To enable QUIC bridging during the build process, use the following command:

```bash
cmake -G Ninja -DNNG_ENABLE_QUIC=ON ..
ninja
```

### TLS

By default, TLS is disabled in NanoMQ. If you want to add TLS support for secure communication, you will need to install [mbedTLS](https://tls.mbed.org/). After installing mbedTLS, you can enable TLS by using the `-DNNG_ENABLE_TLS=ON` flag during the build process:

With `Ninja`:

```bash
cmake -G Ninja -DNNG_ENABLE_TLS=ON ..
```

Or with `make`:

```bash
cmake -DNNG_ENABLE_TLS=ON ..
```

::: tip

For more TLS configuration parameters, you may refer to the config file `etc/nanomq_example.conf`

:::

### Client Control

By default, the client, which includes `pub`, `sub`, and `conn` tools, is built during the installation. If you want to disable these, use the `-DBUILD_CLIENT=OFF` flag:

```bash
cmake -G Ninja -DBUILD_CLIENT=OFF ..
ninja
```

### Gateway Tool

The gateway tool, for example, ZeroMQ, isn't built by default. For example, to enable the ZMQ gateway, use the `-DBUILD_ZMQ_GATEWAY=ON` flag:

```
cmake -G Ninja -DBUILD_ZMQ_GATEWAY=ON ..
ninja
```

### Benchmarking Tool

The benchmarking tool isn't built by default. To enable it, use the `-DBUILD_BENCH=ON` flag:

```
cmake -G Ninja -DBUILD_BENCH=ON ..
ninja
```

### JWT Dependency

 JWT dependency, which is required for the HTTP server, isn't built by default. To enable it, use the `-DENABLE_JWT=ON` flag:

```
cmake -G Ninja -DENABLE_JWT=ON ..
ninja
```

### SQLite Support

SQLite3, which is used for message persistence, isn't built by default. To enable it, use the `-DNNG_ENABLE_SQLITE=ON` flag:

```
cmake -G Ninja -DNNG_ENABLE_SQLITE=ON ..
ninja
```

### Static Library

By default, NanoMQ isn't built as a static library. To enable it, use the `-DBUILD_STATIC_LIB=ON` flag:

```
cmake -G Ninja -DBUILD_STATIC_LIB=ON ..
ninja libnano
```

### Shared Library

Similarly, NanoMQ isn't built as a shared library by default. To enable it, use the `-DBUILD_SHARED_LIBS=ON` flag:

```
cmake -G Ninja -DBUILD_SHARED_LIBS=ON ..
ninja
```

### NanoNNG Dependency

NanoNNG, which is a fork of the NNG repository with MQTT support and maintained by NanoMQ, can be compiled independently:

```
cd nng/build
cmake -G Ninja ..
ninja
```

## Performance Tuning

NanoMQ provides several options for optimizing performance based on your system's needs.

### Arguments

**Thread Limitation:** You can limit the number of threads in NanoMQ:

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNNG_RESOLV_CONCURRENCY=1                                														 -DNNG_NUM_TASKQ_THREADS=5 -DNNG_MAX_TASKQ_THREADS=5 ..
```

**Debugging System:** NanoMQ has a debugging system that logs all information from all threads, which aligns with the Syslog standard. You can disable or enable it:

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=1  ..
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=0  ..
```

**MQTT client:** MQTT client is enabled by default, but it can be disabled with -DBUILD_CLIENT=OFF:

```bash
# Disable client
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DBUILD_CLIENT=OFF ..
# Enable client
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DBUILD_CLIENT=ON ..
```

**Message Queue Support:** For macOS, mqueue is not supported by default, but you can set -DMQ=0 to disable it:

```sh
# Enable MQ
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=1  ..
# Disable MQ
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=0  ..
```

### System Tunning

::: tip

Remember to replace `{size}` and `{PARALLEL}` with your desired numbers.

:::

Set max size of fixed header + variable header for MQTT packet, default is 64 bytes:

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

Set queue length for a resending message, default is 64:

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_MSQ_LEN={size} ..
```


Set logical concurrency limitation by -DPARALLEL, default is 32:

```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DPARALLEL={PARALLEL} ..
```

### Cross Compile NanoMQ with static linked libraries (QUIC + Parquet)

Take Arm64 as an example.
```sh
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ -DBUILD_NANOMQ_CLI=OFF  -DNNG_ENABLE_QUIC=ON -DQUIC_BUILD_SHARED=OFF -DNNG_ENABLE_TLS=ON -DENABLE_PARQUET=ON -DNNG_ENABLE_SQLITE=ON -DNOLOG=0 -DPARALLEL=24 -DASAN=OFF -DDEBUG=ON -DCMAKE_BUILD_TYPE=Debug -DBUILD_STATIC=ON -DBUILD_SHARED_LIBS=OFF -DNNG_TESTS=OFF -DCMAKE_CROSSCOMPILING=ON -DONEBRANCH=1 -DCMAKE_TARGET_ARCHITECTURE=arm64 -DGNU_MACHINE=aarch64-linux-gnu -DCMAKE_FIND_ROOT_PATH=/usr/lib/aarch64-linux-gnu/ ..
```
The command above requires a pre-installed aarch64 version of Parquet and MbedTLS.