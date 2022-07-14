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

Add `NNG_ENABLE_TLS` to enable **TLS**:
>[mbedTLS](https://tls.mbed.org) needs to be installed first.
```bash
cmake -G Ninja -DNNG_ENABLE_TLS=ON ..
```
or
```bash
cmake -DNNG_ENABLE_TLS=ON ..
```
> View config file `nanomq.conf` for more parameters about TLS.


## Compile dependency

Please be aware that NanoMQ depends on nng

dependency can be compiled independently

```bash
$PROJECT_PATH/nanomq/nng/build$ cmake -G Ninja ..
$PROJECT_PATH/nanomq/nng/build$ ninja install
```

## Start MQTT Broker

```bash
nanomq start &
```

Currently, NanoMQ only supports MQTT 3.1.1, partially supports MQTT 5.0



## MQTT Client

```bash
# Publish
nanomq_cli pub --url <url> -t <topic> -m <message> [--help]

# Subscribe
nanomq_cli sub --url <url> -t <topic> [--help]

# Connect*
nanomq_cli conn --url <url> [--help]
```
