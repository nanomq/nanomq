# LF Edge NanoMQ

[![GitHub Release](https://img.shields.io/github/release/emqx/nanomq?color=brightgreen&label=Release)](https://github.com/emqx/nanomq/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/emqx/nanomq/build_packages.yaml?branch=master&label=Build)](https://github.com/emqx/nanomq/actions)
[![Docker Pulls](https://img.shields.io/docker/pulls/emqx/nanomq?label=Docker%20Pulls)](https://hub.docker.com/r/emqx/nanomq)
[![Discord](https://img.shields.io/discord/931086341838622751?label=Discord&logo=discord)](https://discord.gg/xYGf3fQnES)
[![Twitter](https://img.shields.io/badge/Follow-EMQ-1DA1F2?logo=twitter)](https://twitter.com/EMQTech)
[![YouTube](https://img.shields.io/badge/Subscribe-EMQ-FF0000?logo=youtube)](https://www.youtube.com/channel/UC5FjR77ErAxvZENEWzQaO5Q)
[![Community](https://img.shields.io/badge/Community-NanoMQ-yellow?logo=github)](https://github.com/emqx/nanomq/discussions)
[![codecov](https://codecov.io/gh/emqx/nanomq/branch/master/graph/badge.svg?token=24E9Q3C0M0)](https://codecov.io/gh/emqx/nanomq)
[![License](https://img.shields.io/github/license/emqx/nanomq.svg?logoColor=silver&logo=open-source-initiative&label=&color=blue)](https://github.com/emqx/nanomq/blob/master/LICENSE.txt)

NanoMQ MQTT Broker (NanoMQ) is an all-around Edge Messaging Platform that includes a blazing-fast MQTT Broker for the IoT/IIoT and a lightweight Messaging Bus for SDV.

NanoMQ's embedded Actor architecture extends NNG's internal asynchronous I/O, plus an enhanced message passing and scheduling system to maximize the overall capacity. Fine-tuned towards the embedded environment and mission-critical scenarios.

NanoMQ fully supports MQTT V3.1.1/3.1 and MQTT V5.0.

For more information, please visit [NanoMQ homepage](https://nanomq.io/).

## Features

- Cost-effective on an embedded platform;
- Fully based on native POSIX. High Compatibility;
- Pure C implementation. High portability;
- Fully asynchronous I/O and multi-threading;
- Good support for SMP;
- Low latency & High handling capacity;

![image](https://user-images.githubusercontent.com/64823539/182988350-f6e2520f-6e6f-46db-b469-685bec977270.png)

## Get Started

### Run NanoMQ using Docker

```bash
docker run -d --name nanomq -p 1883:1883 -p 8083:8083 -p 8883:8883 emqx/nanomq:latest
```

### More installation options

If you prefer to install and manage NanoMQ yourself, you can download the latest version from [nanomq.io/downloads](https://nanomq.io/downloads).

#### Run NanoMQ:

```bash
nanomq start
## or run nanomq with a specified configuration file
nanomq start --conf <config_file>
```


## Build From Source

NanoMQ is dedicated to delivering a simple but powerful Messaging Hub on various edge platforms.

With this being said, NanoMQ can run on different architectures such like x86_64 and ARM with minor migration efforts.

Building NanoMQ requires a C99-compatible compiler and [CMake](http://www.cmake.org/) (version 3.13 or newer). 

- It is recommended to compile with `Ninja`:

  ```bash
  git clone https://github.com/emqx/nanomq.git
  cd nanomq
  git submodule update --init --recursive
  mkdir build && cd build
  cmake -G Ninja ..
  ninja
  ```

- Or compile with `make`:

  ``` bash
  git clone https://github.com/emqx/nanomq.git 
  cd nanomq
  git submodule update --init --recursive
  mkdir build && cd build
  cmake .. 
  make
  ```

### Build option

There are some configuration options specified using CMake defines in addition to the standard options like `CMAKE_BUILD_TYPE`:

- `-DNNG_ENABLE_QUIC=ON`: to build NanoMQ with QUIC bridging feature
- `-DNNG_ENABLE_TLS=ON`: to build with TLS support. (Need to install  [mbedTLS](https://tls.mbed.org) in advance)
- `-DBUILD_CLIENT=OFF`: to disable nanomq tools client suite  (including pub / sub / conn )
- `-DBUILD_ZMQ_GATEWAY=ON`: to build `nanomq_cli` with zeromq gateway tool
- `-DBUILD_NFTP=ON`: to build `nanomq_cli` with nftp client
- `-DBUILD_DDS_PROXY=ON`: to build `nanomq_cli` with dds client ( proxy / sub / pub )
- `-DBUILD_BENCH=ON`: to build  `nanomq_cli` mqtt bench
- ` -DENABLE_JWT=ON`: to build  JWT dependency for http server
- `-DNNG_ENABLE_SQLITE=ON`: to build nanomq with sqlite support
- `-DBUILD_STATIC_LIB=ON`: to build nanomq as a static library
- `-DBUILD_SHARED_LIBS=ON`: to build nanomq as a shared library
- `-DDEBUG=ON`: to enable debug flag
- `-DASAN=ON`: to enable sanitizer
- `-DDEBUG_TRACE=ON`: to enable ptrace (ptrace is a mechanism that allows one process to “trace” the execution of another process. The tracer is able to
  pause execution, and inspect and modify memory and registers in the tracee process)



## Resources

- NanoMQ 
  - [Blog](https://www.emqx.com/en/blog/category/nanomq)
  
  - [Official website](https://nanomq.io/)

- MQTT Specifications 
  - [MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html)
  - [MQTT Version 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/cs02/mqtt-v5.0-cs02.html)
  - [MQTT SN](http://mqtt.org/new/wp-content/uploads/2009/06/MQTT-SN_spec_v1.2.pdf)
  - *Unsupported features of MQTT 5.0*
    - Auth https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901217
    - Server Redirection https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901255

- MQTT Client Examples
  - [MQTT-Client-Examples](https://github.com/emqx/MQTT-Client-Examples)

- MQTT Client SDK
  - [NanoSDK](https://github.com/nanomq/NanoSDK)

- Internet of Vehicles
  - [Internet of Vehicles](https://www.emqx.com/en/blog/category/internet-of-vehicles). Build a reliable, efficient, and industry-specific IoV platform based on EMQ's practical experience, from theoretical knowledge such as protocol selection to practical operations like platform architecture design.

- DDS 
  - [CycloneDDS](https://cyclonedds.io/)
  - [DDS proxy on NanoMQ_CLI](./nanomq_cli/dds2mqtt/README.md)



## Get Involved

### Our Website

Visit our [official website](https://nanomq.io/) to have a good grasp on NanoMQ MQTT broker and see how it can be applied in current industries.

### Test Report

This [test report](https://nanomq.io/docs/latest/test-report.html#about-nanomq) shows how extraordinary and competitive the NanoMQ is in Edge Computing.

*Currently the benchmark is for 0.2.5, the updated one with ver 0.3.5 is coming soon*

### Questions

The [Github Discussions](https://github.com/emqx/nanomq/discussions) provides a place for you to ask questions and share your ideas with users around the world.

### Slack

You could join us on [Slack](https://slack-invite.emqx.io/). We now share a workspace with the entire EMQ X team. After joining, find your channel! 

- `#nanomq`: is a channel for general usage, where for asking questions or sharing using experience; 
- `#nanomq-dev`: is a channel for MQTT lovers and developers, your great thoughts are what we love to hear;
- `#nanomq-nng`: is a channel for guys who are interested in NNG, one of our fabulous dependencies.



## Community

Some quotes from NNG's maintainer --- Garrett:
I’m very excited about the synergy between the NanoMQ and NNG projects, and grateful for sponsorship that NNG has received from the NanoMQ team. The NanoMQ team has been able to push NNG's envelope, and the collaboration has already yielded substantial improvements for both projects. Further, the cooperation between these two project will make MQTT and SP (nanomsg) protocols easy to use within a single project as well as other capabilities (such as websockets, HTTPS clients and servers), greatly expanding the toolset within easy reach of the IoT developer. Further this comes without the usual licensing or portability/embeddability challenges that face other projects. Additional planned collaborative work will further expand on these capabilities to the benefit of our shared communities.

### Open Source 

NanoMQ is fully open-sourced!



## License

[MIT License](./LICENSE.txt)



## Authors


The EMQ Edge Computing team.
