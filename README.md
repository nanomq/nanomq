# NanoMQ

[![GitHub Release](https://img.shields.io/github/release/nanomq/nanomq?color=brightgreen)](https://github.com/nanomq/nanomq/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/nanomq/nanomq)](https://hub.docker.com/r/nanomq/nanomq)
[![Twitter](https://img.shields.io/badge/Follow-EMQ-1DA1F2?logo=twitter)](https://twitter.com/EMQTech)
[![YouTube](https://img.shields.io/badge/Subscribe-EMQ-FF0000?logo=youtube)](https://www.youtube.com/channel/UC5FjR77ErAxvZENEWzQaO5Q)
[![Community](https://img.shields.io/badge/Community-NanoMQ-yellow?logo=github)](https://github.com/nanomq/nanomq/discussions)


[![The best IoT MQTT open source team looks forward to your joining](https://static.emqx.net/images/github_readme_en_bg.png)](https://www.emqx.com/en/careers)NanoMQ MQTT Broker (NanoMQ) is a lightweight and blazing-fast MQTT Broker for the IoT Edge platform. 

NanoMQ bases on NNG's asynchronous I/O threading model, with an extension of MQTT support in the protocol layer and reworked transport layer, plus an enhanced asynchronous IO mechanism maximizing the overall capacity.

NanoMQ currently supports MQTT V3.1.1 and partially supports MQTT V5.0.

For more information, please visit [NanoMQ homepage](https://nanomq.io/).



## Features

- Cost-effective on an embedded platform;
- Fully base on native POSIX. High Compatibility;
- Pure C/C++ implementation. High portability;
- Fully asynchronous I/O and multi-threading;
- Good support for SMP;
- Low latency & High handling capacity.



## Quick Start

**NanoMQ broker usage**

```bash
nanomq broker start -url <url>
nanomq broker stop
nanomq broker restart -url <url>
```

**POSIX message queue usage**

```bash
nanomq broker mq start
nanomq broker mq stop
```
*Incoming feature: NanoMQ Zmq usage*

```bash
nanomq sp req -port 5555
nanomq sp rep -port 5555
```

**Note: NanoMQ provides several ways of configurations so that user can achieve better performance on different platforms**, check [here](#Configuration ) for details.



## Compile & Install

NanoMQ dedicates to delivering a simple but powerful Messaging Hub on various edge platforms.

With this being said, NanoMQ can run on different architectures such like x86_64 and ARM with minor migration efforts.



#### Docker

```bash
docker run -d --name nanomq nanomq/nanomq:0.3.5
```



#### Building From Source

To build NanoMQ, requires a C99 & C++11 compatible compiler and [CMake](http://www.cmake.org/) (version 3.13 or newer). 

- It is recommended to compile with Ninja:

  ```bash
  git clone https://github.com/nanomq/nanomq.git ; cd nanomq
  git submodule update --init --recursive
  mkdir build & cd build
  cmake -G Ninja ..
  ninja
  ```

- Or to compile without Ninja:

  ``` bash
  git clone https://github.com/nanomq/nanomq.git ; cd nanomq
  git submodule update --init --recursive
  mkdir build & cd build
  cmake .. 
  make
  ```

**Note for Mac users: mq (one of the features) is not supported** on Mac, please disable it before compiling.

  ``` bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=0  ..
  ninja
  ```

**Note (optional): nanolib & nanonng are dependencies of NanoMQ that can be compiled independently**.

To compile nanonng (*nanonng is the fork of nng repository with MQTT support*):

```bash
cd nng/build
cmake -G Ninja ..
ninja
```

To compile nanolib:

```bash
cd nanolib/build
cmake -G Ninja ..
ninja
```



## Configuration 

NanoMQ as an MQTT broker with good compatibility and portability, it provides several options for optimizing performance according to your system.



### Compiling parameters

With CMake, NanoMQ allows user to have broker natively tuned/configured when building from source. Please kindly find the parameters as follows:



#### CMake Configuration

To use CMake configuration, navigating to `./nanomq/build` and typing the following command :

```bash
cmake -DCFG_METHOD=CMAKE_CONFIG ..
```

Be aware that, CMake configuration is enabled by default, If you leave all parameters empty, the default value will take effect.

- Limiting the number of threads by specifying the number of and the max number of taskq threads:

  Recommendation: equal to your CPU cores

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNNG_NUM_TASKQ_THREADS=<num> ..
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNNG_MAX_TASKQ_THREADS=<num> ..
  ```

- Setting the number of concurrent resolver threads:

  Recommendation: 1

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNNG_RESOLV_CONCURRENCY=<num> ..
  ```

  *Inherited from NNG*

- For debugging, NanoMQ has a debugging system that logs all information from all threads. Which is aligned with syslog standard. Enabling or disabling the debugging messages by (Mac users should disable it before compilation):

  Default: disabled (1)

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=0  ..
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=1  ..
  ```

- Enabling or disabling messaging queue function 

  Default: enabled (1)

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=1  ..
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=0  ..
  ```

- Setting the logical concurrency limitation:

  Default: 32

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DPARALLEL=<num> ..
  ```



#### config.cmake.in

In the root directory of NanoMQ(`./nanomq`), there is a file named 'config.cmake.in'. It provides bunch of modifiable configurations (same as the parameters above).

navigating to `./nanomq/build` , then:

```bash
cmake -DCFG_METHOD=FILE_CONFIG ..
ninja
```

to make your modification effective. 



### Booting Parameters

Users can also change the configuration parameters of NanoMQ while booting. However, part of the parameters is excluded in this method.



#### NanoMQ configuration file

In the `etc` directory of NanoMQ (`./nanomq/etc/nanomq.conf`), there is a 'nanomq.conf' configuration file. This file is different from 'config.cmake.in'. This 'nanomq.conf' allows you to configure broker when booting. Please be noted that if you start NanoMQ in the project's root directory, this file will be read automatically.



You can also write your own configuration file. Be sure to start NanoMQ in this fashion to specify an effective configuration file:

```bash
nanomq broker start -conf <$FILE_PATH>
```



#### NanoMQ Command-Line Arguments 

The same configuration can be achieved by adding some command-line arguments when you start NanoMQ broker. There are a few arguments for you to play with. And the general usage is:

```bash
nanomq broker {{start|restart -url <url> [-conf <$FILE_PATH>] [-daemon] [-tq_thread <num>] [-max_tq_thread <num>] [-parallel <num>] [-qos_timer <num>] }|stop}
```

- `start`, `restart`, and `stop` command is mandatory as it indicates whether you want to start a new broker, or replace an existing broker with a new one, or stop a running broker;

  If `stop` is chosen, no other arguments are needed, and an existing running broker will be stopped:

  ```bash
  nanomq broker stop
  ```

  All arguments are useful when `start` and `restart` are chosen. An URL is mandatory (unless an URL is specified in the 'nanomq.conf', or in your configuration file), as it indicates on which the host and port a broker is listening:

  ```bash
  nanomq broker start|restart -url <url>
  nanomq broker start|restart 					## only if an url is specified in 'nanomq.conf'
  nanomq broker start|restart -conf <$FILE_PATH>  ## only if an url is specified in your conf file
  ```

- Telling broker that it should read your configuration file. 

  Be aware that command line arguments always has a higher priority than both 'nanomq.conf' and your configuration file: 

  ```bash
  nanomq broker start|restart -conf <$FILE_PATH>
  ```

- Running broker in daemon mode:

  ```bash
  nanomq broker start|restart -url <url> -daemon
  ```

- Limiting the number of threads by specifying the number of and the max number of taskq threads:

  ```bash
  nanomq broker start|restart -url <url> -tq_thread <num>
  nanomq broker start|restart -url <url> -max_tq_thread <num>
  ```

- Limiting the maximum number of logical threads:

  ```bash
  nanomq broker start|restart -url <url> -parallel <num>
  ```
  
- Setting the max property size for MQTT packet:

  Default: 32 bytes

  ```bash
  nanomq broker start|restart -url <url> -property_size <num>
  ```

- Setting the queue length for a resending message:

  Default: 64 bytes

  ```bash
  nanomq broker start|restart -url <url> -msq_len <num>
  ```

- Setting the interval of the qos timer (*Also a global timer interval for session keeping*):

  Default: 30 seconds

  ```bash
  nanomq broker start|restart -url <url> -qos_timer <num>
  ```

*For tuning NanoMQ according to different hardware, please check the Doc.*



## Community

### Our Website

Visit our [official website](https://nanomq.io/) to have a good grasp on NanoMQ MQTT broker and see how it can be applied in current industries.



### Test Report

This [test report](https://nanomq.io/docs/latest/test-report.html#about-nanomq) shows how extraordinary and competitive the NanoMQ is in Edge Computing.

*Currently the benchmark is for 0.2.5, the updated one with ver 0.3.5 is coming soon*



### Open Source 

NanoMQ is fully open-sourced!



### Questions

The [Github Discussions](https://github.com/nanomq/nanomq/discussions) provides a place for you to ask questions and share your ideas with users around the world.



### Slack

You could join us on [Slack](https://slack-invite.emqx.io/). We now share a workspace with the entire EMQ X team. After joining, find your channel! 

- `#nanomq`: is a channel for general usage, where for asking question or sharing using experience; 
- `#nanomq-dev`: is a channel for MQTT lover and developer, your great thoughts are what we love to hear;
- `#nanomq-nng`: is a channel for guys who are interested in NNG, one of our fabulous dependencies.



## Link Exchange

### MQTT Specifications 

[MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html)

[MQTT Version 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/cs02/mqtt-v5.0-cs02.html)

[MQTT SN](http://mqtt.org/new/wp-content/uploads/2009/06/MQTT-SN_spec_v1.2.pdf)



### EMQ X Broker

[EMQ X Broker](https://www.emqx.io)



### HStreamDB

[HStreamDB](https://hstream.io/)



## License

[MIT License](./LICENSE.txt)



## Authors


The EMQ X team.
