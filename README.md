# NanoMQ

NanoMQ MQTT Broker (NanoMQ) is a light-weight and blazing-fast MQTT Broker for IoT Edge platform. 

NanoMQ bases on NNG's asynchronous I/O threading model, with an extension of MQTT support in the protocol layer and reworked transport layer. Plus an enhanced asynchronous IO mechanism to maximize the overall capacity.

NanoMQ currently supports MQTT V3.1.1, and partially supports MQTT V5.0.

For more information, please visit [NanoMQ homepage](https://nanomq.io/).



## Features

1. Cost-effective on an embedded platform;
2. Fully base on native POSIX. High Compatibility;
3. Pure C/C++ implementation. High portability;
4. Fully asynchronous I/O and multi-threading;
5. Good support for SMP;
6. Low latency & High handling capacity.



## Installation

NanoMQ dedicates to delivering a simple but powerful Messaging Hub on various edge platforms. With this being said, NanoMQ can run on both x86_63 architecture and ARM devices. Or operation systems such as Linux, Unix, macOS, etc.

There are two ways available for downloading, through installing Docker Image or building from source.

### Installing Docker Image

```bash
docker run -d --name nanomq nanomq/nanomq:0.3.5
```

### Building From Souce

To build NanoMQ, your machine should equip with a C99 & C++11 compatible compiler and [CMake](http://www.cmake.org/) (version 3.13 or newer). 

- Other than those, it is recommanded to compile with Ninja:

  ```bash
  git clone https://github.com/nanomq/nanomq.git
  cd nanomq
  mkdir build & cd build
  cmake -G Ninja ..
  sudo ninja install
  ```

- Or to compile without Ninja:

  ``` bash
  git clone https://github.com/nanomq/nanomq.git
  cd nanomq
  mkdir build & cd build
  cmake .. 
  make
  ```

**Note for Mac users: mqueue (one of the functions) is not supported** due to the operating system limitation, use [mqueue argument](###Modifying-Compilation-()-Arguments) to disable it during compilation.

**Note (optional): configurations other than mqueue are modifiable**, see [here](###Modifying-Compilation-()-Arguments) for how to modify them.

**Note (optional): nanolib & nng are dependencies of NanoMQ that can be compiled independently**.

To compile nng:

```bash
cd nng/build
cmake -G Ninja ..
ninja install
```

To compile nanolib:

```bash
cd nanolib/build
cmake -G Ninja ..
ninja install
```



## Quick Start

After building, NanoMQ could be started from any directory in the device:

```bash
nanomq broker start -url <url> &
```

NanoMQ could be stopped or restarted respectively by:

```bash
nanomq broker stop
nanomq broker restart -url <url>
```

**Note: some of the configurations could be modified via adding command-line arguments**, see [here](###Modifying-Command-Line-Arguments ) for details.

**Note: POSIX message queue could be tested using:**

```bash
nanomq broker mq start
nanomq broker mq stop
```



## Modifying Configuration 

The configurations of NanoMQ could be modified, which provides the power for optimizing performance according to a specific system. There are four ways to achieve this:

- Modifying 'config.cmake.in' before executing `cmake` ············· (before compilation/all modifiable/low-level priority)
- Modifying compilation arguments when executing `cmake` ··· (during compilation/all modifiable/low-level priority)
- Modifying 'nanomq.conf' configuration file ····························· (after compilation/some modifiable/mid-level priority)
- Modifying command-line arguments ········································ (after compilation/some modifiable/high-level priority)

### Modifying 'config.cmake.in' file

In the directory `./nanomq`, there is a file named 'config.cmake.in'. The file provides a number of modifiable configurations. Try them out in your editor before navigating to `./nanomq/build` and typing:

```bash
cmake -DCFG_METHOD=FILE_CONFIG ..
```

to make your modification effective. 

### Modifying Compilation (`cmake`) Arguments

Before adding arguments, navigating to `./nanomq/build` and typing the following command:

```bash
cmake -DCFG_METHOD=CMAKE_CONFIG ..
```

Then a number of configurations are ready for you to modify (**should be completed in `./nanomq/build`**):

- Limiting the number of threads by speicifying the number of and the max number of taskq threads:

  Default: depends on the number of CPU cores

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNNG_NUM_TASKQ_THREADS=<num> ..
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNNG_MAX_TASKQ_THREADS=<num> ..
  ```

- Setting the number of concurrent resolver threads:

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNNG_RESOLV_CONCURRENCY=<num> ..
  ```

- Enabling or disabling print for the debug messages that contain information from all threads) :

  Default: disabled (1)

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=0  ..
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=1  ..
  ```

- Enabling or disabling message queue function (Mac users should disable it before compilation):

  Default: enabled (1)

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=1  ..
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=0  ..
  ```

- Setting the max size of a fixed header and variable header for a  MQTT packet:

  Default: 64 bytes

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_PACKET_SIZE=<size> ..
  ```

- Setting the max fixed header size for a MQTT packet:

  Default: 5 bytes

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_HEADER_SIZE=<size> ..
  ```

- Setting the max property size for a MQTT packet:

  Default: 32 bytes

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_PROPERTY_SIZE=<size> ..
  ```

- Setting the queue length for a QoS message:

  Default: 64 bytes

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_QOS_LEN=<size> ..
  ```

- Setting the queue length for a resending message:

  Default: 64 bytes

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_MSQ_LEN=<size> ..
  ```

- Setting the nano qos time:

  Default: 30 seconds

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_QOS_TIMER=<interval> ..
  ```

- Setting the logical concurrency limitation:

  Default: 32

  ```bash
  cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DPARALLEL=<num> ..
  ```

### Modifying 'nanomq.conf' configuration file

In the directory `./nanomq`, there is a 'nanomq.conf' configuration file. This file is different from 'config.cmake.in'. This 'nanomq.conf' gives you the power to modified a limited number of configurations even after compilation. 

Open and edit 'nanomq.conf' in your editor before start NanoMQ. Be sure to start NanoMQ in this fashion to read the file:

```bash
nanomq broker start --conf
```

### Modifying Command-Line Arguments 

The same configuration modifications can be achieved by adding some command-line arguments when a NanoMQ is started. There are a few arguments for you to play with. And the general usage is:

```bash
nanomq broker {{start|restart -url <url> [--conf] [-daemon] [-tq_thread <num>] [-max_tq_thread <num>] [-parallel <num>] }|stop}
```

- `start`, `restart`, and `stop` command is mandatory as it indicates whether you want to start a new broker, or replace an existing broker with a new one, or stop a running broker;

  If `stop` is chosen, no other arguments are needed, and an existing running broker will be stopped:

  ```bash
  nanomq broker stop
  ```

  All arguments are useful when `start` and `restart` are chosen. An URL is mandatory (unless an URL is specified in the 'nano.conf'), as it indicates on which the host and port a broker is built on:

  ```bash
  nanomq broker start|restart -url <url>
  nanomq broker start|restart --conf ## only if an url is specified in 'nano.conf'
  ```

- Telling broker that it should read 'nano.conf' file. NanoMQ supports parsing command line argument while reading the configuration file. If the same configuration is set in both ways simultaneously, NanoMQ will take the command-line argument as a final decision. This means the command-line will always have a higher priority comparing to 'nanomq.conf':

  ```bash
  nanomq broker start|restart --conf
  ```

- Running broker in a daemon mode on your device:

  ```bash
  nanomq broker start|restart -url <url> -daemon
  ```

- Limiting the number of threads by speicifying the number of and the max number of taskq threads:

  ```bash
  nanomq broker start|restart -url <url> -tq_thread <num>
  nanomq broker start|restart -url <url> -max_tq_thread <num>
  ```

- Limiting the maximum number of outstanding requests a broker can handle

  ```bash
  nanomq broker start|restart -url <url> -parallel <num>
  ```



## Community

### Our Website

Visit our [official website](https://nanomq.io/) to have a good grasp on NanoMQ MQTT broker and see how it can be employed in current industries.

### Test Report

This [test report](https://nanomq.io/docs/latest/test-report.html#about-nanomq) shows how extraordinary and competitive the NanoMQ is in Edge Computing.

### Open Source 

NanoMQ is fully open-sourced! This [Github page](https://github.com/nanomq/nanomq) shows you our great work.

### Questions

The [Github Discussions](https://github.com/nanomq/nanomq/discussions) provides a place for you to ask questions and share your ideas with users around the world.

### Slack

You could join us on [Slack](https://slack-invite.emqx.io/). We now share a workspace with the entire EMQ X team. After joining, find your channel! 

- `#nanomq`: is a channel for general usage, where for asking question or sharing using experience; 
- `#nanomq-dev`: is a channel for MQTT lover and developer, your great thoughts are what we love to hear;
- `#nanomq-nng`: is a channel for guys who are interested in NNG, one of our fabulous dependencies.



## Link Exchange

### MQTT Specifications 

MQTT protocol could be found via the following links:

[MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html)

[MQTT Version 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/cs02/mqtt-v5.0-cs02.html)

[MQTT SN](http://mqtt.org/new/wp-content/uploads/2009/06/MQTT-SN_spec_v1.2.pdf)

### EMQ X Broker

Find another MQTT broker, even a commercial one, and an IoT industry-scale solution that our company is currently working on.

[EMQ X Broker](https://www.emqx.io/)

### HStreamDB

Find a steaming database built specialized for IoT data storage and real-time processing. This is another project that we are working on.

[HStreamDB](https://hstream.io/)



## License

[MIT License](./LICENSE.txt)



## Authors


The EMQ X team.
