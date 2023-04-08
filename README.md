# NanoMQ

[![GitHub Release](https://img.shields.io/github/release/emqx/nanomq?color=brightgreen&label=Release)](https://github.com/emqx/nanomq/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/emqx/nanomq/build_packages.yaml?branch=master&label=Build)](https://github.com/emqx/nanomq/actions)
[![Docker Pulls](https://img.shields.io/docker/pulls/nanomq/nanomq?label=Docker%20Pulls)](https://hub.docker.com/r/nanomq/nanomq)
[![Discord](https://img.shields.io/discord/931086341838622751?label=Discord&logo=discord)](https://discord.gg/xYGf3fQnES)
[![Twitter](https://img.shields.io/badge/Follow-EMQ-1DA1F2?logo=twitter)](https://twitter.com/EMQTech)
[![YouTube](https://img.shields.io/badge/Subscribe-EMQ-FF0000?logo=youtube)](https://www.youtube.com/channel/UC5FjR77ErAxvZENEWzQaO5Q)
[![Community](https://img.shields.io/badge/Community-NanoMQ-yellow?logo=github)](https://github.com/emqx/nanomq/discussions)
[![License](https://img.shields.io/github/license/emqx/nanomq.svg?logoColor=silver&logo=open-source-initiative&label=&color=blue)](https://github.com/emqx/nanomq/blob/master/LICENSE.txt)

NanoMQ is an Ultra-lightweight and Blazing-fast MQTT Broker for IoT Edge. 

NanoMQ uses NNG,a Lightweight Messaging Library,to implement asynchronous I/O.

NanoMQ fully supports MQTT V3.1.1, V5.0 and QoS 0,1,2.

NanoMQ also provides `nanomq_cli` utility for publishing, subscribing and testing.

For more detailed information, please visit [NanoMQ homepage](https://nanomq.io/).

## Features

- Cost-effective on embedded platforms.
- High Compatibility. Fully based on standard POSIX.
- High portability. Pure C implementation.
- Fully asynchronous I/O and multi-threading;
- Good support for SMP;
- Low latency & High handling capacity;

![image](https://user-images.githubusercontent.com/64823539/182988350-f6e2520f-6e6f-46db-b469-685bec977270.png)

## Installing
See [NanoMQ Download](https://nanomq.io/downloads) for details on installing binaries for various platforms.

## Quick Start

Start NanoMQ with default configuration:
```bash
nanomq start 
```
Use `nanomq_cli` to subscribe a topic:
```bash
nanomq_cli sub -t 'test/topic' [--help]
```
And publish a message to a topic:
```bash
nanomq_cli pub -t 'test/topic' -m "Hello World!" [--help]
```
You can use `bench` to conduct performance and stress tests:
```bash
nanomq_cli bench { pub | sub | conn } [--help]
```

**NanoMQ nng message proxy**

NanoMQ is also able to convert MQTT msg and NNG msg.

start a proxy to sub NNG url and convey nng msg to qos 2 MQTT msg and send to a specific topic "nng-mqtt" of MQTT broker:
```bash
nanomq_cli nngproxy sub0 --mqtt_url "mqtt-tcp://localhost:1883" --listen "tcp://127.0.0.1:10000" -t nng-mqtt --qos 1
nanomq_cli sub -t nng-mqtt
nanomq_cli nngcat --pub --dial="tcp://127.0.0.1:10000" --data "cuckoo" --interval 1
```

start a proxy sub to topic "nng-mqtt" of MQTT broker, and convert MQTT msg to NNG msg, then pub to NNG url:
```bash
nanomq_cli nngcat --sub --listen="tcp://127.0.0.1:10000" -v  --quoted
nanomq_cli nngproxy pub0 --mqtt_url "mqtt-tcp://localhost:1883" --dial "tcp://127.0.0.1:10000" -t nng-mqtt --qos 0
nanomq_cli pub -t nng-mqtt -m test
```

**Note: NanoMQ provides several ways of configurations so that user can achieve better performance on different platforms**, check [here](#Configuration ) for details.



## Building from source

A C99 compatible compiler and [CMake](http://www.cmake.org/) (version 3.13 or newer) is required to build NanoMQ. 

- It is recommended to compile with Ninja:

  ```bash
  git clone https://github.com/emqx/nanomq.git ; cd nanomq
  git submodule update --init --recursive
  mkdir build && cd build
  cmake -G Ninja ..
  ninja
  ```

- You can also compile without Ninja:

  ``` bash
  git clone https://github.com/emqx/nanomq.git ; cd nanomq
  git submodule update --init --recursive
  mkdir build && cd build
  cmake .. 
  make
  ```
  
  NanoMQ supports various features: QUIC bridging, TLS, MQTT client, zeromq, dds proxy, bench tool,JWT dependency (for http server), SQLite3 (for message persistence), etc. You can build NanoMQ with these features optionally. Check [build options](https://nanomq.io/docs/en/latest/build-options.html#arguments) for details.

## Debugging guide

NanoMQ provides dozens of ways of debugging in case you need troubleshooting any issue when doing cross-compiling & self-development.

**Note (optional): debug NanoMQ with GDB**.

```bash
cmake -G Ninja -DDEBUG=ON ..
ninja
```

**Note (optional): debug NanoMQ with Sanitizer**.

```bash
cmake -G Ninja -DASAN=ON -DTSAN=ON ..
ninja
```

**Note (optional): debug NanoMQ with ptrace**.

ptrace is a mechanism that allows one process to “trace” the execution of another process. The tracer is able to
pause execution, and inspect and modify memory and registers in the tracee process:

```bash
cmake -G Ninja -DDEBUG_TRACE=ON ..
ninja
```


## Configuration 

NanoMQ as an MQTT broker with good compatibility and portability, it provides several options for optimizing performance according to your system.



### Compiling parameters

With CMake, NanoMQ allows user to have broker natively tuned/configured when building from source. Please kindly find the parameters as follows:



#### CMake Configuration

To use CMake configuration, navigating to `./nanomq/build` and typing the following command :

```bash
cmake ..
```

Be aware that, CMake configuration is enabled by default, If you leave all parameters empty, the default value will take effect.

- Limiting the number of threads by specifying the number of and the max number of taskq threads:

  Recommendation: equal to your CPU cores

  ```bash
  cmake -G Ninja -DNNG_NUM_TASKQ_THREADS=<num> ..
  cmake -G Ninja -DNNG_MAX_TASKQ_THREADS=<num> ..
  ```

- Setting the number of concurrent resolver threads:

  Recommendation: 1

  ```bash
  cmake -G Ninja -DNNG_RESOLV_CONCURRENCY=<num> ..
  ```

  *Inherited from NNG*

- For logging, NanoMQ has a loger built-in which logs all information from all threads.  Enabling or disabling the debugging messages by (Mac users should disable it before compilation):

  Default: disabled (1)

  ```bash
  cmake -G Ninja -DNOLOG=0  ..
  cmake -G Ninja -DNOLOG=1  ..
  ```

- Setting the logical concurrency limitation:

  Default: 32

  ```bash
  cmake -G Ninja -DPARALLEL=<num> ..
  ```


### Booting Parameters

Users can also change the configuration parameters of NanoMQ while booting. However, part of the parameters is excluded in this method.

#### NanoMQ configuration file

NanoMQ will look up to it's configuration file in `/etc/` by default. Please remember to copy conf file to `/etc/` in your system if you wanna start NanoMQ without setting conf path manually. This 'nanomq.conf' allows you to configure broker when booting. Please be noted that if you start NanoMQ in the project's root directory, this file will be read automatically.

You can also write your own configuration file. Be sure to start NanoMQ in this fashion to specify an effective configuration file:

```bash
nanomq start --conf <$FILE_PATH>
```

Docker version:
  Specify config file path from host:

  ```bash
  docker run -d -p 1883:1883 -v {YOU LOCAL PATH}: /etc \
              --name nanomq  emqx/nanomq:0.9.0
  ```

#### NanoMQ Environment Variables 
| Variable | Type  | Value |
| ------------------------------------------------------------ |     ------------------------------------------------------------ | ------------------------------------------------------------ |
|NANOMQ_BROKER_URL |String | 'nmq-tcp://host:port', 'tls+nmq-tcp://host:port'|
|NANOMQ_DAEMON |Boolean | Set nanomq as daemon (default: false).|
|NANOMQ_NUM_TASKQ_THREAD | Integer | Number of taskq threads used, `num` greater than 0 and less than 256.|
|NANOMQ_MAX_TASKQ_THREAD | Integer | Maximum number of taskq threads used, `num` greater than 0 and less than 256.|
|NANOMQ_PARALLEL | Long | Number of parallel.|
|NANOMQ_PROPERTY_SIZE | Integer | Max size for a MQTT user property.|
|NANOMQ_MSQ_LEN | Integer | Queue length for resending messages.|
|NANOMQ_QOS_DURATION | Integer |  The interval of the qos timer.|
|NANOMQ_ALLOW_ANONYMOUS | Boolean | Allow anonymous login (default: true).|
|NANOMQ_WEBSOCKET_ENABLE | Boolean | Enable websocket listener (default: true).|
|NANOMQ_WEBSOCKET_URL | String | 'nmq-ws://host:port/path', 'nmq-wss://host:port/path' |
|NANOMQ_HTTP_SERVER_ENABLE | Boolean | Enable http server (default: false).|
|NANOMQ_HTTP_SERVER_PORT | Integer | Port for http server (default: 8081).|
|NANOMQ_HTTP_SERVER_USERNAME | String | Http server user name for auth.|
|NANOMQ_HTTP_SERVER_PASSWORD | String | Http server password for auth.|
|NANOMQ_TLS_ENABLE|Boolean|Enable TLS connection.|
|NANOMQ_TLS_URL| String | 'tls+nmq-tcp://host:port'.|
|NANOMQ_TLS_CA_CERT_PATH| String | Path to the file containing PEM-encoded CA certificates.|
|NANOMQ_TLS_CERT_PATH| String |  Path to a file containing the user certificate.|
|NANOMQ_TLS_KEY_PATH| String | Path to the file containing the user's private PEM-encoded key.|
|NANOMQ_TLS_KEY_PASSWORD| String |  String containing the user's password. Only used if the private keyfile is password-protected.|
|NANOMQ_TLS_VERIFY_PEER| Boolean | Verify peer certificate (default: false).|
|NANOMQ_TLS_FAIL_IF_NO_PEER_CERT| Boolean | Server will fail if the client does not have a certificate to send (default: false).|
|NANOMQ_CONF_PATH | String | NanoMQ main config file path (defalt: /etc/nanomq.conf).|

- Specify a broker url.
  On host system: 
  ```bash
  export NANOMQ_BROKER_URL="nmq-tcp://0.0.0.0:1883"
  export NANOMQ_TLS_ENABLE=true
  export NANOMQ_TLS_URL="tls+nmq-tcp://0.0.0.0:8883"
  ```
  Creating docker container:
  ```bash
  docker run -d -p 1883:1883 -p 8883:8883 \
             -e NANOMQ_BROKER_URL="nmq-tcp://0.0.0.0:1883" \
             -e NANOMQ_TLS_ENABLE=true \
             -e NANOMQ_TLS_URL="tls+nmq-tcp://0.0.0.0:8883" \
             --name nanomq emqx/nanomq:0.8.0
  ```

- Specify a nanomq config file path.
  On host system: 
  ```bash
  export NANOMQ_CONF_PATH="/usr/local/etc/nanomq.conf"
  ```
  Creating docker container:
  ```bash
  docker run -d -p 1883:1883 -e NANOMQ_CONF_PATH="/usr/local/etc/nanomq.conf" \
              [-v {LOCAL PATH}:{CONTAINER PATH}] \
              --name nanomq emqx/nanomq:0.8.0
  ```

#### NanoMQ Command-Line Arguments 

The same configuration can be achieved by adding some command-line arguments when you start NanoMQ broker. There are a few arguments for you to play with. And the general usage is:

```bash
Usage: nanomq { { start | restart [--url <url>] [--conf <path>] [-t, --tq_thread <num>]
                     [-T, -max_tq_thread <num>] [-n, --parallel <num>] 
                     [--old_conf <path>] [-D, --qos_duration <num>] [--http] [-p, --port] [-d, --daemon] 
                     [--cacert <path>] [-E, --cert <path>] [--key <path>] 
                     [--keypass <password>] [--verify] [--fail] } 
                     | reload [--conf <path>] 
                     | stop }

Options: 
  --url <url>                 Specify listener's url: 'nmq-tcp://host:port', 
                              'tls+nmq-tcp://host:port', 
                              'nmq-ws://host:port/path', 
                              'nmq-wss://host:port/path'
  --conf <path>               The path of a specified nanomq HOCON style configuration file 
  --old_conf <path>           Parse old config file
  --http                      Enable http server (default: false)
  -p, --port <num>            The port of http server (default: 8081)
  -t, --tq_thread <num>       The number of taskq threads used, 
                              `num` greater than 0 and less than 256
  -T, --max_tq_thread <num>   The maximum number of taskq threads used, 
                              `num` greater than 0 and less than 256
  -n, --parallel <num>        The maximum number of outstanding requests we can handle
  -s, --property_size <num>   The max size for a MQTT user property
  -S, --msq_len <num>         The queue length for resending messages
  -D, --qos_duration <num>    The interval of the qos timer
  -d, --daemon                Run nanomq as daemon (default: false)
  --cacert                    Path to the file containing PEM-encoded CA certificates
  -E, --cert                  Path to a file containing the user certificate
  --key                       Path to the file containing the user's private PEM-encoded key
  --keypass                   String containing the user's password. 
                              Only used if the private keyfile is password-protected
  --verify                    Set verify peer certificate (default: false)
  --fail                      Server will fail if the client does not have a 
                              certificate to send (default: false)
  --log_level   <level>       The level of log output 
                              (level: trace, debug, info, warn, error, fatal)
                              (default: warn)
  --log_file    <file_path>   The path of the log file 
  --log_stdout  <true|false>  Enable/Disable console log output (default: true)
  --log_syslog  <true|false>  Enable/Disable syslog output (default: false)
```

- `start`, `restart`, `reload` and `stop` command is mandatory as it indicates whether you want to start a new broker, or replace an existing broker with a new one, or stop a running broker;

  If `stop` is chosen, no other arguments are needed, and an existing running broker will be stopped:

  ```bash
  nanomq stop
  ```

  All arguments are useful when `start` and `restart` are chosen. An URL is mandatory (unless an URL is specified in the 'nanomq.conf', or in your configuration file), as it indicates on which the host and port a broker is listening:

  ```bash
  nanomq start|restart 					
  nanomq start|restart --conf <$FILE_PATH> 
  ```

- Telling broker that it should read your configuration file. 

  Be aware that command line arguments always has a higher priority than both 'nanomq.conf' and your configuration file: 

  ```bash
  nanomq start|restart --conf <$FILE_PATH> 
  ```

- Running broker in daemon mode:

  ```bash
  nanomq start|restart --daemon
  ```

- Running broker with *tls*:

  ```bash
  nanomq start --url "tls+nmq-tcp://0.0.0.0:8883" [--cacert <path>] [-E, --cert <path>] [--key <path>] [--keypass <password>] [--verify] [--fail]
  ```

- Limiting the number of threads by specifying the number of and the max number of taskq threads:

  ```bash
  nanomq start|restart  --tq_thread <num>
  nanomq start|restart  --max_tq_thread <num>
  ```

- Limiting the maximum number of logical threads:

  ```bash
  nanomq start|restart --parallel <num>
  ```
  
- Setting the max property size for MQTT packet:

  Default: 32 bytes

  ```bash
  nanomq start|restart --property_size <num>
  ```

- Setting the queue length for a resending message:
 'please be aware that this parameter also defines the upper limit of memory used by NanoMQ'
  'And affect the flying window of message, please set to > 1024 if you do not want to lose message'

  Default: 256

  ```bash
  nanomq start|restart --msq_len <num>
  ```

- Setting the interval of the qos timer (*Also a global timer interval for session keeping*):

  Default: 30 seconds

  ```bash
  nanomq start|restart --qos_duration <num>
  ```

- Setting the log option: 
  
  Default: log_level=warn, log_file=none, log_stdout=true, log_syslog=false

  ```bash
  nanomq start|restart --log_level=<level> [--log_file <file_path>] [--log_stdout <true|false>]  [--log_syslog <true|false>]
  ```

- Reload configuration file:
  Note: Only take effect for the parameters which marked "Hot updatable" in the configuration file;
  ```bash
  nanomq reload [--conf <$FILE_PATH>]
  ```

  

**Priority: Command-Line Arguments > Environment Variables > Config files**

*For tuning NanoMQ according to different hardware, please check the Doc.*



## Community

Some quotes from NNG's maintainer --- Garrett:
I’m very excited about the synergy between the NanoMQ and NNG projects, and grateful for sponsorship that NNG has received from the NanoMQ team. The NanoMQ team has been able to push NNG's envelope, and the collaboration has already yielded substantial improvements for both projects. Further, the cooperation between these two project will make MQTT and SP (nanomsg) protocols easy to use within a single project as well as other capabilities (such as websockets, HTTPS clients and servers), greatly expanding the toolset within easy reach of the IoT developer. Further this comes without the usual licensing or portability/embeddability challenges that face other projects. Additional planned collaborative work will further expand on these capabilities to the benefit of our shared communities.
### Our Website

Visit our [official website](https://nanomq.io/) to have a good grasp on NanoMQ MQTT broker and see how it can be applied in current industries.



### Test Report

This [test report](https://nanomq.io/docs/latest/test-report.html#about-nanomq) shows how extraordinary and competitive the NanoMQ is in Edge Computing.

*Currently the benchmark is for 0.2.5, the updated one with ver 0.3.5 is coming soon*



### Open Source 

NanoMQ is fully open-sourced!



### Questions

The [Github Discussions](https://github.com/emqx/nanomq/discussions) provides a place for you to ask questions and share your ideas with users around the world.



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

*Unsupport features of MQTT 5.0* 
- Auth https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901217
- Server Redirection https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901255
### MQTT Client Examples

[MQTT-Client-Examples](https://github.com/emqx/MQTT-Client-Examples)

### MQTT Client SDK

[NanoSDK](https://github.com/nanomq/NanoSDK)



## License

[MIT License](./LICENSE.txt)



## Authors


The EMQ Edge Computing team.
