# Bench

Bench is a concise and powerful MQTT protocol performance testing tool written with NanoSDK. 

## Compile 

**Note**: bench tool isn't built by default, you can enable it via `-DBUILD_BENCH=ON`.

```bash
$ mkdir build && cd build
$ cmake -G Ninja -DBUILD_BENCH=ON ..
$ Ninja
```

After the compilation, an executable file named `nanomq_cli` will be generated. Execute the following command to confirm that it can be used normally:

```bash
$ nanomq_cli
available tools:
   * pub
   * sub
   * conn
   * bench
   * nngproxy
   * nngcat
   * ddsproxy

Copyright 2022 EMQ Edge Computing Team
```

```bash
$ nanomq_cli bench
Usage: nanomq_cli bench { pub | sub | conn } [--help]
```

The output of the above content proves that `bench` has been correctly compiled.

## Use

There are three subcommands of `bench`:

1. `pub`: used to create a large number of clients to perform the operation of publishing messages.
2. `sub`: Used to create a large number of clients to subscribe to topics and receive messages.
3. `conn`: used to create a large number of connections.

## Publish

When executing `nanomq_cli bench pub --help`, you will get the available parameter output.

| Parameter         | abbreviation | Optional value | Default value  | Description                                               |
| ----------------- | ------------ | -------------- | -------------- | --------------------------------------------------------- |
| --host            | -h           | -              | localhost      | Address of the MQTT server to connect                     |
| --port            | -p           | -              | 1883           | MQTT service port                                         |
| --version         | -V           | 3 4 5          | 5              | MQTT protocol version used                                |
| --count           | -c           | -              | 200            | Total number of clients                                   |
| --interval        | -i           | -              | 10             | Interval to create a client; unit: ms                     |
| --interval_of_msg | -I           | -              | 1000           | Interval to publish a message                             |
| --username        | -u           | -              | None; optional | Client username                                           |
| --password        | -P           | -              | None; optional | Client password                                           |
| --topic           | -t           | -              | None; required | Published topics                                          |
| --size            | -s           | -              | 256            | Message Payload size; unit: bytes                         |
| --qos             | -q           | -              | 0              | Qos level                                                 |
| --retain          | -r           | true false     | false          | Whether the message sets the Retain flag                  |
| --keepalive       | -k           | -              | 300            | Client keepalive time                                     |
| --clean           | -C           | true false     | true           | Whether to establish a connection by cleaning the session |
| --ssl             | -S           | true false     | false          | Whether to enable SSL                                     |
| --certfile        | -            | -              | None           | Client SSL certificate                                    |
| --keyfile         | -            | -              | None           | Client SSL key file                                       |
| --ws              | -            | true false     | false          | Whether to establish a connection via Websocket           |

For example, we start 10 connections and send 100 Qos0 messages to the topic `t` every second, where the size of each message payload is`16` bytes:

```bash
$ nanomq_cli bench pub -t t -h nanomq-server -s 16 -q 0 -c 10 -I 10
```

## Subscribe

Execute `nanomq_cli bench sub --help` to get all available parameters of this subcommand. Their explanations have been included in the table above and are omitted here.

For example, we start 500 connections, and each subscribes to the `t` topic with Qos0:

```bash
$ nanomq_cli bench sub -t t -h nanomq-server -c 500
```

## Connect

Execute `nanomq_cli bench conn --help` to get all available parameters of this subcommand. Their explanations have been included in the table above and are omitted here.

For example, we start 1000 connections:

```bash
$ nanomq_cli bench conn -h nano-server -c 1000
```

## SSL connection

`bench` supports establishing a secure SSL connection and performing tests.

One-way certificate:

```bash
$ nanomq_cli bench sub -c 100 -i 10 -t bench -p 8883 -S
$ nanomq_cli bench pub -c 100 -I 10 -t bench -p 8883 -s 256 -S
```

Two-way certificate:

```bash
$ nanomq_cli bench sub -c 100 -i 10 -t bench -p 8883 --certfile path/to/client-cert.pem --keyfile path/to/client-key.pem
$ nanomq_cli bench pub -c 100 -i 10 -t bench -s 256 -p 8883 --certfile path/to/client-cert.pem --keyfile path/to/client-key.pem
```
