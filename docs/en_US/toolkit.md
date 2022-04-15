# NanoMQ Toolkit

NanoMQ contains abundant toolkit include broker, bench, conn, pub, sub client. Here we will show you one by one.

## broker

NanoMQ MQTT Broker (NanoMQ) is a lightweight and blazing-fast MQTT Broker for the IoT Edge platform.

| Parameter       | abbreviation | Optional value | Default value            | Description                                                  |
| --------------- | ------------ | -------------- | ------------------------ | ------------------------------------------------------------ |
| --url           | -            | -              | nmq-tcp://127.0.0.1:1883 | Specify listener's url: 'nmq-tcp://host:port', 'tls+nmq-tcp://host:port' or 'nmq-ws://host:port/path' or 'nmq-wss://host:port/path' |
| --conf          | -            | -              | -                        | The path of a specified nanomq configuration file            |
| --bridge        | -            | -              | -                        | The path of a specified bridge configuration file            |
| --auth          | -            | -              | -                        | The path of a specified authorize configuration file         |
| --http          | -            | true false     | false                    | Enable http server                                           |
| --port          | -p           | -              | 8081                     | The port of http server                                      |
| --tq_thread     | -t           | -              | -                        | The number of taskq threads used, `num` greater than 1 and less than 256 |
| --max_tq_thread | -T           | -              | -                        | The maximum number of taskq threads used, `num` greater than 1 and less than 256 |
| --parallel      | -n           | -              | -                        | The maximum number of outstanding requests we can handle     |
| --property_size | -s           | -              | -                        | The max size for a MQTT user property                        |
| --msq_len       | -S           | -              | -                        | The queue length for resending messages                      |
| --qos_duration  | -D           | -              | -                        | The interval of the qos timer                                |
| --daemon        | -d           | true false     | false                    | Run nanomq as daemon                                         |
| --cacert        | -            | -              | -                        | Path to the file containing PEM-encoded CA certificates      |
| --cert          | -E           | -              | -                        | Path to a file containing the user certificate               |
| --key           | -            | -              | -                        | Path to the file containing the user's private PEM-encoded key |
| --keypass       | -            | -              | -                        | String containing the user's password. Only used if the private keyfile is password-protected |
| --verify        | -            | true false     | false                    | Set verify peer certificate                                  |
| --fail          | -            | true false     | false                    | Server will fail if the client does not have a certificate to send |

For example, we start NanoMQ listen mqtt message on url nmq-tcp://localhost:1884, websocket message on url nmq-ws://localhost:8085, enable http server on port 30000.

```bash
$ nanomq broker start --url nmq-tcp://localhost:1884 --url nmq-ws://localhost:8085 --http -p 30000
```

## bench

Bench is a concise and powerful MQTT protocol performance testing tool written with NanoSDK. 

### Compile 

**Note **: bench tool isn't built by default, you can enable it via `-DBUILD_BENCH=ON`.

```bash
$ cmake -G Ninja -DBUILD_BENCH=ON ..
$ Ninja
```

After the compilation, an executable file named `nanomq` will be generated. Execute the following command to confirm that it can be used normally:

```bash
$ nanomq
available applications:
   * broker
   * pub
   * sub
   * conn
   * bench
   * nngcat

EMQX Edge Computing Kit v0.6.0-3
Copyright 2022 EMQX Edge Team
```

```bash
$ nanomq bench start
Usage: nanomq bench start { pub | sub | conn } [--help]
```

The output of the above content proves that `bench` has been correctly compiled.

### Use

There are three subcommands of `bench`:

1. `pub`: used to create a large number of clients to perform the operation of publishing messages.
2. `sub`: Used to create a large number of clients to subscribe to topics and receive messages.
3. `conn`: used to create a large number of connections.

### Publish

When executing `nanomq bench start pub --help`, you will get the available parameter output.

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
$ nanomq bench start pub -t t -h nanomq-server -s 16 -q 0 -c 10 -I 10
```

### Subscribe

Execute `nanomq bench start sub --help` to get all available parameters of this subcommand. Their explanations have been included in the table above and are omitted here.

For example, we start 500 connections, and each subscribes to the `t` topic with Qos0:

```bash
$ nanomq bench start sub -t t -h nanomq-server -c 500
```

### Connect

Execute `nanomq bench start conn --help` to get all available parameters of this subcommand. Their explanations have been included in the table above and are omitted here.

For example, we start 1000 connections:

```bash
$ nanomq bench start conn -h nano-server -c 1000
```

### SSL connection

`bench` supports establishing a secure SSL connection and performing tests.

One-way certificate:

```bash
$ nanomq bench start sub -c 100 -i 10 -t bench -p 8883 -S
$ nanomq bench start pub -c 100 -I 10 -t bench -p 8883 -s 256 -S
```

Two-way certificate:

```bash
$ nanomq bench start sub -c 100 -i 10 -t bench -p 8883 --certfile path/to/client-cert.pem --keyfile path/to/client-key.pem
$ nanomq bench start pub -c 100 -i 10 -t bench -s 256 -p 8883 --certfile path/to/client-cert.pem --keyfile path/to/client-key.pem
```

## client

An MQTT version 3.1/3.1.1 client for now.

### Pub

When executing `nanomq pub --help`, you will get the available parameter output.

| Parameter       | abbreviation | Optional value | Default value             | Description                                               |
| --------------- | ------------ | -------------- | ------------------------- | --------------------------------------------------------- |
| --url           | -            | -              | mqtt-tcp://127.0.0.1:1883 | The url for mqtt broker                                   |
| --version       | -V           | 3 4 5          | 4                         | MQTT protocol version used                                |
| --parallel      | -n           | -              | 1                         | The number of parallel for client                         |
| --verbose       | -v           | -              | disable                   | Enable verbose mode                                       |
| --user          | -u           | -              | None; optional            | Client username                                           |
| --password      | -P           | -              | None; optional            | Client password                                           |
| --topic         | -t           | -              | None; required            | Published topics                                          |
| --msg           | -m           | -              | None; required            | Publish message                                           |
| --qos           | -q           | -              | 0                         | Qos level                                                 |
| --retain        | -r           | true false     | false                     | Whether the message sets the Retain flag                  |
| --keepalive     | -k           | -              | 300                       | Client keepalive time                                     |
| --count         | -C           | -              | 1                         | Num of client                                             |
| --clean_session | -c           | true false     | true                      | Whether to establish a connection by cleaning the session |
| --ssl           | -s           | true false     | false                     | Whether to enable SSL                                     |
| --cacert        | -            | -              | None                      | Client SSL certificate                                    |
| --cert          | -E           | -              | None                      | Certificate file path                                     |
| --key           | -            | true false     | false                     | Private key file path                                     |
| --keypass       | -            | -              | None                      | Private key password                                      |
| --interval      | -i           | -              | 10                        | Interval to create a client; unit: ms                     |
| --identifier    | -I           | -              | random                    | The client identifier UTF-8 String                        |
| --limit         | -L           | -              | 1                         | Max count of publishing message                           |
| --will-qos      | -            | -              | 0                         | Quality of service level for the will message             |
| --will-msg      | -            | -              | None                      | The payload of the will message                           |
| --will-topic    | -            | -              | None                      | The topic of the will message                             |
| --will-retain   | -            | true false     | false                     | Will message as retained message                          |

For example, we start 1 client with username nano and send 100 Qos2 messages test to the topic `t` .

```bash
$ nanomq pub start -t t -h nanomq-server -q 2 -u nano -L 100 -m test
```

### Sub

Execute `nanomq sub start --help` to get all available parameters of this command. Their explanations have been included in the table above and are omitted here.

For example, we start 1 client with username nano and set Qos1 from topic `t` .

```bash
$ nanomq sub start -t t -h nanomq-server -q 1
```

### Conn

Execute `nanomq conn start --help` to get all available parameters of this command. Their explanations have been included in the table above and are omitted here.

For example, we start 1 client with username nano and set Qos1 .

```bash
$ nanomq conn start -h nanomq-server -q 1
```

