# Command Line Interface Guide

This page introduces how to use the command line interface for broker, client, and rule-related operations. 

- **[Broker](#broker)**: The broker section provides details about the parameters that can be used when starting the NanoMQ broker.
- **[Client](#client)**: This part discusses how to interact with the NanoMQ broker as a client. The operations are split into three main categories: Publish, Subscribe, and Conn.
- **[Rule](#rule)**: This section is dedicated to creating and managing rules. 

Each command comes with a range of optional parameters, allowing for a high degree of control and customization over how you interact with the NanoMQ broker and MQTT messages. 

## Broker

NanoMQ MQTT Broker (NanoMQ) is a lightweight and blazing-fast MQTT Broker for the IoT Edge platform.

| Parameter       | abbreviation | Optional value                         | Default value            | Description                                                  |
| --------------- | ------------ | -------------------------------------- | ------------------------ | ------------------------------------------------------------ |
| --url           | -            | -                                      | nmq-tcp://127.0.0.1:1883 | Specify listener's url: 'nmq-tcp://host:port', 'tls+nmq-tcp://host:port' or 'nmq-ws://host:port/path' or 'nmq-wss://host:port/path' |
| --conf          | -            | -                                      | -                        | The path of a specified nanomq configuration file            |
| --http          | -            | true false                             | false                    | Enable http server                                           |
| --port          | -p           | -                                      | 8081                     | The port of http server                                      |
| --tq_thread     | -t           | -                                      | -                        | The number of taskq threads used, `num` greater than 1 and less than 256 |
| --max_tq_thread | -T           | -                                      | -                        | The maximum number of taskq threads used, `num` greater than 1 and less than 256 |
| --parallel      | -n           | -                                      | -                        | The maximum number of outstanding requests we can handle     |
| --property_size | -s           | -                                      | -                        | The max size for a MQTT user property                        |
| --msq_len       | -S           | -                                      | -                        | The queue length for resending messages                      |
| --qos_duration  | -D           | -                                      | -                        | The interval of the qos timer                                |
| --daemon        | -d           | true false                             | false                    | Run nanomq as daemon                                         |
| --cacert        | -            | -                                      | -                        | Path to the file containing PEM-encoded CA certificates      |
| --cert          | -E           | -                                      | -                        | Path to a file containing the user certificate               |
| --key           | -            | -                                      | -                        | Path to the file containing the user's private PEM-encoded key |
| --keypass       | -            | -                                      | -                        | String containing the user's password. Only used if the private keyfile is password-protected |
| --verify        | -            | true false                             | false                    | Set verify peer certificate                                  |
| --fail          | -            | true false                             | false                    | Server will fail if the client does not have a certificate to send |
| --log_level     | -            | trace, debug, info, warn, error, fatal | warn                     | Log level                                                    |
| --log_file      | -            | -                                      | -                        | The path of the log file                                     |
| --log_stdout    | -            | true, false                            | true                     | Enable/Disable console log output                            |
| --log_syslog    | -            | true, false                            | false                    | Enable/Disable syslog (only enable on Linux)                 |

For example, we start NanoMQ listen mqtt message on url nmq-tcp://localhost:1884, websocket message on url nmq-ws://localhost:8085, enable http server on port 30000.

```bash
$ nanomq start --url nmq-tcp://localhost:1884 --url nmq-ws://localhost:8085 --http -p 30000
```

nanomq support multiple log types; For example, set output log to file ,console and syslog with log level debug: 

```bash
$ nanomq start --log_level=debug --log_file=nanomq.log  --log_stdout=true --log_syslog=true
```

or start with a specified configuration file:

```bash
$ nanomq start --conf <config_file>
```
### NanoMQ Reload
NanoMQ supports reload command and can dynamically update the configuration parameters of NanoMQ. Currently, it supports dynamic updates in four parts: `basic, sqlite, auth, log`. The detailed description of the parameters can be found in the [Configuration File](../config-description/introduction.md) section.
Running reload requires starting NanoMQ first. Assuming that we have already started NanoMQ, modified the configuration of the log section, and started reload to update the log:
```Bash
$ nanomq reload --conf <config_file>
```
A successful update will return `reload succeeded`.
If you use the old configuration file, you can also use it like `nanomq start --old_conf` to update. 
```Bash
$ nanomq reload --old_conf <config_file>
```


## Client

### Publish

When executing `nanomq_cli pub --help`, you will get the available parameter output.

| Parameter       | abbreviation | Optional value | Default value             | Description                                               |
| --------------- | ------------ | -------------- | ------------------------- | --------------------------------------------------------- |
| --host          | -h           | -              | Defaults to localhost.    | Mqtt host to connect to.  |
| --port          | -p           | -              | Defaults to 1883 for plain MQTT, 8883 for MQTT over TLS, 14567 for MQTT over QUIC | Network port to connect to.                                   |
| --quic          | -            | -              | Defaults to false.    |  QUIC transport option.  |
| --version       | -V           | 4 \| 5        | 4                         | MQTT protocol version used                                |
| --parallel      | -n           | -              | 1                         | The number of parallel for client                         |
| --verbose       | -v           | -              | disable                   | Enable verbose mode                                       |
| --user          | -u           | -              | None; optional            | Client username                                           |
| --password      | -P           | -              | None; optional            | Client password                                           |
| --topic         | -t           | -              | None; required            | Published topics                                          |
| --msg           | -m           | -              | None; required            | Publish message                                           |
| --qos           | -q           | -              | *0* for publish<br>*2* for subscribe | Qos level                                 |
| --retain        | -r           | true false     | false                     | Whether the message sets the Retain flag                  |
| --keepalive     | -k           | -              | 300                       | Client keepalive time                                     |
| --count         | -C           | -              | 1                         | Num of client                                             |
| --clean_session | -c           | true false     | true                      | Whether to establish a connection by cleaning the session |
| --ssl           | -s           | true false     | false                     | Whether to enable SSL                                     |
| --cafile        | -            | -              | None                      | Client SSL certificate                                    |
| --cert          | -E           | -              | None                      | Certificate file path                                     |
| --key           | -            | true false     | false                     | Private key file path                                     |
| --keypass       | -            | -              | None                      | Private key password                                      |
| --interval      | -I           | -              | 10                        | Interval to create a client; unit: ms                     |
| --identifier    | -i           | -              | random                    | The client identifier UTF-8 String                        |
| --limit         | -L           | -              | 1                         | Max count of publishing message                           |
| --stdin-line    | -l           | -              | false                     | Send messages read from stdin, splitting separate lines into separate messages.
| --will-qos      | -            | -              | 0                         | Quality of service level for the will message             |
| --will-msg      | -            | -              | None                      | The payload of the will message                           |
| --will-topic    | -            | -              | None                      | The topic of the will message                             |
| --will-retain   | -            | true false     | false                     | Will message as retained message                          |

For example, we start 1 client with username *nano* and send *100* *Qos2* messages *test* to the topic `t` .

```bash
$ nanomq_cli pub -t "topic" -q 2 -u nano -L 100 -m test -h broker.emqx.io -p 1883
```

### Subscribe

Execute `nanomq_cli sub --help` to get all available parameters of this command. Their explanations have been included in the table above and are omitted here.

For example, we start 1 client with username nano and set Qos1 from topic `t` .

```bash
$ nanomq_cli sub -t t -q 1 -h broker.emqx.io -p 1883 
```

### Conn

Execute `nanomq_cli conn --help` to get all available parameters of this command. Their explanations have been included in the table above and are omitted here.

For example, we start 1 client with username nano and set Qos1 .

```bash
$ nanomq_cli conn -q 1 -h broker.emqx.io -p 1883
```

### Rule

Execute `nanomq_cli rule --help` to get all available parameters of this command. 

#### Rules create

Create a new rule with the following parameter:

- *`<sql>`*:rule SQL
- *`<actions>`*:  Action list in JSON format

Example:
```bash
## Create a sqlite rule，store all datas sent to  'abc' 
$ nanomq_cli rules --create --sql 'SELECT * FROM "abc"' --actions '[{"name":"sqlite", "params": {"table": "test01"}}]'

{"rawsql":"SELECT * FROM \"abc\"","id":4,"enabled":true}

```

#### Rules list

List all rules:
```bash
## list all rules
$ nanomq_cli rules --list

{"rawsql":"SELECT payload.x.y as y, payload.z as z FROM \"#\" WHERE y > 10 and z != 'str'","id":1,"enabled":true}
{"rawsql":"SELECT * FROM \"abc\"","id":2,"enabled":true}
{"rawsql":"SELECT payload, qos FROM \"#\" WHERE qos > 0","id":3,"enabled":true}
{"rawsql":"SELECT * FROM \"abc\"","id":4,"enabled":true}

```
#### Rules show

Query rules:
```bash
## Query rule with RuleID  '1' 
$ nanomq_cli rules --show --id 1

{"rawsql":"SELECT payload.x.y as y, payload.z as z FROM \"#\" WHERE y > 10 and z != 'str'","id":1,"enabled":true}
```
#### rules delete

Delete a rule:
```bash
## Delete rule with RuleID '1' 
$ nanomq_cli rules --delete --id 1

{"code":0}
```

