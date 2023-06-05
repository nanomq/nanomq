# Deploy with Docker

This chapter introduces how to use the official Docker image to install and run NanoMQ, and provides some ways to configure it;



## Use Docker to run NanoMQ

This section will introduce how to use the Docker image to install the latest version of NanoMQ. If you want to work with other versions, please visit the [NanoMQ Deployment page](https://www.emqx.com/en/try?product=nanomq).

1. To get the Docker image, run:

```bash
docker pull emqx/nanomq:lastest
```

2. To start the Docker container, run:

```bash
docker run -d --name nanomq -p 1883:1883 -p 8083:8083 -p 8883:8883 emqx/nanomq:latest
```

For more information about NanoMQ official docker image, see [Docker Hub - nanomq](https://hub.docker.com/r/emqx/nanomq)

### Configuring

Here are some ways to modify configuration file on Docker container:

- Modify `/etc/nanomq.conf ` on docker container, refer to [configruation description](./config-description/v014.md)
- Copy your configuration file from local host to container path `/etc/nanomq.conf`:  `docker cp nanomq.conf nanomq:/etc/nanomq.conf`
- Modify configuration parameters by environment variables, for example: 

```bash
docker run -d -p 1883:1883 -p 8883:8883 \
           -e NANOMQ_BROKER_URL="nmq-tcp://0.0.0.0:1883" \
           -e NANOMQ_TLS_ENABLE=true \
           -e NANOMQ_TLS_URL="tls+nmq-tcp://0.0.0.0:8883" \
           --name nanomq emqx/nanomq
```

> The specific parameters are described in the table below

#### NanoMQ Environment variables

| Name                            | Type    | Description                                                  |
| ------------------------------- | ------- | ------------------------------------------------------------ |
| NANOMQ_BROKER_URL               | String  | 'nmq-tcp://host:port', 'tls+nmq-tcp://host:port'             |
| NANOMQ_DAEMON                   | Boolean | Set nanomq as daemon (default: false).                       |
| NANOMQ_NUM_TASKQ_THREAD         | Integer | Number of taskq threads used, `num` greater than 0 and less than 256. |
| NANOMQ_MAX_TASKQ_THREAD         | Integer | Maximum number of taskq threads used, `num` greater than 0 and less than 256. |
| NANOMQ_PARALLEL                 | Long    | Number of parallel.                                          |
| NANOMQ_PROPERTY_SIZE            | Integer | Max size for a MQTT user property.                           |
| NANOMQ_MSQ_LEN                  | Integer | Queue length for resending messages.                         |
| NANOMQ_QOS_DURATION             | Integer | The interval of the qos timer.                               |
| NANOMQ_ALLOW_ANONYMOUS          | Boolean | Allow anonymous login (default: true).                       |
| NANOMQ_WEBSOCKET_ENABLE         | Boolean | Enable websocket listener (default: true).                   |
| NANOMQ_WEBSOCKET_URL            | String  | 'nmq-ws://host:port/path', 'nmq-wss://host:port/path'        |
| NANOMQ_HTTP_SERVER_ENABLE       | Boolean | Enable http server (default: false).                         |
| NANOMQ_HTTP_SERVER_PORT         | Integer | Port for http server (default: 8081).                        |
| NANOMQ_HTTP_SERVER_USERNAME     | String  | Http server user name for auth.                              |
| NANOMQ_HTTP_SERVER_PASSWORD     | String  | Http server password for auth.                               |
| NANOMQ_TLS_ENABLE               | Boolean | Enable TLS connection.                                       |
| NANOMQ_TLS_URL                  | String  | 'tls+nmq-tcp://host:port'.                                   |
| NANOMQ_TLS_CA_CERT_PATH         | String  | Path to the file containing PEM-encoded CA certificates.     |
| NANOMQ_TLS_CERT_PATH            | String  | Path to a file containing the user certificate.              |
| NANOMQ_TLS_KEY_PATH             | String  | Path to the file containing the user's private PEM-encoded key. |
| NANOMQ_TLS_KEY_PASSWORD         | String  | String containing the user's password. Only used if the private keyfile is password-protected. |
| NANOMQ_TLS_VERIFY_PEER          | Boolean | Verify peer certificate (default: false).                    |
| NANOMQ_TLS_FAIL_IF_NO_PEER_CERT | Boolean | Server will fail if the client does not have a certificate to send (default: false). |
| NANOMQ_LOG_TO                   | String  | Array of log types，( _Use vertical line `|` to separate multiple types_ )<br>Log types: _file, console, syslog_ |
| NANOMQ_LOG_LEVEL                | String  | Log level：trace, debug, info, warn, error, fatal |
| NANOMQ_LOG_DIR                  | String  | The dir for log files. (if log to file) |
| NANOMQ_LOG_FILE                 | String  | The log filename. (if log to file) |
| NANOMQ_LOG_ROTATION_SIZE        | String  | Maximum size of each log file;<br>Supported Unit: `KB | MB | GB`;<br>Default:`10MB` |
| NANOMQ_LOG_ROTATION_COUNT       | Integer | Maximum rotation count of log files;<br>Default: `5` |
| NANOMQ_CONF_PATH                | String  | NanoMQ main config file path (defalt: /etc/nanomq.conf).     |