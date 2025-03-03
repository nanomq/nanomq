# Deploy with Docker

This section guides you through the quick installation and running of NanoMQ using the official Docker image. You'll also learn how to load custom configurations in the Docker deployment mode. This section uses the latest version of NanoMQ as an example. If you're interested in trying out other versions, head over to the [NanoMQ Download Page](https://www.emqx.com/zh/try?product=nanomq).

## Docker Images

NanoMQ currently provides three Docker deployment versions, each with distinct functionalities as detailed in the table below:

| Function                | NanoMQ Basic Version (default) | NanoMQ Slim Version | NanoMQ Full Version |
| ----------------------- | ------------------------------ | ------------------- | ------------------- |
| MQTT Broker Function    | ✅                              | ✅                   | ✅                   |
| TLS/SSL                 | ❌                              | ✅                   | ✅                   |
| SQLite                  | ❌                              | ✅                   | ✅                   |
| Rule Engine             | ❌                              | ❌                   | ✅                   |
| MQTT over TCP Bridging  | ✅                              | ✅                   | ✅                   |
| MQTT over QUIC Bridging | ❌                              | ❌                   | ✅                   |
| AWS Bridging *          | ❌                              | ❌                   | ❌                   |
| ZMQ Gateway             | ❌                              | ❌                   | ✅                   |
| SOME/IP Gateway         | ❌                              | ❌                   | ❌                   |
| DDS Gateway             | ❌                              | ❌                   | ❌                   |
| Bench Benchmark Tools   | ❌                              | ❌                   | ✅                   |

[^*]: AWS bridging is currently unavailable with Docker deployment. To use AWS bridging, please [build NanoMQ from the source code](./build-options.md).

Based on your requirements, you can select the Docker image to download. For instance, using `latest` in the command below will download the most recent basic deployment version.

```bash
docker pull emqx/nanomq:latest
```

To get the Slim or Full version of a certain release, don't forget to include the release number.

For the Slim version:

```bash
docker pull emqx/nanomq:0.18.2-slim
```

or Full version

```bash
docker pull emqx/nanomq:0.18.2-full
```

For more information about the official NanoMQ image, please visit [Docker Hub - nanomq](https://hub.docker.com/r/emqx/nanomq).

## Run NanoMQ with Docker

To start NanoMQ, execute the following command:

```bash
docker run -d --name nanomq -p 1883:1883 -p 8083:8083 -p 8883:8883 emqx/nanomq:latest
```

## Load Custom Configurations

NanoMQ also allows loading custom configurations through a configuration file or environment variables.

### Load through Configuration File

If you wish to start NanoMQ via a configuration file:

- Modify `/etc/nanomq.conf` in the Docker container

- Copy the modified configuration file from your local machine to the Docker container's `/etc/nanomq.conf` path using the `docker cp` command:

  ```bash
  docker cp nanomq.conf nanomq:/etc/nanomq.conf
  ```

Here's an example configuration for enabling MQTT bridging with TLS connection. For more explanations on NanoMQ's configurations, please refer to the [Configuration Guide](../config-description/introduction.md):

```bash
bridges.mqtt.name {
	server = "mqtt-tcp://broker.emqx.io:1883"
	proto_ver = 4
	clean_start = true
	keepalive = 60s
	forwards = [
		{
			remote_topic = "fwd/topic1"
			local_topic = "topic1"
			qos = 1
		},
		{
			remote_topic = "fwd/topic2"
			local_topic = "topic2"
			qos = 2
		}
	]
	subscription = [
		{
			remote_topic = "cmd/topic1"
			local_topic = "topic3"
			qos = 1
		},
		{
			remote_topic = "cmd/topic2"
			local_topic = "topic4"
			qos = 2
		}
	]
	max_parallel_processes = 2 
	max_send_queue_len = 1024
	max_recv_queue_len = 1024
}
```

After updating the configuration file, you can start NanoMQ with the following command:

```bash
docker run -d -p 1883:1883 -v {YOU LOCAL PATH}: /etc \
            --name nanomq  emqx/nanomq:latest
```

### Load through Environment Variables

NanoMQ also supports custom configurations through environment variables. Here is a list of supported environment variables:

| Variables                       | Data Type | Description                                                  |
| ------------------------------- | --------- | ------------------------------------------------------------ |
| NANOMQ_BROKER_URL               | String    | `nmq-tcp://host:port`<br /> `tls+nmq-tcp://host:port`        |
| NANOMQ_DAEMON                   | Boolean   | Daemon mode (default: False)                                 |
| NANOMQ_NUM_TASKQ_THREAD         | Integer   | Number of task queue threads (range: 0 ~ 256)                |
| NANOMQ_MAX_TASKQ_THREAD         | Integer   | Maximum task queue threads (range: 0 ~ 256)                  |
| NANOMQ_PARALLEL                 | Long      | Number of parallel operations                                |
| NANOMQ_PROPERTY_SIZE            | Integer   | Maximum property length                                      |
| NANOMQ_MSQ_LEN                  | Integer   | Queue length                                                 |
| NANOMQ_QOS_DURATION             | Integer   | QoS message interval                                         |
| NANOMQ_ALLOW_ANONYMOUS          | Boolean   | Allow anonymous login (default: True)                        |
| NANOMQ_WEBSOCKET_ENABLE         | Boolean   | Enable WebSocket listening (default: True)                   |
| NANOMQ_WEBSOCKET_URL            | String    | `nmq-ws://host:port/path`  |
| NANOMQ_WEBSOCKET_TLS_URL        | String    | `nmq-wss://host:port/path` |
| NANOMQ_HTTP_SERVER_ENABLE       | Boolean   | Enable HTTP server listening (default: False)                |
| NANOMQ_HTTP_SERVER_PORT         | Integer   | HTTP server listening port (default: 8081)                   |
| NANOMQ_HTTP_SERVER_USERNAME     | String    | Username to access HTTP service                              |
| NANOMQ_HTTP_SERVER_PASSWORD     | String    | Password to access HTTP service                              |
| NANOMQ_TLS_ENABLE               | Boolean   | Enable TLS listening (default: False)                        |
| NANOMQ_TLS_URL                  | String    | 'tls+nmq-tcp://host:port'                                    |
| NANOMQ_TLS_CA_CERT_PATH         | String    | Path to TLS CA certificate data                              |
| NANOMQ_TLS_CERT_PATH            | String    | Path to TLS Cert certificate data                            |
| NANOMQ_TLS_KEY_PATH             | String    | Path to TLS private key data                                 |
| NANOMQ_TLS_KEY_PASSWORD         | String    | Password for TLS private key                                 |
| NANOMQ_TLS_VERIFY_PEER          | Boolean   | Verify client certificate (default: False)                   |
| NANOMQ_TLS_FAIL_IF_NO_PEER_CERT | Boolean   | Deny connection without a certificate, used with tls.verify_peer (default: False) |
| NANOMQ_LOG_TO                   | String    | Log output types, separated by vertical line `|`<br />Values: file, console, syslog |
| NANOMQ_LOG_LEVEL                | String    | Log level: trace, debug, info, warn, error, fatal            |
| NANOMQ_LOG_DIR                  | String    | Path to store log files (effective when output is file)      |
| NANOMQ_LOG_FILE                 | String    | Log file name (effective when output is a file)              |
| NANOMQ_LOG_ROTATION_SIZE        | String    | Maximum occupied space per log file; <br /><br />Unit: `KB | MB | GB`;<br /><br />Default: `10MB` |
| NANOMQ_LOG_ROTATION_COUNT       | Integer   | Maximum number of rotated log files;<br />Default: `5`       |
| NANOMQ_CONF_PATH                | String    | NanoMQ configuration file path (default: `/etc/nanomq.conf`) |

**Example: Specify the configuration file path through environment variables**

```bash
docker run -d -p 1883:1883 -e NANOMQ_CONF_PATH="/usr/local/etc/nanomq.conf" \
            [-v {LOCAL PATH}:{CONTAINER PATH}] \
            --name nanomq emqx/nanomq:0.18.2-slim
```

## Performance Tunning

To achieve better performance, you can adjust the following configurations in the `nanomq.conf` file:

| Configuration Item      | Type    | Description                                                  |
| ----------------------- | ------- | ------------------------------------------------------------ |
| system.num_taskq_thread | Unsigned Integar 32 (Long) | Number of task queue threads used, recommended to match the number of CPU cores. |
| system.max_taskq_thread | Unsigned Integar 32 (Long) | Maximum number of task queue threads that can be used, recommended to match the number of CPU cores. |
| system.parallel         | Unsigned Integar 32 (Long) | Number of parallel processing tasks, recommended to match the number of CPU cores. |
| mqtt.session.msq_len    | Integer | Length of the Inflight window/queue for resending messages. It's recommended (depending on the memory) to set it to the maximum value: 65535. |

**Example**

Suppose you are working with a 4-core operating system, you can set as follows for optimized performance. The updates will take effect after NanoMQ restarts.

```bash
system.num_taskq_thread = 4
system.max_taskq_thread = 4
system.parallel = 8
mqtt.session.msq_len = 65535
```

