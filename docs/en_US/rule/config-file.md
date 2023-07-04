# Configure with Rule Engine

This section provides a comprehensive guide on setting up the rule engine according to your specific needs using a configuration file.

## Rule Engine Configuration

By default, the rule engine function is disabled. To enable it, please compile with the `-DENABLE_RULE_ENGINE=ON` option. Once the rule engine is enabled, the `repub` function is supported by default.

## Rule Configuration for Republish

Republish is a feature in NanoMQ that enables republishing of MQTT messages. The following parameters control its behavior:

Name                            | Type    | Description
------------------------------- | ------- | ----------------------------------------------------------
rules.repub.rules[0].server      | String  | Rule engine option repub address (mqtt-tcp://host:port)
rules.repub.rules[0].topic       | String  | Rule engine option repub topic
rules.repub.rules[0].username    | String  | Rule engine option repub username
rules.repub.rules[0].password    | String  | Rule engine option repub password
rules.repub.rules[0].proto_ver   | Integer | Rule engine option repub protocol version, default is 4
rules.repub.rules[0].clientid    | String  | Rule engine option repub clientid
rules.repub.rules[0].keepalive   | Duration| Rule engine option repub keepalive
rules.repub.rules[0].clean_start | Boolean | Rule engine option repub clean_start flag, default is true
rules.repub.rules[0].sql         | String  | Rule engine sql clause

**example**
```sh
rules.repub {
	rules = [
		{
			# # Repub address: host:port .
			# #
			# # Value: String
			# # Example: mqtt-tcp://127.0.0.1:1883
			server = "mqtt-tcp://localhost:1883"
			# # Repub topic .
			# #
			# # Value: String
			# # Example: topic/repub
			topic = "topic/repub1"
			# # Protocol version of the Repub.
			# #
			# # Value: Enum
			# # - 5: mqttv5
			# # - 4: mqttv311
			# # - 3: mqttv31
			proto_ver = 4
			# # The ClientId of a Repub client.
			# # Default random string.
			# #
			# # Value: String
			clientid = "repub_client1"
			# # Ping interval of a Repub client.
			# #
			# # Value: Duration
			# # Default: 60 seconds
			keepalive = 60s
			# # The Clean start flag of a Repub client.
			# #
			# # Value: boolean
			# # Default: true
			# #
			# # NOTE: Some IoT platforms require clean_start
			# #       must be set to 'true'
			clean_start = true
			# # The username for a Repub client.
			# #
			# # Value: String
			username = username
			# # The password for a Repub.
			# #
			# # Value: String
			password = passwd
			# # Rule engine option sql
			# # Rule engine sql clause.
			# # 
			# # Value: String
			sql =  "SELECT topic, payload FROM \"abc\""
		}
	]
}
```

The example above opens the repub of the NanoMQ rule engine in the config. When a message is received from the topic `abc`, the `topic` and `payload` will be packaged as JSON and sent to the topic `topic/repub1`.

Add the above configuration to `/etc/nanomq.conf` and start `nanomq` in the first terminal window.
```sh
$ nanomq start

```
Start `nanomq_cli` in the second terminal window and subscribe to the topic `topic/repub1` from the address pointed to by `server` in the configuration file.
```sh
$ nanomq_cli sub -t topic/repub1
connect_cb: mqtt-tcp://127.0.0.1:1883 connect result: 0 
topic/repub1: {"topic":"abc","payload":"aaa"}
```
In the third terminal window, publish the message `aaa` to the topic `abc` with the following command:
```sh
$ nanomq_cli pub -t abc -m aaa
```
You should see the message received in the second window from the topic `topic/repub1`.


## Data Persistence with SQLite

NanoMQ supports data persistence with SQLite, see below for the configuration items. 
To enable `SQLite`, please compile with the `-DNNG_ENABLE_SQLITE=ON` option.

Name                         | Type   | Description
---------------------------- | ------ | ------------------------------------------------------------------------
rules.sqlite.path             | String | Rule engine option SQLite3 database path, default is /tmp/rule_engine.db
rules.sqlite.rules[0].table   | String | Rule engine option SQLite3 database table name
rules.sqlite.rules[0].sql     | String | Rule engine sql clause

**example**
```sh
rules.sqlite {
	# # Rule engine option SQLite3 database path
	# # Rule engine db path, default is exec path.
	# # 
	# # Value: File
	path = "/tmp/sqlite_rule.db"
	rules = [
		{
			# # Rule engine option sql
			# # Rule engine sql clause.
			# # 
			# # Value: String
			sql = "SELECT topic, payload FROM \"abc\""
			# # Rule engine option SQLite3 database table name
			# # Rule engine db table name.
			# # 
			# # Value: String
			table = broker
		}
	]
}
```
When a message is received from the topic `abc`, the rule engine of NanoMQ will be triggered to store the contents of the `topic` and `payload` fields in a database table called `broker` in the database file specified by the `path` field. The process is similar to the `repub` as follows:

Add the above configuration to `/etc/nanomq.conf` and start `nanomq` in the first terminal window.
```sh
$ nanomq start

```
Publish the message `aaa` to the topic `abc` in the second terminal window with the following command:
```sh
$ nanomq_cli pub -t abc -m aaa
```
Then, in the second terminal window, view the messages saved in SQLite:
```sh
$ sqlite3 /tmp/sqlite_rule.db
SQLite version 3.11.0 2016-02-15 17:29:24
Enter ".help" for usage hints.
sqlite> .header on
sqlite> .table
broker
sqlite> select * from broker1;
RowId|Topic|Payload
1|abc|aaa
```
**📢Note**: Make sure that `sqlite3` command is installed before using it. If it is not installed, you can install it using the following command:
```sh
apt update
apt install sqlite3
```

## Data Persistence with MySQL

NanoMQ supports data persistence with MySQL, see below for the configuration items. 
To enable `MySQL`, please install the dependencies first:
- ubuntu
```shell
apt-get install pkg-config
apt install libmysqlclient-dev
```
- mac
```shell
brew install pkg-config
brew install mysql
```
Compile with the `-DENABLE_MYSQL=ON` option enabled.

Name                                | Type   | Description
----------------------------------  | ------ | ----------------------------------------------------------------
rules.mysql.name.conn.database      | String | Rule engine option mysql database name, default is mysql_rule_db
rules.mysql.name.conn.host          | String | Rule engine option mysql database host
rules.mysql.name.conn.username      | String | Rule engine option mysql database username
rules.mysql.name.conn.password      | String | Rule engine option mysql database password
rules.mysql.name.rules[0].table     | String | Rule engine option mysql database table name
rules.mysql.name.rules[0].sql       | String | Rule engine sql clause

