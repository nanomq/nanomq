# 配置文件

本节将介绍如何通过 `nanomq.conf` 配置文件来配置规则引擎。

## 规则引擎配置

默认情况规则引擎功能是关闭的，如需要启用，请[开启 `-DENABLE_RULE_ENGINE=ON` 选项进行编译](../installation/build-options.md)。规则引擎开启后，默认支持 `repub` 功能。

## 转发规则

用户可通过转发规则实现 MQTT 消息的转发，具体的配置项如下表所列：

参数名                             | 数据类型     | 参数说明
--------------------------------- | -------- | ---------------------------------
rules.repub.rules[0].address      | String   | 规则引擎重新发布地址 (mqtt-tcp://host:port)
rules.repub.rules[0].topic        | String   | 规则引擎重新发布主题
rules.repub.rules[0].username     | String   | 规则引擎重新发布用户名
rules.repub.rules[0].password     | String   | 规则引擎重新发布密码
rules.repub.rules[0].proto_ver    | Integer  | 规则引擎重新发布协议版本，默认是 4 
rules.repub.rules[0].clientid     | String   | 规则引擎重新发布客户端标识符
rules.repub.rules[0].keepalive    | Duration | 规则引擎重新发布保活时间，默认值是 60 
rules.repub.rules[0].clean_start  | Boolean  | 规则引擎重新发布 clean_start 标志，默认是 True 
rules.repub.rules[0].sql          | String   | 规则引擎 SQL 语句

### 创建规则

假设我们希望配置一条 `repub`  规则，根据规则，当收到从主题 `abc` 发来的消息时，NanoMQ 会将 `topic` 和 `payload` 打包成 JSON 并转发到 `topic/repub1`。

:::: tabs type:card

::: tab HOCON 配置格式

希望使用 HOCON 配置格式的用户，可参考以下格式，将配置写入 `nanomq.conf`文件，相关设置将在 NanoMQ 重启后生效。

- 完整的配置项列表，可参考 [配置说明 - v019](../config-description/rules.md)

- NanoMQ 0.14 ~ 0.18 版本用户，可参考 [配置说明 - v0.14](../config-description/v014.md)

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

:::

::: tab KV 配置格式

希望使用 KV 配置格式的用户，可参考以下格式，将配置写入 `nanomq_old.conf `文件，相关设置将在 NanoMQ 重启后生效。

完整的配置项列表，可参考 [经典 KV 格式配置说明](../config-description/v013.md)

```bash
rule_option.repub=enable 
rule.repub.1.address=mqtt-tcp://localhost:1883
rule.repub.1.topic=topic/repub1
rule.repub.1.proto_ver=4
rule.repub.1.clientid=repub_client1
rule.repub.1.keepalive=60
rule.repub.1.clean_start=true
rule.repub.1.username=username
rule.repub.1.password=passwd
rule.repub.event.publish.1.sql="SELECT topic, payload FROM "abc""
```

:::

::::

### 测试规则

在第一个窗口启动 `nanomq`：
```sh
$ nanomq start
```
在第二个窗口启动 `nanomq_cli`，订阅指定服务器地址下的 `topic/repub1` 主题：
```sh
$ nanomq_cli sub -t topic/repub1
connect_cb: mqtt-tcp://127.0.0.1:1883 connect result: 0 
topic/repub1: {"topic":"abc","payload":"aaa"}
```
在第三个窗口启动一个新的 `nanomq_cli`，发布消息 `aaa` 到主题 `abc`：
```sh
$ nanomq_cli pub -t abc -m aaa
```
可以看到第二个窗口收到来自主题 `topic/repub1` 的消息。

## SQLite 规则

如需启用 `SQLite`，请[开启 `-DNNG_ENABLE_SQLITE=ON` 选项进行编译](../installation/build-options.md)。

参数名                          | 数据类型   | 参数说明
------------------------------ | ------    | -------------------------------------------
rules.sqlite.path              | String    | 规则引擎 SQLite3 数据库路径, 默认是 /tmp/rules_engine.db
rules.sqlite.rules[0].table    | String    | 规则引擎 SQLite3 数据库表名
rules.sqlite.rules[0].sql      | String    | 规则引擎 SQL 语句

### 创建规则

假设我们希望配置一条 `sqlite`  规则，根据规则，当收到从主题 `abc` 发来的消息时，触发 NanoMQ 的规则引擎存储，并将 `topic` 和 `payload` 两个字段的内容存储到 database 文件的表 `broker` 中。

:::: tabs type:card

::: tab HOCON 配置格式

希望使用 HOCON 配置格式的用户，可参考以下格式，将配置写入 `nanomq.conf`文件，相关设置将在 NanoMQ 重启后生效。

- 完整的配置项列表，可参考 [配置说明 - v019](../config-description/rules.md)

- NanoMQ 0.14 ~ 0.18 版本用户，可参考 [配置说明 - v0.14](../config-description/v014.md)

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
:::

::: tab KV 配置格式

希望使用 KV 配置格式的用户，可参考以下格式，将配置写入 `nanomq_old.conf `文件，相关设置将在 NanoMQ 重启后生效。

完整的配置项列表，可参考 [经典 KV 格式配置说明](../config-description/v013.md)

```bash
rule_option=ON
rule_option.sqlite=enable
rule.sqlite.path=/tmp/sqlite_rule.db
rule.sqlite.1.table=broker
rule.sqlite.event.publish.1.sql=SELECT topic, payload FROM "abc"
```

:::

::::

### 测试规则

 在第一个窗口启动 `nanomq`：

```sh
$ nanomq start
```
在第二个窗口启动 `nanomq_cli`，发布消息 `aaa` 到主题 `abc`:
```sh
$ nanomq_cli pub -t abc -m aaa
```
在第二个窗口查看 SQLite 保存的消息。
```sh
$ sqlite3 /tmp/sqlite_rule.db
SQLite version 3.11.0 2016-02-15 17:29:24
Enter ".help" for usage hints.
sqlite> .header on
sqlite> .table
broker
sqlite> select * from broker;
RowId|Topic|Payload
1|abc|aaa
```
**📢注意**：使用 `sqlite3` 命令前确保已安装，如未安装可通过以下命令安装：

```sh
apt update
apt install sqlite3
```

## MySQL 规则配置

### 前置准备

如需启用 `MySQL`，请先安装依赖:

- ubuntu
   ```shell
   apt-get install pkg-config
   apt install libmysqlclient-dev
   ```
- macOS
   ```shell
   brew install pkg-config
   brew install mysql
   ```
### 配置项

开启 `-DENABLE_MYSQL=ON` 选项进行编译，具体操作，见[通过源代码编译安装 NanoMQ](../installation/build-options.md)。相关配置项如下表所列：

参数名                              | 数据类型   | 参数说明
---------------------------------- | -------- | -----------------------------------
rules.mysql.name.conn.table        | String   | 规则引擎 mysql 数据库表名字
rules.mysql.name.conn.host         | String   | 规则引擎 mysql 数据库主机名
rules.mysql.name.conn.username     | String   | 规则引擎 mysql 数据库用户
rules.mysql.name.conn.password     | String   | 规则引擎 mysql 数据库密
rules.mysql.name.rules[0].table    | String   | 规则引擎 mysql 数据库名字, 默认是 mysql_rules_db
rules.mysql.name.rules[0].sql      | String   | 规则引擎 sql 语句

### 创建规则

我们希望创建如下规则，当收到来自主题 `abc` 的消息，会触发 NanoMQ 的规则引擎存储，并将 `field` 的所有字段的内容存到 `database` 指定的表 `broker1` 内。

:::: tabs type:card

::: tab HOCON 配置格式

希望使用 HOCON 配置格式的用户，可参考以下格式，将配置写入 `nanomq.conf`文件，相关设置将在 NanoMQ 重启后生效。

- 完整的配置项列表，可参考 [配置说明 - v019](../config-description/rules.md)

- NanoMQ 0.14 ~ 0.18 版本用户，可参考 [配置说明 - v0.14](../config-description/v014.md)

```sh
# # Currently, MySQL rule only supports the configuration of one database.
rules.mysql.mysql_rule_db {
	conn = {
		# # The host for a mqsql client.
		# #
		# # Value: String
		host = localhost
		# # The username for a mqsql client.
		# #
		# # Value: String
		username = username
		# # The password for a mysql client.
		# #
		# # Value: String
		password = password
		# # Rule engine option mysql database name
		# # Rule engine db path, default is exec path.
		# # 
		# # Value: File
		database = db_name
	}
	
	rules = [
		{
			# # Rule engine option mysql database table name
			# # Rule engine db table name.
			# # 
			# # Value: String
			table = broker1
			# # Rule engine option sql
			# # Rule engine sql clause.
			# # 
			# # Value: String
			sql = "SELECT * FROM \"abc\""
		}
	]
}
```

:::

::: tab KV 配置格式

希望使用 KV 配置格式的用户，可参考以下格式，将配置写入 `nanomq_old.conf `文件，相关设置将在 NanoMQ 重启后生效。

完整的配置项列表，可参考 [配置说明 - v013 ](../config-description/v013.md) <!--这里的第一个参数名称觉得不太合理-->

```bash
rule_option=ON
rule_option.mysql=enable
rule.mysql.name=mysql_rule.db
rule.mysql.1.table=broker
rule.mysql.1.host=localhost
rule.mysql.1.username=username
rule.mysql.1.password=password
rule.mysql.event.publish.1.sql=SELECT * FROM "abc"
```

:::

::::

### 测试规则

在第一个窗口启动 `nanomq`:
```sh
$ nanomq start
```
在第二个窗口启动 `nanomq_cli`，发布消息 `aaa` 到主题 `abc`:
```sh
$ nanomq_cli pub -t abc -m aaa
```
在第二个窗口查看 MySQL 保存的消息。
```sh
$ mysql -u username -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 18
Server version: 5.7.33-0ubuntu0.16.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use db_name
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> select * from broker1;
+-----+------+------+-------+-----------------+----------+----------+------------+-----------------+
| idx | Qos  | Id   | Topic | Clientid        | Username | Password | Timestamp  | Payload         |
+-----+------+------+-------+-----------------+----------+----------+------------+-----------------+
|   1 |    0 |    0 | abc   | nanomq-fcfd2f11 | (null)   | (null)   | 1688437187 | aaaaaaaaaaaaaaa |
+-----+------+------+-------+-----------------+----------+----------+------------+-----------------+
1 row in set (0.00 sec)

```
**📢注意**：确保 `conn` 配置项中各个参数是有效的，其中 `database` 需要提前创建。