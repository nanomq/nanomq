## 配置文件

本节将介绍如何通过 `nanomq.conf` 配置文件来配置规则引擎，并将覆盖以下主题：

- [配置文件](#配置文件)
- [规则引擎配置](#规则引擎配置)
- [Repub 规则配置](#repub-规则配置)
- [SQLite 规则配置](#sqlite-规则配置)
- [MySQL 规则配置](#mysql-规则配置)

## 规则引擎配置

默认情况规则引擎功能是关闭的，如需要启用，请开启 `-DENABLE_RULE_ENGINE=ON` 选项进行编译。规则引擎开启后，默认支持 `repub` 功能。

## Repub 规则配置

参数名                             | 数据类型     | 参数说明
--------------------------------- | -------- | ---------------------------------
rules.repub.rules[0].address      | String   | 规则引擎重新发布地址 (mqtt-tcp://host:port)
rules.repub.rules[0].topic        | String   | 规则引擎重新发布主题
rules.repub.rules[0].username     | String   | 规则引擎重新发布用户名
rules.repub.rules[0].password     | String   | 规则引擎重新发布密码
rules.repub.rules[0].proto_ver    | Integer  | 规则引擎重新发布协议版本, 默认是 4
rules.repub.rules[0].clientid     | String   | 规则引擎重新发布客户端标识符
rules.repub.rules[0].keepalive    | Duration | 规则引擎重新发布保活时间, 默认值是 60
rules.repub.rules[0].clean_start  | Boolean  | 规则引擎重新发布 clean_start 标志, 默认是 true
rules.repub.rules[0].sql          | String   | 规则引擎 sql 语句
**事例**
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

上面的 `config` 的事例将 NanoMQ 规则引擎的 `repub` 打开，当收到从主题 `abc` 来的消息时，将把 `topic` 和 `payload` 打包成 JSON 发到 `topic/repub1`。

将上面的配置加入到 `/etc/nanomq.conf` 中, 在第一个窗口启动 `nanomq`:
```sh
$ nanomq start

```
在第二个窗口启动 `nanomq_cli` 从配置文件中的 `server` 指向的地址订阅主题 `topic/repub1`:
```sh
$ nanomq_cli sub -t topic/repub1
connect_cb: mqtt-tcp://127.0.0.1:1883 connect result: 0 
topic/repub1: {"topic":"abc","payload":"aaa"}
```
在第三个窗口发布消息 `aaa` 到主题 `abc`:
```sh
$ nanomq_cli pub -t abc -m aaa
```
可以看到第二个窗口收到来自主题 `topic/repub1` 的消息。

## SQLite 规则配置

如需启用 `SQLite` 请开启 `-DNNG_ENABLE_SQLITE=ON` 选项进行编译。

参数名                          | 数据类型   | 参数说明
------------------------------ | ------    | -------------------------------------------
rules.sqlite.path              | String    | 规则引擎 SQLite3 数据库路径, 默认是 /tmp/rules_engine.db
rules.sqlite.rules[0].table    | String    | 规则引擎 SQLite3 数据库表名
rules.sqlite.rules[0].sql      | String    | 规则引擎 sql 语句



## MySQL 规则配置

如需启用 `MySQL`，请先安装依赖:
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
开启 `-DENABLE_MYSQL=ON` 选项进行编译。

参数名                              | 数据类型   | 参数说明
---------------------------------- | -------- | -----------------------------------
rules.mysql.name.conn.table        | String   | 规则引擎 mysql 数据库表名字
rules.mysql.name.conn.host         | String   | 规则引擎 mysql 数据库主机名
rules.mysql.name.conn.username     | String   | 规则引擎 mysql 数据库用户
rules.mysql.name.conn.password     | String   | 规则引擎 mysql 数据库密
rules.mysql.name.rules[0].table    | String   | 规则引擎 mysql 数据库名字, 默认是 mysql_rules_db
rules.mysql.name.rules[0].sql      | String   | 规则引擎 sql 语句


