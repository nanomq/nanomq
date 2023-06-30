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


