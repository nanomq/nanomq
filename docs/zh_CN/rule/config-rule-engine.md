## 配置文件

本节将介绍如何通过 `nanomq.conf` 配置文件来配置规则引擎，并将覆盖以下主题：

- [数据持久化到 SQLite](#sqlite-规则配置)
- [数据持久化到 MySQL](#mysql-规则配置)
- [重新发布操作](#repub-规则配置)

## 规则引擎配置

| 参数名      | 数据类型 | 参数说明                                                     |
| ----------- | -------- | ------------------------------------------------------------ |
| rule.option | String   | 规则引擎开关, 当时用规则引擎进行持久化，必须设置该选项为 ON。 |

## SQLite 规则配置

| 参数名                       | 数据类型 | 参数说明                                                |
| ---------------------------- | -------- | ------------------------------------------------------- |
| rule.sqlite.path             | String   | 规则引擎 SQLite3 数据库路径, 默认是 /tmp/rule_engine.db |
| rule.sqlite.enabled          | Boolen   | 规则引擎 SQLite3 数据库开关状态, 默认是 true            |
| rule.sqlite.rules[0].enabled | Boolen   | 规则引擎 SQLite3 数据库当前规则开关状态, 默认是 true    |
| rule.sqlite.rules[0].table   | String   | 规则引擎 SQLite3 数据库表名                             |
| rule.sqlite.rules[0].sql     | String   | 规则引擎 sql 语句                                       |

## MySQL 规则配置

| 参数名                       | 数据类型 | 参数说明                                           |
| ---------------------------- | -------- | -------------------------------------------------- |
| rule.mysql.name              | String   | 规则引擎 mysql 数据库名字, 默认是 mysql_rule_db    |
| rule.mysql.enabled           | Boolen   | 规则引擎 mysql 数据库开关状态, 默认是 true         |
| rule.mysql.rules[0].enabled  | Boolen   | 规则引擎 mysql 数据库当前规则开关状态, 默认是 true |
| rule.mysql.rules[0].table    | String   | 规则引擎 mysql 数据库表名字                        |
| rule.mysql.rules[0].host     | String   | 规则引擎 mysql 数据库主机名                        |
| rule.mysql.rules[0].username | String   | 规则引擎 mysql 数据库用户                          |
| rule.mysql.rules[0].password | String   | 规则引擎 mysql 数据库密                            |
| rule.mysql.rules[0].sql      | String   | 规则引擎 sql 语句                                  |

## Repub 规则配置

| 参数名                          | 数据类型 | 参数说明                                       |
| ------------------------------- | -------- | ---------------------------------------------- |
| rule.repub.enabled              | Boolen   | 规则引擎 repub 开关状态, 默认是 true           |
| rule.repub.rules[0].enabled     | Boolen   | 规则引擎 repub 当前规则开关状态, 默认是 true   |
| rule.repub.rules[0].address     | String   | 规则引擎重新发布地址 (mqtt-tcp://host:port)    |
| rule.repub.rules[0].topic       | String   | 规则引擎重新发布主题                           |
| rule.repub.rules[0].username    | String   | 规则引擎重新发布用户名                         |
| rule.repub.rules[0].password    | String   | 规则引擎重新发布密码                           |
| rule.repub.rules[0].proto_ver   | Integer  | 规则引擎重新发布协议版本, 默认是 4             |
| rule.repub.rules[0].clientid    | String   | 规则引擎重新发布客户端标识符                   |
| rule.repub.rules[0].keepalive   | Duration | 规则引擎重新发布保活时间, 默认值是 60          |
| rule.repub.rules[0].clean_start | Boolean  | 规则引擎重新发布 clean_start 标志, 默认是 true |
| rule.repub.rules[0].sql         | String   | 规则引擎 sql 语句                              |

