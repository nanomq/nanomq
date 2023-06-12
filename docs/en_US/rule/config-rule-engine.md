# Configure with Rule Engine

#### Rule Engine Configuration

| Name        | Type   | Description                                                  |
| ----------- | ------ | ------------------------------------------------------------ |
| rule.option | String | Rule engine option, when persistent with rule engine, this option is must be ON. |

#### Rule Configuration for SQLite

| Name                         | Type   | Description                                                  |
| ---------------------------- | ------ | ------------------------------------------------------------ |
| rule.sqlite.path             | String | Rule engine option SQLite3 database path, default is /tmp/rule_engine.db |
| rule.sqlite.enabled          | Boolen | Rule engine option SQLite3 is enabled, default is true       |
| rule.sqlite.rules[0].enabled | Boolen | Rule engine option rule is enabled, default is true          |
| rule.sqlite.rules[0].table   | String | Rule engine option SQLite3 database table name               |
| rule.sqlite.rules[0].sql     | String | Rule engine sql clause                                       |


#### Rule Configuration for MySQL

| Name                         | Type   | Description                                                  |
| ---------------------------- | ------ | ------------------------------------------------------------ |
| rule.mysql.name              | String | Rule engine option mysql database name, default is mysql_rule_db |
| rule.mysql.enabled           | Boolen | Rule engine option mysql is enabled, default is true         |
| rule.mysql.rules[0].enabled  | Boolen | Rule engine option rule is enbaled, default is true          |
| rule.mysql.rules[0].table    | String | Rule engine option mysql database table name                 |
| rule.mysql.rules[0].host     | String | Rule engine option mysql database host                       |
| rule.mysql.rules[0].username | String | Rule engine option mysql database username                   |
| rule.mysql.rules[0].password | String | Rule engine option mysql database password                   |
| rule.mysql.rules[0].sql      | String | Rule engine sql clause                                       |


#### Rule configuration for repub

| Name                            | Type     | Description                                                |
| ------------------------------- | -------- | ---------------------------------------------------------- |
| rule.repub.enabled              | Boolen   | Rule engine option repub is enabled, default is true       |
| rule.repub.rules[0].enabled     | Boolen   | Rule engine option rule is enbaled, default is true        |
| rule.repub.rules[0].address     | String   | Rule engine option repub address (mqtt-tcp://host:port)    |
| rule.repub.rules[0].topic       | String   | Rule engine option repub topic                             |
| rule.repub.rules[0].username    | String   | Rule engine option repub username                          |
| rule.repub.rules[0].password    | String   | Rule engine option repub password                          |
| rule.repub.rules[0].proto_ver   | Integer  | Rule engine option repub protocol version, default is 4    |
| rule.repub.rules[0].clientid    | String   | Rule engine option repub clientid                          |
| rule.repub.rules[0].keepalive   | Duration | Rule engine option repub keepalive                         |
| rule.repub.rules[0].clean_start | Boolean  | Rule engine option repub clean_start flag, default is true |
| rule.repub.rules[0].sql         | String   | Rule engine sql clause                                     |


### 