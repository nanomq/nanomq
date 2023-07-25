# 规则引擎

NanoMQ 规则引擎可实现对系统内各种事件的动态响应，可以帮助管理复杂消息路由场景，触发自动化动作，以及集成其他系统等场景。

## 使用 SQLite 实现数据持久化

本节介绍如何通过配置实现使用 SQLite 处理 MQTT 消息，包括 SQLite 数据库路径及用于操作 MQTT 消息的 SQL 规则。

### 配置示例

```hcl
rules.sqlite = {
  path = "/tmp/sqlite_rule.db"          # SQLite 数据库文件路径
  rules = [
    {
      sql = "SELECT payload.x.y as y, payload.z as z FROM \"#\" WHERE y > 10 and z != 'str'"  # 规则 SQL
      table = "broker"                  # 规则的表名
    },
    {
      sql = "SELECT topic, payload FROM \"abc\""   # 第二条规则 SQL
      table = "broker1"                 # 第二条规则的表名
    }
  ]
}
```

在这个示例配置中，定义了两条 SQL 规则：

- 第一条规则将基于`y > 10` 和 `z != 'str'`  筛选和处理 MQTT 消息，并将结果存储在表 `broker` 中。
- 第二条规则将从主题为 `"abc"` 的 MQTT 消息中选择 `topic` 和 `payload`，并将结果存储在表 `broker1` 中。

### **配置项**

- `path`：指定 SQLite 数据库文件的路径。
- `rules`：规则对象数组，每个对象定义了一条针对 MQTT 消息的 SQL 规则。
  - `sql`：规则 SQL，用于从 MQTT 消息中筛选和管理数据。
  - `table`：制定处理结果的存储 SQLite 表。

## 使用 MySQL 实现数据持久化

本节介绍如何通过配置实现使用 MySQL 处理 MQTT 消息，包括 MySQL 数据库路径及用于操作 MQTT 消息的 SQL 规则。

### **配置示例**

```hcl
rules.mysql.mysql_rule_db = {
  conn = {
    host = "localhost"                  # MySQL 主机
    username = "username"               # MySQL 用户名
    password = "password"               # MySQL 密码
    database = "db_name"                # MySQL 数据库名称
  }

  rules = [
    {
      table = "broker"                  # 规则的 MySQL 表名
      sql = "SELECT payload.x.y as y, payload.z as z FROM \"#\" WHERE y > 10 and z != 'str'" # 规则 SQL
    },
    {
      table = "broker1"                 # 第二条规则的 MySQL 表名
      sql = "SELECT * FROM \"abc\""     # 第二条规则的 SQL
    }
  ]
}

```

在这个示例配置中，定义了两条 SQL 规则：

- 第一条规则将基于`y > 10` 和 `z != 'str'`  筛选和处理 MQTT 消息，并将结果存储在表 `broker` 中。
- 第二条规则将筛选主题 `"abc"` 下的所有 MQTT 消息，并将结果存储在表 `broker1` 中。

### **配置项**

- `conn`：连接相关设置
  - `host`： MySQL 服务器的主机。
  - `username`：MySQL 服务器的用户名。
  - `password`：MySQL 服务器的密码。
  - `database`：MySQL 服务器上的数据库名称；默认为 `mysql_rule_db`。**注意**：只能配置一个 MySQL 数据库。<!-- @jaylin 这里对吗？-->
- `rules`：规则对象数组，每个对象定义了一条针对 MQTT 消息的 SQL 规则。
  - `table`：规则适用的 MySQL 数据库表。
  - `sql`：规则 SQL，用于从 MQTT 消息中筛选和管理数据。

## 消息重新发布

本节介绍如何通过配置实现 MQTT 消息的重新发布，包括目标 MQTT 服务器，目标主题，以及在重新发布前对消息进行处理的 SQL 规则。

### **配置示例**

```hcl
rules.repub = {
  rules = [
    {
      server = "mqtt-tcp://localhost:1883"   # 重新发布的 MQTT 服务器地址
      topic = "topic/repub1"                 # 重新发布的主题
      proto_ver = 4                          # MQTT 协议版本
      clientid = "repub_client1"             # 重新发布客户端的客户端 ID
      keepalive = "60s"                      # 重新发布保活时间
      clean_start = true                     # clean_start 标志
      username = "username"                  # 重新发布客户端的用户名
      password = "passwd"                    # 重新发布客户端的密码
      sql = "SELECT payload.x.y as y, payload.z as z FROM \"#\" WHERE y > 10 and z != 'str'" # 规则 SQL
    },
    {
      server = "mqtt-tcp://localhost:1883"   # 第二条规则的 MQTT 服务器地址
      topic = "topic/repub2"                 # 第二条规则的重新发布的主题
      proto_ver = 4                          # 第二条规则的 MQTT 协议版本
      clientid = "repub_client2"             # 第二条规则的客户端 ID
      keepalive = "60s"                      # 第二条规则的保活时间
      clean_start = true                     # 第二条规则的clean_start 标志
      username = "username"                  # 第二条规则的用户名
      password = "passwd"                          # 第二条规则的密码
      sql = "SELECT topic, payload FROM \"abc\""   # 第二条规则的规则 SQL
    }
  ]
}
```

在这个示例配置中，定义了两条重新发布规则：

- 第一条规则将根据 `y > 10` 和 `z != 'str'` 从 MQTT 消息中选择和处理消息，并将结果重新发布到 MQTT 服务器 `mqtt-tcp://localhost:1883` 的 `topic/repub1` 主题上。
- 第二条规则从主题为 `"abc"` 的 MQTT 消息中选择所有数据，并将结果重新发布到 MQTT 服务器 `mqtt-tcp://localhost:1883` 的 `topic/repub2` 主题上。

### **配置项**

`rules`：规则对象数组，每个对象定义了一个用于处理 MQTT 消息的重新发布规则。

- `server`：重新发布的目标 MQTT 服务器地址。
- `topic`：重新发布的目标主题。
- `proto_ver`：MQTT 协议版本；默认为 4，可选值包括：
  - `5`： MQTT v5
  - `4`：MQTT v3.1.1
  - `3`：MQTT v3.1
- `clientid`：重新发布客户端的客户端 ID。
- `keepalive`：重新发布保活时间，缺省为 60s
- `clean_start`：是否清除会话。注意：有些 IoT 平台要求该选项设为 true。
- `username`：重新发布客户端的用户名。
- `password`：重新发布客户端的密码。
- `sql`：规则 SQL，用于从 MQTT 消息中选择和操作数据。
