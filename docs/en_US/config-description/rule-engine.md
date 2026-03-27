# Rule Engine

In NanoMQ, you can leverage the powerful rule engine to implement dynamic responses to various events within the system. NanoMQ rule engine is an indispensable tool for managing complex message routing scenarios, triggering automated actions, and integrating other systems with your MQTT setup.

## Data Persistence with SQLite

This part introduces the settings for handling MQTT messages using SQLite. This includes settings for the SQLite database path and SQL rules for manipulating MQTT messages.

### Example Configuration

```hcl
rules.sqlite = {
  path = "/tmp/sqlite_rule.db"           # SQLite database file path
  rules = [
    {
      sql = "SELECT payload.x.y as y, payload.z as z FROM \"#\" WHERE y > 10 and z != 'str'"    # SQL clause for the rule
      table = "broker"                  # Table name for the rule
    },
    {
      sql = "SELECT topic, payload FROM \"abc\""   # Another SQL clause for the second rule
      table = "broker1"                # Table name for the second rule
    }
  ]
}
```

In this example configuration, two SQL rules are defined.

- The first rule selects and manipulates data from MQTT messages where `y > 10` and `z != 'str'`. The resulting data will be stored in the `broker` table in the SQLite database.
- The second rule selects the `topic` and `payload` from MQTT messages where the topic is `"abc"`. The resulting data from these rules will be stored in the  `broker1` table in the SQLite database.

### **Configuration Items**

- `path`: Specifies the path to the SQLite database file. 
- `rules`: This is an array of rule objects. Each object defines a SQL rule for manipulating MQTT messages.
  - `sql`: Specifies the SQL clause for the rule. This clause is used to select and manipulate data from MQTT messages.
  - `table`: Specifies the SQLite database table that the rule applies to.

## Data Persistence with MySQL

This part specifies settings for handling MQTT messages using MySQL. This includes settings for the MySQL database connection and SQL rules for manipulating MQTT messages.

### **Example Configuration**

```hcl
rules.mysql.mysql_rule_db = {
  conn = {
    host = "localhost"                  # MySQL host
    username = "username"               # MySQL username
    password = "password"               # MySQL password
    database = "db_name"                # MySQL database name
  }

  rules = [
    {
      table = "broker"                  # MySQL table name for the rule
      sql = "SELECT payload.x.y as y, payload.z as z FROM \"#\" WHERE y > 10 and z != 'str'"    # SQL clause for the rule
    },
    {
      table = "broker1"                 # MySQL table name for the second rule
      sql = "SELECT * FROM \"abc\""     # SQL clause for the second rule
    }
  ]
}

```

In this example configuration, two SQL rules are defined:

- The first rule selects and manipulates data from MQTT messages where `y > 10` and `z != 'str'`. The resulting data will be stored in the `broker` table.
- The second rule selects all data from MQTT messages where the topic is `"abc"`. The resulting data will be stored in the `broker1` table.

### **Configuration Items**

- `conn`: This object defines the connection settings for the MySQL client.
  - `host`: Specifies the host of the MySQL server. 
  - `username`: Specifies the username for the MySQL server.
  - `password`: Specifies the password for the MySQL server.
  - `database`: Specifies the name of the database on the MySQL server; default: `mysql_rule_db`. **Note**: Only one MySQL database can be configured. <!--@jaylin 这里对吗？-->
- `rules`: This is an array of rule objects. Each object defines a SQL rule for manipulating MQTT messages.
  - `table`: Specifies the MySQL database table that the rule applies to.
  - `sql`: Specifies the SQL clause for the rule. This clause is used to select and manipulate data from MQTT messages.

## Message Republishing

This part introduces the settings for handling the republishing of MQTT messages. This includes settings for the MQTT server where messages will be republished, the topic to republish on, and SQL rules for manipulating MQTT messages before republishing.

### **Example Configuration**

```hcl
rules.repub = {
  rules = [
    {
      server = "mqtt-tcp://localhost:1883"   # MQTT server address for republishing
      topic = "topic/repub1"                 # Topic to republish on
      proto_ver = 4                          # MQTT protocol version
      clientid = "repub_client1"             # Client ID for the republishing client
      keepalive = "60s"                      # Ping interval for the republishing client
      clean_start = true                     # Clean start flag for the republishing client
      username = "username"                  # Username for the republishing client
      password = "passwd"                    # Password for the republishing client
      sql = "SELECT payload.x.y as y, payload.z as z FROM \"#\" WHERE y > 10 and z != 'str'"    # SQL clause for the rule
    },
    {
      server = "mqtt-tcp://localhost:1883"   # MQTT server address for the second rule
      topic = "topic/repub2"                 # Topic to republish on for the second rule
      proto_ver = 4                          # MQTT protocol version for the second rule
      clientid = "repub_client2"             # Client ID for the second rule
      keepalive = "60s"                      # Ping interval for the second rule
      clean_start = true                     # Clean start flag for the second rule
      username = "username"                  # Username for the second rule
      password = "passwd"                          # Password for the second rule
      sql = "SELECT topic, payload FROM \"abc\""   # SQL clause for the second rule
    }
  ]
}
```

In this example configuration, two republishing rules are defined:

- The first rule selects and manipulates data from MQTT messages where `y > 10` and `z != 'str'` and republishes the messages on `topic/repub1`. 
- The second rule selects the `topic` and `payload` from MQTT messages where the topic is `"abc"` and republishes the messages on `topic/repub2`.

### **Configuration Items**

`rules`: This is an array of rule objects. Each object defines a republishing rule.

- `server`: Specifies the MQTT server address where messages will be republished.
- `topic`: Specifies the topic to republish on.
- `proto_ver`: Specifies the MQTT protocol version to use. Options are：
  - `5` for MQTT v5
  - `4` for MQTT v3.1.1
  - `3` for MQTT v3.1
- `clientid`: Specifies the client ID for the republishing client.
- `keepalive`: Specifies the ping interval for the republishing client.
- `clean_start`: Specifies the clean start flag for the republishing client. **Note**: Some IoT platforms require this to be set to `true`.
- `username`: Specifies the username for the republishing client.
- `password`: Specifies the password for the republishing client.
- `sql`: Specifies the SQL clause for the rule. This clause is used to select and manipulate data from MQTT messages before republishing.
