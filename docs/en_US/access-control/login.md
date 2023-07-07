# Login Authentication

This feature folllows MQTT protocol username/password authenticaton [5.4.1 Authentication of Clients by the Server](http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Security). It can be used by the Server for authentication and authorization.

User Login authorization configuration allows users to authenticate using a simple username and password.

## Configuration Items

| Name       | Type   | Description |
| ---------- | ------ | ----------- |
| `username` | String | Username    |
| `password` | String | Password    |

Write the username and password in the format below and save it to the `nanomq_pwd.conf` file. 

```bash
username:password
```

**Example**

```bash
# # Write "username":"password" in this way.
admin: public
client: public
```

::: tip 

The User Name MUST be a UTF-8 encoded string as defined in MQTT Standard.

:::

In this configuration, there are two users, `admin` and `client`, both with the password `public`. So user `admin` and `client` are allowed to work with NanoMQ when `allow_anonymous` is `false` unless explicitly denied by the system.  

And include it in `nanomq.conf`, as described in the [Access Control Introduction](introduction.md).

**Example:**

```bash
password = {include "/etc/nanomq_pwd.conf"}
```

## Configure in KV Format

Users wishing to use the KV configuration format can refer to the following structure and write their configurations into the `nanomq_old.conf` file. The relevant settings will take effect after NanoMQ is restarted.

```bash
username=admin
password=public
```

