# Access Control

Authentication and authorization are two fundamental security measures required in any system to verify the identity of users and ensure they have the necessary permissions to perform various actions. In the context of NanoMQ, a broker for MQTT services, these two aspects play a crucial role in ensuring the integrity and security of the entire system. In this document, we will explore various methods used for authentication and authorization in NanoMQ: User Login Authorization, Access Control List (ACL), and HTTP Authorization.

## Authentication Configuration

In NanoMQ, authentication is configured using a structure similar to the one below:

:::tip

NanoMQ also supports configuring in KV format. For details, see [Configuration Parameters - v013](../config-description/v013.md)

:::

```bash
auth {
  allow_anonymous = true
  no_match = allow
  deny_action = ignore
  password = {include "/etc/nanomq_pwd.conf"}
  acl = {include "/etc/nanomq_acl.conf"}
}
```

where, 

- `allow_anonymous` data type is `boolean`, with a default value of `true`, which allows anonymous login.
- `no_match` determines the default action for a request if none of the configured authenticators found any authentication rules.
- `deny_action` determines what to do if a request was rejected according to the authorization checks. The available options are `ignore` or `disconnect`
- `password` is the password file path. This will include the contents of the `nanomq_pwd.conf` file in your configuration, so make sure that the file only contains the password in the correct format, using `include` to include your password file.
- `acl` is the ACL file path, This will include the contents of the "nanomq_acl.conf" file in your configuration, so make sure that the file only contains the ACL in the correct format, using `include` to include your ACL file.
