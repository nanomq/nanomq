# Login Authentication

User Login authorization configuration allows users to authenticate using a simple username and password.

## Configuration Items

| Name       | Type   | Description |
| ---------- | ------ | ----------- |
| `username` | String | Username    |
| `password` | String | Password    |

Write the username and password in this format `username:password` and save it to the `nanomq_pwd.conf` file. And include it in `nanomq.conf`, as described in the [Access Control Introduction](introduction.md).

## Configuration Example

```bash
# # Write "username":"password" in this way.
admin: public
client: public
```

In this configuration, there are two users, `admin` and `client`, both with the password `public`. So user `admin` and `client` are allowed to work with NanoMQ when `allow_anonymous` is `false` unless explicitly denied by the system.  

