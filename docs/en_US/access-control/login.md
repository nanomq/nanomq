# Login Authentication

User Login authorization configuration allows users to authenticate using a simple username and password.

## Configuration Items

| Name       | Type   | Description |
| ---------- | ------ | ----------- |
| `username` | String | Username    |
| `password` | String | Password    |

## Configuration Example

```bash
authorization {
	no_match = allow
	deny_action = ignore
	cache = {
		enable = false
		max_size = 32
		ttl = 1m
	}
	sources = [
		{
			type = simple
			enable = false
			users = [
				{
					username = "admin"
					password = "public"
				}
				{
					username = "client"
					password = "public"
				}
			]
		}
  ]
}
```

In this configuration, 

- `no_match` and `deny_action` are set to `allow` and `ignore` respectively.
- `cache` is disabled.
- `sources` is the users that can access NanoMQ, two users are listed here, `admin` and `client`, both with the password `public`. 

According to the setting, user `admin` and `client` are allowed to work with NanoMQ unless explicitly denied by the system.  

