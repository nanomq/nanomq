# Access Control

Authentication and authorization are two fundamental security measures required in any system to verify the identity of users and ensure they have the necessary permissions to perform various actions. In the context of NanoMQ, a broker for MQTT services, these two aspects play a crucial role in ensuring the integrity and security of the entire system. In this document, we will explore various methods used for authentication and authorization in NanoMQ: User Login Authorization, Access Control List (ACL), and HTTP Authorization.

## Authentication Configuration

In NanoMQ, authentication is configured using a structure similar to the one below:

```bash
authorization {
  sources = [
    { ...   },
    { ...   }
  ]
  no_match = allow
  deny_action = ignore
  cache {
    enable = true
    max_size = 1024
    ttl = 1m
  }
}
```

where, 

- `sources` is an optional list that configures the chain of authenticators;
- `no_match` determines the default action for a request if none of the configured authenticators found any authentication rules
- `deny_action` determines what to do if a request was rejected according to the authorization checks
-  `cache` is an optional value with caching settings.

## Authorization Configuration

In NanoMQ, authorization is configured using a structure similar to the one below:
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
        type = file
        enable = false

        rules = [
          {"permit": "allow", "username": "dashboard", "action": "subscribe", "topics": ["$SYS/#"]}
          {"permit": "allow", "ipaddr": "127.0.0.1", "action": "pubsub", "topics": ["$SYS/#", "#"]}
          {"permit": "deny", "username": "#", "action": "subscribe", "topics": ["$SYS/#", "#"]}
          {"permit": "allow"}
        ]
      }
	]
}
```

where, 

- `no_match` determines the default action for a publish/subscribe request if none of the configured authorizers found any authorization rules.
- `deny_action` determines what to do if a request was rejected according to the checks
-  `cache` is an optional value with caching settings.
- `sources`  is an optional list that configures the chain of authorizers;