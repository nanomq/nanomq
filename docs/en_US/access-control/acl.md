# Access Control Configuration

Access Control List (ACL) provides a more fine-grained approach to authorization. It defines rules that are matched from top to bottom. Once a rule is matched, its permission is applied, and the remaining rules are ignored.

## Configuration Items

| Name     | Type           | Required | Description                                  |
| -------- | -------------- | -------- | -------------------------------------------- |
| permit   | enum           | Yes      | permission: `allow` ,`deny`                  |
| action   | enum           | No       | operation : `publish`, `subscribe`, `pubsub` |
| topics   | Arrary[String] | No       | Array of Topic                               |
| username | String         | No       | Username: "`#`" means all users              |
| clientid | String         | No       | ClientID: "`#`" means all client IDs         |
| and      | Array[Object]  | No       | `AND` operator                               |
| or       | Array[Object]  | No       | `OR` operator                                |

## Configuration Example

This configuration defines various rules for different users and topics, providing a flexible mechanism for managing permissions.
```bash
authorization {
	## Allow or deny if no ACL rules matched.
	##
	## Value: allow | deny
	no_match = allow
	
	## The action when acl check rejects the current operation
	##
	## Value: ignore | disconnect
	## Default: ignore
	deny_action = ignore

	cache = {
		## Whether to enable ACL cache.
		##
		## If enabled, ACLs roles for each client will be cached in the memory
		##
		## Value: on | off
		enable = false

		## The maximum count of ACL entries can be cached for a client.
		##
		## Value: Integer greater than 0
		## Default: 32
		max_size = 32

		## The time after which an ACL cache entry will be deleted
		##
		## Value: Duration
		## Default: 1 minute
		ttl = 1m
	}
	sources = [
    {
        type = file
        enable = false

        rules = [
          ## Allow MQTT client using username "dashboard"  to subscribe to "$SYS/#" topics
          {"permit": "allow", "username": "dashboard", "action": "subscribe", "topics": ["$SYS/#"]}

          ## Allow users with IP address "127.0.0.1" to publish/subscribe to topics "$SYS/#", "#"
          {"permit": "allow", "ipaddr": "127.0.0.1", "action": "pubsub", "topics": ["$SYS/#", "#"]}

          ## Deny "All Users" subscribe to "$SYS/#" "#" Topics
          {"permit": "deny", "username": "#", "action": "subscribe", "topics": ["$SYS/#", "#"]}

          ## Allow any other publish/subscribe operation
          {"permit": "allow"}
        ]
      }
	]
	
}
```

