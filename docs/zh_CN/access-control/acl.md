# 访问控制列表

访问控制列表（ACL）提供了一种更细化的授权方法，它会按照自上而下的顺序进行授权检查。当一个规则匹配到当前客户端时，规则允许或拒绝的动作就会生效，后面的规则不再继续检查。

| 字段名   | 数据类型       | 必填 | 描述                                                         |
| -------- | -------------- | ---- | ------------------------------------------------------------ |
| permit   | enum           | 是   | 规则权限：允许：`allow`；拒绝：`deny`                        |
| action   | enum           | 否   | 指定动作：发布：`publish`；订阅：`subscribe`；发布/订阅： `pubsub` |
| topics   | Arrary[String] | 否   | 主题或主题过滤器数组                                         |
| username | String         | 否   | 用户名若输入值为 "`#`"，表示所有用户                         |
| clientid | String         | 否   | 客户端 ID 若输入值为 "`#`"，表示所有客户端                   |
| and      | Array[Map]     | 否   | 与操作                                                       |
| or       | Array[Map]     | 否   | 或操作                                                       |

## 配置实例

在以下配置文件中，我们为不同的用户和主题定义了不同的访问规则，实现了灵活的授权检查机制。

```bash
authorization {
	## 如未匹配到任何 ACL 规则，允许或拒绝操作，可选值：allow | deny
	no_match = allow
	
	## 如 ACL 检查拒绝当前操作，则应执行哪个动作，可选值：ignore | disconnect；默认值：ignore
	deny_action = ignore

	cache = {
		## 是否启用 ACL 缓存。启用后，将在内存中缓存每个客户端的 ACL 角色，可选值：on | off
		enable = false

		## 单个客户端允许缓存的最大 ACL 条目数。类型：大于 0 的整数。默认值：32
		max_size = 32

		## 删除 ACL 缓存条目的等待时间；类型：Duration；默认值：1 分钟
		ttl = 1m
	}
	sources = [
    {
        type = file
        enable = false

        rules = [
          ## 允许用户名为"dashboard" 的 MQTT 客户端通过订阅"$SYS/#"主题
          {"permit": "allow", "username": "dashboard", "action": "subscribe", "topics": ["$SYS/#"]}

          ## 允许 IP 为 "127.0.0.1" 的用户订阅"$SYS/#", "#"主题或向其发送消息。
          {"permit": "allow", "ipaddr": "127.0.0.1", "action": "pubsub", "topics": ["$SYS/#", "#"]}

          ## 拒绝"所有用户"订阅"$SYS/#" "#"主题
          {"permit": "deny", "username": "#", "action": "subscribe", "topics": ["$SYS/#", "#"]}

          ## 允许任何其他发布/订阅操作
          {"permit": "allow"}
        ]
      }
	]
	
}
```

