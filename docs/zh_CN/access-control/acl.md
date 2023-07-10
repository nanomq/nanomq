# 访问控制列表

访问控制列表（ACL）提供了一种更细化的授权方法，它会按照自上而下的顺序进行授权检查。当一个规则匹配到当前客户端时，规则允许或拒绝的动作就会生效，后面的规则不再继续检查。

## 配置项

| 字段名   | 数据类型       | 必填 | 描述                                                         |
| -------- | -------------- | ---- | ------------------------------------------------------------ |
| permit   | enum           | 是   | 规则权限：允许：`allow`；拒绝：`deny`                        |
| action   | enum           | 否   | 指定动作：发布：`publish`；订阅：`subscribe`；发布/订阅： `pubsub` |
| topics   | Array[String]  | 否   | 主题或主题过滤器数组                                         |
| username | String         | 否   | 用户名若输入值为 "`#`"，表示所有用户                         |
| clientid | String         | 否   | 客户端 ID 若输入值为 "`#`"，表示所有客户端                   |
| and      | Array[Map]     | 否   | 与操作                                                       |
| or       | Array[Map]     | 否   | 或操作                                                       |

## 配置示例

在以下配置文件中，我们为不同的用户和主题定义了不同的访问规则，实现了灵活的授权检查机制。请以正确的格式将规则写入 `nanomq_acl.conf` 文件，并在 `nanomq.conf` 中 `include`，可参照 [访问控制介绍](./introduction.md)。
示例：

### 创建访问控制规则

```bash
rules = [
  ## 允许用户名为"dashboard" 的 MQTT 客户端通过订阅"$SYS/#"主题
  {"permit": "allow", "username": "dashboard", "action": "subscribe", "topics": ["$SYS/#"]}

  ## 拒绝"所有用户"订阅"$SYS/#" "#"主题
  {"permit": "deny", "username": "#", "action": "subscribe", "topics": ["$SYS/#", "#"]}

  ## 允许任何其他发布/订阅操作
  {"permit": "allow"}
]
```

### 在配置文件中引用

```bash
acl = {include "/etc/nanomq_acl.conf"}
```

## 通过 KV 格式配置

希望使用 KV 配置格式的用户，可参考以下格式，将配置写入 `nanomq_old.conf `文件，相关设置将在 NanoMQ 重启后生效。

完整的配置项列表，可参考[配置说明 - v013](../config-description/v013.md)

语法

```
acl.rule.<No>=<Spec>
```

示例

```bash
## Allow MQTT client using username "dashboard"  to subscribe to "$SYS/#" topics
acl.rule.1={"permit": "allow", "username": "dashboard", "action": "subscribe", "topics": ["$SYS/#"]}

## Deny "All Users" subscribe to "$SYS/#" "#" Topics
acl.rule.2={"permit": "deny", "username": "#", "action": "subscribe", "topics": ["$SYS/#", "#"]}

## Allow any other publish/subscribe operation
acl.rule.3={"permit": "allow"}
```

