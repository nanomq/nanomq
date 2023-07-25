# 配置说明
NanoMQ 配置文件有 2 个版本：经典 KV 版本和 HOCON 版本。

从 NanoMQ 0.14 版本开始，NanoMQ 已经整合了对 HOCON 语法的支持，并在 0.19 版本中对该语法进行了进一步的更新。 **本章重点介绍 NanoMQ 最新的 HOCON 配置语法。**

NanoMQ 会长期保持对 KV 版本配置文件的支持，具体配置，可参考[经典 KV 格式配置说明](./v013.md)。注意：一些新功能将只支持新 HOCON 配置格式。

NanoMQ 0.14 - 0.18 版本的用户请参考 [NanoMQ 0.14-0.18 配置说明](./v014.md)。

## HOCON
NanoMQ 的默认配置文件格式是 HOCON 。 HOCON（ Human-Optimized Config Object Notation ）是一个 JSON 的超集，非常适用于易于人类读写的配置数据存储。你可以在 etc 目录找到这些配置文件，周边功能如鉴权/网关等可以使用独立的配置文件（通过 Include 方式指定路径），主要配置文件包括：

| 配置文件                | 说明                                    |
| ----------------------- | --------------------------------------- |
| etc/nanomq.conf         | NanoMQ 主配置文件                         |
| etc/nanomq_pwd.conf | NanoMQ 用户名密码登录鉴权配置文件                 |
| etc/nanomq_acl.conf | NanoMQ ACL 访问控制鉴权配置文件                 |
| etc/nanomq_vsomeip_gateway.conf | NanoMQ SOME/IP 网关配置文件(用于 `nanomq_cli`)          |
| etc/nanomq_dds_gateway.conf | NanoMQ DDS 网关配置文件(用于 `nanomq_cli`)          |
| etc/nanomq_bridge.conf | NanoMQ 桥接配置文件(用于 `nanomq_cli`)          |
| etc/nanomq_zmq_gateway.conf | NanoMQ ZeroMQ 配置文件 (用于 `nanomq_cli`) |

## Classical KV
在经典配置文件中，所有功能都统一在单一配置文件中，可以参考 etc/nanomq_old.conf 中的注释。
如需使用 SOME/IP和DDS 网关等功能，还需要使用最新 HOCON 格式配置。

以下内容以 HOCON 配置文件为基准。

## 配置文件语法

在配置文件中，值可以被记为类似 JSON 的对象，例如

```bash
log {
    dir = "/tmp"
    file = "nanomq.log"
}
```

另一种等价的表示方法是扁平的，例如

```bash
log.dir = "/tmp"
log.file = "nanomq.log"
```

这种扁平格式几乎与 NanoMQ 的配置文件格式向后兼容（所谓的 'cuttlefish' 格式）。

它并不是完全兼容，因为 HOCON 经常要求字符串两端加上引号。
而 cuttlefish 把`=`符右边的所有字符都视为值。

例如，cuttlefish: `websocket.bind = 0.0.0.0:8083/mqtt`， HOCON: `websocket.bind = "0.0.0.0:8083/mqtt"`。

### 配置重载规则

HOCON 的值是分层覆盖的，普遍规则如下：

- 在同一个文件中，后（在文件底部）定义的值，覆盖前（在文件顶部）到值。
- 当按层级覆盖时，高层级的值覆盖低层级的值。

结下来的文档将解释更详细的规则。

合并覆盖规则。在如下配置中，最后一行的 `debug` 值会覆盖覆盖原先 `level` 字段的 `error` 值，但是 `to` 字段保持不变。

```bash
log {
    to=[file,console]
    level=error
}

## 控制台日志打印先定义为 `error` 级别，后被覆写成 `debug` 级别

log.level=debug
```

