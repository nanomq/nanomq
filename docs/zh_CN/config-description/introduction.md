# 配置说明

NanoMQ 的配置文件格式是 HOCON 。 HOCON（ Human-Optimized Config Object Notation ）是一个 JSON 的超集，非常适用于易于人类读写的配置数据存储。你可以在 etc 目录找到这些配置文件，主要配置文件包括：

| 配置文件                | 说明                                    |
| ----------------------- | --------------------------------------- |
| etc/nanomq.conf         | NanoMQ 配置文件                         |
| etc/nanomq_gateway.conf | NanoMQ 网关配置文件 (用于 `nanomq_cli`) |


## 配置文件语法

在配置文件中，值可以被记为类似 JSON 的对象，例如

```bash
websocket {
     enable=false
     bind="0.0.0.0:8083/mqtt"
}
```

另一种等价的表示方法是扁平的，例如

```bash
websocket.enable = false
websocket.bind ="0.0.0.0:8083/mqtt"
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

