# NNG Bridge 配置与测试

本节介绍如何基于当前的 `etc/nanomq.conf`，分别配置并验证 `bridges.nng.pub` 和 `bridges.nng.sub`。文中的命令均已在本仓库构建产物上实际验证通过。

相关参数说明可参考[NNG 数据桥接](../config-description/nng_bridges.md)。

## 准备工作

在开始测试前，请先确认已经完成以下准备：

1. 已在仓库根目录完成构建。
2. `nngcat` 可执行文件位于 `build/nng/src/tools/nngcat/nngcat`。
3. 如果希望用 Mangos 的 `macat` 替代 `nngcat`，请确保环境中可执行 `macat` 命令。
4. `nanomq_cli` 可执行文件位于 `build/nanomq_cli/nanomq_cli`。
5. NanoMQ 使用 `etc/nanomq.conf` 启动，并且其中的 `bridges.nng.pub.t1` 和 `bridges.nng.sub.t2` 均已启用。

如果尚未启动 NanoMQ，可在 `build` 目录执行：

```bash
./nanomq/nanomq start --conf ../etc/nanomq.conf
```

本文测试使用的 Socket 地址如下：

- `bridges.nng.pub.t1.pub_url = "ipc:///tmp/nng_pub.ipc"`
- `bridges.nng.sub.t2.sub_url = "ipc:///tmp/nng_sub.ipc"`

---

## 配置并测试 `bridges.nng.pub`

`bridges.nng.pub` 的方向是：**MQTT -> NanoMQ -> NNG**。

### 配置流程

在当前 `etc/nanomq.conf` 中，`bridges.nng.pub.t1` 的配置如下：

```hcl
# MQTT(local_topic) -> NanoMQ -> NNG(remote_topic)
bridges.nng.pub.t1 {
  enable = true
  pub_url = "ipc:///tmp/nng_pub.ipc"
  clientid = "nng_proxy"

  forwards = [
    {
      # MQTT topic filter
      local_topic = "mqtt/local/#"
      # NNG topic
      remote_topic = "nng/remote"
      # NNG 消息中 remote_topic 与 payload 的分隔符
      nng_delimiter = ":"
      qos = 1
    },
    {
      local_topic = "mqtt/ekuiper"
      remote_topic = "nng/ekuiper"
      nng_delimiter = ":"
    }
  ]
}
```

该配置的含义是：

- NanoMQ 在 `ipc:///tmp/nng_pub.ipc` 上监听 NNG `pub0` Socket。
- 外部 NNG `sub0` 客户端连接到该地址后，可以接收由 NanoMQ 转发出的消息。
- 当 MQTT 客户端向 `mqtt/local/#` 匹配的主题发布消息时，NanoMQ 会把配置的 `remote_topic` 作为前缀，按 `remote_topic + nng_delimiter + payload` 拼接为 NNG 原始消息（默认分隔符为 `/`）。
- 若某条转发规则中 `remote_topic` 未填写或为空字符串，NanoMQ 会将 `remote_topic` 按 `local_topic` 处理后再构造消息。

### 测试流程

以下命令均在 `build` 目录执行。

**1. 启动 NNG 订阅端**

先启动一个 `nngcat` 客户端，订阅主题 `nng/remote`：

```bash
./nng/src/tools/nngcat/nngcat --sub0 --dial ipc:///tmp/nng_pub.ipc --subscribe "nng/remote" --raw
```

等价的 `macat` 命令：

```bash
macat --sub --connect ipc:///tmp/nng_pub.ipc --subscribe "nng/remote" --raw
```

这里使用 `--raw` 是为了直接观察 NanoMQ 转发出去的 NNG 原始消息内容。

**2. 发送 MQTT 消息**

在另一个终端中执行：

```bash
./nanomq_cli/nanomq_cli pub -t "mqtt/local/123" -m "hello" -q 1
```

该主题匹配配置中的 `local_topic = "mqtt/local/#"`，因此会命中 `bridges.nng.pub.t1` 的第一条转发规则。

**3. 查看测试结果**

`nngcat` 终端会收到如下原始消息：

```text
nng/remote:hello
```

这说明本次桥接过程为：

- MQTT 主题：`mqtt/local/123`
- MQTT payload：`hello`
- NNG 前缀：`nng/remote`
- 配置的分隔符：`:`
- 最终发送到 NNG 对端的原始消息：`nng/remote:hello`

也就是说，`bridges.nng.pub` 并不会把原始 MQTT 主题 `mqtt/local/123` 一并透传给 NNG 对端；对端看到的是由 `remote_topic` 和 payload 组成的消息体。

---

## 配置并测试 `bridges.nng.sub`

`bridges.nng.sub` 的方向是：**NNG -> NanoMQ -> MQTT**。

### 配置流程

在当前 `etc/nanomq.conf` 中，`bridges.nng.sub.t2` 的配置如下：

```hcl
# NNG(remote_topic) -> NanoMQ -> MQTT(local_topic)
bridges.nng.sub.t2 {
  enable = true
  sub_url = "ipc:///tmp/nng_sub.ipc"
  clientid = "nng_proxy_2"
  subscription = [
    {
      remote_topic = "test/123"
      local_topic = "test/forward"
      qos = 1
      nng_delimiter = ":"
    },
    {
      remote_topic = "ekuiper"
      local_topic = "ekuiper/forward"
      qos = 2
      nng_delimiter = ":"
    }
  ]
}
```

该配置的含义是：

- NanoMQ 在 `ipc:///tmp/nng_sub.ipc` 上监听 NNG `sub0` Socket。
- 外部 NNG `pub0` 客户端连接到该地址后，可以向 NanoMQ 推送原始 NNG 消息。
- 对于第一条未配置 `nng_delimiter` 的规则，NanoMQ 使用默认分隔符 `/`。当收到以 `test/123/` 为前缀的消息时，NanoMQ 会去掉此前缀，把剩余部分作为 MQTT payload，并发布到 `test/forward`。
- 对于显式配置了 `nng_delimiter`（例如 `:`）的规则，NanoMQ 会按 `remote_topic:` 进行前缀匹配与截断后再发布 MQTT 消息。
- 这一条规则中，发布到本地 MQTT Broker 的主题是 `test/forward`，不是 `test/123`。

### 测试流程

以下命令均在 `build` 目录执行。

**1. 启动 MQTT 订阅端**

先启动一个 `nanomq_cli` 订阅客户端，监听映射后的本地 MQTT 主题：

```bash
./nanomq_cli/nanomq_cli sub -t "test/forward"
```

注意，这里订阅的是 `local_topic`，而不是 `remote_topic`。

**2. 从 NNG 侧发送消息**

在另一个终端执行：

```bash
./nng/src/tools/nngcat/nngcat --pub0 --dial ipc:///tmp/nng_sub.ipc --data "test/123:hello nanomq"
```

等价的 `macat` 命令：

```bash
macat --pub --connect ipc:///tmp/nng_sub.ipc --data "test/123:hello nanomq"
```

这条消息以前缀 `test/123:` 开头，因此会命中第一条映射规则。NanoMQ 会截掉前缀，只把后面的 `hello nanomq` 作为 MQTT payload 发布出去。

**3. 查看测试结果**

`nanomq_cli sub` 终端会收到如下输出：

```text
test/forward: hello nanomq
HEX : 68656c6c6f206e616e6f6d71
```

这说明本次桥接过程为：

- NNG 原始消息：`test/123:hello nanomq`
- 匹配的 `remote_topic`：`test/123`
- 发布到本地 MQTT Broker 的主题：`test/forward`
- MQTT payload：`hello nanomq`

也就是说，`bridges.nng.sub` 的测试要点有两个：

- MQTT 订阅端应监听 `local_topic`。
- NNG 发送端应携带 `remote_topic + nng_delimiter` 前缀（默认是 `remote_topic/`），NanoMQ 会在转换时剥离此前缀。

---

## 常见排查

如果测试结果和本文不一致，可以优先检查以下几点：

1. NanoMQ 是否确实使用 `etc/nanomq.conf` 启动。
2. `pub_url` 和 `sub_url` 对应的 IPC 文件是否被其他进程占用。
3. `bridges.nng.pub.t1` 和 `bridges.nng.sub.t2` 的 `enable` 是否为 `true`。
4. `bridges.nng.pub` 测试时，MQTT 发布主题是否匹配 `mqtt/local/#`。
5. `bridges.nng.sub` 测试时，NNG 消息是否以前缀 `remote_topic + nng_delimiter`（默认 `/`）开头，以及 MQTT 订阅主题是否为映射后的 `local_topic`。

如果你需要进一步核对字段含义和数据流细节，请回看[NNG 数据桥接](../config-description/nng_bridges.md)。