# Stream Plugin 快速 Demo 手册

本手册目标：让你在本机快速完成一次可见效果的端到端验证（编译插件、加载运行、订阅输出、验证落盘）。

---

## 1. 准备环境

假设仓库路径：

```bash
REPO=/home/maoyi/mm/home/maoyi/geely/NanoMQ_mirror
```

---

## 2. 编译 NanoMQ（未编译时执行）

```bash
cd "$REPO"
mkdir -p build
cd build
cmake .. -DENABLE_PLUGIN=ON
make -j"$(nproc)" nanomq nanomq_cli
```

---

## 3. 编译模板插件（`my_stream_plugin.so`）

```bash
cd "$REPO/nanomq/plugin/templates"
make NMQ_INCLUDE="$REPO/nanomq/include"
ls -la my_stream_plugin.so
```

---

## 4. 生成最小配置

创建 `/tmp/nmq-sp.conf`：

```bash
cat > /tmp/nmq-sp.conf <<'EOF'
listeners.tcp {
    bind = "0.0.0.0:11884"
}

log {
    to = [console]
    level = info
}

stream_plugin {
    sp0 {
        path  = "/ABS/PATH/TO/my_stream_plugin.so"
        topic = "canudp"
        name  = "demo"
        mode  = "async"
        queue_cap = 10000
        full_op   = "drop"
    }
}

stream_inject {
    enable = true
    queue_cap = 4096
    worker_num = 1
    full_op = "drop"
}
EOF
```

替换 `.so` 绝对路径：

```bash
SO="$REPO/nanomq/plugin/templates/my_stream_plugin.so"
sed -i "s|/ABS/PATH/TO/my_stream_plugin.so|$SO|g" /tmp/nmq-sp.conf
```

---

## 5. 启动 NanoMQ

```bash
"$REPO/build/nanomq/nanomq" start --conf /tmp/nmq-sp.conf
```

看到插件加载成功日志后继续下一步。

---

## 6. 订阅输出 topic

另开终端：

```bash
CLI="$REPO/build/nanomq_cli/nanomq_cli"
$CLI sub -h 127.0.0.1 -p 11884 -t "metrics/example" -V 4
```

---

## 7. 发布输入消息触发处理

再开终端执行：

```bash
CLI="$REPO/build/nanomq_cli/nanomq_cli"
for v in 0 A B P 0 A; do
  $CLI pub -h 127.0.0.1 -p 11884 -t canudp -m "$v" -V 4 -i "p-$RANDOM"
  sleep 1
done
```

预期结果：

- 约 5 秒内在订阅端看到 `metrics/example` 消息
- 约 3 秒内（或累计到 batch 条件）出现 `/tmp/stream_plugin.jsonl`

说明：

- 本文使用的是 `nanomq/plugin/templates/skeleton.c` 编译出的模板插件
- 若你要验证更完整业务链路，可改为编译并加载 `nanomq/plugin/can_pipeline_sample.c`

---

## 8. 验证落盘与停止

```bash
ls -la /tmp/stream_plugin.jsonl
tail -n 5 /tmp/stream_plugin.jsonl
pkill -9 nanomq
```

---

## 9. 常见问题

- 收不到输出：确认 `stream_plugin.sp0.topic` 与发布 topic 一致，且插件成功加载
- 没有落盘文件：等待超过 3 秒，确认 `/tmp` 可写
- broker 卡顿：优先使用 `mode = "async"`，避免在 `on_msg` 做慢 I/O
