# Stream Plugin 模板目录

这个目录只保留一个目的：提供最小可编译模板，帮助你快速产出 `my_stream_plugin.so`。

## 保留文件

- `skeleton.c`：最小插件骨架（`on_msg` / `on_start` / `on_stop` + `nano_plugin_init`）
- `Makefile`：把 `skeleton.c` 编译为 `my_stream_plugin.so`，并自动链接 `nano_skill` 相关源码
- `README.md`：本说明

> 需要完整示例时，请直接看 `../can_pipeline_sample.c`。

## 快速使用

1. 在仓库根目录编译 NanoMQ（首次）：

```bash
cd build
cmake .. -DENABLE_PLUGIN=ON
make -j"$(nproc)" nanomq nanomq_cli
```

1. 在本目录编译模板插件：

```bash
make NMQ_INCLUDE=../../include
```

产物：`./my_stream_plugin.so`

2.5) 一键自验证（推荐）：

```bash
make verify NMQ_INCLUDE=../../include
```

说明：

- `verify` 会调用 `./self_verify.sh`
- 自动流程：启动临时 NanoMQ -> 订阅输出 topic -> 发布输入消息 -> 校验输出与落盘 -> 返回退出码
- 成功返回 `0`，失败返回非 `0`，适合 CI/脚本集成

1. 写最小配置并加载插件：

```bash
cat > /tmp/nmq-sp.conf <<'EOF'
listeners.tcp { bind = "0.0.0.0:11884" }
log { to = [console] level = info }

stream_plugin {
  sp0 {
    path  = "/ABS/PATH/TO/my_stream_plugin.so"
    topic = "canudp"
    mode  = "async"
    queue_cap = 4096
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

把路径替换为真实 `.so` 绝对路径后执行：

```bash
./../../build/nanomq/nanomq start --conf /tmp/nmq-sp.conf
```

更完整的端到端演示可参考 `docs/zh_CN/stream-plugin/quick-demo.md`。