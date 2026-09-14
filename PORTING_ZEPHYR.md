# NanoMQ → Zephyr 移植方案与实施报告(v1)

本文件是 NanoMQ broker 移植到 Zephyr RTOS 的完整交付文档:适配接口、
改动内容、构建/测试步骤、问题解决清单与未完成功能清单。
实施基于两个仓库(见 §2),验收目标全部通过(见 §6)。

- 工作分支:nanomq `nanomq-zephyr-v1`(基于 b6f1c422,未 rebase 上游)
- NanoNNG(nng fork)子模块:`develop` @ `a5ad52ca4`(原冻结点 `fa25da9` + 2 个修复)
- 演示应用:`demo/nanomq_zephyr_qemu_x86/`(本仓库)
- 目标板:qemu_x86(Zephyr 4.4 @ 11a87708d41);真实板卡适配见 §8
- 复核:§9 待办清单 2026-09 复核 —— REST/webhook(§9-4)、持久会话/离线
  (§9-6)、$SYS client_status(§9-7)、性能(§9-10)已完成验证并补记
  §7 行 10-17 与 §4 追加 commit

---

## 1. 移植目标与范围

| 项 | 决策 |
|---|---|
| 集成形态 | demo 应用 + ExternalProject 编译 NanoNNG,不做 Zephyr module 抽象 |
| 配置来源 | 无文件系统;`conf_init()` 默认值 + 代码内最小覆盖(url/ipc_internal/log level),直调 `broker(conf)`,绕开 `broker_start()` 的文件解析/daemon 流程 |
| 协议面 | MQTT v3.1.1 + v5、QoS 0/1/2、retain、will、$SYS/client 上下线事件、`nmq-tcp://` 与 `nmq-ws://` 监听 |
| 编译面 | broker 核心源全量编译;webhook/rest/rule/aws_bridge 等按 NanoMQ 惯例"全量编入、运行时由 conf 关闭";仅剔除 process.c/tests/plugin |
| 不包含(TLS/QUIC/SQLite/Parquet 等) | 见 §9 待完成清单 |

## 2. 仓库与代码布局

```
nanomq/  (工作分支 nanomq-zephyr-v1)
├── nanomq/                  broker 核心应用层(移植裁剪处)
│   ├── apps/broker.c        __ZEPHYR__ 门控:signal 安装
│   ├── nanomq.c             __ZEPHYR__ 门控:<sys/ptrace.h>
│   └── mqtt_api.c           __ZEPHYR__ 门控:log_file_init() 的 W_OK 检查
├── nng/                     NanoNNG 子模块(fork,nanolib + MQTT 协议栈)
│   ├── src/sp/protocol/mqtt/nmq_mqtt.c   修复:nano lmq in-struct free guard
│   └── src/platform/zephyr/zephyr_pollq_poll.c   修复:zvfs_poll 失败降级(§4/§7-10)
└── demo/
    ├── cmake/nanonng_external.cmake      共享 NanoNNG ExternalProject 构建
    └── nanomq_zephyr_qemu_x86/                    演示应用(CMakeLists/prj.conf/main.c/stubs/
                                           mqtt_accept.py/hook_receiver.py 验收工具)
```

## 3. 移植适配接口

### 3.1 平台适配(nng 侧,已在 NanoNNG Zephyr 移植中完成,本移植消费)

nng 通过 `nni_plat_*` 接口隔离平台。Zephyr 平台实现位于 NanoNNG
`src/platform/zephyr/`,本移植直接依赖以下事实(勿改):

| 接口/事实 | 行为 | 对 broker 的含义 |
|---|---|---|
| `nni_alloc` | `zephyr_alloc.c` = 裸 `malloc()` | **libc malloc arena 就是 broker 堆**(§5.3 的 1 MB 配置由此而来;`CONFIG_HEAP_MEM_POOL_SIZE` 只服务 `k_malloc()`,对 nng 无效) |
| 时钟/睡眠/随机 | `zephyr_clock.c` 等 | keepalive 定时、重传退避可用 |
| 网络传输 | Zephyr 原生 socket(BSD 兼容层) | tcp/ws 传输走 poll 驱动;无 IPC 传输(`NNG_TRANSPORT_IPC=OFF`) |
| 文件系统 | 无 FS 分支(`zephyr_file.c` 的 no-FS stub) | `nni_plat_file_exists/size` 已上提补齐(commit `21daab5`,§4):no-FS 分支 stub(exists→false,size→`NNG_ENOTSUP`),FS 分支为 `stat()` 实现 |
| taskq/poller | 固定线程数(见 ExternalProject:`TASKQ=2/POLLER=1/EXPIRE=1`) | broker 并发受限于此,叠加 §5.6 的 pthread 池 |
| POSIX API | Zephyr `CONFIG_POSIX_API` + 动态线程池 | nng 平台与 broker 的 pthread 都来自 16 线程池(§5.6) |

### 3.2 POSIX 依赖裁剪接口(应用层,本次新增)

broker 应用层的 POSIX 残留是唯一硬阻断,统一用 `__ZEPHYR__` 预定义
门控,不引入新抽象层:

| 文件 | 原 POSIX 依赖 | 裁剪 |
|---|---|---|
| `apps/broker.c` | `signal()`/`sigaction` 安装(DEBUG/ASAN 与常规路径) | `#if !defined(__ZEPHYR__)` 整段跳过 —— Zephyr 的 ^C/quit 由 QEMU/终端通道处理,`for(;;) nng_msleep` 主循环足够 |
| `nanomq.c` | `#include <sys/ptrace.h>` | 门控;`check_trace()` 调用点仅在 CLI 路径(不达),平台无实现不报错 |
| `mqtt_api.c` | `nng_access(dir, W_OK)`(文件日志目录检查) | 门控;文件日志后端对嵌入式恒关(`LOG_TO_FILE` 不设),跳过检查无副作用 |
| `process.c`(整个编译单元剔除) | fork/kill/chdir/`<paths.h>` | 由 demo `process_stub.c` 提供 6 个 `process.h` 符号(返回 -1)。被引用点全部位于 `daemon=true`/CLI 路径,嵌入式 broker 永不触达 |

### 3.3 编译期宏契约(应用与 libnng 必须一致)

| 宏 | 作用 |
|---|---|
| `ENABLE_LOG` | nanolib `conf.c` 据此初始化 conf_log、`log_*()` 才编出实体。**必须同时**经 app 侧 `target_compile_definitions` 与 nng 侧 `-DENABLE_LOG`(nng CMake 只吃 `NNG_*` 缓存变量,普通宏须走 `CMAKE_C_FLAGS`)传入,否则 broker 日志静默失效 |
| `SUPP_NANO_LIB` | 隐藏 `nanomq.c` 的 `main()`;保留 `get_cache_argc/argv`(rest_api.c 引用) |
| `ACL_SUPP` | conf 结构含 ACL 字段(默认开)。**应用侧与 libnng 侧必须同时定义**(libnng 经 `NNG_EXTRA_CFLAGS` 传入),仅一侧定义时 `struct conf` 布局错位(§7-12) |
| `NNG_STATIC_LIB` | NNG_DECL 修饰一致 |
| `SUPP_SYSLOG` **不设** | Zephyr 无 syslog();nanolib `log.c` 有 `__ZEPHYR__` 控制台输出路径 |

## 4. 改动内容(文件级清单)

### nng 子模块(NanoNNG,commit `c66e0cb`)
`src/sp/protocol/mqtt/nmq_mqtt.c` — 真实 broker bug 修复:
`nano_nni_lmq_fini()` / `nano_nni_lmq_resize()` 无条件 `nni_free(lmq->lmq_msgs)`。
当 rlmq cap ≤ 2 或扩容 malloc 失败时,`nni_lmq_init` 把队列数组放在
**结构体内嵌的 `lmq_buf`**(`lmq_alloc == 0`),free 结构体内指针 = 堆损坏,
客户端断开即崩。修复:镜像 core/lmq.c,仅当 `lmq_alloc > 0` 才 free。

### nanomq 应用层(commit `af0efc49`)
见 §3.2 三处 `__ZEPHYR__` 门控,行为对 POSIX 零变化(门控两侧代码完全相同)。

### demo(commit `606dfcbe`)
```
demo/cmake/nanonng_external.cmake   共享构建(§5.2)
demo/nanomq_zephyr_qemu_x86/CMakeLists.txt   SOURCES 镜像 + 宏契约(§3.3)
demo/nanomq_zephyr_qemu_x86/Kconfig          app 级 Kconfig 壳(KCONFIG_ROOT 语义)
demo/nanomq_zephyr_qemu_x86/prj.conf         资源/网络配置(§5.3)
demo/nanomq_zephyr_qemu_x86/src/main.c       入口:conf 最小覆盖 → broker()
demo/nanomq_zephyr_qemu_x86/src/process_stub.c      §3.2(nng 文件缺口已上提,§4)
demo/nanomq_zephyr_qemu_x86/accept.sh        宿主验收脚本(§6.2)
demo/nanomq_zephyr_qemu_x86/README.md        构建/运行/验收速览
```
`CMakeLists.txt` 的 SOURCES 镜像自 `nanomq/nanomq/CMakeLists.txt`,剔除
`process.c`(stub 替代)与 `tests/`,`plugin/plugin.c` 随 `NNG_ENABLE_PLUGIN=OFF`
一并去掉。

### 2026-09 复核追加(§9-4/6/7/10 验证前置)

**demo 配置/开关与宏契约(commit `7e16adc47`)**:prj.conf 补
`CONFIG_ZVFS_POLL_MAX=16`、pthread mutex/cond 池 1024、hostfwd 8081;
Kconfig 增 `BROKER_REST_API`/`BROKER_WEBHOOK`;main.c 覆盖
`qos_duration=1`(默认 10 s,keepalive/会话到期检查粒度太粗)并启用
REST(NONE_AUTH)与 webhook(inproc hook 通道,`MESSAGE_PUBLISH(hook/#)` +
`CLIENT_CONNACK` 两条规则);CMakeLists 把 `ACL_SUPP` 并入
`NNG_EXTRA_CFLAGS`。各动机详见 §7 行 10-13。

**验收工具(commit `bd96660af`)**:`mqtt_accept.py` —— stdlib-only raw-socket
MQTT 3.1.1/5 客户端(`--clean/--keepalive/--expiry/--expect/--proto`),
编码 MQTT5 PUBLISH 头顺序规范(§7-14),驱动 §9-4/6/7 场景;
`hook_receiver.py` —— webhook POST 接收器(§9-4)。

**nng 子模块追加(commit `a5ad52ca4`,superproject bump `646631ce5`)**:
`src/platform/zephyr/zephyr_pollq_poll.c` — `poll()` 失败降级与 100 ms
超时轮询(§7-10)。

**nng 文件探针补齐(commits `21daab5` + `c66e0cb`,superproject bump `2e4fb162`)**:
`zephyr_file.c` 的 no-FS 与 FS 两个分支此前都未实现
`nni_plat_file_exists/size`(platform.h 声明、posix/win 均已实现)——nanolib
`file.c`(`nano_file_exists`)与 `log.c` 无条件引用,消费即缺符号(§3.1),
demo 原以 `nng_plat_stub.c` 兜底,本次上提后该文件与 CMake 条目一并删除;
core/file 增 `nni_file_exists/size` 中间层,公共 `nng.h` 暴露
`nng_file_exists`/`nng_file_size`(nng.c 封装,对齐既有 `nng_file_*` 族)。

### Zephyr 环境补丁(不在本仓库,§5.4)
`drivers/ethernet/eth_e1000.{c,priv.h}` — RCTL_BAM(上游缺失 bug)。

## 5. 编译步骤

### 5.1 环境
- Zephyr 4.x west workspace(SDK 含 qemu_x86 hosttools);Zephyr checkout **必须**含 §5.4 补丁
- 本文档开发环境:docker 容器 `zephyr-tap`,`ZephyrProject` 目录 bind-mount 到 `/workdir`;宿主 Fedora 提供 mosquitto-clients(仅验收用)
- 代码同步:`git submodule update --init nng`(锁定 `c66e0cb`)

### 5.2 构建
在容器 `zephyr-tap` 内构建(仓库 bind 于 `/workdir/nanomq`,west 顶在
`/workdir`;SDK/工具链只在容器里,宿主不可编译;`-u root` 因 bind 文件
属主是宿主 uid 1001 而容器默认用户是 1000):
```sh
docker exec -u root zephyr-tap sh -lc '
  cd /workdir/nanomq &&
  git submodule update --init nng &&
  ZEPHYR_TOOLCHAIN_VARIANT=zephyr ZEPHYR_SDK_INSTALL_DIR=/opt/toolchains/zephyr-sdk-1.0.1 \
    west build -b qemu_x86 -d /workdir/build/nanomq_zephyr_qemu_x86 demo/nanomq_zephyr_qemu_x86'
```
普通(非容器)west workspace 同命令去掉两个环境变量即可;输出目录默认
`build/nanomq_zephyr_qemu_x86/`,本环境为 `/workdir/build/nanomq_zephyr_qemu_x86/`。
- NanoNNG 经 ExternalProject 编入 `build/nanomq_zephyr_qemu_x86/nanonng_build/`
  (`cmake --build <dir> --target nng`),libnng.a 静态导入链接
- 架构旗标(32 位 x86):`-march=i686 -mno-sse2/-sse3/-ssse3/-movbe`
  (cmpxchg8b 提供 64 位原子;剥离 SoC 的 `-march=atom`,QEMU `qemu32` CPU 不支持 movbe,#UD)
- **坑**:子模块源改动后 `west build` 增量可能不触发 ExternalProject 重编 ——
  用 `strings zephyr.elf | grep <旧串>` 断言;必要时
  `cmake --build build/nanomq_zephyr_qemu_x86/nanonng_build --target nng` 强制
- 产物:RAM 占用约 2.4 MB / 31 MB(≈1 MB 为 malloc arena)

### 5.3 prj.conf 关键项(完整见文件)
```
CONFIG_POSIX_API=y / POSIX_THREAD_THREADS_MAX=16 / DYNAMIC_THREAD_STACK_SIZE=16384
CONFIG_ETH_E1000=y                         # SLIRP 只认以太网 L2,必须有真实 NIC 驱动
CONFIG_NET_QEMU_USER=y
CONFIG_NET_QEMU_USER_EXTRA_ARGS="hostfwd=tcp:0.0.0.0:1883-:1883,hostfwd=tcp:0.0.0.0:8081-:8081,hostfwd=tcp:0.0.0.0:8083-:8083"  # 8081=REST(§9-4),8083=WS(§9-2)
CONFIG_NET_CONFIG_MY_IPV4_ADDR="10.0.2.15" # SLIRP 固定 guest 概念地址
CONFIG_COMMON_LIBC_MALLOC_ARENA_SIZE=1048576   # ★ MMU 下 malloc arena 即 broker 堆
CONFIG_ZVFS_POLL_MAX=64 / MAX_PTHREAD_MUTEX/COND_COUNT=1024     # §7-10/11/18
CONFIG_MAX_PTHREAD_RWLOCK_COUNT=256                            # §7-21(topic 树节点按把)
CONFIG_NET_MAX_CONTEXTS=32 / CONFIG_NET_MAX_CONN=32            # ★ §7-18 连接池
CONFIG_ZVFS_OPEN_ADD_SIZE_NET=32                               #   zvfs fd 表
CONFIG_BROKER_REST_API=y / CONFIG_BROKER_WEBHOOK=y / CONFIG_BROKER_WS=y   # §9-4;WS 见 §9-2
CONFIG_X86_SSE/SSE2/SSE3(SSSE3 禁)
CONFIG_BROKER_LOG_DEBUG=y                  # 调试用;正式运行可关
```

### 5.4 运行与 Zephyr 补丁
杀旧实例与启动分两条独立 `docker exec`(`[i]` 括号防 pkill 自匹配,
§7-5/8);串口日志在容器内 `/tmp/qemu3.log`:
```sh
docker exec -u root zephyr-tap pkill -f "qemu-system-[i]386" || true

docker exec -u root zephyr-tap sh -lc '
  /opt/toolchains/zephyr-sdk-1.0.1/hosttools/sysroots/x86_64-pokysdk-linux/usr/bin/qemu-system-i386 \
    -m 32 -cpu qemu32,+nx,+pae,sse,sse2,pni -machine q35 \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 -no-reboot -machine acpi=off \
    -serial file:/tmp/qemu3.log -display none \
    -netdev user,id=n1,hostfwd=tcp:0.0.0.0:1883-:1883,hostfwd=tcp:0.0.0.0:8081-:8081,hostfwd=tcp:0.0.0.0:8083-:8083 \
    -device e1000,netdev=n1 \
    -kernel /workdir/build/nanomq_zephyr_qemu_x86/zephyr/zephyr.elf &'
```
**就绪判据**(`docker exec zephyr-tap tail -f /tmp/qemu3.log`):依次出现
`rtc: CMOS clock … UTC, realtime seeded` → `net: ipv4 10.0.2.15` →
`broker: NanoMQ (ver 0.25.1) Serving HTTP Server on http://(null):8081` →
`NanoMQ Broker is started successfully!`。日志时间为**真实 UTC**(demo
main.c 启动时从 QEMU CMOS RTC 播种 CLOCK_REALTIME,2026-09 修复;
Zephyr 无 TZ 数据库,显示恒为 UTC,见 §8)。hostfwd 三端口(1883/8081/8083)与
prj.conf `CONFIG_NET_QEMU_USER_EXTRA_ARGS` 一致 —— `west build -t run`
会自动带上,手动 qemu 必须显式列出,漏 8081 则 REST(§9-4)不通,漏
8083 则 WS(§9-2)不通。
客户端落点:宿主 mosquitto/accept.sh → 容器 IP(`docker inspect -f
'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' zephyr-tap`,
实测 172.17.0.2):1883,或经宿主 socat 转发用 127.0.0.1(命令见 demo
README);容器内 python(mqtt_accept.py/hook_receiver.py) → 127.0.0.1;
宿主 curl → 容器 IP:8081(容器内无 mosquitto/curl);宿主 paho
(`transport="websockets"`,路径 `/mqtt`)→ 容器 IP:8083。
**必需环境补丁(RCTL_BAM)**:QEMU e1000 设备模型复位后清零 RCTL(真实硬件
默认置位 BAM=bit15),Zephyr `eth_e1000` 驱动从不置 BAM → **所有广播帧
(ARP!)被模型静默丢弃**,SLIRP 永远无法完成首个 TCP 连接。
上游 Zephyr 同缺(main 2026-06 核实)。补丁 2 行:
```c
// eth_e1000_priv.h
#define RCTL_BAM    (1 << 15)
// eth_e1000.c(e1000_eth_init 的 RCTL 写)
iow32(dev, RCTL, RCTL_EN | RCTL_MPE | RCTL_BAM | DT_INST_PROP(inst, rdmts) << RDMTS_OFFSET);
```

## 6. 测试

### 6.1 单元/构建级回归
- **宿主基线构建回归**(任务 4):nng 子模块在 POSIX 宿主上编译通过 —
  保证 `__ZEPHYR__` 门控与 lmq 修复不破坏非 Zephyr 构建(nng 自身
  `NNG_TESTS` 与 NanoMQ `NANOMQ_TESTS` 在本移植保持关闭;门控代码在
  POSIX 侧逐字不变,由 #if 双侧同源码保证)。
- **插桩残留断言**:`strings zephyr.elf` 不含 `DBG PIPEFINI/LMQFINI/E1000: isr/IP4IN/TCPIN`。
- **崩溃回归对比**:修复前(16 KB arena + 无 lmq guard)首次连接断开即
  heap 损坏(`right_chunk`),≤25 次连接循环内必崩;修复后连续
  **92 次 PIPEFINI(连接/断开)零崩溃**(验收两轮另计)。

### 6.2 功能验收(宿主 mosquitto)
```sh
./demo/nanomq_zephyr_qemu_x86/accept.sh [host] [port]   # 默认 127.0.0.1:1883
# 容器开发环境:accept.sh 172.17.0.2 1883
```
用例与结果(干净构建 ×2 轮,均 7/7 PASS):

| # | 用例 | 覆盖点 | 结果 |
|---|---|---|---|
| 1 | QoS0 pub/sub | 连接建立、订阅树、投递 | PASS |
| 2 | QoS1 pub/sub | PUBACK 流程 | PASS |
| 3 | QoS2 pub/sub | PUBREC/PUBREL/PUBCOMP 流程 | PASS |
| 4 | Retain | retained 消息存储、迟到订阅者投递(`--retained-only`) | PASS |
| 5 | Will | SIGKILL 异常断开 → broker 检测 → will 发布 | PASS |
| 6 | MQTT v5 pub/sub | v5 CONNECT、user-property 透传 | PASS |
| 7 | v5 response-topic + correlation-data | 请求/响应辅助属性往返 | PASS |

额外观察(诊断中确认的协议正确性):正常 DISCONNECT 清除 will(DISCONNECT
处理后 `will_flag=0`,观察者收不到 will —— 合规行为);$SYS 上下线事件
(`$SYS/brokers/client_status/<id>`)正常发布;v3 与 v5 客户端混跑无串扰。

### 6.3 验收过程中的脚本陷阱(已编码进 accept.sh 注释)
- mosquitto `-k` keepalive 最小值为 **5**;`-k 2` 直接退出,will-client
  从未连接(曾误判为 broker 不发布 will)
- `kill -9` 必须打在 mosquitto_sub 自身,而非 `timeout` 包装进程 ——
  包装进程被杀后子进程存活并正常 DISCONNECT(行为正确但测不到 will)

## 7. 问题解决清单

| # | 现象 | 根因 | 修复/规避 | 归属 |
|---|---|---|---|---|
| 1 | SLIRP→guest 连接全部失败(host 握手完成、guest 无收包) | QEMU e1000 模型复位清 RCTL_BAM;Zephyr 驱动不置 BAM → 广播 ARP 被模型丢弃 | Zephyr 补丁 2 行(§5.4);README 记录;上游修复候选 | 环境(上游 bug) |
| 2 | 客户端断开即 heap 崩溃(free→sys_heap right_chunk) | 双根因:(a) MMU 下 malloc arena 默认仅 16 KB,nng 裸 malloc,per-pipe rlmq 扩容全失败;(b) NanoMQ nano lmq fini/resize 无条件 free 内嵌 `lmq_buf` | prj.conf `COMMON_LIBC_MALLOC_ARENA_SIZE=1 MB` + nng `lmq_alloc>0` guard(§4) | 配置 + 真实 bug |
| 3 | 首次 probe 偶发假阳性 "CONNACK ok" | 诊断 poller(100 ms 循环 accept fd==3)抢走并 close 了 pending 连接 | 移除诊断插桩(git checkout 恢复平台文件) | 调试自伤 |
| 4 | ISR 插桩后 RX 永不触发 | 插桩 printk 二次读 ICR 将其清零(ICR 读即清),真实分支永远看不到位 | 先读一次到局部变量再打印;最终插桩全部移除 | 调试自伤 |
| 5 | kill 脚本把 qemu 一起杀掉(exit 143) | `pgrep -f "qemu-system-i386"` 匹配自身 bash 命令行 | `pgrep -f "qemu-system-[i]386"` + 独立命令 kill | 脚本 |
| 6 | will 用例失败 | mosquitto `-k 2` 非法(min 5),客户端从未连接 | 改 `-k 5`(§6.3) | 脚本 |
| 7 | v5r 用例"挂起" | v5r pub 无超时等待 PUBACK;当时环境偶发(单测与终验均通过,多轮 7/7) | pub 全部加 `timeout -s KILL` 包裹;脚本永不无限挂 | 脚本健壮性 |
| 8 | qemu hostfwd 端口被旧实例占用(qemu25 无网) | 旧 qemu 未杀净,hostfwd 绑定失败 | 统一 kill 流程(bracket 技巧) | 流程 |
| 9 | 容器 heredoc/python 相对路径失效、git checkout 权限拒绝 | bind mount + 容器 root/宿主 uid 差异;`docker exec` 默认不接 stdin | `docker exec -i -u root`、`-w <dir>` 显式化;宿主对 zephyr/.git 只读操作改容器内 root 执行 | 环境操作 |
| 10 | connect 后首个 MQTT 包 ~5 s 才处理,负载下间歇 stall | Zephyr `CONFIG_ZVFS_POLL_MAX` 默认 3;fd 集超限时 `zvfs_poll` 整组返回 -1/ENOMEM 且不标 POLLNVAL,nng pollq 无错误分支 → 忙等自旋,全部 socket I/O 饿死 | `CONFIG_ZVFS_POLL_MAX=16` + nng `zephyr_pollq_poll.c` `poll()` 失败降级(msleep 10)与 100 ms 超时轮询(commit `7e16adc47`/`a5ad52ca4`) | 配置 + nng 平台修复 |
| 11 | REST+webhook 同开时 boot 期线程不可见挂死 | pthread mutex/cond 固定池耗尽(nng 动态分配,REST+webhook 基线即 ~245/256);`zephyr_thread.c` 池耗尽 RETRY FOREVER | `CONFIG_MAX_PTHREAD_MUTEX_COUNT/COND_COUNT=1024` | 配置 |
| 12 | REST 开时偶发 boot 崩溃(`pthread_mutex_lock: Invalid argument` → nni_panic) | `struct conf` 布局两侧不一致:app 侧 `-DACL_SUPP`、libnng 侧未定义 → `auth_http` 字段错位,锁到垃圾 `acl_cache_mtx` | `ACL_SUPP` 并入 `NNG_EXTRA_CFLAGS`(与 ENABLE_LOG 同机制,§3.3) | 构建契约 |
| 13 | keepalive/会话到期按 10 s 粒度触发,验收不可控 | `conf_init` 默认 `qos_duration=10 s`,NanoMQ 每 qos_duration tick 做一次检查 | main.c 覆盖 `qos_duration=1`(嵌入式 demo 无配置文件) | 配置 |
| 14 | v5 QoS1 发布被 broker 断开(rc 130 Malformed Packet) | 验收客户端照抄 SUBSCRIBE 布局,把 v5 PUBLISH properties 放在包标识符前;MQTT5 PUBLISH 头顺序 = topic → pid → properties,broker 解析 pid=0 → 130 | `mqtt_accept.py` 修正(properties 移至 pid 后;broker 行为合规) | 脚本 |
| 15 | REST `clients` 查询恒空 | 返回 JSON 顶层键是 `data`(非 `clients`) | 轮询脚本取 `data` 数组 | 脚本 |
| 16 | 每 host↔guest 交换固定 ~110 ms(QoS1 PUBACK、PINGRESP 等) | Zephyr TCP delayed-ACK(`tcp.c ACK_DELAY=K_MSEC(100)`,RFC 813:无 PSH 段或小窗口时推迟 ACK ~100 ms) | 识别为栈特性非缺陷;QoS0 单向数据面不受影响(§9-10) | 环境(Zephyr 栈) |
| 17 | DEBUG 日志镜像吞吐骤降(qos0 ~150-250 msg/s) | 每包多次 DEBUG 经仿真串口,串口是吞吐瓶颈(~380 行/s) | 压测用静默镜像(临时去 `CONFIG_BROKER_LOG_DEBUG`),产线默认关 | 方法/环境 |
| 18 | 并发/连发新连接被 RST(mosquitto `Connection was lost`,CI v5 套件逐轮随机失败) | Zephyr 连接池默认过小:`NET_MAX_CONTEXTS=6`(每 socket 一个 context)+`NET_MAX_CONN=8`,两个 listener 已占 2;池尽时 `tcp_conn_new()` 的 `net_context_get()` 失败 → `net_tcp_reply_rst()`(`subsys/net/ip/tcp.c`),客户端见 RST | prj.conf 提池:`NET_MAX_CONTEXTS/NET_MAX_CONN=32`、`ZVFS_OPEN_ADD_SIZE_NET=32`、`ZVFS_POLL_MAX=64`(§9-12) | 配置 |
| 19 | 无流量时 guest CPU ~90% 自旋(webhook 接收器未启动时必现) | webhook 的 HTTP 出站拨号失败后该 pfd 未被 fini,仍以 POLLOUT(0x04)挂在 pollq;`poll()` 每轮都报 POLLERR(0x08),而 `pfd->events &= ~events` 用 0x08 清不掉 0x04 → 每轮立即返回,空转 | nng `zephyr_pollq_poll.c`:revents 含 POLLERR/POLLHUP/POLLNVAL 时置 `pfd->events = 0`(该描述符已不可用,重挂或拆除交由回调决定);复现脚本 CPU 86–94% → 1.3–3.0% | nng 平台修复 |
| 20 | WS 反复连接/断开后 broker 停摆:新连接能 CONNACK,但管道不再收发也不回收 | `nmq_websocket.c` 的 `wstran_pipe_recv_cancel` 先清空 `p->user_rxaio` 再 abort rxaio,却没完成用户 aio(完成行被注释掉);rxaio 的完成路径见 `user_rxaio` 已空即跳过完成 → 该 aio 永久挂起 → `nano_pipe_stop` 中 `nni_aio_stop(&p->aio_recv)` 阻塞全局唯一的 reap 线程 → 所有 pipe 回收停摆 | 采用上游修复 `6467b6c` + `1d8127c`(两个 cancel 路径都完成用户 aio;cb 在 `skip:`/`reset:` 先释放 `user_rxaio` 再完成;qsaio 回调不再无锁读 `user_txaio`);gdb 复核 reap 线程空闲、pollq 仅剩 3 个 listener fd | 真实 bug(上游已修) |
| 21 | 生存组压到 ~30 个主题时 guest `panic: pthread_rwlock_init: pool exhausted` → 客户端 `Connection refused` | Zephyr rwlock 为固定池(默认 32),nanolib 每个 topic 树节点取一把(`mqtt_db.c` 的 `dbtree_node_new`/`dbtree_node_free` 成对),负载测试的主题数轻易超池 | prj.conf `CONFIG_MAX_PTHREAD_RWLOCK_COUNT=256`(§5.3/§9-13);宿主 POSIX 无固定池,仅 Zephyr 需显式预算 | 配置 |

## 8. 局限与已知取舍
- 线程模型:nng 平台 poller/taskq + POSIX 动态线程池上限 16(`CONFIG_POSIX_THREAD_THREADS_MAX`),broker 连接并发受其约束;栈 16 KB/线程
- 时间戳:两个 demo 均已是真实 UTC(lib/os/clock.c 的 offset+uptime 模型,
  播种后持续走时),但**时间源有意不同** —— qemu 启动时读 QEMU CMOS RTC
  (默认 `-rtc base=utc`)播种;S3 实机无 RTC,改由 SNTP 播种(§22-4)。
  Zephyr 无 TZ 数据库,显示恒为 UTC;时区仍需自行处理
- 无文件系统:配置/日志/持久会话均无落盘;`$SYS` 只服务运行时
- 目标板:qemu_x86(32 位)与 **ESP32-S3 实机**(xtensa,见 §22)均已验证;同
  ExternalProject 已含 32 位 ARM 原子回退(`NNG_ZEPHYR_NO_STDATOMIC`),但
  **未在真实 ARM 板卡验证**(网络驱动、中断、内存预算均需重验)
- qemu_x86 MMU 分支 → arena 静态 1 MB;小内存目标板需重算(见 §9)

## 9. 移植功能清单与验证状态(2026-09 复核)

验证环境:qemu_x86 同一镜像(demo 已从 QEMU CMOS RTC 播种真实时钟,
日志为 UTC,§5.4)。
扩展场景由 demo 验收工具(commit `bd96660af`)驱动:`mqtt_accept.py` 在
qemu 容器内连 `127.0.0.1:1883`(SLIRP hostfwd 在容器命名空间内),
REST 走 `:8081`,webhook 接收器 `hook_receiver.py` 挂在 10.0.2.2 别名
对应的容器内。

1. **Zephyr 上游修复跟进**(待办):eth_e1000 RCTL_BAM 提 PR(上游缺失,
   2026-06 核实,§5.4)。nng no-FS stub 缺 `nni_plat_file_exists/size` 一项
   已于 2026-09 上提修复(commit `21daab5`/`c66e0cb`,§4),demo 兜底 stub
   随之删除
2. **WS 传输**(✅ 2026-09-08 端到端验证):demo 加运行时 WS 监听
   (`CONFIG_BROKER_WS` → main.c 设 `websocket.enable/url`,§5.3)+ SLIRP
   8083 hostfwd;宿主 paho(`transport="websockets"`,路径 `/mqtt`)与
   CI `ws_test.py`(v3.1.1)/`ws_v5_test.py`(v5)全绿(§9-13)。两处此前
   未暴露的缺陷随之修复:① `nng/src/sp/transport/CMakeLists.txt:32` 的
   门控写成从未定义的 `NNG_TRANSPORT_MQTT_WS`,导致 mqttws 传输在**所有**
   构建里被静默排除(demo 的 `NNG_TRANSPORT_MQTT_BROKER_WS=ON` 一直空转),
   改为 `NNG_TRANSPORT_MQTT_BROKER_WS OR ..._WSS`;② WS 管道回收停摆
   (§7-20,上游已修,采用 `6467b6c`+`1d8127c`)。TLS(`nmq-wss://`)仍不可用
   (NanoNNG Zephyr 关闭 TLS)
3. **TLS/QUIC/SQLite/Parquet**(保持关闭):NanoNNG Zephyr 移植明确未包含
   (NNG_ENABLE_TLS/QUIC/SQLITE=OFF);如需支持需先在 NanoNNG 完成
4. **HTTP/REST/Webhook**(✅ 行为已验证,2026-09;rule-engine 除外):
   - REST:`curl :8081/api/v4/clients` 返回 JSON,连接建立 ~0.4 s 后出现
     于 `data` 列表、断开 ~5.7 s 后消失(顶层键是 `data`,§7-15);
     conf 侧 `http_server.enable` + `auth_type=BASIC`
   - **REST 认证(2026-09-11 改为 BASIC)**:两个 demo 的 main.c 设
     `auth_type = BASIC` 并显式填 `username="admin"` / `password="public"`
     (与 `etc/nanomq.conf`、上游文档一致)。**必须填凭据**:`conf_http_server_init()`
     只把 auth_type 置为 BASIC,username/password 留 NULL,而
     `basic_authorize()`(`rest_api.c`)对两者做 `strlen()` —— 只改枚举不填
     凭据会在首个 REST 请求上解引用 NULL。实测:无凭据 401、`admin:public`
     200、错误口令 401(实机与 qemu 均验)。注意 Basic + 明文 HTTP 只是
     base64,不是加密(TLS 未编译进 Zephyr NanoNNG)。
   - webhook:host 侧 `hook_receiver.py` 收到规则 POST —— 每个连接 1 条
     `client_connack`(含 clientid/proto_ver/keepalive/conn_ack),每条
     `hook/#` 发布 1 条 `message_publish`(含 ts/topic/qos/payload);
     验证了"嵌入式 conf → inproc hook 通道 → nng HTTP client → 外部
     接收器"整条转发链。**接收端地址改为构建期配置**
     `CONFIG_BROKER_WEBHOOK_URL`(空则不启用转发器),且**两个 demo 现均
     默认关闭**(§22-6 的开关建议):qemu 填宿主别名 `10.0.2.2:18080`
     (即跑 qemu 的机器本身),实机在 `local.conf` 填宿主的 LAN 地址
   - rule-engine:嵌入式 conf 无对应开关路径,未验证(维持原状)
5. **IPC cmd server**(保持关闭):`ipc_internal=false`,NNG_TRANSPORT_IPC=OFF
   —— `nanomq ctl` 管理通道不可用;如需需引入 IPC 传输
6. **持久会话/离线消息**(✅ 4 场景全过,2026-09):
   前提:main.c `qos_duration=1`(§7-13,keepalive/会话检查按 1 s tick);
   broker keepalive backoff 默认 1.5(conf.c)
   - v3.1.1 `clean=0`:客户端离线期间 broker 日志 `msg cached`,同 ID
     clean=0 重连收到缓存 QoS1 消息(CONNACK session_present=1)
   - v5 `clean=0` + `--expiry 30`:expiry 窗口内重连同样收到离线 QoS1
   - v5 expiry 到期清理:断开后 31 s(expiry 30 + 1 tick)broker 清会话/
     订阅树($SYS 下线、缓存释放)
   - keepalive 超时:keepalive=2 的静默客户端 ~5.6 s 被踢(1.5×2 s +
     检查粒度),REST 列表消失,$SYS offline reason_code `8d`
     (141,Keep Alive timeout)
7. **$SYS 指标面**(✅ client_status 已验证;其余未逐项):外部客户端订阅
   `$SYS/brokers/client_status/#`,收到成对 JSON —— 上线事件与下线事件
   (payload 含 clientid/ts/reason_code;§9-6④ 同一次 keepalive 踢除,
   reason_code `8d`)。其余 $SYS/brokers/* 指标(消息/字节计数等)未逐项
   验收
8. **真实硬件/其他板**(待办):32 位 ARM(原子回退)、64 位板、真实
   e1000/其他网卡;内存预算:小 RAM 板需把 arena/队列/线程数重配(§8)
9. **上游对齐**(待办):nanomq-zephyr-v1 落后 origin/master 155+ commits
   (0.25.6+),发布/PR 前需 rebase 并重跑验收;NanoMQ-Zephyr 独立镜像仓库
   推送(如采用原交付决策)需同步 NanoNNG 子模块 URL
10. **性能与压力**(✅ best-effort 完成,2026-09,qemu/SLIRP):
    静默日志镜像(临时关 `CONFIG_BROKER_LOG_DEBUG`,§7-17)实测:

    | 场景 | 结果 |
    |---|---|
    | QoS0 单向,1 订阅,500 条 | ~1418 msg/s,零丢失 |
    | QoS0 单向,3 订阅,400 条 | ~1136 msg/s,零丢失 |
    | QoS1 单向,1 订阅,200 条 | ~9 msg/s(受每次交换 ~110 ms 限制) |
    | QoS1 无订阅 PUBACK / PINGREQ-PINGRESP | 中位 109.9 / 110.0 ms |

    - 数据面下推吞吐 ~1.1-1.4 k msg/s;双向/请求-应答型交互被 Zephyr
      TCP delayed-ACK 钉在 ~110 ms/次(§7-16),是栈特性而非 NanoMQ 缺陷
    - DEBUG 日志经仿真串口是主要瓶颈(§7-17);并发受 §8 线程/栈预算约束
    - SLIRP 是代理网络,qemu 数值与真实网络/板卡不可比 —— 数据面结论
      需在真实网络/板卡上复测(§8-9)
11. **CI 功能测试套件在 qemu 镜像上跑通**(✅ 2026-09-08):
    `.github/scripts/` 中适用于本 demo 的子集全绿 —— `mqtt_test.py`
    (v3.1.1)、`mqtt_test_v5.py`、`rest_api_test.py`(其余套件需 TLS/WS
    监听或宿主 nanomq 二进制,不适用)。此前 v5 套件 7 轮全败、失败点在
    会话过期/user-property/共享订阅间漂移,根因即 §7-18 连接池耗尽(池尽
    即 RST),非 broker 语义缺陷:提池 + `max_topic_alias`(见下)后
    **3/3 连续全绿**;实测同一条连接池,6 并发 CONNECT 由 2/6 变 6/6、
    50 ms 间隔连发由 9/20 变 20/20。另发现 `test_topic_alias` 依赖
    `mqtt.max_topic_alias`:`conf_init` 默认 0(CONNACK 广播
    `TOPIC_ALIAS_MAXIMUM=0`,带别名的 PUBLISH 被拒),宿主 CI conf 在
    **master** 上是 `max_topic_alias=1024`、develop 分支缺该行 —— demo
    main.c 现按 1024 对齐。运行须知:宿主 python 走系统代理会把
    `172.17.0.2:8081` 打成 502,跑 REST 套件需 `NO_PROXY=<容器 IP>`;
    本 demo 侧套件(§9-13)的 REST 组只做 GET(不碰会翻转运行配置的
    POST `/reload`)
12. **VFS 支持变体**(待定,2026-09 评估):做"可挂文件系统、进而按宿主
    方式解析 HOCON 配置/落盘"的编译开关版本。nng 平台层 `zephyr_file.c`
    已按 Zephyr 官方 Kconfig `CONFIG_FILE_SYSTEM` 分双分支(无 FS 桩:
    exists→false/size→ENOTSUP;有 FS:POSIX 风格真实实现,§4 `21daab5`
    起)—— 宏开关在 nng 层是现成架构,但开关只是必要条件,剩余门槛:
    ① 宏双侧注入(本 demo 的 libnng 是 ExternalProject 独立构建,看不到
    prj.conf 的 Kconfig,须 `NNG_EXTRA_CFLAGS -DCONFIG_FILE_SYSTEM`,守
    §3.3 宏契约);② 板级介质与挂载(storage 分区/dts + `fs_mount`,须先于
    conf 解析,qemu_x86 默认无介质);③ 路径主机假设(`/etc/nanomq.conf`、
    conf_file 推导须映射到 VFS 挂载点);④ 激活整层被桩代码(日志落盘/
    pid/license 等逐条审计);⑤ 双变体(no-FS 基线 + VFS)验证与腐烂成本。
    触发条件:真实板需要运行时改配置/持久会话落盘;此前维持内嵌最小
    conf(§1),无动作
13. **Zephyr 专用功能测试套件**(✅ 2026-09-08 8/8 全绿):
    `demo/nanomq_zephyr_qemu_x86/function_test.py` —— 宿主侧 runner,自管 qemu
    生命周期(杀旧实例 → 全新日志名启动 → 轮询就绪串 → 结束回收),8 组
    各以独立子进程执行(组级崩溃/超时隔离),`--group` 单组重跑、
    `--no-manage` 复用已在跑的 broker、`--list` 列组、`-v` 显示通过组输出。
    复用 `.github/scripts/` 模块而**不改其代码**:mqtt 组覆写模块级
    `g_addr/g_port/g_url`;ws_v311 包一层 `Test.init`;ws_v5 打
    `paho.mqtt.client.Client.connect` 补丁(该脚本硬编码 `localhost:8083`)。
    组表与实测时长:

    | 组 | 驱动 | 实测 |
    |---|---|---|
    | mqtt_v311 | CI `mqtt_test.py` | 16.1 s |
    | mqtt_v5 | CI `mqtt_test_v5.py` | 28.0 s |
    | rest_get | 自写(7 条路由 + `/configuration/websocket` 镜像运行 conf) | 0.9 s |
    | ws_v311 | CI `ws_test.py`(WS 上 MQTT 3.1.1) | 209.5 s |
    | ws_v5 | CI `ws_v5_test.py`(WS 上 MQTT 5) | 6.1 s |
    | webhook_smoke | 自写(`hook_receiver.py` 收 `client_connack`/`message_publish`) | 2.8 s |
    | capacity | 自写(12 并发 CONNECT + QoS1 echo,连接池回归) | 6.2 s |
    | survival | `survival_test.py`(缩规模 `attack.py` + 压后探活) | 33.4 s |

    - 定位:CI `test.py` 在本 demo 不可用(需宿主 nanomq 二进制 + TLS/WS
      listener,并驱动 mosquitto CLI/TLS/鉴权等宿主侧工具),故按同样的
      "复用模块、注入地址"思路做 Zephyr 版
    - 抖动如实记录:ws_v5 修前首跑 11.7 s 失败,原因是树内
      `.github/scripts/ws_v5_test.py` 为旧版 —— 把 CONNECT 专属属性
      `MaximumPacketSize` 设进 PUBLISH 属性,paho 2.x 在客户端线程抛
      `MQTTException`,v5 发布端全部未能连接;换上游 master 版本(其
      `func()` 自行处理 `conn_prop`,并给等待加上界)后 6.1 s 通过。ws 组
      默认多一次重试(`--retry-ws`):上游脚本用固定 sleep 适配宿主 broker,
      SLIRP 延迟下首跑可能抖动;真实抖动不做隐藏
    - 生存组压出 §7-21(rwlock 池耗尽),修复后 33.4 s 通过;组内
      `attack.py` 常量缩规模(30 s、2 发布者、8 噪声客户端、2 节点共享
      订阅):宿主规模是崩溃放大器,SLIRP 每连接约 9 msg/s
    - 失败语义:默认跑完全部组(`--fail-fast` 可停);FAIL 组打印末 40 行
      输出 + 串口日志尾部;组失败 exit 1,结构性失败(docker/qemu/依赖
      缺失)exit 2
    - 失败路径实测(2026-09-08):① `--no-manage --addr 10.255.255.1` →
      `ERROR: no broker answering` / exit 2;② 组间容器内 pkill qemu →
      日志 `broker not answering — restarting qemu`,该组计 FAIL(exit 1),
      后续组在新 guest 上自动继续并通过(实测 `pass=2 fail=1`)
    - 完整用法与组说明见 demo README「Functional test suite」;命令速查见
      §10 第 3b 步

## 10. 复现命令速查(容器环境 `zephyr-tap`,§5.1)
```sh
# 0) 打 Zephyr 补丁(§5.4 两行,改 /workdir/zephyr 内树,须 -u root)
# 1) 构建(§5.2 全文;镜像 zephyr-build:main 已含 SDK/工具链)
docker exec -u root zephyr-tap sh -lc 'cd /workdir/nanomq && ZEPHYR_TOOLCHAIN_VARIANT=zephyr \
  ZEPHYR_SDK_INSTALL_DIR=/opt/toolchains/zephyr-sdk-1.0.1 \
  west build -b qemu_x86 -d /workdir/build/nanomq_zephyr_qemu_x86 demo/nanomq_zephyr_qemu_x86'
# 2) 启动(先 pkill 旧实例再启动,命令全文见 §5.4);就绪判据:
docker exec zephyr-tap sh -lc 'grep -a "NanoMQ Broker is started" /tmp/qemu3.log || tail -f /tmp/qemu3.log'
# 3) 验收(宿主;期望 RESULT: pass=7 fail=0;IP 用 §5.4 的 docker inspect 结果)
./demo/nanomq_zephyr_qemu_x86/accept.sh 172.17.0.2 1883
# 3b) 功能测试套件(§9-13;宿主,自管 qemu 生命周期,期望 RESULT: pass=8 fail=0)
python3 demo/nanomq_zephyr_qemu_x86/function_test.py
python3 demo/nanomq_zephyr_qemu_x86/function_test.py --group ws_v5 -v      # 单组重跑
python3 demo/nanomq_zephyr_qemu_x86/function_test.py --no-manage --addr 172.17.0.2  # 复用已跑 broker
# 4) 扩展场景(§9-4/6/7:容器内跑 python,宿主跑 curl)
docker exec -d zephyr-tap python3 /workdir/nanomq/demo/nanomq_zephyr_qemu_x86/hook_receiver.py \
    --port 18080 --out /tmp/webhook.log            # webhook 接收器(§9-4)
docker exec zephyr-tap python3 /workdir/nanomq/demo/nanomq_zephyr_qemu_x86/mqtt_accept.py 127.0.0.1 1883 \
    sub --proto 5 --clean 0 --expiry 30 --topic v5/offline --qos 1   # 离线会话(§9-6②)
curl -s http://172.17.0.2:8081/api/v4/clients      # REST(§9-4;键为 data)
```

---

## §22 ESP32-S3 实机 bring-up(demo/nanomq_zephyr_esp32s3)

实机:ESP32-S3-LCD-EV-Board(N16R16V,16 MB flash + 16 MB octal PSRAM),
宿主 Fedora + `esp-zephyr` 环境,`west flash` + idf-monitor。验证记录
2026-09-09。

### §22-1 已通过

- PSRAM 16 MB octal 识别 + memory test(80 MHz);构建/烧录/串口无碍。
- Wi-Fi STA(DHCP):`wifi: connected` → `net: ipv4 192.168.1.10`。
- broker banner + REST :8081 可达(host curl)。
- 日志时间戳:原为 `1970-01-01`(无 RTC);2026-09-10 起经 SNTP 播种为
  真实 UTC(§22-4)。

### §22-2 bring-up 修掉的坑(均落 repo/子模块)

- **blob 缺失**:`west blobs fetch hal_espressif` 不跑则 `WIFI_ESP32` 静默隐藏。
- **`CONFIG_WIFI` 伞开关**:只设 `WIFI_ESP32=y` 无效。
- **ExternalProject 不重编**:nng 源改动不触发 rebuild(曾连续数版跑旧
  libnng.a)→ `BUILD_ALWAYS TRUE`。
- **xtensa**:`-mno-movbe` 仅 x86;32 位非 x86 全部要 `NNG_ZEPHYR_NO_STDATOMIC`
  (链接期 `__sync_*_8` 未解析)。
- **net_mgmt 事件**:不同 layer-code 的事件 OR 进一个 mask 会被
  `mgmt_run_slist_callbacks` 整条丢弃(等值比较)→ 每事件单独回调。
- **STA 驱动默认**:`WIFI_STA_AUTO_DHCPV4`(驱动自起 DHCP、不发
  CONNECT_RESULT)与自动重连会与 app 侧连接流程打架 → prj.conf 显式关。
- **shared_multi_heap 非线程安全**(裸 sys_heap 无锁)→ nng 分配器改
  `k_heap` 托管 PSRAM 窗(nng 子模块 `zephyr_alloc.c`,
  `NNG_ZEPHYR_ALLOC_SMH` 分支)。
- **SRAM 预算**:整包 broker 数据面必须进 PSRAM;`ESP_SPIRAM_BSS_RELOC`
  搬 posix 池/net_buf;内核堆池 192 KB 留 picolibc 裸 malloc 余量
  (dram0_0_seg 77 %)。

### §22-3 根因与修复记录(2026-09-10 更新)

**(a) 分配器家族错配——已修复**(nng 80cf26b / nanomq 84fd90f6):
上游在 POSIX 下 `nng 分配器 == libc malloc`,nanolib/nanomq 里大量
"一族分配、另一族释放"的对象因此永远安全(汽车十余年无感)。把 nng
分配器改到 PSRAM k_heap 后,每一次跨族释放都会打坏其中一侧的堆:
- `mqtt_db.c topic_queue_free`(nni_zalloc ↔ free) — 订阅/断开路径;
- `hash_table.c` 八处(nni/nng_* ↔ free,删除器已全 libc,已归一);
- `mqtt_parser.c` 订阅队列生产者(nng_alloc ↔ libc 释放);
- `webhook_post.c` 三处(cJSON_Print(libc) ↔ nng_strfree)— 每次连接
  经 hook_entry 触发,把 k_heap 链接写进 libc arena,随后 libc free
  把 `$SYS...` 主题字节当链表指针 → 确定性野写 panic。
定位手段(可复用,已从仓库撤除):qemu 无损控制台实验室 +
`--wrap=free` 正向探针 + `nni_free` 反向探针 + 逐操作堆校验环 +
zfree 调用点探针;主机 ASAN 与上游同负载全绿用于排除共享代码。

**(b) 根因定位与修复(2026-09-10 终局)**

真凶:**`mqtt_codec.c` 的 MQTT 协议层把 `NNI_ALLOC_STRUCT`/`property_alloc`
(nni_zalloc → PSRAM)分配的对象用裸 libc `free()` 释放**(4 处:proto_data
结构 + 三处 property);`mqtt_qos_db.c` 另有两处 `nng_zalloc` ↔ `free`。
上游 POSIX 两族同堆故无感;移植后 libc free 把 PSRAM 指针当成自家块——
既污染 libc arena 的 bucket,又把 libc 链表指针写进 PSRAM 块负载;当该块
正挂在 k_heap 空闲链上(payload 首部即 FREE_NEXT/FREE_PREV),下一次分配
走到被毒化的 bucket → `set_prev_free_chunk` 野写(0x1ff8138d 之类的数据值)。
这解释了此前全部现象:每连接必崩(编解码每条消息都走)、
`$SYS`/主题层 5 字节小块被反复点名、双堆(PSRAM + 内核堆)先后告警。

定位方法(决定性的一步):在 nng Zephyr 分配器里做**锁内逐操作
`sys_heap_validate`**(拿 k_heap 自身 spinlock,排除并发假阳性)+
最近 32 次操作环形记录(含调用方地址)。首个失败操作的精确定位:
`nni_msg_free:483 → nni_mqtt_msg_free:451 free(mqtt)`;EXTREME canary
下同一调用链在 libc 侧以"canary: corruption"复现。交叉验证:
qemu(k_heap 经我们的 PSRAM 分配器)修复后全流程通过,上游 host ASAN
与 qemu libc-malloc 分支始终干净(因为两族同堆,这个 bug 在那里不存在)。

修复:nng commit `cb34268`(mqtt_codec 4 处 + qos_db 2 处),
nanomq `7ae89a2b` 子模块 bump。S3 实机结果:QoS0/1/2 投递、
retain 回读、REST、连接/断开 churn(即旧崩溃路径)全部通过,零 panic。

**教训(移植契约)**:NanoNNG 的 Zephyr 分配器一旦不是 libc malloc,
全仓库"一族分配、另一族释放"的写法都会变成堆腐蚀。此类已修:
nanolib topic 队列(nng 80cf26b)、webhook cJSON(nanomq 84fd90f6)、
mqtt codec/qos_db(nng cb34268)、dbhash_copy_topic_queue(见下文 (c))、
nni_strndup(见下文 (d))。

**错配是双向的,审计必须两个方向都查**:"nng 分配 → libc 释放"以及
"libc 分配 → nng 释放"。前三次修的都是前者,(c) 正是后者的漏网实例。

**这类 bug 在 POSIX 上单元测试抓不到**(两族同堆),回归只能靠 target
集成测试。后续审计建议:以 `--wrap=free` + `nni_free` 越界探针做 CI
门禁,或在 nng 的 Zephyr 分配器里加"指针必须落在堆内"的断言
(最省事,能把整类问题在调用点当场炸出来)。

**(c) 第二处家族错配——canary 假象(2026-09-10 定位并修复)**

现象:实机漂移 panic `CANARY mem=0x3fcdXXXX exp=... found=00000000`,约
2/6 次,一度被记为"间歇性堆 canary 损坏",并怀疑栈溢出或越界写零。

真凶:**`dbhash_copy_topic_queue`(`nng/src/supplemental/nanolib/hash_table.c`)
用 libc `calloc`/`strdup` 造副本,唯一调用者 `get_subscriptions`
(`nanomq/rest_api.c` ~1966)却用 `nng_strfree`/`nng_free` 释放** ——
即 (a)/(b) 同族的**反方向**实例。`nng_strfree` 把 SRAM 指针送进 PSRAM
k_heap,`mem_to_chunkid` 算出堆外 chunk id,`chunk_trailer` 又绕回指针
附近,读到零内存 → `found=00000000`。**根本不存在写入者,canary 报文
是假象,不是腐蚀。**

判别方法(一次定性,建议固化为探针):在 canary 失败处打印**堆边界**与
**指针是否落在其中**。现场 `mem=0x3fcd3ff0`(SRAM 侧 libc 堆)而
`heap=0x3c0e9d40..0x3c4e9d40`(PSRAM 侧 nng 堆)→ `inheap=0`,跨族释放
实锤;payload 首字节即 `strdup` 出的主题串 `"topic"`。

触发路径纠正:与 MQTT v5 断开风暴**无关**。最小复现 = 一条存活订阅 +
`GET /api/v4/subscriptions/`,100% 必崩(单次请求打死板子)。这解释了
v5 单组连跑 6 轮不出现、完整三组第一轮即命中。§22-3(b) 末尾所记
"S3 实机 REST 全部通过"不准确:`--group rest_get` 当时为 FAIL
(31.5s,`/api/v4/nodes/` 超时),正是本 bug 所致。

修复:`dbhash_copy_topic_queue` 改用 `nng_zalloc`/`nng_strdup`(消费者已按
nng 族释放,生产者对齐即可)。S3 结果:`GET /api/v4/subscriptions/`
HTTP 200 稳定复跑;`--group rest_get` **FAIL 31.5s → PASS 3.7s**。

**已排除的错误线索(别重走)**:
- `CONFIG_HW_STACK_PROTECTION` 在 **xtensa 上不存在**
  (`ARCH_HAS_STACK_PROTECTION` 仅由 arc/arm/arm64/riscv/x86 select),
  写进 conf 是空操作,不能用来验证栈溢出;
- Xtensa 是窗口寄存器 ABI、无帧链,`__builtin_return_address(≥1)`
  **不可靠**,会给出貌似合理的错误调用链(取证中曾误得
  `inplace_realloc → k_heap_free`)。调用链取证请用栈扫描 + 离线符号化;
- 现场地址落在哪个堆,必须用符号表核对边界(`_system_heap` 只有
  192 KB 且**不含** libc 堆;libc 堆是 `[_end, _heap_sentry)` ≈ 88 KB,
  两者相邻但不同)。

待修(已记录,不属本 bug):`dbhash_get_topic_queue_all` 在循环里
`*res++` 后直接 `return res`,返回越界 4 字节的指针;当前零调用者
(死代码),留待单独修复。

**(d) 第三处:单函数根因 `nni_strndup`(2026-09-10 定位并修复)**

`nni_strndup`(`nng/src/core/strs.c`)用 **libc `malloc`**,而它的三个兄弟
`nni_strdup`/`nni_strnins`/`nni_strncat` 都用 nng 家族分配器。它对外暴露为
`nng_strndup`(`nng.h`),调用方理所当然按 nng 族释放 —— 一行不一致,
九个受害者。

**实机取证**:一条 `SUBSCRIBE` + `UNSUBSCRIBE` 即 100% 打死板子
(与 (c) 同一表现:`CANARY ... found=00000000`、`inheap=0`,
payload 首字节为本例主题串 `"unsub/probe"`)。

**功能测试套件抓不到它**:`mosquitto_sub/pub` 退出时只断开、**不发
UNSUBSCRIBE**,所以 v5/v311 组连跑 6 轮全绿照样漏掉。这不是"偶发",
是**套件覆盖盲区** —— 值得记住的教训:报"偶发"前先确认套件真的走到了
那条路径。

九个调用点已逐一核对,**全部按 nng 族释放**(故"改生产者"是唯一正确方向):
`unsub_handler.c:221`(nng_free)、`conf_ver2.c:269`(nng_strfree)、
`mqtt_parser.c:927-932` 六处 conn_param 字段(nng_free)、
`bridge.c:1881`(nng_free)、`conf.c:694`(nni_strfree)。

修复:`malloc` → `nni_alloc`。实机验证:UNSUBSCRIBE 正常走完
(`nano_pipe_close: ... pipe close!`,无 panic),三组功能测试复跑全绿。

**待修清单(已记录,本次不修)**

以下由 2026-09-10 全仓库**双向**家族审计发现,均**未修复**:

1. `conf.c` 销毁侧整体用 libc `free()`,而对象由 `conf_ver2.c`(HOCON,
   即 Zephyr 默认解析器)按 nng 族分配。含 `nanomq_conf` 本身
   (`broker.c:1852` `nng_zalloc` ↔ `conf.c:4611` `free`),以及
   `conf_tls_destroy` / `conf_bridge_node_destroy` / `conf_web_hook_destroy` /
   `conf_auth_http_req_destroy` / `conf_auth_destroy` / `conf_sqlite_destroy` /
   `conf_tcp_node_destroy` / `conf_tlslist_destroy`。注意 `conf.c` 内**已有**
   正确的 nng 族释放(如 `nng_free(node->dialer)`),上述 libc `free()` 是异类。
   当前 demo 里 `conf_fini` 多只在错误路径走到,故未爆发。
2. `FREE_NONULL`(`nanolib/conf.h:52`)是 libc `free`,却被用于 nng 族字段;
   `broker.c` 侧重复 `-url` / `--tls-keypass` 参数即可命中(两个参数即触发)。
3. `get_conf_value()`(`conf.c`)返回 libc 内存,而 30+ 处调用方用
   `nng_strfree(value)` 释放(同文件另有 `free(value)` 的正确写法,故生产者
   本身两族混用);连带 `conf_log_parse` 把该结果存进
   `log->file/dir/rotation_sz_str`,由 `conf_log_destroy` 的 `nni_strfree` 释放。
4. `file_load_data`(`nanolib/file.c:117`)对 `nni_alloc` 的缓冲用 libc
   `realloc` —— 当前被 `CONFIG_FILE_SYSTEM` 关掉(§12 VFS 变体待做),开启即生效。
5. SCRAM 路径(`mqtt_tcp.c` / `mqtt_tls.c`)libc `strndup` ↔ `nng_free(pwd2, 0)`,
   由 `NNG_ENABLE_SCRAM` 关闭,当前不可达。
6. **同现场但不同根因**(panic 长相一样,记录以免误判):
   - `demo/nanomq_zephyr_qemu_x86/src/main.c:248,286` 把**字符串字面量**赋给
     `nmq_conf->url` / `websocket.url`,而 `conf_fini` 用 `nng_strfree` 释放
     (即释放字面量;当前 `broker()` 不返回故不可达);
   - `conf_fini` 释放 `nanomq_conf`,而同一指针归 `nano_sock_fini`
     (`nmq_mqtt.c:487`)所有 —— **双重释放隐患**,与分配器家族无关。

已核查为**干净、不必重查**的区域:`nanolib/hash_table.c`(除已修的
`dbhash_copy_topic_queue`)、`mqtt_db.c`、`acl_conf.c`、`rule.c`、
`parser.c`/`scanner.c`、`hocon.c`、`cJSON.c`(`cJSON_InitHooks` 从未调用)、
`nanolib/linkedlist/`、`utils.c`/`md5.c`/`base64.c`、`rest_api.c`、
`web_server.c`、`cmd_proc.c`、`core/zmalloc.c`。

**(e) 测试台的陷阱:失败会自我放大(2026-09-10 查明)**

`mqtt_v5` 的 `$share` 子测试曾连续 TIMEOUT,一度被怀疑是 (d) 引入的回归。
实为**测试台缺陷**,与 broker 无关:

- 上游 `mqtt_test_v5.py` 的 `test_shared_subscription()` 起 3 个
  `$share/a/topic_share` 订阅者,断言三者**合计**收到 10 条;
- **失败路径在 `return False` 前不 terminate 任何订阅者进程**(只有成功路径
  terminate),于是每次失败都泄漏 5 个订阅者,其中 3 个仍在 `$share/a` 组
  且会自动重连;
- 下一次运行时 10 条消息在 3+3=6 个组内订阅者之间轮转,新的三个更收不满
  → 再失败 → 再泄漏 3 个 …… **一旦失败过一次,之后再也过不了**;
- 该脚本里本有 `clear_subclients()`(按 `pidof mosquitto_sub` 杀),
  但**定义了却从未被调用**;
- 本地 wrapper 的 `--no-manage` 又明确跳过 `kill_host_mosquitto_clients()`,
  等于关掉了唯一的兜底清理。

证据:先 `pkill -x mosquitto_sub; pkill -x mosquitto_pub` 清干净再跑,
`mqtt_v5 PASS` 立即恢复;且成功的那次运行 `orphans left = 0`
(成功路径确实会 terminate,失败路径不会 —— 与上述分析一致)。

**实机验收操作建议**:
1. **实机参数已自动判定,无需再手记**:`function_test.py` 启动时实测到 broker 的
   TCP 连接中位延迟(loopback <1 ms、docker 桥 ~1 ms、ESP32-S3 经 Wi-Fi 实测
   14–600 ms),慢则默认 `--time-scale 4 --retry 2`,快则 `1.0/0`;显式传入的
   `--time-scale` / `--retry` 始终优先,启动时会打印实际取值与依据。二者
   **缺一不可**:scale 治"sleep 余量不足",retry 治"子测试本身带竞速"(见 (g));
2. 泄漏已由 runner 自动清理(见 (f)),不必再手动 `pkill`;要确认的话数
   `pgrep -xc mosquitto_sub`;
3. 判"偶发"之前先数 `pgrep -xc mosquitto_sub` —— 泄漏的订阅者会让 `$share`
   断言必然失败,把它当成 broker bug 会白查很久。

这与 (d) 是同一类教训:**先确认测试台可信,再怀疑被测对象**。
另外注意 `--time-scale` 只缩放固定 sleep,对这类"进程泄漏型"失败无效。

**(f) 失败被伪装成"卡死":管道 EOF(2026-09-11 查明并修复)**

现象:`mqtt_v311` 快速 FAIL 后,`mqtt_v5` 一直"卡住",要等满整组超时才继续
(mqtt_v5 的组超时为 **600s**)。一度以为 worker 卡在 CI 脚本里,实测
**worker 早已退出**:

```
orchestrator 已跑 04:57
worker 子进程:不存在,只剩 <defunct> 僵尸
父进程仍持有 1 个 pipe fd
```

真因:`run_worker()` 原用 `subprocess.run(..., capture_output=True)`,它等的
是**管道 EOF**,而非仅仅子进程退出。泄漏的 `mosquitto_sub` 孙进程继承了
管道写端且永不退出 → EOF 永不到来 → worker 虽已死,orchestrator 仍要读到
超时才返回。**这是 (e) 那个泄漏的第二个症状:失败不只毒化下一轮,还把
"快速失败"伪装成"卡死"。**

修复(已落地 `demo/nanomq_zephyr_qemu_x86/function_test.py`,未动 vendored 上游脚本):
1. worker 输出改为重定向到**临时文件**而非管道 —— 文件没有 EOF 可等;
2. worker 以 `start_new_session=True` 启动,每次尝试后
   `os.killpg(worker_pid, SIGKILL)` —— 精确清掉它自己那一组的泄漏客户端,
   **不误伤用户手动起的 mosquitto**;
3. worker 环境加 `PYTHONUNBUFFERED=1`,让 CI 脚本的 print 与 traceback 按
   真实时序落盘(块缓冲会把明细排到 traceback 之后,读起来是倒的);
4. 失败 + `--time-scale 1.0` + broker 非本机时打印 HINT —— **只在真失败时**
   出现,故 qemu/localhost 流程(那里 1.0 本就正确)不会看到假阳性。

实测(同一命令,不带 `--time-scale`):由"卡满 600s"变为 **12.6s 结束**
(v311 FAIL 2.1s、v5 FAIL 5.6s、rest_get PASS 3.3s),运行后
`mosquitto_sub` 计数为 0、无僵尸进程。

**(g) 上游 retain 子测试的固有竞速:普通订阅者看不见实时投递(2026-09-11 查明)**

现象:`mqtt_v5` 反复失败在链尾 `Retain As Published test failed!`,且**每次
尝试都可能失败**(实测带 `--retry 2` 时连续 2 次失败、第 3 次才过);每次
耗时约 106s,等于跑满整条链。

**先排除一个错误假设(留档以免重走)**:一度认为是上一轮残留在 `topic` 上的
保留消息让订阅者收到 2 条。据此在 wrapper 里加过"每次尝试前清保留消息",
**实测证伪**:清干净后每次尝试依然可能失败,而且**反而更糟**(见下方推论 2)。

**真因**:`mqtt_test_v5.py::test_retain_as_publish()` 用
`cnt_substr(..., " r1,")` 数输出行里的 **RETAIN 标志位**,而它有两个订阅者:

| 订阅者 | 消息来自保留存储 | 消息为实时投递 |
|---|---|---|
| `--retain-as-published` | `r1` → 计 1 | `r1` → 计 1 |
| **普通订阅者(无 RAP)** | `r1` → 计 1 | **`r0` → 计 0** |

按 MQTT 规定,**实时投递**给非 RAP 订阅者的 PUBLISH 其 RETAIN 被置 0。于是
普通订阅者**只有"订阅晚于保留发布"时才计得到 1**;它若抢先订阅成功,收到的
实时投递是 ` r0,`,计数为 0 → `cnt.value != 1` → 失败。

实测(单独复现该子测试 5 次,打印真实计数 —— 上游脚本自己从不打印它们):

```
run 1: plain=0 rap=1  -> FAIL
run 2: plain=0 rap=1  -> FAIL
run 3: plain=0 rap=1  -> FAIL
run 4: plain=1 rap=1  -> PASS
run 5: plain=1 rap=1  -> PASS
```

**两个反直觉的推论(均已实测)**:

1. **`--time-scale` 对它无效**:竞速在"`mosquitto_pub` 与两个 `mosquitto_sub`
   的**进程启动顺序**"上,不是 sleep 时长 —— 缩放那个 1s 的 sleep 影响不到它;
2. **不要清 `topic` 的保留消息**:保留消息在时,普通订阅者总能从存储拿到
   ` r1,` → 确定性通过;清空后每次尝试都退回竞速。曾加过的
   `reset_broker_state()` 正是踩了这个坑(把"只有第 1 次可能失败"变成"每次
   都可能失败"),**已撤除**。

**为何 `--retry` 在这里"碰巧"有效**:第 1 次尝试若失败,它自己就把保留消息留
在了 `topic` 上(上游那条清理命令 `pcr_cmd = "... -m \"\" -d"` **漏了
`--retain`**,按 MQTT 根本清不掉,而 v311 的 `test_retain()` 用 `-n -r` 是
对的),于是第 2 次起变成确定性通过。**这是状态残留的副作用,不是"重试能修
竞态"** —— 记下来以免后人据此得出错误结论。

**判读建议**:`Retain As Published test failed!` 单独出现时,看 `--retry` 是否
已让整组通过,并用**通过率**(而非单次结果)判断 broker 是否有问题。

**顺带修掉一个妨碍诊断的老问题**:`run_worker()` 此前只在**最终**失败时返回
输出;若第 1 次失败、第 2 次通过,则第 1 次的明细被丢弃 —— 正是判"真缺陷 vs
竞态"所需的那份证据。现在每次失败的尝试都会立即打印其尾部 25 行(本节结论
正是靠它才拿到的)。

### §22-4 实机时钟:SNTP 播种 CLOCK_REALTIME(2026-09-10)

**现象**:S3 无 RTC,`time()` 只反映开机时长,全部日志时间戳恒为
`1970-01-01`(§22-1 曾记为"已知外观,非缺陷")。日志格式化本身的代码路径
没问题 —— `nanolib/log.c` 走 `time(NULL)` → `localtime_r` → `strftime`
(`log.c:464-465`),**只要 `CLOCK_REALTIME` 有真实种子,日志自动正确**,
log.c 一行都不用改。

**方案**:DHCP 绑定后、`broker()` 之前,用公开 API `sntp_simple()` 依次查询
若干 NTP 服务器(带按序回退),成功后 `sys_clock_settime(SYS_CLOCK_REALTIME,
&tspec)` 播种。实现在 `main.c` 的 `seed_realtime_from_sntp()`(约 25 行),
只用到公开头文件 `<zephyr/net/sntp.h>` 与 `<zephyr/sys/clock.h>`。

**为何没复用 Zephyr 现成的 `net_init_clock_via_sntp()`(试过,链接期失败)**
`subsys/net/lib/config/init_clock_sntp.c` 里的这个函数功能完全对口 —— 它连
分数换算 `tspec.tv_nsec = ((uint64_t)ts->fraction * NSEC_PER_SEC) >> 32` 和
`sys_clock_settime` 都写好了,还顺带支持 DHCP option 42。但它所在**目录**的
构建门禁是另一个符号:

```
# subsys/net/lib/CMakeLists.txt:14
add_subdirectory_ifdef(CONFIG_NET_CONFIG_SETTINGS    config)
```

即**整个 `config` 目录(含该文件)只在 `CONFIG_NET_CONFIG_SETTINGS=y` 时才
加入构建**。只开 `CONFIG_NET_CONFIG_CLOCK_SNTP_INIT=y`(它在 Kconfig 里确实
只 `depends on SNTP`、不被 SETTINGS 包住)得到的是一个**链接错误**:

```
undefined reference to `net_init_clock_via_sntp'
```

**教训:核实"该符号可选"是不够的,必须一路核到"这个编译单元是否进构建"。**
Kconfig 层与 CMake 层是两个独立门禁,前者能开不代表后者会编译。(另一面:
这类失败是**响的** —— 链接期硬失败,而不是"编译通过但静默不生效"。)

**为复用它而开 `NET_CONFIG_SETTINGS=y` 不划算**:该模块的语义是"用 Kconfig
配静态 IP",与本 demo 自建的 Wi-Fi/DHCP 流程相反;更麻烦的是
`NET_CONFIG_AUTO_INIT` **默认为 y**(`default y if !(USB_DEVICE_NETWORK ||
...)`),得显式写 `=n` 才挡得住 `SYS_INIT` 钩子复活 —— 任何一次 Kconfig
清理漏掉那行,`net_config_init_app()` 就会在 Wi-Fi 连接**之前**运行。为 25
行代码引入这种"沉默的默认值"风险不值,故改为自写。

**该内置路径的另一重障碍(留档备查)**:它的自动调用点挂在
`net_config_init_app()`,由 `SYS_INIT(init_app, APPLICATION, ...)` 驱动
(`init.c:557-567`),**早于 `main()` 里的 Wi-Fi 连接**;该函数找不到已 up 的
接口就直接 `return 0`(`init.c:515-520`),SNTP 那一步根本走不到。此外
`init_clock_sntp.c:25-28` 有 `BUILD_ASSERT`,要求服务器字符串非空。

**为何 qemu 姊妹 demo 不接 SNTP(勿"顺手补齐")**:qemu 侧已有更优时间源 ——
`seed_realtime_from_cmos()` 读 QEMU 仿真 CMOS RTC
(`nanomq_zephyr_qemu_x86/src/main.c:123-185`),即时且不依赖网络。而 SNTP 的自动路径在
`SYS_INIT` 执行,**先于** `main()` 里的 CMOS 播种,结果是 SNTP 的值会被 CMOS
无条件覆盖,除多一次启动期往返外毫无收益;要让它有意义就得把 CMOS 降级为
兜底,那是给一台本来就有 RTC 的目标增加启动延迟与复杂度。故两 demo 时间源
**有意不同**:qemu 用 CMOS,S3 用 SNTP。

**实机验证(2026-09-10)**:

```
wifi: IPv4 address assigned (DHCPv4)
sntp: ntp.aliyun.com: epoch=1789037388, realtime seeded
net: iface 0x3fc96fa0 dev=wifi up=1
net: ipv4 192.168.1.10
2026-09-10 10:49:48 [0] INFO ... print_conf: This NanoMQ instance configured as:
```

`epoch=1789037388` 换算即 2026-09-10 10:49:48 UTC,与紧随其后的日志时间戳
一致 —— 即日志时间戳确已由网络时间驱动,而非巧合。linker report:FLASH
962 KB、`dram0_0_seg` 313992 B / 399108 B(**78.67%**;开启
`CONFIG_DNS_RESOLVER` 前约 77%)—— SRAM 余量仍约 83 KB,故未启用"字面 IP"
退路。

**已知取舍**:Zephyr 无 TZ 数据库,日志显示恒为 UTC(§8);无 RTC 意味着每次
重启都要重新同步,断网开机则退回 1970,启动最多被推迟约 9s(2 轮 × 2 服务器
× 2s 超时 + 1s 轮间隔)。`CONFIG_DNS_RESOLVER` 因用主机名而开启,它 `select
NET_SOCKETS_SERVICE`(多一个线程 + 缓冲);若 SRAM 吃紧,可改用字面 IPv4 并把
DNS 整个关掉。

**顺带记录(非本类,未修)**:REST `/api/v4/brokers/` 的 `uptime` 字段恒为
`15360 Hours` 之类的离谱值(整数溢出嫌疑),与时钟播种无关。

### §22-5 WS 中止连接泄漏:约 25 次耗尽连接池(2026-09-11 查明并修复)

**现象**:对 8083 反复做"WebSocket 握手成功 → 立刻关闭"(**不发 MQTT
CONNECT**),约 25 次后 broker 的**全部监听面**停止服务:1883/8081/8083 对新
连接一律 `ConnectionRefused`(即 Zephyr 池尽时回的 RST,§7-18),ICMP 仍正常
(IP 栈没死),**不自愈,必须复位板子**。

**复现与关键数字**(从刚复位、零客户端的板子起):

```
第 1–25 次 WS 握手: 全部成功
第 26 次:           WS 握手开始失败(mqtt/rest 尚存)
第 27 次:           三面全停
```

**对照实验(排除探针自身)**:
- 同样节奏但**不含 WS**(只做 TCP 连 1883 + HTTP GET 8081):**120 次连接
  全部正常**;
- **正常 WS 用法**各 40 轮均无泄漏:paho 完整 MQTT-over-WS(v3.1.1)、
  MQTTv5-over-WS、固定 `client_id` 快速重连。

即**泄漏专属于"握手完成、但 MQTT 协商从未进行就断开"这条路径**,而不是
"WS 连接多了就会死"。

#### 根因(已插桩证实)

`nng/src/sp/transport/mqttws/nmq_websocket.c` 的 `wstran_pipe_recv_cb()`
`reset:` 分支。ws 传输在 **nng 接管之前**就为连接建好了 `ws_pipe`:握手一完成
`wstran_accept_cb()` 就 `wstran_pipe_alloc()` 并置 `p->ep_aio = uaio`(监听器
的 accept aio),此刻该 aio 同时充当首个 MQTT 报文的接收方(`done:` 处的
`uaio = p->ep_aio`)。只要 peer 在 MQTT CONNECT 之前断开,recv 先失败,于是:

1. `reset:` 看到 `p->ep_aio != NULL` → 按原注释的意图
   `nni_aio_finish_error(p->ep_aio, NNG_ECONNABORTED)`(避免监听器把
   `NNG_ECLOSED` 误判成"监听器自己被关");
2. 但**accept aio 以错误收尾 ⇒ nng 永远不会把这个 ws_pipe 变成 `nni_pipe`**
   ⇒ `wstran_pipe_init()` 不执行、`p->ep_aio` 不被清空、**没有任何人会调用
   `wstran_pipe_fini()`**;
3. 于是 `ws_pipe` 结构体、其 stream 及底层 socket 一起泄漏 —— 每条中止连接
   泄漏一个 `net_context`。

**插桩证据**(qemu_x86,29 条中止连接,`ctx` = 在用 `net_context` 数):
`accept_cb: pipe_ok` × 29,`recv_cb reset … ep_aio=0x… uaio=0` × 29,
**`pipe_fini` × 0**;`ctx` 从 4 单调涨到 **32**(= `CONFIG_NET_MAX_CONTEXTS`)
后握手开始 RST。修复后同样 400 条中止连接:`ctx` 只在 4↔5 间摆动,
结束回到 **4**,`pipe_ok` 与 `pipe_fini` 各 400,一一对应。

**曾怀疑并已证伪**(§22-5 旧版记的两个候选点,**实测从未进入这两个分支**):
①`wstran_accept_cb` 的 `uaio == NULL` 分支丢弃 stream —— 实测该分支执行 0 次;
②`wstran_pipe_alloc()` 失败时只 close 不 free —— 同样是 0 次。另外旧版已排除
"`wstran_pipe_fini` 漏了 `nng_stream_free`"。真正的分支是 `ep_aio != NULL`。

#### 修复

`wstran_pipe_recv_cb()` 在 `ep_aio != NULL` 分支置 `orphan`,并在**函数尾部**
(不再触碰 `p` 之后)用 `nni_reap(&ws_pipe_reap_list, p)` 交回 reaper 线程回收。
必须走 reap 而不能就地 `wstran_pipe_fini()`:后者会 `nni_aio_free(p->rxaio)`,
而此刻正在执行的**就是这个 aio 的回调**,就地释放会自等待。

`wstran_pipe_fini()` 对"未 init 的 pipe"是安全的,无需新增清理路径:
`p->npipe` / `p->tmp_msg` / `p->ws_param` / `p->qos_buf` 均为零值且各自有
NULL 判断(或 `nni_free`/`nni_msg_free` 接受 NULL),`nni_lmq_flush/fini` 对零值
lmq 是空操作;既有代码本来就会在这种状态下调用它们(`nni_lmq_flush` 在
`reset:`、`wstran_pipe_fini` 在 `wstran_pipe_alloc` 失败路径)。

提交:nng 子模块 `FIX [mqttws] reap the pipe when a ws peer drops before MQTT CONNECT`。

#### 验证

| 场景 | 修复前 | 修复后 |
|---|---|---|
| qemu_x86,400 次中止握手 | 第 30 次起永久失败 | **400/400 通过** |
| ESP32-S3 实机,200 次中止握手 | 第 26/27 次起三面全停 | **200/200 通过** |
| `function_test.py --group ws_abort`(新增,实机) | FAIL(第 30 次) | **PASS**(30.3s) |
| 全量功能套件(qemu_x86,8 组) | — | `pass=8 fail=0` |
| 全量功能套件(实机,7 组) | — | `pass=7 fail=0` |

实机那轮逐组:`mqtt_v311` 64.1s、`mqtt_v5` 321.6s、`rest_get` 3.0s、`ws_v311`
289.4s、`ws_v5` 16.4s、`capacity` 12.2s、`ws_abort` 30.3s。其中 `mqtt_v5` 是
§22-3(g) 那个**上游脚本固有竞速**,由 `--retry` 兜过(与前几次实测一致),
**与本修复无关**:该子测试全程只走 :1883 的 mosquitto CLI,而本次改动只落在
ws 传输的 accept/teardown 路径。

**回归测试**:`function_test.py` 新增 `ws_abort` 组 —— 先做 60 次"握手即断"
(默认,可用 `ZF_WS_ABORT_N` 调),再要求 1883 的 MQTT CONNECT 拿到 CONNACK、
8083 的完整 MQTT-over-WS 会话拿到 CONNACK 才算通过。**注意不能只用裸 TCP
connect 判活**:Zephyr 监听器在 broker 已无法 accept 时仍会从 backlog 完成
TCP 握手,裸 connect 照样成功,必须驱动真实会话。

**本缺陷与 ws 功能测试的关系**:`ws_v311` / `ws_v5` 走的是**完整 MQTT-over-WS**
(每次都发 CONNECT),实测在干净板子上**都能通过**(287.4s / 15.3s),不属于本条
路径。曾有"ws 组卡住 = 本缺陷发作"的判断,已证伪。

**已知残留(良性,不随 N 增长)**:修复后 `ctx` 在**背靠背**压测中会高于基线
4 —— 实测 N=200 峰值 8、N=400 峰值 7,静置 10s 后为 7;这是 reaper 线程滞后
加上 TCP TIME_WAIT 在途连接所致(**未逐一定性**)。判据是它与 N **无关**:
N=50 与 N=400(=8 倍)峰值同为 7。改为 700ms 间隔的慢速压测后,`ctx` 全程
恒为 4。原缺陷是**每条中止连接 +1 且永不回落**,与此有本质区别。

### §22-6 webhook 发送失败不排空队列:接收端不可达时吃光内存(2026-09-11 查明并修复)

**现象**:S3 实机开启 webhook 后,**接收端不在线**时跑 `ws_v311`,broker
**静默卡死**——三个端口仍能完成 TCP 三次握手(backlog 应答),REST 返回
`000`(无响应),串口**无任何输出**(不是 panic),ICMP 正常。复位后立即恢复。
这正是 §22-5 那条教训的另一个实例:*裸 TCP connect 不是判活手段*。

**对照实验**(同一固件、同一测试):
- **接收端不在线** → broker 卡死;
- **接收端在线** → broker 存活(REST 200、MQTT CONNACK `2002`)。

**根因**:`nanomq/webhook_inproc.c` 的 `http_aio_cb()`。函数末尾有一段
drain(取出 `w->lmq` 里的下一条事件并发送),**只有成功路径会落到那里**;
aio 出错时走的是:

```c
nng_mtx_unlock(work->mtx);
return;              /* 跳过 drain */
```

于是发送失败一次,队列就少排空一次。而 `send_msg()` 在 aio 忙时把新事件
`nng_lmq_put()` 入队,队列满时还会 `nng_lmq_resize()` **扩容**。接收端持续
不可达 ⇒ 队列只进不出 ⇒ 内存单调增长。qemu 有 31 MB 放着看不出来;S3 只剩
约 85 KB SRAM,几百条事件即耗尽。

**为何现在才暴露**:S3 demo 此前 **webhook 是关的**(§22-5 的那句旧 README
"WS/webhook/DEBUG log stay off"),这条路径从未在实机跑过。2026-09-11 为
webhook 测试支持而启用后立即命中。**是既有缺陷被新配置暴露,不是本次引入。**

**修复**:`http_aio_cb()` 中三处"清理完就 return"改为一律 `goto drain`
(共 9 行):aio 错误路径、`work->conn == NULL`、`nng_http_req_alloc` 失败。
`nng_http_conn_write_req()` 那处的 `return` **保持不动** —— 它是发起了异步
写,由该写的回调回来 drain,不是"放弃"。

**同一批发现的另一件事(已一并处理)**:demo 的 webhook 规则主题原本是
`MESSAGE_PUBLISH(test/#)`,而 CI 的 `ws_test.py` **恰好就用 `test/...`**
(16 处)。于是 WS 测试每发一条消息都触发一次跨 Wi-Fi 的 HTTP POST —— 在 S3
上把 `ws_v311` 压到超时/丢消息。已核查其余三个 CI 脚本(`mqtt_test.py`、
`mqtt_test_v5.py`、`ws_v5_test.py`)不使用该命名空间,故只有 ws_v311 受影响。
规则主题改为 `hook/#`,webhook 测试组相应发到 `hook/webhook`。

**开关建议:webhook 默认关闭,需要时再开(2026-09-11 实测)**。`CLIENT_CONNACK`
规则对**每次客户端连接**都触发一次 POST,接收端不在线时每次连接就多一次失败的
HTTP 连接 + 两行同步日志(`CONFIG_LOG_MODE_IMMEDIATE=y`)。实测实机单跑
`mqtt_v5`:**97 次** POST 失败 / 114 次连接;该组里那个"按 `mosquitto_pub` 与
两个 `mosquitto_sub` 的进程启动顺序决出胜负"的 retain 子测试(§22-3(g))
**三轮全败**,而关闭 webhook 后恢复为"重试后通过"。即 webhook 的每连接开销
**恰好打在**最计时敏感的竞态判定点上。故 `prj.conf` 保持 webhook 关闭,只在
验证 webhook 本身时于 `local.conf` 打开。

#### §22-6-补 未定性的第二种 webhook 相关死机(2026-09-11,已知未解,**暂不追**)

上述排空缺陷修好之后,仍观察到一次**间歇性**死机:某轮整套测试跑到 `mqtt_v5`
失败后 broker 停止服务(端口仍能完成 TCP 握手、REST 000、串口无 panic)。它
**不是**排空缺陷——那一轮**接收端在线**、POST 是成功的,故障路径根本没被走到,
且修复已在固件里。

**放大实验(决定性 A/B)**:同一块板、同一个高频连接脚本(600 次
CONNECT/DISCONNECT、6 路并发)、同一固件,**唯一变量是 webhook 开关**:

| 条件 | 连接数 | 失败数 | broker |
|---|---|---|---|
| webhook **开** + 接收端在线 | 400(提前中止) | **275** | 约第 200 次起卡死,未恢复 |
| webhook **关**(对照) | 600 | **13** | 全程存活 |

即**确实与 webhook 相关**(21 倍失败率 + 硬卡死)。机制**已定位到崩溃点**
(2026-09-11 续查,见下),但**根因未修**。

**续查结论:不是池耗尽,是 net_pkt 池被写坏后崩溃。**
① 接上串口复现,崩溃现场为 Xtensa 异常 `EXCCAUSE 28 (load prohibited)`,
`PC` 经 addr2line 解析落在 **`k_mem_slab_alloc`(`kernel/mem_slab.c:245`)** ——
即 `slab->free_list = *(char **)(slab->free_list)` 解引用了野指针;
② 用崩溃时的 `A2`(= slab 指针 `0x3fc97210`)对 ELF 查符号,该 slab 是
**`rx_pkts`**(Zephyr 的 net_pkt 接收池,`CONFIG_NET_PKT_RX_COUNT=32`)。
即**有 net_pkt 被重复释放/释放后仍在使用**,把该 slab 的空闲链表写坏,
下一次分配即崩。崩溃后 broker 再不自愈(端口仍答 TCP、REST 000)。

**已用实验排除的三个直觉方向**(都实测过,别再重走):
- **不是排空缺陷**:那一轮接收端在线、POST 成功,故障路径没被走到;而排空修复
  已在固件里。
- **不是 webhook worker 数**:`web_hook.pool_size` 从默认 32 调到 2,同样崩
  (`pool_size` 每个 worker 一条自己的 HTTP 连接,直觉上很像,但不是它)。
- **不是 net_context 不够**:把 `NET_MAX_CONTEXTS/NET_MAX_CONN` 从 32 提到 64,
  照样在第 200 次连接左右崩;且 ctx 峰值只到 **39/64**,根本没顶到上限。
  对照组(webhook 关)同负载下 ctx 峰值 14–24、结束时回落到 5,**不泄漏**。

**归属判断**:webhook 关、同样 600 次连接 churn 下**全程存活**;开则崩。故触发
条件是 webhook 引入的额外流量,但**写坏 net_pkt 的地方在 Zephyr 网络栈 /
ESP32 Wi-Fi 驱动的收包路径**,不在 NanoMQ 侧——修复需要沿着 net_pkt 的
分配/释放归属去查(建议开 `CONFIG_NET_PKT_*` 相关调试或给 net_pkt 加
owner 标记),属于与前述几处不同量级的排查。

**处置**:两个 demo 的 webhook 默认关闭(§22-6 的开关建议),因此**默认配置不受
影响**——webhook 关时实机整套 `pass=8 fail=0 skip=1`、qemu 同样。放大脚本
(`/tmp/connect_hammer.py`,600 次连接 / 6 路并发)、A/B 表与上面这条崩溃链
是续查的起点。

**排查教训**:这次是"启用一个默认关闭的功能"暴露出既有缺陷。判断"是不是我
改坏的"靠的是**对照实验**(接收端开/关各跑一次、webhook 开/关各跑一次),
而不是读代码猜。

**另一条操作教训**:用 `pkill -f <pattern>` / `pgrep -f <pattern>` 清理进程时,
若该 pattern 字面量出现在**当前命令行**的其它位置(例如后台任务的整条命令里
就含 `hook_receiver.py`),会杀掉自己。本次连踩两次。改用 `ss -ltnp` 取 PID 后
`kill <pid>`,或用 `pgrep -x`。

### §22-3-old 历史记录(保留)

**现象**:首个 MQTT 客户端 CONNECT(纯订阅亦可)确定性写穿 PSRAM 堆 →
`heap canary: corruption` / `double free` panic(EXTREME 下
`heap validation failed`,alloc size 1)。

**取证**(已确认与 Zephyr 集成无关):
- 被写穿对象 = topic 树路径上的小层缓冲(5 B `$SYS`/`test` 等,
  由 `mqtt_db.c topic_parse()` 按 `层长+1` 分配);损坏为 chunk 尾 canary。
- 排除:REST 开关、$SYS client_status 通知(源码级旁路后仍崩)、
  分配器(smh vs k_heap)、堆加固等级、是否有订阅、qemu 侧长期套件不现。
- 怀疑:上游 dbtree/路由对 topic 层缓冲存在越界写(时机/堆布局决定
  是否炸;qemu libc 堆恰好不炸)。现场日志与逐操作堆轨迹
  (`zephyr_alloc.c` 环形 + heap.c 挂载均已在收尾时清除)见会话记录。

**建议**:在上游 nng(nanolib/mqtt db)修 topic 层缓冲越界后再跑实机
`function_test.py --no-manage --addr <板IP>`(mqtt_v311/mqtt_v5/rest_get);
当前 demo 仅验证到 §22-1。
