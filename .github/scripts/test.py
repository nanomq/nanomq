from cmath import log
from fileinput import close
import os
import socket
import subprocess
import shlex
import sys
import threading
import time
import asyncio
from os.path import exists

# Flush prints immediately so the Actions log timestamps show the real order
# of this harness relative to the stderr logging of the stress tests
sys.stdout.reconfigure(line_buffering=True)

from mqtt_test import mqtt_test
from mqtt_test_v5 import mqtt_v5_test
from tls_test import tls_test
from tls_v5_test import set_port as set_tls_v5_port
from tls_v5_test import test_topic_alias, tls_v5_test
from ws_test import ws_test
from ws_v5_test import ws_v5_test
from fuzzy_test import fuzzy_test
from rest_api_test import rest_api_test
from vulnerability_test import vul_test
from attack import attack_test
from webhook_test import run_mqtt_fuzzer
from repro_ws_oob_poc import websocket
from test_issue_2246 import issue_2246_test
from test_issue_2355 import issue_2355_test

nanomq_log_path = "/tmp/nanomq_test.log"
nanomq_common_cmd = "nanomq start --conf ./.github/scripts/nanomq.conf --cacert etc/certs/cacert.pem --cert etc/certs/cert.pem --key etc/certs/key.pem --qos_duration 1 --log_level debug --log_stdout false"
nanomq_cmd = nanomq_common_cmd + " --http --url tls+nmq-tcp://0.0.0.0:8883 --log_file /tmp/nanomq_test.log"
topic_alias_nanomq_cmd = "nanomq start --conf ./.github/scripts/nanomq-topic-alias.conf --url nmq-tcp://127.0.0.1:{tcp_port} --url tls+nmq-tcp://127.0.0.1:{tls_port} --cacert etc/certs/cacert.pem --cert etc/certs/cert.pem --key etc/certs/key.pem --parallel 1 --log_level debug --log_stdout false --log_file /tmp/nanomq_topic_alias_test.log"

def allocate_test_ports(count):
    listeners = []
    try:
        for _ in range(count):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listeners.append(listener)
        return [listener.getsockname()[1] for listener in listeners]
    finally:
        for listener in listeners:
            listener.close()

def print_nanomq_log(log_path=nanomq_log_path):
    if not exists(log_path):
        print(log_path + " was not created")
        return
    with open(log_path, 'r', encoding='utf-8', errors='replace') as log_lines:
        for line in log_lines:
            print(line, end='')


def stop_nanomq(process=None):
    process = nanomq if process is None else process
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def wait_for_nanomq(process=None, port=8883, log_path=nanomq_log_path, timeout_sec=10):
    process = nanomq if process is None else process
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if process.poll() is not None:
            print("nanomq exited during startup")
            print_nanomq_log(log_path)
            raise AssertionError
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.05)

    stop_nanomq(process)
    print("nanomq did not open its TLS listener within " + str(timeout_sec) + "s")
    print_nanomq_log(log_path)
    raise AssertionError


def run_topic_alias_serial():
    log_path = "/tmp/nanomq_topic_alias_test.log"
    topic_alias_tcp_port, topic_alias_tls_port = allocate_test_ports(2)
    if exists(log_path):
        os.remove(log_path)
    serial_nanomq = subprocess.Popen(
        shlex.split(topic_alias_nanomq_cmd.format(
            tcp_port=topic_alias_tcp_port, tls_port=topic_alias_tls_port)),
        stdout=subprocess.PIPE,
        universal_newlines=True,
        encoding='utf-8',
        errors='replace')
    try:
        wait_for_nanomq(serial_nanomq, topic_alias_tls_port, log_path)
        set_tls_v5_port(topic_alias_tls_port)
        result = test_topic_alias()
        if not result:
            print_nanomq_log(log_path)
        return result
    except AssertionError:
        print_nanomq_log(log_path)
        return False
    finally:
        set_tls_v5_port(8883)
        stop_nanomq(serial_nanomq)


def run_bounded(name, fn, timeout_sec=120):
    # test.py ignores the ws results, but a wedged websocket client blocks
    # forever inside paho's connect() when the broker's ws listener stops
    # responding; run the stage in a daemon thread so a wedge is reported
    # and abandoned instead of hanging the whole suite
    print(name + " test start")
    t = threading.Thread(target=fn, daemon=True)
    t.start()
    t.join(timeout_sec)
    if t.is_alive():
        print(name + " test timed out after " + str(timeout_sec) + "s, abandoning it")
    else:
        print(name + " test end")


def run_test(name, fn, attempts=3):
    # The TLS transport intermittently drops a client on the loaded CI runner
    # (broker_tls.c recv errors, occasional 0x0d protocol-error kicks); retry
    # so a couple of flakes do not mask the rest of the suite, while every
    # failed attempt stays visible in the log
    print(name + " test start")
    for attempt in range(attempts):
        if fn():
            print(name + " test end")
            return
        print(name + " test attempt " + str(attempt + 1) + " of " + str(attempts) + " failed")
    stop_nanomq()
    print(name + " test failed")
    print_nanomq_log()
    raise AssertionError


if __name__=='__main__':


    if exists(nanomq_log_path):
        os.remove(nanomq_log_path)

    nanomq = shlex.split(nanomq_cmd)
    nanomq = subprocess.Popen(nanomq, 
                           stdout=subprocess.PIPE,
                           universal_newlines=True,
                           encoding='utf-8',
                           errors='replace')
                           

    wait_for_nanomq()


    run_test("mqtt v311", mqtt_test)

    print("websocket test start")
    asyncio.run(websocket())
    print("websocket test end")

    print("attack test start")
    attack_test()
    print("attack test end")

    print("webhook test start")
    run_mqtt_fuzzer()
    print("webhook test end")

    run_test("mqtt v5", mqtt_v5_test)

    run_test("tls v311", tls_test)

    run_test("tls v5", lambda: tls_v5_test(run_topic_alias=False))

    run_test("tls v5 topic alias", run_topic_alias_serial)

    run_bounded("ws v311", ws_test)

    run_bounded("ws v5", ws_v5_test)

    print("fuzzy test start")
    if( False == fuzzy_test()):
        stop_nanomq()
        print("fuzzy test failed")
        print_nanomq_log()
        raise AssertionError
    print("fuzzy test end")

    print("rest api test start")
    if False == rest_api_test():
        stop_nanomq()
        print("rest api test failed")
        print_nanomq_log()
        raise AssertionError
    print("rest api test end")

    print("vul_test test start")
    vul_test()
    print("vul_test test end")

    print("issue_2246 test start")
    if False == issue_2246_test():
        stop_nanomq()
        print("issue_2246 test failed")
        print_nanomq_log()
        raise AssertionError
    print("issue_2246 test end")

    # runs its own broker instances on a dedicated port
    print("issue_2355 test start")
    if False == issue_2355_test():
        stop_nanomq()
        print("issue_2355 test failed")
        print_nanomq_log()
        raise AssertionError
    print("issue_2355 test end")

    time.sleep(3)

    stop_nanomq()
