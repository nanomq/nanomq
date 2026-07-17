from cmath import log
from fileinput import close
import os
import subprocess
import shlex
import sys
import time
import asyncio
from os.path import exists

# Flush prints immediately so the Actions log timestamps show the real order
# of this harness relative to the stderr logging of the stress tests
sys.stdout.reconfigure(line_buffering=True)

from mqtt_test import mqtt_test
from mqtt_test_v5 import mqtt_v5_test
from tls_test import tls_test
from tls_v5_test import tls_v5_test
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
nanomq_cmd = "nanomq start --conf ./.github/scripts/nanomq.conf --url tls+nmq-tcp://0.0.0.0:8883 --http --cacert etc/certs/cacert.pem --cert etc/certs/cert.pem --key etc/certs/key.pem --qos_duration 1 --log_level debug  --log_stdout false --log_file /tmp/nanomq_test.log"

def print_nanomq_log():
    log_lines = open(nanomq_log_path, 'r', encoding='utf-8', errors='replace')
    for line in log_lines:
        print(line)
    log_lines.close()


def run_test(name, fn, attempts=2):
    # The TLS transport intermittently drops a client on the loaded CI runner
    # (broker_tls.c recv errors, occasional 0x0d protocol-error kicks); retry
    # once so a single flake does not mask the rest of the suite, while the
    # failed attempt stays visible in the log
    print(name + " test start")
    for attempt in range(attempts):
        if fn():
            print(name + " test end")
            return
        print(name + " test attempt " + str(attempt + 1) + " of " + str(attempts) + " failed")
    nanomq.terminate()
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
                           

    time.sleep(2)


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

    run_test("tls v5", tls_v5_test)

    print("ws v311 test start")
    ws_test()
    print("ws v311 test end")

    print("ws v5 test start")
    ws_v5_test()
    print("ws v5 test end")

    print("fuzzy test start")
    if( False == fuzzy_test()):
        nanomq.terminate()
        print("fuzzy test failed")
        print_nanomq_log()
        raise AssertionError
    print("fuzzy test end")

    print("rest api test start")
    if False == rest_api_test():
        nanomq.terminate()
        print("rest api test failed")
        print_nanomq_log()
        raise AssertionError
    print("rest api test end")

    print("vul_test test start")
    vul_test()
    print("vul_test test end")

    print("issue_2246 test start")
    if False == issue_2246_test():
        nanomq.terminate()
        print("issue_2246 test failed")
        print_nanomq_log()
        raise AssertionError
    print("issue_2246 test end")

    # runs its own broker instances on a dedicated port
    print("issue_2355 test start")
    if False == issue_2355_test():
        nanomq.terminate()
        print("issue_2355 test failed")
        print_nanomq_log()
        raise AssertionError
    print("issue_2355 test end")

    time.sleep(3)

    nanomq.terminate()
