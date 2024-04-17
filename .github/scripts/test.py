from cmath import log
from fileinput import close
import os
import subprocess
import shlex
import time
from os.path import exists

from mqtt_test import mqtt_test
from mqtt_test_v5 import mqtt_v5_test
from tls_test import tls_test
from tls_v5_test import tls_v5_test
from ws_test import ws_test
from ws_v5_test import ws_v5_test
from fuzzy_test import fuzzy_test
from rest_api_test import rest_api_test
from vulnerability_test import vul_test

nanomq_log_path = "/tmp/nanomq_test.log" 
nanomq_cmd = "nanomq start --url tls+nmq-tcp://0.0.0.0:8883 --http --cacert etc/certs/cacert.pem --cert etc/certs/cert.pem --key etc/certs/key.pem --qos_duration 1 --log_level debug  --log_stdout false --log_file /tmp/nanomq_test.log"

def print_nanomq_log():
    log_lines = open(nanomq_log_path, 'r')
    for line in log_lines:
        print(line)
    log_lines.close()


if __name__=='__main__':

    if exists(nanomq_log_path):
        os.remove(nanomq_log_path)

    nanomq = shlex.split(nanomq_cmd)
    nanomq = subprocess.Popen(nanomq, 
                           stdout=subprocess.PIPE,
                           universal_newlines=True)
                           

    time.sleep(2)

    print("mqtt v311 test start")
    if False == mqtt_test():
        nanomq.terminate()
        print("mqtt v311 test failed")
        print_nanomq_log()
        raise AssertionError
    print("mqtt v311 test end")

    print("mqtt v5 test start")
    if False == mqtt_v5_test():
        nanomq.terminate()
        print("mqtt v5 test failed")
        print_nanomq_log()
        raise AssertionError
    print("mqtt v5 test end")

    print("tls v311 test start")
    if False == tls_test():
        nanomq.terminate()
        print("tls v311 test failed")
        print_nanomq_log()
        raise AssertionError
    print("tls v311 test end")

    print("tls v5 test start")
    if False == tls_v5_test():
        nanomq.terminate()
        print("tls v5 test failed")
        print_nanomq_log()
        raise AssertionError
    print("tls v5 test end")

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

    time.sleep(3)

    nanomq.terminate()
