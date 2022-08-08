import subprocess
import shlex
import time
import os

from mqtt_test import mqtt_test
from mqtt_test_v5 import mqtt_v5_test
from tls_test import tls_test
from tls_v5_test import tls_v5_test
from ws_test import ws_test
from ws_v5_test import ws_v5_test


if __name__=='__main__':
    nanomq = shlex.split("nanomq start --url tls+nmq-tcp://0.0.0.0:8883 --cacert etc/certs/cacert.pem --cert etc/certs/cert.pem --key etc/certs/key.pem --qos_duration 1")
    nanomq = subprocess.Popen(nanomq, 
                           stdout=subprocess.PIPE,
                           universal_newlines=True)

    time.sleep(0.5)

    print("mqtt v311 test start")
    if False == mqtt_test():
        nanomq.terminate()
        print("mqtt v311 test failed")
        raise AssertionError
    print("mqtt v311 test end")

    print("mqtt v5 test start")
    if False == mqtt_v5_test():
        nanomq.terminate()
        print("mqtt v5 test failed")
        raise AssertionError
    print("mqtt v5 test end")

    print("tls v311 test start")
    if False == tls_test():
        nanomq.terminate()
        print("tls v311 test failed")
        raise AssertionError
    print("tls v311 test end")

    print("tls v5 test start")
    if False == tls_v5_test():
        nanomq.terminate()
        print("tls v5 test failed")
        raise AssertionError
    print("tls v5 test end")

    print("ws v311 test start")
    if False == ws_test():
        nanomq.terminate()
        print("ws v311 test failed")
        raise AssertionError
    print("ws v311 test end")

    print("ws v5 test start")
    if False == ws_v5_test():
        nanomq.terminate()
        print("ws v5 test failed")
        raise AssertionError
    print("ws v5 test end")
    time.sleep(1)

    nanomq.terminate()
