import subprocess
import shlex
import time
import os

from mqtt_test import mqtt_test
from tls_test import tls_test


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

    print("tls v311 test start")
    if False == tls_test():
        nanomq.terminate()
        print("tls v311 test failed")
        raise AssertionError
    print("tls v311 test end")


    nanomq.terminate()
