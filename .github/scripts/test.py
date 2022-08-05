from cgi import print_arguments
import subprocess
import shlex
import time

from mqtt_test import mqtt_test


if __name__=='__main__':
    nanomq = shlex.split("nanomq start --url tls+nmq-tcp://0.0.0.0:8883 --cacert /etc/certs/cacert.pem --cert /etc/certs/cert.pem --key /etc/certs/key.pem --qos_duration 1")
    sub = shlex.split("mosquitto_sub -t abc")
    pub = shlex.split("mosquitto_pub -t abc -m msg")
    nanomq = subprocess.Popen(nanomq, 
                           stdout=subprocess.PIPE,
                           universal_newlines=True)

    time.sleep(1)

    print("mqtt test start")
    mqtt_test()
    print("mqtt test end")


    nanomq.terminate()

