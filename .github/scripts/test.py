import subprocess
import shlex
import time


if __name__=='__main__':
    nanomq = shlex.split("nanomq start --url tls+nmq-tcp://0.0.0.0:8883 --cacert /etc/certs/cacert.pem --cert /etc/certs/cert.pem --key /etc/certs/key.pem --qos_duration 1")
    sub = shlex.split("mosquitto_sub -t abc")
    pub = shlex.split("mosquitto_pub -t abc -m msg")
    nanomq = subprocess.Popen(nanomq, 
                           stdout=subprocess.PIPE,
                           universal_newlines=True)

    time.sleep(1)
    sub = subprocess.Popen(sub, 
                           stdout=subprocess.PIPE,
                           universal_newlines=True)
    time.sleep(1)
    pub = subprocess.Popen(pub, 
                           stdout=subprocess.PIPE,
                           universal_newlines=True)

    while True:
        output = sub.stdout.readline()
        print(output)
        break
        if output.strip() == "msg":
            break


    time.sleep(10)
    nanomq.terminate()

