#!/usr/bin/python3
import subprocess
import shlex
import os
from multiprocessing import Process, Value
import time
import signal
import os

g_port = 8883
g_addr = "127.0.0.1"
g_cacert = "etc/certs/cacert.pem"
g_cert = "certs/client-cert.pem"
g_key = "certs/client-key.pem"

# g_url = " -h {addr} -p {port} ".format(addr = g_addr, port = g_port)
# g_url = " -h {addr} -p {port} --cafile {cacert} --cert {cert} --key {key} --insecure".format(addr = g_addr, port = g_port, cacert = g_cacert, cert = g_cert, key = g_key)
g_url = " -h {addr} -p {port} --cafile {cacert} --insecure".format(addr = g_addr, port = g_port, cacert = g_cacert)

def cnt_message(cmd, n, pid, message):
    process = subprocess.Popen(cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    pid.value = process.pid
    
    while True:
        output = process.stdout.readline()
        if output.strip() == message:
            n.value += 1

def test_clean_session():
    clean_session_cmd = shlex.split("mosquitto_sub -t topic {} -q 1".format(g_url))
    persist_session_cmd = shlex.split("mosquitto_sub -t topic {} -c -i id -q 1".format(g_url))
    pub_cmd = shlex.split("mosquitto_pub -m message {} -t topic -q 1".format(g_url))
    is_success = True

    # persistence session
    process = subprocess.Popen(persist_session_cmd, 
                               stdout=subprocess.PIPE,
                               universal_newlines=True)

    time.sleep(1)
    process.terminate()
    time.sleep(1)

    process = subprocess.Popen(pub_cmd, 
                               stdout=subprocess.PIPE,
                               universal_newlines=True)

    time.sleep(1)
    process.terminate()
    time.sleep(1)

    cnt = Value('i', 0)
    pid = Value('i', 0)
    process = Process(target=cnt_message, args=(persist_session_cmd, cnt, pid, "message"))
    process.start()

    time.sleep(5)
    process.terminate()
    if cnt.value == 1:
        print("clean session test passed!")
    else:
        is_success = False
        print("clean session test failed!")

    os.kill(pid.value, signal.SIGKILL)
    pid = Value('i', 0)
    process = Process(target=cnt_message, args=(clean_session_cmd, cnt, pid, "message"))
    process.start()

    time.sleep(1)
    process.terminate()
    os.kill(pid.value, signal.SIGKILL)
    return is_success

def test_retain():
    retain_pub_cmd = shlex.split("mosquitto_pub -m message {} -t topic -r".format(g_url))
    clean_retain_pub_cmd = shlex.split("mosquitto_pub -n {} -t topic -r".format(g_url))
    sub_cmd = shlex.split("mosquitto_sub -t topic {}".format(g_url))
    process = subprocess.Popen(retain_pub_cmd, 
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    time.sleep(1)
    is_success = True
    cnt = Value('i', 0)
    pid = Value('i', 0)
    process = Process(target=cnt_message, args=(sub_cmd, cnt, pid, "message"))
    process.start()
    time.sleep(1)

    process.terminate()
    process = subprocess.Popen(clean_retain_pub_cmd, 
                               stdout=subprocess.PIPE,
                               universal_newlines=True)

    time.sleep(1)
    process.terminate()
    if cnt.value != 1:
        is_success = False
        print("Retain test failed!")
    else:
        print("Retain test passed!")
    os.kill(pid.value, signal.SIGKILL)

    return is_success

def test_v4_v5():
    sub_cmd_v4 = shlex.split("mosquitto_sub -t topic/v4/v5 {} -V 311".format(g_url))
    sub_cmd_v5 = shlex.split("mosquitto_sub -t topic/v4/v5 {} -V 5".format(g_url))
    pub_cmd_v4 = shlex.split("mosquitto_pub -m message  -t topic/v4/v5 {} -V 311".format(g_url))
    pub_cmd_v5 = shlex.split("mosquitto_pub -m message  -t topic/v4/v5 {} -V 5".format(g_url))

    is_success = True
    cnt = Value('i', 0)
    pid = Value('i', 0)
    process = Process(target=cnt_message, args=(sub_cmd_v4, cnt, pid, "message"))
    process.start()
    time.sleep(1)
    process2 = subprocess.Popen(pub_cmd_v5, 
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    time.sleep(1)
    process.terminate()
    os.kill(pid.value, signal.SIGKILL)
    pid = Value('i', 0)

    if cnt.value != 1:
        print("V4/V5 test failed!")
        return False

    process = Process(target=cnt_message, args=(sub_cmd_v5, cnt, pid, "message"))
    process.start()
    time.sleep(1)
    process4 = subprocess.Popen(pub_cmd_v4, 
                               stdout=subprocess.PIPE,
                               universal_newlines=True)

    time.sleep(1)
    process.terminate()
    os.kill(pid.value, signal.SIGKILL)

    if cnt.value != 2:
        print("V4/V5 test failed!")
        return False
    print("V4/V5 test passed!")
    return True
            

def test_will_topic():
    pub_cmd = shlex.split("mosquitto_pub {} -t msg -d -l --will-topic will_topic --will-payload will_payload".format(g_url))
    sub_cmd = shlex.split("mosquitto_sub -t will_topic {}".format(g_url))

    is_success = True
    cnt = Value('i', 0)
    pid = Value('i', 0)
    process = Process(target=cnt_message, args=(sub_cmd, cnt, pid, "will_payload"))
    process.start()

    time.sleep(1)
    process2 = subprocess.Popen(pub_cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    time.sleep(1)
    process2.terminate()
    times = 0
    while True:
        if cnt.value == 1:
            print("Will topic test passed!")
            break
        time.sleep(1)
        times += 1
        if times == 5:
            is_success = False
            print("Will topic test failed!")
            break
    process.terminate()
    os.kill(pid.value, signal.SIGKILL)
    return is_success

def tls_test():
    # ret1 = test_will_topic()
    ret2 = test_v4_v5()
    ret3 = test_clean_session()
    ret4 = test_retain()
    return ret2 and ret3 and ret4
    # return ret1 and ret2 and ret3 and ret4
