#!/usr/bin/python3
from cgi import test
from re import T
import subprocess
import shlex
import os
import paho.mqtt.client as mqtt
from multiprocessing import Process, Value
import time
import signal
import os

g_port = 1883
g_addr = "127.0.0.1"

g_url = " -h {addr} -p {port} ".format(addr = g_addr, port = g_port)

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
        print("clean session test failed!")

    os.kill(pid.value, signal.SIGKILL)
    pid = Value('i', 0)
    process = Process(target=cnt_message, args=(clean_session_cmd, cnt, pid, "message"))
    process.start()

    time.sleep(1)
    process.terminate()
    os.kill(pid.value, signal.SIGKILL)

def test_retain():
    retain_pub_cmd = shlex.split("mosquitto_pub -m message {} -t topic -r".format(g_url))
    clean_retain_pub_cmd = shlex.split("mosquitto_pub -n {} -t topic -r".format(g_url))
    sub_cmd = shlex.split("mosquitto_sub -t topic {}".format(g_url))
    process = subprocess.Popen(retain_pub_cmd, 
                               stdout=subprocess.PIPE,
                               universal_newlines=True)

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
        print("Retain test failed!")
        return
    print("Retain test passed!")
    os.kill(pid.value, signal.SIGKILL)

def test_v4_v5():
    sub_cmd_v4 = shlex.split("mosquitto_sub -t topic/v4/v5 {} -V 311".format(g_url))
    sub_cmd_v5 = shlex.split("mosquitto_sub -t topic/v4/v5 {} -V 5".format(g_url))
    pub_cmd_v4 = shlex.split("mosquitto_pub -m message  -t topic/v4/v5 {} -V 311".format(g_url))
    pub_cmd_v5 = shlex.split("mosquitto_pub -m message  -t topic/v4/v5 {} -V 5".format(g_url))

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
        return

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
        return
    print("V4/V5 test passed!")
            

def test_will_topic():
    pub_cmd = shlex.split("mosquitto_pub {} -t msg -d -l --will-topic will_topic --will-payload will_payload".format(g_url))
    sub_cmd = shlex.split("mosquitto_sub -t will_topic {}".format(g_url))

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
            print("Will topic test failed!")
            break
    process.terminate()
    os.kill(pid.value, signal.SIGKILL)

def mqtt_test():
    test_will_topic()
    test_v4_v5()
    test_clean_session()
    test_retain()
