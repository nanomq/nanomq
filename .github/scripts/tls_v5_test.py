#!/usr/bin/python3
from cgi import test
from curses import termattrs
from operator import is_
from re import S, T
import subprocess
import shlex
import os
import paho.mqtt.client as mqtt
from multiprocessing import Process, Value
import time
import threading
import signal

g_port = 8883
g_addr = "127.0.0.1"
g_cacert = "/home/lee/workspace/nanomq/etc/certs/cacert.pem"
g_cert = "../certs/client-cert.pem"
g_key = "../certs/client-key.pem"

# g_url = " -h {addr} -p {port} ".format(addr = g_addr, port = g_port)
# g_url = " -h {addr} -p {port} --cafile {cacert} --cert {cert} --key {key} --insecure".format(addr = g_addr, port = g_port, cacert = g_cacert, cert = g_cert, key = g_key)
g_url = " -h {addr} -p {port} --cafile {cacert} --insecure".format(addr = g_addr, port = g_port, cacert = g_cacert)

cnt = 0
non_cnt = 0
shared_cnt = 0
lock = threading.Lock()

def clear_subclients():
    entries = os.popen("pidof mosquitto_sub")

    for line in entries:
        for pid in line.split():
            os.kill(int(pid), signal.SIGKILL)

def wait_message(process, route):
    global cnt 
    global non_cnt 
    global shared_cnt 
    while True:
        output = process.stdout.readline()
        if output.strip() == 'message':
            lock.acquire()
            if route == 1:
                cnt += 1
            elif route == 2:
                non_cnt += 1
            else:
                shared_cnt += 1
            lock.release()

def cnt_substr(cmd, n, pid, message):
    process = subprocess.Popen(cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    pid.value = process.pid
    while True:
        output = process.stdout.readline()
        if message in output:
            n.value += 1

def cnt_message(cmd, n, pid, message):
    process = subprocess.Popen(cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)

    pid.value = process.pid
    while True:
        output = process.stdout.readline()
        if output.strip() == message:
            n.value += 1

def test_shared_subscription():
    pub_cmd = shlex.split("mosquitto_pub -t topic_share -V 5 -m message {} -d --repeat 10".format(g_url))
    sub_cmd = shlex.split("mosquitto_sub -t '$share/a/topic_share' {}".format(g_url))
    sub_cmd_shared = shlex.split("mosquitto_sub -t '$share/b/topic_share' {}".format(g_url))
    sub_cmd_non_shared = shlex.split("mosquitto_sub -t topic_share {}".format(g_url))
    process1 = subprocess.Popen(sub_cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    time.sleep(0.05)
    process2 = subprocess.Popen(sub_cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    time.sleep(0.05)
    process3 = subprocess.Popen(sub_cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    time.sleep(0.05)
    process4 = subprocess.Popen(sub_cmd_non_shared,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    time.sleep(0.05)
    process5 = subprocess.Popen(sub_cmd_shared,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    time.sleep(2)
    process6 = subprocess.Popen(pub_cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)

    t1 = threading.Thread(target=wait_message, args=(process1, 1))
    t2 = threading.Thread(target=wait_message, args=(process2, 1))
    t3 = threading.Thread(target=wait_message, args=(process3, 1))
    t4 = threading.Thread(target=wait_message, args=(process4, 2))
    t5 = threading.Thread(target=wait_message, args=(process5, 3))

    t1.daemon = True
    t2.daemon = True
    t3.daemon = True
    t4.daemon = True
    t5.daemon = True

    t1.start()
    t2.start()
    t3.start()
    t4.start()
    t5.start()
    
    times = 0
    while True:
        lock.acquire()
        if cnt == 10:
            lock.release()
            process1.terminate()
            process2.terminate()
            process3.terminate()
            break
        lock.release()
        times += 1
        time.sleep(1)
        if times == 5:
            print("Shared subscription test failed!")
            return
    
    times = 0
    while True:
        lock.acquire()
        if non_cnt == 10:
            lock.release()
            process4.terminate()
            break
        lock.release()
        times += 1
        time.sleep(1)
        if times == 5:
            print("Shared subscription test failed!")
            return
    
    times = 0
    while True:
        lock.acquire()
        if shared_cnt == 10:
            lock.release()
            process5.terminate()
            break
        lock.release()
        times += 1
        time.sleep(1)
        if times == 5:
            print("Shared subscription test failed!")
            return

    print("Shared subscription test passed!")

def test_topic_alias():
    pub_cmd = shlex.split("mosquitto_pub -t topic -V 5 -m message -D Publish topic-alias 10 {} -d --repeat 10".format(g_url))
    sub_cmd = shlex.split("mosquitto_sub -t topic {}".format(g_url))

    cnt = Value('i', 0)
    pid = Value('i', 0)
    process1 = Process(target=cnt_message, args=(sub_cmd, cnt, pid, "message"))
    process1.start()
    time.sleep(1)
    process2 = subprocess.Popen(pub_cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)

    times = 0
    while True:
        if cnt.value == 10 or times == 5:
            break
        time.sleep(1)
        times += 1
    
    process1.terminate()
    os.kill(pid.value, signal.SIGKILL)
    if cnt.value == 10:
        print("Topic alias test passed!")
    else:
        print("Topic alias test failed!")


def test_user_property():
    pub_cmd = shlex.split("mosquitto_pub -t topic_test {} -m aaaa -V 5 -D Publish user-property user property".format(g_url))
    sub_cmd = shlex.split("mosquitto_sub -t topic_test {} -V 5 -F %P".format(g_url))

    cnt = Value('i', 0)
    pid = Value('i', 0)
    process1 = Process(target=cnt_message, args=(sub_cmd, cnt, pid, "user:property"))
    process1.start()

    time.sleep(1)
    process2 = subprocess.Popen(pub_cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)

    times = 0
    while True:
        if cnt.value == 1:
            process1.terminate()
            break
        time.sleep(1)
        times += 1
        if times == 5:
            break
    
    process1.terminate()
    os.kill(pid.value, signal.SIGKILL)
    if times == 5:
        print("User property test failed!")
    else:
        print("User property test passed!")

def test_session_expiry():


    pub_cmd = shlex.split("mosquitto_pub -t topic_test {} -m message -V 5 -q 1".format(g_url))
    sub_cmd = shlex.split("mosquitto_sub -t 'topic_test' {} --id client -x 6 -c -q 1 -V 5".format(g_url))

    process1 = subprocess.Popen(sub_cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)

    time.sleep(0.5)
    process1.terminate()

    process2 = subprocess.Popen(pub_cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    time.sleep(0.5)
    cnt = Value('i', 0)
    pid = Value('i', 0)
    process3 = Process(target=cnt_message, args=(sub_cmd, cnt, pid, "message"))
    process3.start()
    time.sleep(4)
    process3.terminate()
    os.kill(pid.value, signal.SIGKILL)
    if cnt.value != 1:
        print("Session expiry interval test failed")
        return

    process2 = subprocess.Popen(pub_cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    cnt = Value('i', 0)
    pid = Value('i', 0)
    time.sleep(1)
    process3 = Process(target=cnt_message, args=(sub_cmd, cnt, pid, "message"))
    process3.start()
    time.sleep(2)
    process3.terminate()
    os.kill(pid.value, signal.SIGKILL)
    
    if cnt.value == 1:
        print("Session expiry interval test passed!")
    else:
        print("Session expiry interval test failed")

def test_message_expiry():
    pub_cmd = shlex.split("mosquitto_pub -t topic_test {} -m message -V 5 -q 1 -D publish message-expiry-interval 3 -r".format(g_url))
    sub_cmd = shlex.split("mosquitto_sub -t topic_test {} -q 1 -V 5".format(g_url))

    process1 = subprocess.Popen(pub_cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)

    time.sleep(1)
    cnt = Value('i', 0)
    pid = Value('i', 0)
    process2 = Process(target=cnt_message, args=(sub_cmd, cnt, pid, "message"))
    process2.start()
    time.sleep(2)
    process2.terminate()
    os.kill(pid.value, signal.SIGKILL)
    if cnt.value != 1:
        print("Message expiry interval test failed!")
        return

    time.sleep(3)

    pid = Value('i', 0)
    process2 = Process(target=cnt_message, args=(sub_cmd, cnt, pid, "message"))
    process2.start()
    time.sleep(2)
    process2.terminate()
    os.kill(pid.value, signal.SIGKILL)
    if cnt.value == 1:
        print("Message expiry interval test passed!")
    else:
        print("Message expiry interval test failed!")

def test_retain_as_publish():
    pub_retain_cmd = shlex.split("mosquitto_pub -t topic {} -V 5 -m retain/as/published -d --retain".format(g_url))
    sub_retain_cmd = shlex.split("mosquitto_sub -t topic {} -V 5 --retain-as-published -d".format(g_url))
    sub_common_cmd = shlex.split("mosquitto_sub -t topic {} -V 5 -d".format(g_url))
    pub_clean_retain_cmd = shlex.split("mosquitto_pub -t topic {} -V 5 -m \"\" -d".format(g_url))

    process1 = subprocess.Popen(pub_retain_cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    
    time.sleep(0.05)
    cnt = Value('i', 0)
    pid1 = Value('i', 0)
    process2 = Process(target=cnt_substr, args=(sub_common_cmd, cnt, pid1, " r0,"))
    process2.start()
    time.sleep(0.05)

    cnt1 = Value('i', 0)
    pid2 = Value('i', 0)
    process3 = Process(target=cnt_substr, args=(sub_retain_cmd, cnt1, pid2, " r1,"))
    process3.start()

    time.sleep(1)

    if cnt.value != 1 or cnt1.value != 1:
        print("Retain As Published test failed!")
    else:
        print("Retain As Published test passed!")

    process4 = subprocess.Popen(pub_clean_retain_cmd,
                               stdout=subprocess.PIPE,
                               universal_newlines=True)

    process1.terminate()
    process2.terminate()
    process3.terminate()
    process4.terminate()

    os.kill(pid1.value, signal.SIGKILL)
    os.kill(pid2.value, signal.SIGKILL)

    time.sleep(2)
    # clear_subclients()

if __name__ == '__main__':
    # test_message_expiry()
    test_session_expiry()
    test_user_property()
    test_shared_subscription()
    test_topic_alias()
    test_retain_as_publish()

