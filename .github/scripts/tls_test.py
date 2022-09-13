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
g_sub = "mosquitto_sub"
g_pub = "mosquitto_pub"

# g_url = " -h {addr} -p {port} ".format(addr = g_addr, port = g_port)
# g_url = " -h {addr} -p {port} --cafile {cacert} --cert {cert} --key {key} --insecure".format(addr = g_addr, port = g_port, cacert = g_cacert, cert = g_cert, key = g_key)
g_url = " -h {addr} -p {port} --cafile {cacert} --insecure ".format(addr = g_addr, port = g_port, cacert = g_cacert)

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
    cs_cmd = g_sub + g_url + "-t topic -q 1"
    ps_cmd = g_sub + g_url + "-t topic -c -i id -q 1"
    p_cmd =  g_pub + g_url + "-t topic -m message -q 1"

    clean_session_cmd = shlex.split(cs_cmd)
    persist_session_cmd = shlex.split(ps_cmd)
    pub_cmd = shlex.split(p_cmd)
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
        print("Persistence sub client does not receive Session reservation message 'message'")
        print(cs_cmd)
        print(ps_cmd)
        print(p_cmd)
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
    rp_cmd = g_pub + g_url + "-m message -t topic -r"
    crp_cmd = g_pub + g_url + "-n -t topic -r"
    s_cmd =  g_sub + g_url + " -t topic"

    retain_pub_cmd = shlex.split(rp_cmd)
    clean_retain_pub_cmd = shlex.split(crp_cmd)
    sub_cmd = shlex.split(s_cmd)
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
        print(rp_cmd)
        print(crp_cmd)
        print(s_cmd)
        print("Retain test failed!")
    else:
        print("Retain test passed!")
    os.kill(pid.value, signal.SIGKILL)

    return is_success

def test_v4_v5():
    s_cmd_v4 = g_sub + g_url + " -t topic/v5/v4 -V 311"
    s_cmd_v5 = g_sub + g_url + " -t topic/v4/v5 -V 5"
    p_cmd_v4 = g_pub + g_url + " -m message  -t topic/v4/v5 -V 311"
    p_cmd_v5 = g_pub + g_url + " -m message  -t topic/v5/v4 -V 5"

    sub_cmd_v4 = shlex.split(s_cmd_v4)
    sub_cmd_v5 = shlex.split(s_cmd_v5)
    pub_cmd_v4 = shlex.split(p_cmd_v4)
    pub_cmd_v5 = shlex.split(p_cmd_v5)

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
        print(s_cmd_v4)
        print(p_cmd_v5)
        print("V5 => v4 test failed!")
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
        print(s_cmd_v5)
        print(p_cmd_v4)
        print("V4 => V5 test failed!")        
        return False
    print("V4/V5 test passed!")
    return True
            

def test_will_topic():
    p_cmd = g_pub + g_url + " -t msg -d -l --will-topic will_topic --will-payload will_payload"
    s_cmd = g_sub + g_url + "-t will_topic"
    pub_cmd = shlex.split(p_cmd)
    sub_cmd = shlex.split(s_cmd)

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
           print("Sub client does not receive will message 'will_payload'")
           print(s_cmd)
           print(p_cmd)
           print("Will topic test failed!")
           break
    process.terminate()
    os.kill(pid.value, signal.SIGKILL)
    return is_success

def tls_test():
    # test_will_topic()
    return test_v4_v5() and test_clean_session() and test_retain()
