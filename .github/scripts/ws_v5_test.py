#!/usr/local/bin/pytest
import re
import sys
import paho.mqtt.client as mqtt
from paho.mqtt.client import *
from paho.mqtt import *
from paho.mqtt.packettypes import *
from paho.mqtt.properties import *
from multiprocessing import Process, Value
from threading import Thread, Lock

import subprocess
import shlex

g_send_times = 0
g_recv_times = 0
g_pub_times = 1
g_sub_times = 0

user_properties = [("filename","test.txt"),("count","1")]
topic_alias = 10
session_expiry_interval = 10
recv_msg = ""

def on_message_topic_alias(self, obj, msg):
    print("Receive:" + msg.topic+" "+str(msg.qos)+" "+str(msg.payload))
    assert msg.topic == str(msg.payload, 'utf-8')
    # if self._protocol == MQTTv5:
    #     print("topic alias: " + str(msg.properties.TopicAlias))
    #     assert msg.properties.TopicAlias == topic_alias
    self.disconnect()

def on_message_user_property(self, obj, msg):
    print("Receive:" + msg.topic+" "+str(msg.qos)+" "+str(msg.payload))
    assert msg.topic == str(msg.payload, 'utf-8')
    if self._protocol == MQTTv5:
        print("user property: " + str(msg.properties.UserProperty))
        assert msg.properties.UserProperty == user_properties
    self.disconnect()

def on_message_session_expiry_interval(self, obj, msg):
    print("Receive:" + msg.topic+" "+str(msg.qos)+" "+str(msg.payload))
    assert msg.topic == str(msg.payload, 'utf-8')
    global recv_msg 
    recv_msg = str(msg.payload, 'utf-8')
    
    self.disconnect()

def on_message(self, obj, msg):
    print("Receive:" + msg.topic+" "+str(msg.qos)+" "+str(msg.payload))
    assert msg.topic == str(msg.payload, 'utf-8')
    # if self._protocol == MQTTv5:
    #     assert msg.properties.UserProperty == user_properties
    self.disconnect()

def on_publish(self, obj, mid):
    self.disconnect()

def on_subscribe(self, obj, mid, granted_qos):
    global g_sub_times
    print("subscribed v4")
    g_sub_times += 1
    
def on_subscribe_v5(self, mqttc, obj, mid, granted_qos):
    global g_sub_times
    # print("subscribed" + self.protocol)
    g_sub_times += 1

def on_subscribe_session_expiry_interval(self, mqttc, obj, mid, granted_qos):
    global g_sub_times
    if g_sub_times == 0:
        self.disconnect()
        g_sub_times += 1

def on_log(client, userdata, level, buf):
    print("log: ",buf)

def func(proto, cmd, topic, prop=None):
    mqttc = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION1, transport='websockets', protocol=proto)   
    mqttc.on_log = on_log
    if cmd == "sub":
        mqttc._client_id = "whoami/sub"
    else:
        mqttc._client_id = "whoami/pub"

    if proto == MQTTv311:
        mqttc.on_subscribe = on_subscribe
    elif proto == MQTTv5:
        mqttc.on_subscribe = on_subscribe_v5

    if "user/property" == topic:
        mqttc.on_message = on_message_user_property
    elif "topic/alias" == topic:
        mqttc.on_message = on_message_topic_alias
    elif "session/expiry/interval" == topic:
        mqttc.on_subscribe = on_subscribe_session_expiry_interval
        mqttc.on_message = on_message_session_expiry_interval
    else:
        mqttc.on_message = on_message

    mqttc.on_publish = on_publish


    if "session/expiry/interval" == topic and cmd == "sub":
        mqttc.connect("localhost", 8083, 60, properties=prop, clean_start=False)
        prop = None
    else:
        mqttc.connect("localhost", 8083, 60)


    global g_sub_times
    if proto == MQTTv311:
        if cmd == "sub":
            mqttc.subscribe(topic, 1)
        elif cmd == "pub":
            while g_sub_times == 0:
                continue
            g_sub_times = 0
            mqttc.publish(topic, topic, 1)
    else:
        if cmd == "sub":
            mqttc.subscribe(topic, 1, properties=prop)
        elif cmd == "pub":
            while g_sub_times == 0:
                continue    
            g_sub_times = 0
            mqttc.publish(topic, topic, 1, properties=prop)
    mqttc.loop_forever()

def ws_v4_v5_test():
    # v311 to v5
    t1 = Thread(target=func, args=(MQTTv5, "sub", "v311/to/v5"))
    t1.start()
    t2 = Thread(target=func, args=(MQTTv311, "pub", "v311/to/v5"))
    t2.start()
    time.sleep(0.5)

    # v5 to v311
    t1 = Thread(target=func, args=(MQTTv311, "sub", "v5/to/v311"))
    t1.start()
    t2 = Thread(target=func, args=(MQTTv5, "pub", "v5/to/v311"))
    t2.start()
    time.sleep(0.5)

def ws_user_properties():

    properties=Properties(PacketTypes.PUBLISH)
    properties.UserProperty=user_properties

    t1 = Thread(target=func, args=(MQTTv5, "sub", "user/property"))
    t1.start()
    t2 = Thread(target=func, args=(MQTTv5, "pub", "user/property", properties))
    t2.start()

def ws_topic_alias():
    properties=Properties(PacketTypes.PUBLISH)
    properties.TopicAlias=topic_alias
    t1 = Thread(target=func, args=(MQTTv5, "sub", "topic/alias"))
    t1.start()
    t2 = Thread(target=func, args=(MQTTv5, "pub", "topic/alias", properties))
    t2.start()


def ws_session_expiry_interval():
    properties=Properties(PacketTypes.CONNECT)
    properties.SessionExpiryInterval=session_expiry_interval
    # sub with property session expiry interval and disconnect when sub success
    # pub within session expiry interval
    # sub within session expiry interval
    # 
    # sub with property session expiry interval and disconnect when sub success
    # pub within session expiry interval
    # sub beyond session expiry interval

    t1 = Thread(target=func, args=(MQTTv5, "sub", "session/expiry/interval", properties))
    t1.start()
    time.sleep(0.1)


    # global g_sub_times
    # g_sub_times = 1
    t2 = Thread(target=func, args=(MQTTv5, "pub", "session/expiry/interval"))
    t2.daemon = True
    t2.start()
    time.sleep(0.1)

    global g_sub_times
    g_sub_times = 1
    t3 = Thread(target=func, args=(MQTTv5, "sub", "session/expiry/interval"))
    t3.daemon = True
    t3.start()
    time.sleep(3)

    global recv_msg 
    print(recv_msg)
    assert recv_msg == "session/expiry/interval"


    # t4 = Thread(target=func, args=(MQTTv5, "pub", "session/expiry/interval"))
    # t4.daemon = True
    # t4.start()
    # time.sleep(0.05)



    # t4 = Thread(target=func, args=(MQTTv5, "sub", "session/expiry/interval", properties))
    # t4.start()

def ws_v5_test():
    ws_v4_v5_test()
    time.sleep(0.5)
    ws_user_properties()
    time.sleep(0.5)
    ws_topic_alias()
    time.sleep(0.5)
    ws_session_expiry_interval()
    time.sleep(0.5)