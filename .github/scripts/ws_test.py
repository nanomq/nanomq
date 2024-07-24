#!/usr/local/bin/pytest
from pydoc import cli
import paho.mqtt.client as mqtt
from paho.mqtt.client import *

g_send_times = 0
g_recv_times = 0
g_pub_times = 1
g_connected = 0

log = ""

def on_log(client, userdata, level, buf):
    log =  log + buf + '\n'

def on_message(self, obj, msg):
    assert msg.topic == str(msg.payload, 'utf-8')
    global g_recv_times 
    global g_pub_times
    g_recv_times += 1
    if g_send_times == g_pub_times:
        g_pub_times = 1
        self.disconnect()
    else:
        g_pub_times += 1


# def on_connect(client_instance, userdata, flags, rc):
#     global g_connected
#     g_connected = 1

def on_publish(self, obj, mid):
    global g_send_times
    global g_pub_times
    # if g_send_times == g_pub_times:
    #     time.sleep(5)
    #     g_pub_times = 1
    #     self.disconnect()
    # else:
    #     g_pub_times += 1

class Test(object):
    def init(self, host="localhost", port=8083, tran='websockets', prot=MQTTv5):
        self._host = host
        self._port = port
        self._tran = tran
        self._prot = prot
    
    def assert_test(self, send_times, _qos, sub, pub):
        global g_send_times
        global g_recv_times
        global g_connected
        g_recv_times = 0
        g_send_times = send_times
        qos = _qos

        # test sub
        while qos >= 0:
            self._mqttc = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION1, client_id="ws_test", transport=self._tran, protocol=self._prot)   
            # self._mqttc.on_connect = on_connect
            self._mqttc.on_message = on_message
            self._mqttc.on_publish = on_publish
            self._mqttc.on_log = on_log

            self._mqttc.connect(self._host, self._port, 60)
            self._mqttc.loop_start()
            # while g_connected == 0:
            #     continue
            self._mqttc.subscribe(sub, qos)
            time.sleep(2)
            self._mqttc.publish(pub, pub, 0)
            self._mqttc.publish(pub, pub, 1)
            self._mqttc.publish(pub, pub, 2)
            g_connected = 0
            time.sleep(2)
            self._mqttc.loop_stop()
            self._mqttc.disconnect()
            qos -= 1

        if(g_send_times * (_qos + 1) != g_recv_times):
            print(log)
            assert(g_send_times * (_qos + 1) == g_recv_times)

        g_recv_times = 0
        qos = _qos

        # test unsub
        while qos >= 0:
            self._mqttc = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION1, client_id="ws_test", transport=self._tran, protocol=self._prot)   
            # self._mqttc.on_connect = on_connect
            self._mqttc.on_message = on_message
            self._mqttc.on_publish = on_publish
            self._mqttc.on_log = on_log

            self._mqttc.connect(self._host, self._port, 60)
            self._mqttc.loop_start()
            # while g_connected == 0:
            #     continue
            self._mqttc.subscribe(sub, qos)
            self._mqttc.unsubscribe(sub)
            self._mqttc.publish(pub, pub, 0)
            self._mqttc.publish(pub, pub, 1)
            self._mqttc.publish(pub, pub, 2)
            g_connected = 0
            time.sleep(1)
            self._mqttc.loop_stop()
            self._mqttc.disconnect()
            qos -= 1

        if(g_recv_times != 0):
            print(log)
            assert(0 == g_recv_times)

def ws_test():
    t1 = Test()
    t1.init(prot=MQTTv311)
    t1.assert_test(3, 2, "test/a/b", "test/a/b")
    t1.assert_test(3, 2, "test/+/+", "test/a/b")
    t1.assert_test(3, 2, "test/a/+", "test/a/b")
    t1.assert_test(3, 2, "test/+/b", "test/a/b")
    t1.assert_test(3, 2, "+/+/b", "test/a/b")
    t1.assert_test(3, 2, "+/a/+", "test/a/b")
    t1.assert_test(3, 2, "+/a/b", "test/a/b")
    t1.assert_test(3, 2, "test/#", "test/a/b")
     
    t1 = Test()
    t1.init(prot=MQTTv5)
    t1.assert_test(3, 1, "test/a/b", "test/a/b")
    t1.assert_test(3, 1, "test/+/+", "test/a/b")
    t1.assert_test(3, 1, "test/a/+", "test/a/b")
    t1.assert_test(3, 1, "test/+/b", "test/a/b")
    t1.assert_test(3, 1, "+/+/b", "test/a/b")
    t1.assert_test(3, 1, "+/a/+", "test/a/b")
    t1.assert_test(3, 1, "+/a/b", "test/a/b")
    t1.assert_test(3, 1, "test/#", "test/a/b")

