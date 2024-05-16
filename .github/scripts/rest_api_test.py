import requests
import json
from collections import namedtuple

base_url = "http://127.0.0.1:8081/api/v4"

def test_get_api():
    #  not all endpoint is tested, CI for 'topic-tree' need more test.
    paths = ["", "/nodes", "/brokers", "/clients",
             "/subscriptions", "/reload", "/configuration"]

    for p in paths:
        print("testing Get API: " + base_url + p)
        response = requests.get(base_url + p, auth=('admin', 'public'), headers={'Connection':'close'})

        if response.status_code != 200:
            print("test get api failed: " + p)
            return False

    return True

def test_post_api():
    Param = namedtuple('Param', ['path', 'payload'])

    param1 = Param(path="/reload", payload={'data': {
        'property_size': 64,
        'max_packet_size': 5120,
        'client_max_packet_size': 5,
        'msq_len': 2048,
        'qos_duration': 10,
        'keepalive_backoff': 1250,
        'allow_anonymous': False
    }})

    param2 = Param(path="/reload", payload={'data': {
        'property_size': 64,
        'max_packet_size': 10240,
        'client_max_packet_size': 5,
        'msq_len': 2048,
        'qos_duration': 90,
        'keepalive_backoff': 1250,
        'allow_anonymous': True
    }})

    param_list = [param1, param2]

    for item in param_list:
        print("testing Post API: " + base_url + item.path)
        response = requests.post(
            base_url + item.path, json.dumps(item.payload), auth=('admin', 'public'), headers={'Connection':'close'})
        if response.status_code != 200:
            print("test Post api failed: " + item.path)
            return False

    return True

def rest_api_test():
    return test_get_api() and test_post_api()
