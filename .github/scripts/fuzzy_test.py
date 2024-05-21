import time 
import socket
import os

data_path = ".github/scripts/vul_dataset/fuzzy_test.txt"
addr = '127.0.0.1'
port = 1883

def try_connect(bytes_flow, sleep_time = 0.01):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	while True:
		try:
			s.connect((addr, port))
			s.send(bytes_flow)      
			s.close()
			break
		except ConnectionResetError:
			continue
		except ConnectionRefusedError:
			return False
	time.sleep(sleep_time)
	return True

def start_fuzzy_test(fuzzy_data):
	flag = True
	for hex_flow in reversed(fuzzy_data):
		bytes_flow = bytearray.fromhex(hex_flow)
		status = try_connect(bytes_flow)
		if status == False:
			print('[+] A crash was detected')
			flag = False
	if(flag == True):
		print('[-] No crash..')
	return flag

def fuzzy_test():
    with open(data_path, 'r') as f:
        fuzzy_data = f.readlines()
	
    if (start_fuzzy_test(fuzzy_data) == False):
        return False
    else:
        return True