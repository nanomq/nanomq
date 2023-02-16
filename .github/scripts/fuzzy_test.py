import time 
import socket
import os

def check_input(input, sleep_time = 0.01):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	while True:
		try:
			s.connect(('127.0.0.1', 1883))
			s.send(input)      
			s.close()
			break
		except ConnectionResetError:
			continue
		except ConnectionRefusedError:
			break

	time.sleep(sleep_time)

def check_crash_log(crash_log):
	for c in reversed(crash_log):
		c_bytes = bytearray.fromhex(c)
		status = check_input(c_bytes, 0.25)
		if status == False:
			print('[+] A crash was detected')
			return False
	print('[-] No crash..')
	return True

def fuzzy_test():
    with open('./.github/scripts/fuzzy_test.txt', 'r') as f:
        crash_log = f.readlines()
	
    if (check_crash_log(crash_log) == False):
        return False
    else:
        return True