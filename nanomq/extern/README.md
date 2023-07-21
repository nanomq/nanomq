# File Transfer

## Preconditions
### paho.mqtt.c
#### Linux/MacOS
```
git clone https://github.com/eclipse/paho.mqtt.c.git
cd org.eclipse.paho.mqtt.c.git
make
sudo make install
```

#### Windows
```
mkdir build.paho
cd build.paho
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x64
cmake -G "NMake Makefiles" -DPAHO_WITH_SSL=TRUE -DPAHO_BUILD_DOCUMENTATION=FALSE -DPAHO_BUILD_SAMPLES=TRUE -DCMAKE_BUILD_TYPE=Release -DCMAKE_VERBOSE_MAKEFILE=TRUE ..
nmake
```

## Compile
Need to compile with option `-DENABLE_FILETRANSFER=ON`
```
mkdir build
cd build
cmake -DENABLE_FILETRANSFER=ON ../
make
```

## How to use
### Configure your nanomq into bridge mode with nanomq.conf
The reason for this is that nanomq needs to bridge to emqx to transfer files to the emqx side.
```
bridges.mqtt.name {
	## TCP URL 格式:  mqtt-tcp://host:port
	## TLS URL 格式:  tls+mqtt-tcp://host:port
	## QUIC URL 格式: mqtt-quic://host:port
	server = "mqtt-tcp://broker.emqx.io:1883"
	## MQTT 协议版本 （ 4 ｜ 5 ）
	proto_ver = 5
	# username = admin
	# password = public
	clean_start = true
	keepalive = 60s
	## 如果通过 TLS 桥接将下面的代码取消注释
	## ssl {
	## 	keyfile = "/etc/certs/key.pem"
	## 	certfile = "/etc/certs/cert.pem"
	## 	cacertfile = "/etc/certs/cacert.pem"
	## }
	forwards = ["$file/#"]
	max_parallel_processes = 2 
	max_send_queue_len = 1024
	max_recv_queue_len = 1024
}
```

### Run nanomq broker
After this command, the file transfer mqtt client thread which behind nanomq broker is running.
This mqtt client will subscribe to the `file transfer` topic and receive messages from nanomq broker.
```
nanomq start
```

### Start file transfer
You can run any mqtt client to publish such a message to nanomq in the following JSON format.
```
{
	"file_path": "/tmp/myfile_2M.txt",
	"file_id": "file-id-2",
	"file_name": "myfile_2M.txt"
}
```
When the file transfer mqtt client receive message like this, it will transfer this files in that path to emqx.
For example(use nanomq_cli):
```
nanomq_cli pub -h "127.0.0.1" -p 1883 -t "file_transfer" -m "{\"file_path\":\"/tmp/myfile_2M.txt\",\"file_id\":\"file-id-2\",\"file_name\":\"myfile_2M.txt\"}"
```
