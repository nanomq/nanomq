# 编译选项

NanoMQ 提供了一些编译选项可以让你根据系统性能进行调优。



## 配置方式

使用以下命令，NanoMQ 可以根据`config.cmake.in`内容设置编译参数:

```bash
$PROJECT_PATH/nanomq/build$ cmake -DCFG_METHOD=FILE_CONFIG  ..
```

也可以使用CMake默认参数进行编译:

```bash
$PROJECT_PATH/nanomq/build$ cmake -DCFG_METHOD=CMAKE_CONFIG ..
```



## 参数设置

限制线程数量:

```bash
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNNG_RESOLV_CONCURRENCY=1                           														-DNNG_NUM_TASKQ_THREADS=5 -DNNG_MAX_TASKQ_THREADS=5 ..
```

NanoMQ支持日志输出，并符合Syslog标准，可以通过以下设置NOLOG变量来选择启用或禁用日志:

```bash
# 禁用日志
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=1  ..
# 启用日志
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNOLOG=0  ..
```

MQTT 客户端

NanoMQ默认支持客户端使用，也可以通过 -DBUILD_CLIENT=OFF来禁用客户端的编译:

```bash
# 禁用客户端
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DBUILD_CLIENT=OFF ..
# 启用客户端
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DBUILD_CLIENT=ON ..
```

消息队列: 

MQ消息队列默认启用，但目前尚未支持macOS，可以通过 -DMQ=0 禁用:

```bash
# 禁用MQ
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=1  ..
# 启用MQ
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DMQ=0  ..
```

系统调优参数:

为MQTT数据包设置**固定头**加**可变头**最大长度，默认为64字节：

```bash
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_PACKET_SIZE={size} ..
```

为MQTT数据包设置**固定头**最大长度，默认为5字节：

```bash
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_HEADER_SIZE={size} ..
```

为MQTT数据包设置**属性**最大长度，默认为32字节：

```bash
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_PROPERTY_SIZE={size} ..
```

为QOS > 0的消息设置队列长度，默认为64: 

```bash
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_QOS_LEN={size} ..
```

设置重发消息的队列长度，默认为64:

```bash
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DNANO_MSQ_LEN={size} ..
```

设置逻辑并发数限制，默认为32，使用-DPARALLEL指定:

```bash
$PROJECT_PATH/nanomq/build$ cmake -G Ninja -DCFG_METHOD=CMAKE_CONFIG -DPARALLEL={parallel} ..
```

如果希望获取更多参数相关信息，请访问项目Wiki页面。
