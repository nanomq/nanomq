# 通过consumer对持久化的数据进行查询
本节将介绍如何使用consumer对持久化的数据进行查询，并提供一个demo供参考.

## mqtt消息在ringbus/file中的存放格式
目前mqtt消息在ringbus/file中是以key/value的形式进行存放的，其中key是通过hash计算出来的(key = hash(clientid+topic+id)).


## consumer demo
目前NanoMQ暴露出了req/rep接口来供用户对ringbus中的数据或者已经落盘的数据进行查询.
同时在NanoMQ仓库中也提供了consumer demo，用户可以自行编译使用.
```
./nng/demo/exchange_consumer/exchange_consumer.c
```

## 如何使用consumer demo
前面已经说过mqtt消息在ringbus/file中的存储方式是key/value，所以用户如果希望对特定的mqtt消息进行查询则需要提供key。

1. 获取所有文件所存放的mqtt消息
```
$ ./demo/exchange_consumer/exchange_consumer "dumpfile"
"{\"file\":[\"61616161616161616161\",\"61616161616161616161\",\"61616161616161616161\",...\"61616161616161616161\"]}"
```

2. 通过特定的key从文件中获取mqtt消息
```
$ ./demo/exchange_consumer/exchange_consumer "dumpkey:5023450830686577130"
"{\"file\":[\"61616161616161616161\"]}"
```

3. 通过特定的一批key从文件中获取批量mqtt消息
```
$ ./demo/exchange_consumer/exchange_consumer "dumpkeys:2062146488009373518,2625100014974548622"
"{\"file\":[\"61616161616161616161\",\"61616161616161616161\"]}"
```