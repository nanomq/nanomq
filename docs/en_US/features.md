# Features

## Cost-effective on the embedded platform

NanoMQ is intended to be cost-effectively on an embedded platform, To achieve a highly performant throughput with minimum resource requirement. For now, NanoMQ can support 800k msg/s with only 200Mb memory usage on a mobile platform.



## Fully base on native POSIX. High Compatibility

POSIX-based operating systems are by far the most popular and widely deployed. To maximize NanoMQ's compatibility, minimize its dependence on APIs—especially proprietary APIs so that we can avoid any vendor locked in. Hence it is easier and cheaper for the community to make the desired changes and embed NanoMQ into various applications if we had written NanoMQ using the POSIX APIs from the beginning.



## Pure C/C++ implementation. High portability

A significant goal of NanoMQ is to be highly portable, which means it only requires a little amount of work to compile and install it on other architecture. To work on many different kinds of edge computing platforms, we inherent NNG's platform portability layer and going to support other Linux-based systems like OpenWRT & Yocto in the future. With minimum dependency and pure C/C++ implementation, NanoMQ is easy to port to different platforms.



## Fully asynchronous I/O & multi-threading

From data-center to the mobile, from mobile to edge, the hardware evolves. More CPUs that were only used on data-center and the mobile platform now shines on edge. We believe multi-cores infrastructure is the future of edge computing platforms. Hence, NanoMQ's asynchronous I/O and multi-threading feature can help users to implement a powerful edge application on such a platform.



## Good support for SMP

NanoMQ base on NNG's asynchronous I/O framework,  so it can scales out to engage multiple cores. With system performance tunning towards Linux & MQTT, we manage to split workload averagely to every core. Hence NanoMQ can handle up to 1 million messages per second with less CPU usage in the modern SMP system.



## Low latency. High handling capacity

Under the circumstance of 500K/s messages throughput, the 90% Avg response time is only 0.2 ms with only 200 MB memory consumption. And all pub/sub-requests are succeeded.
