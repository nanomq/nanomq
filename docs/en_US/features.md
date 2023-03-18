# Features & Advantages


## Efficiency

NanoMQ is intended to be cost-effectively on an embedded platform, To achieve a highly performant throughput with minimum resource requirement and reach a performance-resources equilibrium on any embedded platform. NanoMQ is capable of utilizing the computing power of different hardware in the best effort via its rich tunning options.  Hence it provides high throughput on resource-constrained devices. 

## Scalability

NanoMQ is on multi-threading steroids. Based on the optimized NNG's asynchronous I/O framework towards Linux & MQTT, NanoMQ can scale out easily to engage multiple cores with less CPU usage in the modern SMP system.



## Compatibility

POSIX-based operating systems are by far the most popular and widely deployed, and it is the only prerequisite of NanoMQ. Users can use NanoMQ on any POSIX compatible system to avoid any OS locked-in problem.
To maximize NanoMQ's compatibility, minimize its dependence on APIs—especially proprietary APIs so that we can avoid any vendor locked in. Hence it is easier and cheaper for the community to make the desired changes and embed NanoMQ into various applications if we had written NanoMQ using the POSIX APIs from the beginning.

## Portability

A significant goal of NanoMQ is to be highly portable so that we minimized its dependency. NanoMQ's core features are implemented purely with C and without any third-party library. That means it only requires a tiny amount of work for porting. 
NanoMQ inherent NNG's platform portability layer and going to support other Linux-based systems like OpenWRT & Yocto in the future. With minimum dependency and pure C implementation, NanoMQ is easy to port to different platforms.

## Performant

From data-center to the mobile, from mobile to edge, the hardware evolves. More CPUs that were only used on data-center and the mobile platform now shines on edge. We believe multi-cores infrastructure is the future of edge computing platforms. 

With a built-in Actor framwork, NanoMQ can scales out to engage multiple cores. With system performance tunning towards Linux & MQTT, we manage to split workload averagely to every core. Hence NanoMQ can handle up to 1 million messages per second with less CPU usage in the modern SMP system.

NanoMQ is born for the edge and delivers exceptionally high throughput and low latency with a built-in actor model. Such performance enables more possibilities for data convergence in an edge-centric paradigm.

## All-round
To tackle the fragmented protocol status quo of edge computing. NanoMQ provides an all-around messaging bus for mainstream protocols such as MQTT, nanomsg, WebSocket. Other popular brokerless protocols like ZeroMQ & DDS is also included. Additionally, NanoMQ also provides a benchmarking and MQTT testing toolkit inside the package.