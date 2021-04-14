# NanoMQ 介绍

NanoMQ是于2020年7月开始开发的边缘计算开源项目，是面向物联网边缘计算场景的下一代轻量级高性能MQTT消息服务器。

NanoMQ目标致力于为不同的边缘计算平台交付简单且强大的消息中心服务；站在物联网的十字路口，努力弥和硬件开发与云计算的隔阂；从开源社区出发，连接物理世界和数字智能；从而普及边缘计算应用，助力万物互联愿景。

NanoMQ与NNG深度合作，NanoMQ基于NNG异步IO和多线程模型面向MQTT协议深度优化后诞生。依靠NNG出色的网络API设计，所以NanoMQ自身可以专注于MQTT服务器性能和更多的拓展功能。目标在边缘设备和MEC提供更好的SMP支持和极高的性能性价比。

目前NanoMQ具有的功能和特性有：

完整支持MQTT 3.1.1协议。 由于项目只依赖原生POSIX API， 纯C/C++开发，从而具有极高兼容性和高度可移植性。NanoMQ内部为全异步IO和多线程并行，所以对SMP有良好支持，同时做到了低延时和高吞吐。对于资源利用具有高性价比，适用于各类边缘计算平台。

```shell
$ docker ps
CONTAINER ID        IMAGE                                                                  COMMAND                  CREATED             STATUS              PORTS                                                                                              NAMES
5618c93027a9        nexus3.edgexfoundry.org:10004/docker-device-virtual-go:master          "/device-virtual --p…"   37 minutes ago      Up 37 minutes       0.0.0.0:49990->49990/tcp                                                                           edgex-device-virtual
fabe6b9052f5        nexus3.edgexfoundry.org:10004/docker-edgex-ui-go:master                "./edgex-ui-server"      37 minutes ago      Up 37 minutes       0.0.0.0:4000->4000/tcp                                                                             edgex-ui-go
950135a7041d        emqx/kuiper:0.3.1                                                      "/usr/bin/docker-ent…"   37 minutes ago      Up 37 minutes        0.0.0.0:20498->20498/tcp, 9081/tcp, 0.0.0.0:48075->48075/tcp                                       edgex-kuiper
c49b0d6f9347        nexus3.edgexfoundry.org:10004/docker-support-scheduler-go:master       "/support-scheduler …"   37 minutes ago      Up 37 minutes       0.0.0.0:48085->48085/tcp                                                                           edgex-support-scheduler
4265dcc2bb48        nexus3.edgexfoundry.org:10004/docker-core-command-go:master            "/core-command -cp=c…"   37 minutes ago      Up 37 minutes       0.0.0.0:48082->48082/tcp                                                                           edgex-core-command
4667160e2f41        nexus3.edgexfoundry.org:10004/docker-app-service-configurable:master   "/app-service-config…"   37 minutes ago      Up 37 minutes       48095/tcp, 0.0.0.0:48100->48100/tcp                                                                edgex-app-service-configurable-rules
9bbfe95993f5        nexus3.edgexfoundry.org:10004/docker-core-metadata-go:master           "/core-metadata -cp=…"   37 minutes ago      Up 37 minutes       0.0.0.0:48081->48081/tcp, 48082/tcp                                                                edgex-core-metadata
2e342a3aae81        nexus3.edgexfoundry.org:10004/docker-support-notifications-go:master   "/support-notificati…"   37 minutes ago      Up 37 minutes       0.0.0.0:48060->48060/tcp                                                                           edgex-support-notifications
3cfc628e013a        nexus3.edgexfoundry.org:10004/docker-sys-mgmt-agent-go:master          "/sys-mgmt-agent -cp…"   37 minutes ago      Up 37 minutes       0.0.0.0:48090->48090/tcp                                                                           edgex-sys-mgmt-agent
f69e9c4d6cc8        nexus3.edgexfoundry.org:10004/docker-core-data-go:master               "/core-data -cp=cons…"   37 minutes ago      Up 37 minutes       0.0.0.0:5563->5563/tcp, 0.0.0.0:48080->48080/tcp                                                   edgex-core-data
9e5091928409        nexus3.edgexfoundry.org:10004/docker-support-logging-go:master         "/support-logging -c…"   37 minutes ago      Up 37 minutes       0.0.0.0:48061->48061/tcp                                                                           edgex-support-logging
74e8668f892c        redis:5.0.7-alpine                                                     "docker-entrypoint.s…"   37 minutes ago      Up 37 minutes       0.0.0.0:6379->6379/tcp                                                                             edgex-redis
9b341bb217f9        consul:1.3.1                                                           "docker-entrypoint.s…"   37 minutes ago      Up 37 minutes       0.0.0.0:8400->8400/tcp, 8300-8302/tcp, 8301-8302/udp, 8600/tcp, 8600/udp, 0.0.0.0:8500->8500/tcp   edgex-core-consul
ed7ad5ae08b2        nexus3.edgexfoundry.org:10004/docker-edgex-volume:master               "/bin/sh -c '/usr/bi…"   37 minutes ago      Up 37 minutes                                                                                                          edgex-files
```
