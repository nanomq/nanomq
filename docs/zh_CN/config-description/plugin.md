# Plugin

NanoMQ 提供了Plugin的功能，用户可以基于NanoMQ plugin 框架提供的接口实现符合自己需求的插件。
在NanoMQ broker启动阶段，NanoMQ会去加载用户在config文件中配置的plugins，并在相关的HOOK点位调用用户自定义插件。

1. 目前NanoMQ提供了以下hook点位
- HOOK_USER_PROPERTY: 在MQTT 5消息发送阶段用户可以添加自定义的User Property。

2. 同时我们也提供了plugin的demo供用户参考，路径如下
```
nanomq/plugin/plugin_user_property.c
```

3. 用户需要指定编译器的include路径对插件进行编译，参考如下
```
gcc -I../ -fPIC -shared plugin_user_property.c -o plugin_user_property.so
```

## **配置示例**
下面是plugin插件在配置文件中的样例：
```hcl
plugin {
	libs = [{
		path = "/path/to/plugin_user_property.so"
	}]
}
```

## **配置项**
plugin
- `libs.path`：用户插件所在路径
