# Plugin

NanoMQ provides the function of Plugin, and users can implement their own plugins
based on the interface provided by NanoMQ plugin framework.

During the startup phase of NanoMQ broker, NanoMQ will load the plugins configured
by the user in the config file and invoke the user-defined plugins at the relevant
HOOK points.

1. Currently NanoMQ provides the following hook points
- HOOK_USER_PROPERTY: Users can add custom User properties during the MQTT 5 message sending phase.

2. At the same time, we also provide a demo of the plugin for user reference, the path is as follows:
```
nanomq/plugin/plugin_user_property.c
```

3. You need to specify the include path of the compiler to compile the plugin, as shown here:
```
gcc -I../ -fPIC -shared plugin_user_property.c -o plugin_user_property.so
```

## **Example Configuration**
The following is an example of the plugin configuration file:
```hcl
plugin {
	libs = [{
		path = "/path/to/plugin_user_property.so"
	}]
}
```

## **Configuration items**
plugin
- `libs.path`：Path to the user plugin.
