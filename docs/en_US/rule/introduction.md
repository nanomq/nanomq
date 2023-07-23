# Rule Engine

In NanoMQ, you can leverage the powerful rule engine to implement dynamic responses to various events within the system. NanoMQ rule engine is an indispensable tool for managing complex message routing scenarios, triggering automated actions, and integrating other systems with your MQTT setup.

This chapter is divided into two main parts: configuration via [WebHook](./web-hook-0.19.md) or the [configuration file](./config-file.md).

## Configure with WebHook

WebHook in NanoMQ provides a means for real-time communication with other applications through HTTP requests triggered by certain events. This section introduces how to enable the WebHook feature and describes how to define the rules that govern when and how these WebHooks are triggered. 

## Configure with Configuration File

The section covers how to configure the rule engine through the configuration file `nanomq.conf`. It covers the available rule engine options, including

- Repub rule
- Data persistence to SQLite
- Data persistence to MySQL