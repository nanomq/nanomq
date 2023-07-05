# 规则引擎

NanoMQ 内置简单的规则引擎帮助用户灵活处理边缘数据，实现类似复杂的消息路由场景、触发自动化操作，以及将其他系统与你的 MQTT 环境进行集成等场景，比如与 eKuiper 集成在边缘进行流式数据分析

本章主要介绍如何通过 [WebHook](./web-hook-0.19.md) 或 [配置文件](./config-rule-engine.md) 进行配置。

## 通过 WebHook 配置

NanoMQ 提供了可拓展的事件驱动型 WebHook 接口，本节将介绍如何启用 WebHook 功能，如何通过规则定义 WebHook 的触发时间和方式。

## 通过配置文件配置

本节将介绍如何通过 `nanomq.conf` 配置文件来配置规则引擎，并将覆盖以下主题：

- 重新发布规则
- 数据持久化到 SQLite
- 数据持久化到 MySQL