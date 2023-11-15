# Toolkit

This chapter introduces how to work with the command line interface of NanoMQ, how to leverage the Bench tool for MQTT performance testing and how to transfer files with nftp tool.

## Command Line Interface Guide

This guide introduces how to use the command line interface for broker, client, and rule-related operations:

- **Broker**: The broker section provides details about the parameters that can be used when starting the NanoMQ broker.
- **Client**: This part discusses how to interact with the NanoMQ broker as a client. The operations are split into three main categories: Publish, Subscribe, and Conn.
- **Rule**: This section is dedicated to creating and managing rules. 

## Bench

`Bench` is a powerful MQTT protocol performance testing tool designed using NanoSDK. This tool allows users to conduct comprehensive performance tests such as publishing and subscribing to messages, creating numerous connections, and more, helping users better understand their system's capabilities, limitations, and bottlenecks.

## NFTP

`nftp` is a light-weight, no run time file transfer tool based on MQTT. `nftp` support P to P/ N to 1/ 1 to N，asynchronous send / recv，discontinued transmission.
