# Code Guidance

code structure, state machine, important data structure, nng interface.

## Code Structure

This is a brief introduction for NanoMQ project, note that code structure presented here could be invalidated due to updates and modifications. 

```shell
├── deploy
├── docs
│   ├── en_US            
│   └── zh_CN            
├── etc                    // example configuration files, certs and idl files
├── extern                 // submodules
├── nanomq
│   ├── acl_handler.c    
│   ├── apps
│   │   └── broker.c       // core src code of broker including the state machine
│   ├── aws_bridge.c     
│   ├── bridge.c         
│   ├── cmd_proc.c         // ipc server for receving commands like reload
│   ├── conf_api.c         // APIs to handle configuration
│   ├── db_cli.c           // handle foundation db, only when SUPP_RULE_ENGINE is on
│   ├── mqtt_api.c         // APIs to handle commom mqtt msg and logs
│   ├── nanomq.c           // user interface of NanoMQ
│   ├── nanomq_rule.c      // handle sqlite and mysql db, only when SUPP_RULE_ENGINE is on
│   ├── process.c          // APIs for process
│   ├── pub_handler.c    
│   ├── rest_api.c       
│   ├── sub_handler.c    
│   ├── tests            
│   ├── unsub_handler.c  
│   ├── webhook_inproc.c   // webhook server
│   ├── webhook_post.c   
│   └── web_server.c       // web server to handle web request
├── nanomq_cli             // mqtt client 
└── nng                   
    ├── demo              
    ├── docs             
    ├── etc              
    ├── extern             // submodules of nanonng
    ├── src              
    │   ├── compat       
    │   ├── core           // core src code of nng
    │   ├── mqtt           // nng extension for mqtt
    │   ├── nng.c          // public APIs for applications to use directly
    │   ├── nng_legacy.c   // legacy APIs provided for compatibility for now
    │   ├── platform     
    │   ├── sp             // sp protocal
    │   ├── supplemental   // supplemental APIs for developers to use
    │   ├── testing        // test framework
    │   └── tools        
    └── tests            
```

## State Machine

## Data Structure

## NNG Interface