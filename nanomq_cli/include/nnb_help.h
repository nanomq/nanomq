#ifndef NNB_HELP_H
#define NNB_HELP_H

static char pub_info[] =
    "nanomq_cli bench pub [--help <help>] [-h [<host>]] [-p [<port>]]\n\
                       [-V [<version>]] [-c [<count>]]             \n\
                       [-n [<startnumber>]] [-i [<interval>]]      \n\
                       [-I [<interval_of_msg>]] [-u <username>]    \n\
                       [-P <password>] [-t <topic>] [-s [<size>]]  \n\
                       [-q [<qos>]] [-r [<retain>]]                \n\
                       [-k [<keepalive>]] [-C [<clean>]]           \n\
                       [-L [<limit>]] [-S [<ssl>]]                 \n\
                       [--certfile <certfile>]                     \n\
                       [--keyfile <keyfile>] [--ws [<ws>]]         \n\
                       [--ifaddr <ifaddr>] [--prefix <prefix>]     \n\
                                                                   \n\
  --help                 help information                          \n\
  -h, --host             mqtt server hostname or IP address        \n\
                         [default: localhost]                      \n\
  -p, --port             mqtt server port number [default: 1883]   \n\
  -V, --version          mqtt protocol version: 3 | 4 | 5 [default:\n\
                         4]                                        \n\
  -c, --count            max count of clients [default: 200]       \n\
  -n, --startnumber      start number [default: 0]                 \n\
  -i, --interval         interval of connecting to the broker      \n\
                         [default: 10]                             \n\
  -I, --interval_of_msg  interval of publishing message(ms)        \n\
                         [default: 1000]                           \n\
  -u, --username         username for connecting to server         \n\
  -P, --password         password for connecting to server         \n\
  -t, --topic            topic subscribe, support %u, %c, %i       \n\
                         variables                                 \n\
  -s, --size             payload size [default: 256]               \n\
  -q, --qos              subscribe qos [default: 0]                \n\
  -r, --retain           retain message [default: false]           \n\
  -k, --keepalive        keep alive in seconds [default: 300]      \n\
  -C, --clean            clean start [default: true]               \n\
  -L, --limit            The max message count to publish, 0 means \n\
                         unlimited [default: 0]                    \n\
  -S, --ssl              ssl socoket for connecting to server      \n\
                         [default: false]                          \n\
  --cafile               ca certificate for authentication, if     \n\
                         required by server                        \n\
  --certfile             client certificate for authentication, if \n\
                         required by server                        \n\
  --keyfile              client private key for authentication, if \n\
                         required by server                        \n\
  --keypass              client private key's password for         \n\
                         authentication                            \n\
  --ws                   websocket transport [default: false]      \n\
  --ifaddr               local ipaddress or interface address      \n\
  --prefix               client id prefix                          \n\
";

static char sub_info[] =
    "nanomq_cli bench sub [--help <help>] [-h [<host>]] [-p [<port>]] \n\
                       [-V [<version>]] [-c [<count>]]              \n\
                       [-n [<startnumber>]] [-i [<interval>]]       \n\
                       [-t <topic>] [-q [<qos>]] [-u <username>]    \n\
                       [-P <password>] [-k [<keepalive>]]           \n\
                       [-C [<clean>]] [-S [<ssl>]]                  \n\
                       [--certfile <certfile>]                      \n\
                       [--keyfile <keyfile>] [--ws [<ws>]]          \n\
                       [--ifaddr <ifaddr>] [--prefix <prefix>]      \n\
                                                                    \n\
  --help             help information                               \n\
  -h, --host         mqtt server hostname or IP address [default:   \n\
                     localhost]                                     \n\
  -p, --port         mqtt server port number [default: 1883]        \n\
  -V, --version      mqtt protocol version: 3 | 4 | 5 [default: 4]  \n\
  -c, --count        max count of clients [default: 200]            \n\
  -n, --startnumber  start number [default: 0]                      \n\
  -i, --interval     interval of connecting to the broker [default: \n\
                     10]                                            \n\
  -t, --topic        topic subscribe, support %u, %c, %i variables  \n\
  -q, --qos          subscribe qos [default: 0]                     \n\
  -u, --username     username for connecting to server              \n\
  -P, --password     password for connecting to server              \n\
  -k, --keepalive    keep alive in seconds [default: 300]           \n\
  -C, --clean        clean start [default: true]                    \n\
  -S, --ssl          ssl socoket for connecting to server           \n\
                     [default: false]                               \n\
  --cafile           ca certificate for authentication, if          \n\
                     required by server                             \n\
  --certfile         client certificate for authentication, if      \n\
                     required by server                             \n\
  --keyfile          client private key for authentication, if      \n\
                     required by server                             \n\
  --keypass          client private key's password for              \n\
                     authentication                                 \n\
  --ws               websocket transport [default: false]           \n\
  --ifaddr           local ipaddress or interface address           \n\
  --prefix           client id prefix			            \n\
";

static char conn_info[] =
    "nanomq_cli bench conn [--help <help>] [-h [<host>]] [-p [<port>]]\n\
                        [-V [<version>]] [-c [<count>]]             \n\
                        [-n [<startnumber>]] [-i [<interval>]]      \n\
                        [-u <username>] [-P <password>]             \n\
                        [-k [<keepalive>]] [-C [<clean>]]           \n\
                        [-S [<ssl>]] [--certfile <certfile>]        \n\
                        [--keyfile <keyfile>] [--ifaddr <ifaddr>]   \n\
                        [--prefix <prefix>]                         \n\
                                                                    \n\
  --help             help information                               \n\
  -h, --host         mqtt server hostname or IP address [default:   \n\
                     localhost]                                     \n\
  -p, --port         mqtt server port number [default: 1883]        \n\
  -V, --version      mqtt protocol version: 3 | 4 | 5 [default: 4]  \n\
  -c, --count        max count of clients [default: 200]            \n\
  -n, --startnumber  start number [default: 0]                      \n\
  -i, --interval     interval of connecting to the broker [default: \n\
                     10]                                            \n\
  -u, --username     username for connecting to server              \n\
  -P, --password     password for connecting to server              \n\
  -k, --keepalive    keep alive in seconds [default: 300]           \n\
  -C, --clean        clean session [default: true]                  \n\
  -S, --ssl          ssl socoket for connecting to server           \n\
                     [default: false]                               \n\
  --cafile           ca certificate for authentication, if          \n\
                     required by server                             \n\
  --certfile         client certificate for authentication, if      \n\
                     required by server                             \n\
  --keyfile          client private key for authentication, if      \n\
                     required by server                             \n\
  --keypass          client private key's password for              \n\
                     authentication                                 \n\
  --ifaddr           local ipaddress or interface address           \n\
  --prefix           client id prefix			            \n\
";

#endif
