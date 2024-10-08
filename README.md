# mod_tcpfingerprint
Create a module that retrieves connection tcp fingerprinting from kernel, makes available for logging and environment variables for scripts.

In the future, protentially have database for known fingerprints, especially devices like IoT devcies/SOHO routers/etc commonly used for proxies in residential proxies.

## Attributes

List of attributes we will collect.

## Design

mod_tcpfingerprint will collect information on every new connection at the start of the connection.

We will use two different mechanisms to get data from kernel
 - TCP_INFO to get RTT and things like path_mtu
 - syn packet using TCP_SAVED_SYN
   - This will require enabling TCP_SAVE_SYN on listen socket

The module will add env vars for every request

The module will register a new function for custom logging.

### Notes

See ap_register_log_handler to add new custom log handler

See ap_get_conn_socket to get current socket 

https://stackoverflow.com/questions/53702714/get-the-socket-from-an-apache-module

TCP_SAVE_SYN info: https://lwn.net/Articles/645128/

TCP_INFO: https://linuxgazette.net/136/pfeiffer.html

### References:

https://blog.mygraphql.com/en/notes/low-tec/network/tcp-inspect/#rationale---how-ss-work

https://github.com/apache/trafficserver/blob/master/plugins/tcpinfo/tcpinfo.cc

