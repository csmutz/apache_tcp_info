# apache_tcp_info
adding module that retrieves connection tcp_info from kernel, makes available for logging and environment variables for scripts

## Design
Biggest issue is how to retrieve TCP_INFO in portable way. TCP_INFO differs between platforms and linux has numerous additions across kernel versions. Use getsockopt or netlink on linux? 

Probably getsocktopt because it's more portable and synchronous.

Do we collect TCP_INFO at start or per-request?

### Notes

See ap_register_log_handler to add new custom log handler

See ap_get_conn_socket to get current socket 

https://stackoverflow.com/questions/53702714/get-the-socket-from-an-apache-module




### References:
https://blog.mygraphql.com/en/notes/low-tec/network/tcp-inspect/#rationale---how-ss-work
https://github.com/apache/trafficserver/blob/master/plugins/tcpinfo/tcpinfo.cc

