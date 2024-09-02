# apache_tcp_info
adding module that retrieves connection tcp_info from kernel

## Design
Biggest issue is how to retrieve TCP_INFO in portable way. TCP_INFO differs between platforms and linux has numerous additions across kernel versions. Use getsockopt or netlink on linux? 

### References:
https://blog.mygraphql.com/en/notes/low-tec/network/tcp-inspect/#rationale---how-ss-work
https://github.com/apache/trafficserver/blob/master/plugins/tcpinfo/tcpinfo.cc

