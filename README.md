# mod_tcpfingerprint
Create a module that retrieves connection tcp fingerprinting from kernel, makes available for logging and environment variables for scripts.

In the future, protentially have database for known fingerprints, especially devices like IoT devcies/SOHO routers/etc commonly used for proxies in residential proxies.

## Attributes

List of attributes we will collect.

TCP_INFO
 - TCP_RTT

SAVED_SYN
 - IP TTL
 - Window Size
 - Extension IDs
 - Extension values
   - MSS
   - Window Scale
 - DF?
 - ECN?

Timestamp
 - For Hello Delay

### Tasks

 - ~~basic module skeleton~~
 - ~~Collect TCP_INFO~~
 - ~~Expose TCP_INFO Data~~
 - retrival functions for variables (work for both logging callback and adding vars to env)
   - Callback function for logging
 - Collect SAVED_SYN
   - Patch for apache to set SAVE_SYN on listen socket(s)
 - Expose SAVED_SYN -- test standalone first
 - Configurations (like STDENVVARS)
 - 

## Design

mod_tcpfingerprint will collect information on every new connection at the start of the connection.

We will use two different mechanisms to get data from kernel
 - TCP_INFO to get RTT and things like path_mtu
 - syn packet using TCP_SAVED_SYN
   - This will require enabling TCP_SAVE_SYN on listen socket

The module will add env vars for every request

The module will register a new function for custom logging.

### Notes

#### TCP attributes

See ap_register_log_handler to add new custom log handler

See apr_os_sock_get and ap_get_conn_socket to get current socket 

https://stackoverflow.com/questions/53702714/get-the-socket-from-an-apache-module

TCP_SAVE_SYN info: https://lwn.net/Articles/645128/

TCP_INFO: https://linuxgazette.net/136/pfeiffer.html

#### Module Development

###### Module Basics ######
See modules/examples/mod_example_hooks.c for best documentation on callbacks. https://github.com/apache/httpd/blob/trunk/modules/examples/mod_example_hooks.c

https://httpd.apache.org/docs/2.4/developer/modules.html

Is there a better resource?

Callbacks to use:
 - ap_hook_process_connection: Collect info for connection
 - ap_hook_fixups for making env variables available
 - app_hook_pre_config? to register custom logging function

Example that sets environment variables: https://www.tirasa.net/en/blog/developing-custom-apache2-module

getsockopt fails on non-blocking socket, see apr_socket_opt_set

##### Module data storage #####

See myConnConfigSet() from mod_ssl, ap_set_module_config function

See modules/metadata/mod_remoteip.c as example of storage

#### Changes to Apache

To get access to saved SYN, core apache will need to be modified to set SOCKOPT on listen socket.
 - See server/listen.c
 - Use ListenBackLog as example of configuration directive
 - Use defined(SO_REUSEPORT) as example to ensure TCP_SAVE_SYN functionality
 - Is there any way to get acces to the listen socket (the accept socket is easy) from in the module? Even if we could, isn't global setting best anyway? 

#### Compile/Install

Compile:
```
apxs2 -c mod_tcpfingerprint.c
```

Install and enable:
```
sudo apxs2 -iac mod_tcpfingerprint.c
```

### References:

https://blog.mygraphql.com/en/notes/low-tec/network/tcp-inspect/#rationale---how-ss-work

https://github.com/apache/trafficserver/blob/master/plugins/tcpinfo/tcpinfo.cc

