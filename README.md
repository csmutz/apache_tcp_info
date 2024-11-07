# mod_tcpfingerprint
Create a module that retrieves connection tcp fingerprinting from kernel, makes available for logging and environment variables for scripts.

In the future, protentially have database for known fingerprints, especially devices like IoT devcies/SOHO routers/etc commonly used for proxies in residential proxies.

## Attributes

List of attributes we will collect.

TCP_INFO
 - TCP_RTT

SAVED_SYN
 - IP TTL
 - IP DF
 - IP ECN
 - Window Size
 - Option IDs
 - Option values
   - MSS
   - Window Scale
 - TCP ECN 

Timestamp
 - For Hello Delay

Full SYN Packet ?

### Tasks

 - ~~basic module skeleton~~
 - ~~Collect TCP_INFO~~
 - ~~Expose TCP_INFO Data~~
 - ~~retrival functions for variables (work for both logging callback and adding vars to env)~~
   - Callback function for logging-- Done, need to test
 - ~~Collect TCP_SAVED_SYN~~
   - ~~Patch for apache to set TCP_SAVE_SYN on listen socket(s)~~ -- Not necessary, set in module callback
 - ~~Expose TCP_SAVED_SYN~~
   - ~~Parse syn_packet~~
     - IPv4 and TCP implemented, IPv6 with extensions needs tested
 - Configurations (like STDENVVARS) -- are there any necessary?
   - Possibly option to refresh TCP_INFO to get other attributes
   - Enable full SYN printing (hex encoded), this is typically about 60 bytes/120 hex chars
 - Fix debug/error message (many current errors should be deleted or changed to debug)
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

TCP_SAVE_SYN info: https://lwn.net/Articles/645128/

TCP_INFO: https://linuxgazette.net/136/pfeiffer.html

#### Module Development

###### Module Basics ######
See modules/examples/mod_example_hooks.c for best documentation on callbacks. https://github.com/apache/httpd/blob/trunk/modules/examples/mod_example_hooks.c

https://httpd.apache.org/docs/2.4/developer/modules.html

Callbacks to use:
 - ap_hook_process_connection: Collect info for connection
 - ap_hook_fixups: for making env variables available
 - ap_hook_post_config: to register custom logging function and set SAVE_SYN on listen sockets

getsockopt fails on non-blocking socket, see apr_socket_opt_set

##### Module data storage #####

See modules/metadata/mod_remoteip.c as example of storage

#### Changes to Apache

setting SAVE_SYN in ap_hook_post_config worked -- no patch to apache should be necessary.

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

https://www.tirasa.net/en/blog/developing-custom-apache2-module

