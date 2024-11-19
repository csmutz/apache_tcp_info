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
 - Configurations
   - Per Listener
     - Configure which listeners should have SAVE_SYN set (causes kernel to collect SYN for all connections, this is fairly efficient and is disabled in SYN floods by SYN cookie protections, etc--cost is pretty low)
       - This would be similar to ListenBackLog--but ListenBackLog and their ilk appear to apply globally--not per Listen (this would also require mods to core httpd)
       - Maybe list of IPs/ports which should have SAVE_SYN applied?
   - Per Connection
     - Determine if SAVED_SYN and TCP_INFO should be retrieved for the current connection. (this is moderately expensive, copies ~300 bytes of data to connection)
       - Currently this is prior to reception of data on port, prior to knowledge of SNI or HTTP virtualhost, so most selectors aren't available.
         - If this was delayed until later, could select upon virtualhost
   - Per Request
     - ~~Enable export of environment variables--like STDENVVARS.~~   Done: TCPFingerprintEnvVars
     - ~~Enable full SYN printing (hex encoded), this is typically about 60 bytes/120 hex chars~~ Done: TCPFingerprintEnvSavedSYN
     - ~~Enable full TCP_INFO printing (hex encoded)~~ Done: TCPFingerprintEnvTCPInfo
      - TCP_INFO could be retrieved later (possibly per request) to collect other data like max observed packet size and RTT based on more data
         - Getting SAVED_SYN and TCP_INFO currently requires putting socket in blocking mode--is this safe to do later?
           - Is this safe to do at start of connection?
           - switch to netlink instead of getsockopt?
 - Fix debug/error message (many current errors should be deleted or changed to debug)
 - Implement TCP connection timestamp to compare to TLS Hello timestamp for hello_delay calculation

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

Callbacks used:
 - ap_hook_pre_config: to register custom logging function
 - ap_hook_post_config: set SAVE_SYN on listen sockets
 - ap_hook_process_connection: Collect info for connection
 - ap_hook_fixups: for making env variables available
 

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

