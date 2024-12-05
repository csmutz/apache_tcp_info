# mod_tcpfingerprint
Create a module that retrieves connection tcp fingerprinting data from kernel, makes available for logging and environment variables for scripts.

In the future, integrate database for known fingerprints whenever a solid database becomes available.

## Usage

This module should be ready for use, at least testing. To use this module, compile and install.

```
sudo apxs2 -iac mod_tcpfingerprint.c
```

Then either add to LogFormat defintion or turn TCPFingerprintEnvVars on and use in cgi scripts.

```
LogFormat ... %{FINGERPRINT_TCP_RTT}g %{FINGERPRINT_IP_TTL}g %{FINGERPRINT_TCP_WSIZE}g %{FINGERPRINT_TCP_WSCALE}g %{FINGERPRINT_TCP_OPTIONS}g %{FINGERPRINT_TCP_MSS}g"
```

## Attributes

List of attributes we will collect.

TCP_INFO
 - TCP_RTT - FINGERPRINT_TCP_RTT

SAVED_SYN
 - IP TTL - FINGERPRINT_IP_TTL
 - IP DF - FINGERPRINT_IP_DF
 - IP ECN - FINGERPRINT_IP_ECN
 - Window Size - FINGERPRINT_TCP_WSIZE
 - Option IDs - FINGERPRINT_TCP_OPTIONS
 - Option values
   - MSS - FINGERPRINT_TCP_MSS
   - Window Scale - FINGERPRINT_TCP_WSCALE
 - TCP ECN - FINGERPRINT_TCP_ECN

Timestamp
 - connection accept time - FINGERPRINT_ACCEPT_TIME

Full Structures
 - SYN Packet - FINGERPRINT_SAVED_SYN
 - TCP_INFO - FINGERPRINT_ACCEPT_TIME

### Tasks

 - ~~basic module skeleton~~
 - ~~Collect TCP_INFO~~
 - ~~Expose TCP_INFO Data~~
 - ~~retrival functions for variables (work for both logging callback and adding vars to env)~~
   - ~~Callback function for logging~~ Done, uses %{VARNAME}g for CustomLog definition
 - ~~Collect TCP_SAVED_SYN~~
   - ~~Patch for apache to set TCP_SAVE_SYN on listen socket(s)~~ -- Not necessary, set in module callback
 - ~~Expose TCP_SAVED_SYN~~
   - ~~Parse syn_packet~~
     - IPv4 and TCP implemented, IPv6 with extensions needs tested
 - ~~Fix debug/error message (many current errors should be deleted or changed to debug)~~
 - ~~Implement TCP connection timestamp to compare to TLS Hello timestamp for hello_delay calculation~~
 - ~~Look for additional features in TCP_INFO for inclusion~~
 - Configurations
   - Per Listener
     - **(NOT VALUABLE)** Configure which listeners should have SAVE_SYN set (causes kernel to collect SYN for all connections, this is fairly efficient and is disabled in SYN floods by SYN cookie protections, etc--cost is pretty low)
       - This would be similar to ListenBackLog--but ListenBackLog and their ilk appear to apply globally--not per Listen (this would also require mods to core httpd)
       - Maybe list of IPs/ports which should have SAVE_SYN applied?
       - It's hard to understand use case for this
   - Per Connection
     - **(NOT FEASIBLE)** Determine if SAVED_SYN and TCP_INFO should be retrieved for the current connection. (this is moderately expensive, copies ~300 bytes of data to connection)
       - Currently this is prior to reception of data on port, prior to knowledge of SNI or HTTP virtualhost, so most selectors aren't available.
         - If this was delayed until later, could select upon virtualhost
   - Per Request
     - ~~Enable export of environment variables--like STDENVVARS.~~   Done: TCPFingerprintEnvVars
     - ~~Enable full SYN printing (hex encoded), this is typically about 60 bytes/120 hex chars~~ Done: TCPFingerprintEnvSavedSYN
     - ~~Enable full TCP_INFO printing (hex encoded)~~ Done: TCPFingerprintEnvTCPInfo
      - **(PUNT FOR NOW)** TCP_INFO could be retrieved later (possibly per request) to collect other data like max observed packet size and RTT based on more data
         - Getting SAVED_SYN and TCP_INFO currently requires putting socket in blocking mode--is this safe to do later?
           - Is this safe to do at start of connection?
      - switch to netlink instead of getsockopt?
        - see INET_DIAG_INFO message type
      - If this was implemented, desired additional TCP_INFO attributes:
        - tcpi_rcv_mss (max observed payload size)
 - Database
   - Database of TCP fingerprints, especially SOHO router/IoT devices (right now an effective database does not exist)
   - Configuration for one database to create a label per client (env variable and logging attribute)
   - Possible implementations
     - Whatever database becomes available
     - p0f -- database is out of date and code hasn't been updated but it would be easy to implement
     - yara
 
## Design

mod_tcpfingerprint will collect information on every new connection at the start of the connection.

We will use two different mechanisms to get data from kernel
 - TCP_INFO to get RTT and things like path_mtu
 - syn packet using TCP_SAVED_SYN
   - This will require enabling TCP_SAVE_SYN on listen socket

The module will add env vars for every request

The module will register a new function for custom logging.

### Notes

#### Compile

Compile:
```
apxs2 -c mod_tcpfingerprint.c
```

### References:

https://www.kernel.org/doc/html/next/userspace-api/netlink/intro.html

https://blog.mygraphql.com/en/notes/low-tec/network/tcp-inspect/#rationale---how-ss-work

https://github.com/apache/trafficserver/blob/master/plugins/tcpinfo/tcpinfo.cc

https://www.tirasa.net/en/blog/developing-custom-apache2-module

