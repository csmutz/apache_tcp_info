# mod_tcpfingerprint

A module that retrieves connection tcp fingerprinting data from kernel (SAVED_SYN and TCP_INFO) and makes it available for logging and environment variables for scripts.

This module will instruct the kernel to SAVE_SYN on all apache Listen sockets (all incoming connections).

## Progress

This module should be ready for testing, broader use.

## Installation/Usage

To use this module, compile and install.

```
sudo apxs2 -iac mod_tcpfingerprint.c
```

Then either add to LogFormat defintion or turn TCPFingerprintEnvVars on and use in cgi scripts.

```
LogFormat ... %{FINGERPRINT_TCP_RTT}g %{FINGERPRINT_IP_TTL}g %{FINGERPRINT_TCP_WSIZE}g %{FINGERPRINT_TCP_WSCALE}g %{FINGERPRINT_TCP_OPTIONS}g %{FINGERPRINT_TCP_MSS}g"
```

## Configuration Directives

This module registers "g" for LogFormat directives. Ex. ```%{FINGERPRINT_TCP_OPTIONS}g```

Server Directives (connection level):
  - TCPFingerprintGetSavedSYN: Enable collection of SAVED_SYN from kernel using getsockopt, default on
  - TCPFingerprintGetTCPInfo: Enable collection of TCP_INFO from kernel using getsockopt, default on

Directory Directives (request level):

  - TCPFingerprintEnvVars: Enable creation of CGI environment variables, default off (similar to StdEnvVars of for modssl)
  - TCPFingerprintEnvTCPInfo: Enable dump of raw TCP_INFO in environment variables, default off
  - TCPFingerprintEnvSavedSYN: Enable dump of raw SAVED_SYN in environment variables, default off

## Attributes

List of variables exposed

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

Full Structures (hex encoded)
 - SAVED_SYN - FINGERPRINT_SAVED_SYN
 - TCP_INFO - FINGERPRINT_TCP_INFO

Timestamp
 - connection accept time - ~~FINGERPRINT_ACCEPT_TIME~~
   - Not currently implemented, unable to get actual connection establishment time using existing hooks

### Potential Future Work

Implement TCP handshake RTT calculation. RFC on methods for getting handshake RTT (delta between SYN and first ACK) or accurate connection establishment timestamp from module.

Integrate database for known fingerprints whenever a solid database becomes available.

Possibly collect TCP_INFO at request time (instead of at start of connection) for meaningful collection of other TCP_INFO attributes. This might be better accomplished in a separate module that uses netlink to get TCP_INFO.

Configuration directive to configure SAVE_SYN on a per Listen basis. RFC on what this should look like.

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
 - Get TCP Hanshake RTT (or get timestamp of accept?)
   - ~~Try min_rtt from extended linux attributes~~ -- doesn't appear to work, is same as rtt
   - ~~Try tcpi_rcv_rtt~~ -- what does this mean, does it require timestamps by client. Doesn't appear to be set at start of connection regardless.
   - ~~Try delta between last_data_recv and last_ack_recv~~--this doesn't work because most data packets also include ACK so we cant get time of ACK at end of TCP handshake
   - ~~Try implementing collection of timestamp at ap_hook_create_connection hook~~--see if timestamp is actually end of TCP handshake
     - This is called if done before core
       - Check timestamp, make sure this actually reflects handshake RTT (vs. payload)--it doesn't, this doesn't work--it's comparable to the pre_connection hook--need to find an earlier hook?
   - Potentially override accept_function in ap_listen_rec?
 - Configurations
   - Per Listener
     - **(Too complicated, not sure what's really wanted)** Configure which listeners should have SAVE_SYN set
       - Current/default behavior is to cause kernel to collect SAVED_SYN for all connections
         - This kernel mechanism is fairly efficient and is disabled in SYN floods by SYN cookie protections, etc--so cost is pretty low
       - Directive would be similar to Listen or ListenBackLog--but ListenBackLog are available in global scope only
         - There is no per Listener configuration tracking like there is for server and directory configuration, so this is pretty difficult
       - Maybe list of IPs/ports which should have SAVE_SYN applied (or not applied) like Listen, something like TCPFingerprintSaveSYNExclude with same params as Listen.
         - This would be possible, but is a lot of parsing comparison code for relatively little benefit and would require testing all sorts of edge cases
       - Is there a way to get listen record from server config? Maybe set that way instead of global config?
       
   - Per Connection
     - ~~Determine if SAVED_SYN and TCP_INFO should be retrieved for the current connection. (this is moderately expensive, copies ~300 bytes of data to connection)~~
       - ~~Currently this is prior to reception of data on port, prior to knowledge of SNI or HTTP virtualhost, so most selectors aren't available.~~
         - ~~If this was delayed until later, could select upon virtualhost~~
     - Done: TCPFingerprintGetSavedSYN, TCPFingerprintGetTCPInfo which will default to on and are server only in scope
   - Per Request
     - ~~Enable export of environment variables--like STDENVVARS.~~   Done: TCPFingerprintEnvVars
     - ~~Enable full SYN printing (hex encoded), this is typically about 60 bytes/120 hex chars~~ Done: TCPFingerprintEnvSavedSYN
     - ~~Enable full TCP_INFO printing (hex encoded)~~ Done: TCPFingerprintEnvTCPInfo
       - Are these, should these be server/vhost compatable also?
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

### References:

#### netlink

https://www.kernel.org/doc/html/next/userspace-api/netlink/intro.html

https://blog.mygraphql.com/en/notes/low-tec/network/tcp-inspect/#rationale---how-ss-work

#### Relevant Apache module development example

https://www.tirasa.net/en/blog/developing-custom-apache2-module

