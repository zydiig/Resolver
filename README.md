Resolver
==============
A simple DNS resolver that goes through a SOCKS 5 proxy.

resolve.py
---------
The main program.

1. Modify and save the following snippet as `[CONFIG_FILE_NAME]`:

~~~json
{
  "local_addr":"",
  "proxy_addr":"",
  "remote_addr":"",
  "direct_addr":""
}
~~~

2. Write down the domain suffixes you want to query without the proxy and save as `[RULESET_FILE_NAME]`.

3. Run `python3 resolve.py -c [CONFIG_FILE_NAME] -x [RULESET_FILE_NAME]`.

Command-line flags:

~~~
--config,-c [path to config file]
--rules,-x [path to ruleset file]
--laddr,-l [local listening address]
--paddr,-p [proxy address]
--raddr,-r [server to be queries through proxy]
--daddr,-d [server to be directly queried]
--log-file,-o [file to write log to]
~~~

protocol.py
---------
This file includes an easy-to-use Buffer class, and provides a basic DNS parser with related classes. 
EDNS0-specific RRs are kept as is. 
DNSSEC is not tested.

TODO
---------
* Implement repacking of DNS message
  * Implement repacking with *compression* (kinda pointless nowadays)
* Parse EDNS0 info
* Reuse TCP connection with a relay on a remote server
* Actually truncate UDP response
* Implement DNS caching
* Automatically choose between proxy and direct
* More powerful rule matching
 
License
---------
[GPLv3](https://en.wikipedia.org/wiki/GNU_General_Public_License)