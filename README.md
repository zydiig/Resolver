Resolver
==============
A simple DNS resolver that goes through a SOCKS proxy.

resolve.py
---------
The main program.

Modify and save the following snippet as `[CONFIG_FILE_NAME]`:

~~~
{
  "local_addr":"",
  "proxy_addr":"",
  "remote_addr":"",
  "direct_addr":""
}
~~~

Write down the domain suffixes you want to query without the proxy and save as `[RULESET_FILENAME]`.

Run `python3 resolve.py -c [CONFIG_FILE_NAME] -x [RULESET_FILENAME]` and that's all.

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

License
---------
[GPLv3](https://en.wikipedia.org/wiki/GNU_General_Public_License)