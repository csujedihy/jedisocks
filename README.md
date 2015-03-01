##Jedisocks
####Overview
[![Build Status](https://travis-ci.org/csujedihy/jedisocks.svg?branch=master)](https://travis-ci.org/csujedihy/jedisocks)

Jedisocks is a tunnel proxy with TCP connections multiplexing on a single TCP connection. This project is still under development.



####How to build:
NOTE: Jedisocks is based on libuv. So, before compile this project, make sure [libuv](https://github.com/libuv/libuv) was successfully installed.
 
	$ git clone [git address of this project]
	$ cd build
	$ cmake ..
	$ make

####Usage
```
js-[local|server]
-c <config_file> Path of configuration file that is written in JSON
-r <server_host> Ip address of your remote server
-l <local_host> Ip address of your local server
-p <local_port> Port number of your local server
-P <remote_port> Port number of your remote server
-V Enable verbose log
```
####Example of configuration file
```
{
    "local_address":"127.0.0.1",
    "server":"127.0.0.1",
    "server_port":7001,
    "local_port":7000
}
```
####Todo:
1. ~~Read JSON file to load configuration.~~ (Accomplished)
2. Add encryption to bypass GFW.
3. IPv6 support.
4. Add flexible plugin system to extend functionality.
5. Add re-connect mechanism to long multiplexing connection.

####References
This software is partly based on projects below.

1. [Shadowsocks-libev](https://github.com/shadowsocks/shadowsocks-libev).
2. [js0n](https://github.com/quartzjer/js0n).

####Contact:
csujedi at icloud dot com