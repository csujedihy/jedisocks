####Overview
Jedisocks is a tunnel proxy with TCP connections multiplexing on a single TCP connection. This project is still under development.

####Note
Jedisocks is based on libuv. So, before compile this project, make sure [libuv](https://github.com/libuv/libuv) was successfully installed.

####Installation: 
	$ git clone [git address of this project]
	$ cd build
	$ cmake ..
	$ make

####Todo:
1. Read JSON file to load configuration.
2. Add encryption to bypass GFW.
3. Complete exception handling.
4. IPv6 support.
5. Add flexible plugin system to extend functionality.

####Contact:
csujedi at icloud dot com