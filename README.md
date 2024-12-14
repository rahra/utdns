# utdns

UTdns is a nifty tool which proxies all UDP-based DNS requests through TCP DNS.
This is usefull if you have to tunnel DNS through TCP-only tunnels. This respectively
was the requirement for the development of this tool. 

Have a look at [this article on cypherpunk.at](doc/cypherpunk.at_20130411.md) for some details.

To build utdns either download the latest package from
[releases](https://github.com/rahra/utdns/releases) and run `./configure`,
`make`, and `make install` as usual or directly clone this directory from Github
and run `./bootstrap` to initialize the autotools. Then run `./configure`,
`make`, and `make install`. In the latter case you need to have installed the
*GNU Autotools* packages `autoconf` and `automake`.

