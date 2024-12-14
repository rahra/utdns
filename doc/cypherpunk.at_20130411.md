# DNS/UDP to TCP Translator/Converter

Posted on April 11, 2013 by [rahra](mailto:bf@abenteuerland.at) on cypherpunk.at.

Although there are some discussions found on the web on how to force DNS to use TCP instead of UDP, there seems to be no real solution. And in most cases there is actually no need for such a conversion.

There are also many people asking if BIND offers such a special mode and I found [this great posting](https://lists.isc.org/pipermail/bind-users/2008-August/072114.html):

> >
> > Are there any configuration changes that can be made to BIND to force it to
> > use TCP exclusively and never use UDP?
> > Possible?
> no.
> –
> PaulVixie

Although some people claim that using TCP/DNS instead of UDP/DNS would even violate the RFCs I could not find any references. RFC1035 Section 4.2 says that UDP is preferred but this does not imply that it MUST be used first. TCP is allowed as well.

## Application Scenarios

The question is why would somebody like to use DNS over TCP instead of UDP? And actually I wouldn’t have known any reason until two days ago.

A friend works at a network company which operates and/or maintains networks of customers. One of his customers has a remote site which has access to the central site only through a SOCKS4 proxy. The SOCKS4 protocol offers TCP- only and it has no support for remote name resolution (as SOCKS4A has).

The first idea comes immediately: just tunnel everything through some kind of VPN. The simple but really cool tool socat provides everything you need. Unfortunately, any such solution is based on having two ends, i.e. running socat on the remote as well as on the central side.

And exactly this is the problem in the case described above: it is not allowed to install any piece of software in the central site. That’s bad on one hand but on the other hand this is great There is a need for a new cool network tool.

## The Software
I proudly present a small piece of software which solves your problem: utdns. It opens an UDP port waiting for incoming UDP queries. All queries are then translated into a TCP query to a specific name server. The response of the name server is then translated back and sent as a UDP packet to the original client.

Download the package from here then unpack and compile it. If you want it to bind to port 53 you have to run it as root. But of course it will drop the privileges as soon as possible. If it is bound to port 53 and you want your locally running applications to resolve through it you have to change the nameserver in /etc/resolv.conf to 127.0.0.1.

The option -p lets you specify a different port number but then a redirection is necessary. If you would like to redirect all outgoing UDP/DNS traffic of your host to utdns you can use the following commands (assuming utdns is bound to port 5300):

```
iptables -t nat -A OUTPUT -p udp --dport 53 ! -o lo -j DNAT --to-destination 127.0.0.1:5300
iptables -t nat -A POSTROUTING -p udp --dport 5300
 -j SNAT --to-source 127.0.0.1
# redirect incoming traffic from other host also
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
```

Please note that utdns currently binds to any address, hence, you might protect it with a local firewall if it shall not be reachable by the network. Of course, I will add an option to do specific binding but this first version had to work quickly in a specific environment.

Utdns is written in C and it is currently only tested on Linux (for FreeBSD `#define SOCK_NONBLOCK 0`) but it should easily compile on most systems.

Have fun using utdns and of course don’t hesitate to contact me!

