This is my attempt to block unwanted traffic to relays and (hopefully) help against the ongoing Tor DDoS attacks.

## How does it work?
The rules shown here make use of a mix of the `recent` and `hashlimit` iptables modules. Should an attacker hit 7 SYNs in one second on the ORPort the IP is blocked for 300 seconds. Should another SYN attempt arrive in that timeframe the timer is reset and the IP stays blocked for another 300 seconds.

In addition to that, there are no more SYNs allowed if 4 connections are already in use to the ORPort.

Moreover there are some sysctl tweaks below I strongly recommend.

## How well does it work?
Very well in my observations. Before the rules were in place I had many of the infamous "Your computer is too slow to handle this many circuit creation requests" in my log. After both my relays lost their `Stable`, `Guard` and `HSDir` flags I finally decided to do something against it (and you should too if you are a relay operator).

Since the rules are active, directory authorities are happy again and my relays have their flags back. The infamous log message is gone. Additionally the behaviour of the tor processes are back to pre-DDoS times, both in terms of traffic and on strain on CPU and memory.

## Credits
* Thanks to the friendly peeps from `#netfilter` on libera for helping me wrap my head around these iptables modules.
* @toralf has a more sophisticated solution here: https://github.com/toralf/torutils
* @Enkidu-6 has another approach here: https://github.com/Enkidu-6/tor-ddos

## sysctl tweaks
Sometimes the ORPort gets unresponsive despite not hitting it's file descriptor limit nor a full conntrack table or such. The problem is that the floods come in such fast waves sometimes that the Linux kernel can't keep up with its queue to allow for new connections. This is mitigated by setting:

```
sysctl -w net.ipv4.tcp_max_syn_backlog=65536
sysctl -w net.core.somaxconn=65536
```

Make sure you persist these via `/etc/sysctl.conf` or how it's supposed to work on your distribution. You need to restart your tor process to apply these settings.

## Other tweaks
There are other tweaks that are especially helpful in low-RAM and thrashing situations. First, make sure you enable Zswap:
`echo 1 > /sys/module/zswap/parameters/enabled`
`echo y > /sys/kernel/mm/lru_gen/enabled` (this only works on kernels 6.1+ but should make a huge difference).

Again, make sure you persist these settings for your distribution (`rc.local`?)

## Whitelisting the directory authorities and snowflakes.
Since we always want to allow directory authorities and snowflakes to be able to talk to our relay we always `ACCEPT` them before attempting to ratelimit. To get the addresses of these you can use the following commands. The addresses should very rarely change, if ever. You see these addresses used beneath in the actual ruleset. (shamelessly stolen from @Enkidu-6.)

for v4:
```
curl -s 'https://raw.githubusercontent.com/Enkidu-6/tor-relay-lists/main/authorities-v4.txt' | sed -e '1,3d'
curl -s 'https://raw.githubusercontent.com/Enkidu-6/tor-relay-lists/main/snowflake.txt' | sed -e '1,3d'
```

for v6:
```
curl -s 'https://raw.githubusercontent.com/Enkidu-6/tor-relay-lists/main/authorities-v6.txt' | sed -e '1,3d'
curl -s 'https://raw.githubusercontent.com/Enkidu-6/tor-relay-lists/main/snowflake-v6.txt' | sed -e '1,3d'
```

## The actual rules
These are the actual iptables rules, trimmed down to only the most relevant parts. I left out ip6tables for an exercise to the reader since it's basically the same.

Of course you must change `$DSTIP` and `$DSTPORT` for your environment.

```
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -s 128.31.0.39/32 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
iptables -A INPUT -s 204.13.164.118 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
iptables -A INPUT -s 199.58.81.140 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
iptables -A INPUT -s 193.23.244.244 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
iptables -A INPUT -s 45.66.33.45 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
iptables -A INPUT -s 86.59.21.38 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
iptables -A INPUT -s 66.111.2.131 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
iptables -A INPUT -s 171.25.193.9 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
iptables -A INPUT -s 131.188.40.189 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport $DSTPORT --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 4 --connlimit-mask 32 --connlimit-saddr -m state --state NEW -j DROP
iptables -N TOR_RATELIMIT
iptables -A INPUT -p tcp -m tcp --dport $DSTPORT --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j TOR_RATELIMIT
iptables -A INPUT -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
iptables -A OUTPUT -j ACCEPT
iptables -A TOR_RATELIMIT -m recent --update --seconds 300 --name tor-recent --mask 255.255.255.255 --rsource -j DROP
iptables -A TOR_RATELIMIT -m hashlimit --hashlimit-upto 7/sec --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-name tor-hashlimit -j RETURN
iptables -A TOR_RATELIMIT -m recent --set --name tor-recent --mask 255.255.255.255 --rsource
iptables -A TOR_RATELIMIT -j DROP
```

## Rules written in ferm
Since I use ferm as my firewall frontend tool, this may help you if you are a ferm user aswell. I show only the most relevant parts here and I assume you have other rules like accepting `RELATED/ESTABLISHED` and allowing icmp already in place before this snippet:
```
@def $AUTHORITIES_V4 = `curl -s 'https://raw.githubusercontent.com/Enkidu-6/tor-relay-lists/main/authorities-v4.txt' | sed -e '1,3d'`;
@def $SNOWFLAKES_V4 = `curl -s 'https://raw.githubusercontent.com/Enkidu-6/tor-relay-lists/main/snowflake.txt' | sed -e '1,3d'`;
@def $AUTHORITIES_V6 = `curl -s 'https://raw.githubusercontent.com/Enkidu-6/tor-relay-lists/main/authorities-v6.txt' | sed -e '1,3d'`;
@def $SNOWFLAKES_V6 = `curl -s 'https://raw.githubusercontent.com/Enkidu-6/tor-relay-lists/main/snowflake-v6.txt' | sed -e '1,3d'`;

# never limit dirauths or snowflakes
proto tcp destination $DSTIP dport $DSTPORT source ($AUTHORITIES_V4 $SNOWFLAKES_V4 $AUTHORITIES_V6 $SNOWFLAKES_V6) ACCEPT;

# connlimit
proto tcp dport $DSTPORT syn mod connlimit mod state state NEW connlimit-mask 32 connlimit-above 4 DROP;

# ratelimit
proto tcp destination $DSTIP dport $DSTPORT syn mod state state NEW @subchain TOR_RATELIMIT {
    mod recent name tor-recent seconds 300 update DROP;
    mod hashlimit hashlimit-name tor-hashlimit hashlimit-mode srcip hashlimit 7/sec RETURN;
    mod recent name tor-recent set NOP;
    DROP;
}
```

## Why another attempt at this?
Because I feel it's easier to implement into ones existing firewall workflow and isn't dependent on `ipset` and wrapper scripts. Don't get me wrong though, I don't want to diminish the great work done by both @toralf and @Enkidu-6.

HTH, and thanks for reading. :-)
