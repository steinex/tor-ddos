This is my el cheapo attempt to block unwanted traffic to relays and (hopefully) help against the ongoing Tor DDoS attacks.

## How does it work?
The rules shown here make use of a mix of the `recent` and `hashlimit` iptables modules. Should an attacker hit 7 SYNs/sec on the ORPort the IP is blocked for 60 seconds. Should another SYN attempt arrive in that timeframe the timer is reset and the IP stays blocked for another 60 seconds.

## Credits
* Thanks to the friendly peeps from `#netfilter` on libera for helping me wrap my head around these iptables modules.
* @toralf has a more sophisticated solution here: https://github.com/toralf/torutils
* @Enkidu-6 has another approach here: https://github.com/Enkidu-6/tor-ddos

## Whitelisting the directory authorities and snowflakes.
This is shamelessly stolen from @toralf. Since we always want to allow directory authorities and snowflakes to be able to talk to our relay we always `ACCEPT` them before attempting to ratelimit. To get the addresses of these you can use the following commands. The addresses should very rarely change, if ever. You see these addresses used beneath in the actual ruleset.

for v4:
```
$ getent ahostsv4 snowflake-01.torproject.net. | awk '{ print $1 }' | sort -u | xargs
$ curl -s 'https://onionoo.torproject.org/summary?search=flag:authority' -o - | jq -cr '.relays[].a[0]' | sort | xargs
```

for v6:
```
$ getent ahostsv6 snowflake-01.torproject.net. | awk '{ print $1 }' | sort -u | xargs
$ curl -s 'https://onionoo.torproject.org/summary?search=flag:authority' -o - | jq -cr '.relays[].a | select(length > 1) | .[1]' | tr -d '][' | sort | xargs
```

## The actual rules (iptables-save)
This is the output of iptables-save, trimmed down to only the most basic stuff + the relevant parts for ratelimiting the Tor ORPort. I left out ip6tables for an exercise to the reader, it's basically the same.

Of course you must change `$DSTIP` and `$DSTPORT` for your environment.

```
# Generated by iptables-save v1.8.7 on Mon Oct 31 14:00:34 2022
*filter
:INPUT DROP [4:768]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
:TOR_RATELIMIT - [0:0]
-A INPUT -m state --state INVALID -j DROP
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -s 128.31.0.34/32 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
-A INPUT -s 131.188.40.189/32 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
-A INPUT -s 154.35.175.225/32 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
-A INPUT -s 171.25.193.9/32 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
-A INPUT -s 193.23.244.244/32 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
-A INPUT -s 199.58.81.140/32 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
-A INPUT -s 204.13.164.118/32 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
-A INPUT -s 45.66.33.45/32 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
-A INPUT -s 66.111.2.131/32 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
-A INPUT -s 86.59.21.38/32 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
-A INPUT -s 193.187.88.42/32 -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
-A INPUT -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -m state --state NEW -j TOR_RATELIMIT
-A INPUT -d $DSTIP/32 -p tcp -m tcp --dport $DSTPORT -j ACCEPT
-A OUTPUT -j ACCEPT
-A TOR_RATELIMIT -m recent --update --seconds 60 --name tor-recent --mask 255.255.255.255 --rsource -j DROP
-A TOR_RATELIMIT -m hashlimit --hashlimit-upto 7/sec --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-name tor-hashlimit -j RETURN
-A TOR_RATELIMIT -m recent --set --name tor-recent --mask 255.255.255.255 --rsource
-A TOR_RATELIMIT -j LOG --log-prefix "Tor: "
-A TOR_RATELIMIT -j DROP
COMMIT
# Completed on Mon Oct 31 14:00:34 2022
```

## Rules written in ferm
Since I use ferm as my firewall frontend tool, this may help you if you are a ferm user aswell. I show only the really relevant parts here:
```
proto tcp destination ($dirauths $snowflakes) ACCEPT;

proto tcp destination ($DSTIPs) dport $DSTPORT mod state state NEW @subchain TOR_RATELIMIT {
    mod recent name tor-recent seconds 60 update DROP;
    mod hashlimit hashlimit-name tor-hashlimit hashlimit-mode srcip hashlimit 7/sec RETURN;
    mod recent name tor-recent set NOP;
    LOG log-prefix "Tor: ";
    DROP;
}
```

## Why another attempt at this?
Because I feel it's easier to implement into ones existing firewall workflow and isn't dependent on `ipset` and wrapper scripts. Don't get me wrong though, I don't want to diminish the great work done by both @toralf and @Enkidu-6.

HTH, and thanks for reading. :-)
