#!/bin/bash

IPT=iptables

# The following rules will clear out any existing firewall rules,
# and any chains that might have been created. just to make debug easy
$IPT -F
$IPT -F INPUT
$IPT -F OUTPUT
$IPT -F FORWARD
$IPT -F -t mangle
$IPT -F -t nat
$IPT -X

echo -n 1 > /proc/sys/net/ipv4/ip_forward

$IPT -t mangle -A INPUT -i eth0 -p tcp --sport 80 -j NFQUEUE --queue-num 1
$IPT -t mangle -A OUTPUT  -o eth0 -p tcp  --dport 80 -j NFQUEUE --queue-num 1
$IPT -t mangle -A FORWARD  -p tcp -m multiport --ports 80 -j NFQUEUE --queue-num 1
