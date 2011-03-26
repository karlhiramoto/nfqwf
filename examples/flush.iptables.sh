#!/bin/sh
# flush iptables to remove any rules

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
