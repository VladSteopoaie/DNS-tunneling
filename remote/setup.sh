#!/bin/bash
set -x

ip route del default
ip route add default via 10.8.8.1
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

