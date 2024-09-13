#!/bin/bash
set -x

ip route del default
ip route add default via 192.168.100.1
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

echo -e "\nsource /root/.venv/bin/activate" >> /root/.bashrc
