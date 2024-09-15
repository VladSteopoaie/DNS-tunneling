#!/bin/bash
set -x

ip route del default
ip route add default via 10.8.8.1
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

echo -e "\nsource /root/.venv/bin/activate" >> /root/.bashrc

cd /scripts/
make -f makefile_tunnel
# bin/dns_tunnel # to start the c++ server
# /root/.venv/bin/python dns_tunnel.py # to start the python server