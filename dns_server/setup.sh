#!/bin/bash

set -x
ip route del default
ip route add default via 172.11.180.1
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

cd /scripts
make -f makefile_server
# bin/dns_server 53 # to start the c++ server
/root/.venv/bin/python dns_server.py 53 # to start the python server
