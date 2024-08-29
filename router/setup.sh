#!/bin/bash
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP && \
iptables -t nat -A POSTROUTING -j MASQUERADE 