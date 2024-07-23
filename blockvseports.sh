#!/bin/bash

for port in $(seq 27015 27099); do
    sudo iptables -A INPUT -p udp --dport $port -j DROP
done

sudo iptables-save | sudo tee /etc/iptables/rules.v4
