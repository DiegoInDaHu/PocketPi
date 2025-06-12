#!/bin/bash
# Install all libraries needed for PocketPi network analyzer
set -e

sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-tk nmap arp-scan iputils-ping iproute2

PYTHON=$(which python3)
sudo "$PYTHON" -m pip install --break-system-packages --ignore-installed --upgrade \
    netifaces psutil scapy python-nmap pyroute2
