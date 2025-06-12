#!/bin/bash
# Install all libraries needed for PocketPi network analyzer
set -e

sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-tk nmap arp-scan iputils-ping iproute2

PYTHON=$(which python3)
PIP_OPTS="--ignore-installed --upgrade"
if "$PYTHON" -m pip install --help 2>&1 | grep -q "--break-system-packages"; then
    PIP_OPTS="--break-system-packages $PIP_OPTS"
fi
sudo "$PYTHON" -m pip install $PIP_OPTS \
    netifaces psutil scapy python-nmap pyroute2
