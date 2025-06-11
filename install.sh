#!/bin/bash
# Install all libraries needed for PocketPi network analyzer
set -e

sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-tk nmap arp-scan iputils-ping iproute2

pip3 install --upgrade netifaces psutil scapy python-nmap pyroute2
