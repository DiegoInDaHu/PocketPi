#!/bin/bash
# Install all libraries needed for PocketPi network analyzer
set -e

sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-tk

pip3 install --upgrade netifaces psutil scapy
