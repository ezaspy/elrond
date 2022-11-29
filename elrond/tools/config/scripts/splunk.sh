#!/bin/bash
sleep 1
clear
printf "\n  -> Downloading Splunk...\n\n"
sudo wget -O /opt/elrond/elrond/tools/.splunk.deb "https://download.splunk.com/products/splunk/releases/9.0.0.1/linux/splunk-9.0.0.1-9e907cedecb1-linux-2.6-amd64.deb"
sleep 1