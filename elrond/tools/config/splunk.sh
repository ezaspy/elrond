#!/bin/bash
printf "\n [+] Downloading Splunk...\n\n"
wget -O /opt/elrond/elrond/tools/.splunk-9.0.0.1-9e907cedecb1-linux-2.6-amd64.deb "https://download.splunk.com/products/splunk/releases/9.0.0.1/linux/splunk-9.0.0.1-9e907cedecb1-linux-2.6-amd64.deb"
sudo updatedb
clear
sleep 2