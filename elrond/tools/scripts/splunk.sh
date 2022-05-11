#!/bin/bash
printf "\n [+] Downloading Splunk...\n\n"
wget -O /opt/elrond/elrond/tools/.splunk-8.2.6-a6fe1ee8894b-linux-2.6-amd64.deb "https://download.splunk.com/products/splunk/releases/8.2.6/linux/splunk-8.2.6-a6fe1ee8894b-linux-2.6-amd64.deb"
sudo updatedb
clear
sleep 2