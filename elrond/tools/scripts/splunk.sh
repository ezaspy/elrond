#!/bin/bash
printf "\n [+] Downloading Splunk...\n\n"
wget -O /opt/elrond/elrond/tools/splunk-8.2.5-77015bc7a462-linux-2.6-amd64.deb "https://download.splunk.com/products/splunk/releases/8.2.5/linux/splunk-8.2.5-77015bc7a462-linux-2.6-amd64.deb"
clear
sleep 2