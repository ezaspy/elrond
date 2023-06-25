#!/bin/bash
sleep 1
clear
printf "\n  -> Downloading Splunk...\n\n"
sudo wget -O /opt/elrond/elrond/tools/.splunk.deb "https://download.splunk.com/products/splunk/releases/9.0.5/linux/splunk-9.0.5-e9494146ae5c-linux-2.6-amd64.deb"
sleep 1