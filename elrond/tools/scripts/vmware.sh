#!/bin/bash
clear
printf "\n [+] Installing VMware Tools...\n\n"
sudo tar -xvf /opt/elrond/elrond/tools/VMwareTools-10.3.23-16594550.tar.gz
cd vmware-tools-distrib
sudo ./vmware-install.pl -y
sudo rm -rf vmware-tools-distrib
clear
sleep 2
