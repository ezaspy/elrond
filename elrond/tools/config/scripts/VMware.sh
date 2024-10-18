#!/bin/bash

USERPROFILE=$(cat /etc/passwd | grep 1000 | cut -d ":" -f 1)
HOSTNAME=$(hostname)

sudo tar -xvf /opt/elrond/elrond/tools/config/VMwareTools-10.3.23-16594550.tar.gz
sleep 1
cd vmware-tools-distrib
sudo rm -rf vmware-install.pl
sudo cp /opt/elrond/elrond/tools/config/vmware-install.pl .
sudo chmod 755 vmware-install.pl
sudo apt remove open-vm-tools --purge -y
sudo rm -rf /etc/vmware-tools/
yes '' | sudo ./vmware-install.pl -f
cd ..
sudo rm -rf vmware-tools-distrib
sleep 1
