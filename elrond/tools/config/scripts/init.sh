#!/bin/bash
sleep 1
clear
printf "\n  -> Running initialization script for elrond...\n\n"
# installing vmware_tools
sudo tar -xvf /opt/elrond/elrond/tools/config/VMwareTools-10.3.23-16594550.tar.gz
cd vmware-tools-distrib
sudo rm -rf vmware-install.pl
sudo mv /opt/elrond/elrond/tools/config/vmware-install.pl .
sudo chmod 755 vmware-install.pl
sudo ./vmware-install.pl -f
cd ..
sudo rm -rf vmware-tools-distrib
sleep 1
# creating linux_swap space
sudo mkswap /dev/sdb
sudo swapon /dev/sdb
sudo cp /etc/fstab /etc/fstab.orig
sudo chmod 777 /etc/fstab
echo "/dev/sdb swap swap defaults 0 0" >> /etc/fstab
sudo chmod 664 /etc/fstab
../elrond/tools/config/scripts/./splunk.sh
sudo apt install mlocate build-essential yara john gparted -y --fix-missing
sudo updatedb
# configuring elrond
sudo chmod -R 744 /opt/elrond/
export PATH=$PATH:/opt/elrond
sudo chmod +x /opt/elrond/elrond.py
sudo updatedb
sleep 1