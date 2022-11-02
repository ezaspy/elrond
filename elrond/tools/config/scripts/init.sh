#!/bin/bash
sleep 1
clear
printf "\n  -> Running initialization script for elrond...\n\n"
echo "[Wallet]\nEnabled=false" > /home/sansforensics/.config/kwalletrc
# installing vmware_tools
sudo tar -xvf /opt/elrond/elrond/tools/config/VMwareTools-10.3.23-16594550.tar.gz
sleep 2
cd vmware-tools-distrib
sudo rm -rf vmware-install.pl
sudo cp /opt/elrond/elrond/tools/config/vmware-install.pl .
sudo chmod 755 vmware-install.pl
yes '' | sudo ./vmware-install.pl -f
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
/opt/elrond/elrond/tools/config/scripts/./python.sh
sudo apt install mlocate build-essential qemu wget apt-transport-https software-properties-common mdbtools yara clamav clamav-daemon john gparted -y --fix-missing
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
sift update
sift upgrade
sudo updatedb
# configuring elrond
sudo chmod -R 744 /opt/elrond/
export PATH=$PATH:/opt/elrond
sudo chmod +x /opt/elrond/elrond.py
sudo updatedb
sleep 1