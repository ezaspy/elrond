#!/bin/bash
sleep 1
clear
printf "\n  -> Running initialization script for elrond...\n\n"
# installing vmware_tools
/opt/elrond/elrond/tools/config/scripts/./virtual.sh
# creating linux_swap space
sudo mkswap /dev/sdb
sudo swapon /dev/sdb
sudo cp /etc/fstab /etc/fstab.orig
sudo chmod 777 /etc/fstab
echo "/dev/sdb swap swap defaults 0 0" >> /etc/fstab
sudo chmod 664 /etc/fstab
# downloading indx-parser
python3 -m keyring --disable
/opt/elrond/elrond/tools/config/scripts/./indx.sh
# configuring elrond
sudo chmod -R 744 /opt/elrond/ && sudo chmod +x /opt/elrond/elrond/elrond.py
echo "export PATH=$PATH:/opt/elrond" > /home/sansforensics/.bashrc
sleep 1