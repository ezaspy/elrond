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
# downloading software
python3 -m keyring --disable
/opt/elrond/elrond/tools/config/scripts/./python.sh
sudo wget -O /opt/elrond/elrond/tools/.clamav-0.105.1-2.linux.x86_64.deb "https://www.clamav.net/downloads/production/clamav-0.105.1-2.linux.x86_64.deb"
sudo dpkg -i /opt/elrond/elrond/tools/.clamav-0.105.1-2.linux.x86_64.deb
sudo apt update && sudo apt install mlocate build-essential qemu wget apt-transport-https software-properties-common mdbtools yara clamav clamav-daemon john gparted -y --fix-missing
sudo systemctl stop clamav-freshclam && sudo freshclam && sudo systemctl start clamav-freshclam
# configuring elrond
sudo chmod -R 744 /opt/elrond/ && sudo chmod +x /opt/elrond/elrond/elrond.py
echo "export PATH=$PATH:/opt/elrond" > /home/sansforensics/.bashrc
sudo updatedb
sleep 1