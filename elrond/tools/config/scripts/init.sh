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
# installing required software
wget -q "https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb"
sudo dpkg -i packages-microsoft-prod.deb
wget -q https://packages.microsoft.com/keys/microsoft.asc -O- | sudo apt-key add - # vscode
sudo add-apt-repository "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main" # vscode
wget -q "https://www.clamav.net/downloads/production/clamav-0.105.1-2.linux.x86_64.deb"
sudo dpkg -i clamav-0.105.1-2.linux.x86_64.deb
sudo apt update
sudo apt install mlocate net-tools build-essential qemu apt-transport-https software-properties-common systemd gnupg xz-utils powershell code sqlite3 mdbtools yara clamav clamav-daemon john gparted -y --fix-missing
sudo rm -rf packages-microsoft-prod.deb
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
# downloading indx-parser
python3 -m keyring --disable
/opt/elrond/elrond/tools/config/scripts/./indx.sh
# configuring elrond
sudo chmod -R 744 /opt/elrond/ && sudo chmod +x /opt/elrond/elrond/elrond.py
echo "export PATH=$PATH:/opt/elrond" > /home/sansforensics/.bashrc
sleep 1