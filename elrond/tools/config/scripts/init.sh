#!/bin/bash
# downloading additional repo files
/opt/elrond/elrond/tools/config/scripts/./repo.sh
# creating linux_swap space
sudo swapoff /dev/sdb
sudo umount /dev/sdb
sudo mkswap /dev/sdb
sudo swapon /dev/sdb
sudo cp /etc/fstab /etc/fstab.orig
sudo chmod 777 /etc/fstab
echo "/dev/sdb swap swap defaults 0 0" >> /etc/fstab
sudo chmod 664 /etc/fstab
# installing additional features for elrond
sudo apt update
sudo apt install vim mlocate net-tools build-essential qemu apt-transport-https software-properties-common systemd gnupg xz-utils sqlite3 mdbtools yara clamav clamav-daemon john gparted dos2unix -y --fix-missing
sudo apt update
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
# downloading indx-parser
python3 -m keyring --disable
/opt/elrond/elrond/tools/config/scripts/./indx.sh
# configuring elrond
sudo chmod -R 744 /opt/elrond/
sudo chown -R $USER:$USER /opt/elrond
sudo chmod +x /opt/elrond/elrond/elrond.py
sleep 1