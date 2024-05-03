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
sudo apt install vim mlocate net-tools build-essential qemu apt-transport-https software-properties-common systemd gnupg xz-utils sqlite3 mdbtools yara clamav clamav-daemon john gparted dos2unix sqlitebrowser python3-apt wireshark cutter bless sqlitebrowser flameshot libguestfs-tools mono-devel -y --fix-missing
sudo snap install cyberchef
sudo dpkg -i /tmp/vscode.deb
sleep 1
# installing network-miner
sudo wget https://www.netresec.com/?download=NetworkMiner -O /tmp/nm.zip
sudo unzip /tmp/nm.zip -d /opt/
cd /opt/NetworkMiner*
sudo chmod +x NetworkMiner.exe
sudo chmod -R go+w AssembledFiles/
sudo chmod -R go+w Captures/
cd ~
sleep 1
# installing maltego
sudo apt install openjdk-17-jdk openjdk-17-jre
wget -O /tmp/Maltego.v4.7.0.deb https://downloads.maltego.com/maltego-v4/linux/Maltego.v4.7.0.deb
sudo dpkg -i /tmp/Maltego.v4.7.0.deb
# installing python libraries
python3 -m pip install --upgrade pip
python3 -m pip install requests pandas openpyxl jupyterlab notebook voila
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install requests pandas openpyxl jupyterlab notebook voila
sudo chmod -R 744 /opt/elrond/
sudo chown -R $USER:$USER /opt/elrond
cd /opt/elrond/elrond/tools/etl-parser
python3 -m pip install -e .
cd /opt/elrond/elrond
# cloning additional repositories
/opt/elrond/elrond/tools/config/scripts/./clone.sh
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