#!/bin/bash
sleep 1
clear
cd /opt/elrond/elrond
/opt/elrond/elrond/tools/config/scripts/./init.sh
/opt/elrond/elrond/tools/config/scripts/./apfs-fuse.sh
/opt/elrond/elrond/tools/config/scripts/./volatility3.sh
/opt/elrond/elrond/tools/config/scripts/./dwarf2json.sh
/opt/elrond/elrond/tools/config/scripts/./splunk.sh
/opt/elrond/elrond/tools/config/scripts/./elastic.sh
/opt/elrond/elrond/tools/config/scripts/./navigator.sh
/opt/elrond/elrond/tools/config/scripts/./nsrl.sh
wget -q "https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb"
sudo dpkg -i packages-microsoft-prod.deb
wget -q "https://www.clamav.net/downloads/production/clamav-0.105.1-2.linux.x86_64.deb"
sudo dpkg -i clamav-0.105.1-2.linux.x86_64.deb
sudo apt update
sudo apt install mlocate net-tools build-essential qemu apt-transport-https software-properties-common systemd gnupg powershell sqlite3 mdbtools yara clamav clamav-daemon john gparted -y --fix-missing
sudo rm -rf packages-microsoft-prod.deb
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
sudo chmod -R 755 /opt/elrond/
sudo chmod +x /opt/elrond/elrond/elrond.py
echo "export PATH=$PATH:/opt/elrond" >> /home/sansforensics/.bashrc
sudo updatedb
sleep 1
/opt/elrond/elrond/tools/config/scripts/./finish.sh