#!/bin/bash

# downloading additional repo files
sudo add-apt-repository -y ppa:linuxgndu/sqlitebrowser > /dev/null 2>&1 # db browser for sqlite
yes '' | sudo add-apt-repository ppa:deadsnakes/ppa # INDXRipper
echo 'deb http://download.opensuse.org/repositories/home:/RizinOrg/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/home:RizinOrg.list # cutter-re
curl -fsSL https://download.opensuse.org/repositories/home:RizinOrg/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_RizinOrg.gpg > /dev/null # cutter-re
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
#echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
#sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token --scope kibana
#sudo /usr/share/kibana/bin/kibana-verification-code
#sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
/opt/elrond/elrond/tools/config/scripts/./repo.sh
sudo wget https://www.netresec.com/?download=NetworkMiner -O /tmp/nm.zip
wget -O /tmp/Maltego.v4.7.0.deb https://downloads.maltego.com/maltego-v4/linux/Maltego.v4.7.0.deb
sudo wget -O /opt/elrond/elrond/tools/.splunk.deb "https://download.splunk.com/products/splunk/releases/9.0.5/linux/splunk-9.0.5-e9494146ae5c-linux-2.6-amd64.deb"

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
sudo apt install vim mlocate net-tools build-essential libreadline-dev libncursesw5-dev libssl-dev libc6-dev libffi-dev zlib1g-dev qemu apt-transport-https software-properties-common systemd gnupg xz-utils sqlite3 mdbtools yara clamav clamav-daemon john gparted dos2unix sqlitebrowser python3-apt wireshark libguestfs-tools mono-devel openjdk-17-jdk openjdk-17-jre curl jq openjdk-16-jre-headless elasticsearch kibana python3.9 python3.9-venv -y --fix-missing
sudo apt-get install checkinstall libgdbm-dev libreadline-dev libnss3-dev libsqlite3-dev tk-dev liblzma-dev -y --fix-missing
sudo snap install sqlitebrowser
sudo snap install cyberchef
sleep 1

# installing network-miner
sudo unzip /tmp/nm.zip -d /opt/
cd /opt/NetworkMiner*
sudo chmod +x NetworkMiner.exe
sudo chmod -R go+w AssembledFiles/
sudo chmod -R go+w Captures/
cd ~
sleep 1

# installing maltego
sudo dpkg -i /tmp/Maltego.v4.7.0.deb

# cloning additional repositories
#/opt/elrond/elrond/tools/config/scripts/./cloud.sh
/opt/elrond/elrond/tools/config/scripts/./tools.sh
sudo apt update
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam

# installing python libraries
python3 -m pip install --upgrade pip
python3 -m pip install requests pandas openpyxl jupyterlab notebook voila
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install requests pandas openpyxl jupyterlab notebook voila
sudo chmod -R 744 /opt/elrond/
sudo chown -R $USER:$USER /opt/elrond
cd /opt/elrond/elrond/tools/etl-parser
sudo python3 -m pip install -e .
cd /opt/elrond/elrond

# downloading indx-parser
python3 -m keyring --disable
/opt/elrond/elrond/tools/config/scripts/./indx.sh

# configuring elrond
sudo chmod -R 744 /opt/elrond/
sudo chown -R $USER:$USER /opt/elrond
sudo chmod +x /opt/elrond/elrond/elrond.py
sleep 1