#!/bin/bash
sleep 1
clear
printf "\n  -> Running initialization script for elrond...\n\n"
# downloading additional tools for elrond
cd /tmp
wget --load-cookies /tmp/cookies.txt "https://drive.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://drive.google.com/uc?export=download&id=1mVrkLp84jchHRrAxqXvSpDdZhIKsH9Fi' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1mVrkLp84jchHRrAxqXvSpDdZhIKsH9Fi" -O elrond-archive.zip && rm -rf /tmp/cookies.txt
unzip elrond-archive.zip 1> /dev/null
rm -rf __MACOSX/
#/opt/elrond/elrond/tools/
unzip tools.zip 1> /dev/null
sudo mv avml /opt/elrond/elrond/tools/
sudo mv avml.zip /opt/elrond/elrond/tools/
sudo mv osxpmem.app.zip /opt/elrond/elrond/tools/
sudo mv volatility.zip /opt/elrond/elrond/tools/
sudo mv volatility3.zip /opt/elrond/elrond/tools/
#/opt/elrond/elrond/rivendell/memory/
unzip volatility-sym-prof-plug.zip 1> /dev/null
sudo mv volatility /opt/elrond/elrond/rivendell/memory/
sudo mv volatility3 /opt/elrond/elrond/rivendell/memory/
#/opt/elrond/elrond/rivendell/post/splunk/
unzip apps.zip 1> /dev/null
sudo mkdir /opt/elrond/elrond/rivendell/post/splunk/apps/
sudo mv apps/*.py /opt/elrond/elrond/rivendell/post/splunk/apps/
#/opt/elrond/elrond/tools/config/VMwareTools-10.3.23-16594550.tar.gz
sudo mv VMwareTools-10.3.23-16594550.tar.gz /opt/elrond/elrond/tools/config/
sudo rm -rf /tmp/elrond-archive.zip
cd ~
# installing vmware_tools
/opt/elrond/elrond/tools/config/scripts/./virtual.sh
# updating regripper
sudo cp /usr/share/regripper/rip.pl /usr/share/regripper/rip.pl.old
sudo sed -i 's/my \$VERSION/# Add: Define the variable plugindir\nmy \$plugindir = File::Spec->catfile\(\$scriptdir, "plugins"\);\n\nmy \$VERSION/' /usr/share/regripper/rip.pl
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
sleep 1
