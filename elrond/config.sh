#!/bin/bash

USERPROFILE=$(cat /etc/passwd | grep 1000 | cut -d ":" -f 1)
HOSTNAME=$(hostname)

clear
printf "\n\n  +--------- \e[1;31mOPTIONAL\e[m: RDS Hash Sets Download ---------+\n\n   \e[0;36m$ /opt/elrond/elrond/tools/config/scripts/./nsrl.sh\e[m \n\n\n"
sleep 20

sudo chmod 777 /etc/sysctl.conf
echo fs.inotify.max_user_watches=1048576 | sudo tee -a /etc/sysctl.conf
sudo chmod 644 /etc/sysctl.conf
# creating linux_swap space
sudo swapon /dev/sdb
sudo swapoff /dev/sdb
sudo umount /dev/sdb
sudo mkswap /dev/sdb
sudo swapon /dev/sdb
sudo cp /etc/fstab /etc/fstab.orig
sudo chmod 777 /etc/fstab
echo "/dev/sdb swap swap defaults 0 0" >> /etc/fstab
sudo chmod 664 /etc/fstab

#/opt/elrond/elrond/tools/config/scripts/./cloud.sh
/opt/elrond/elrond/tools/config/scripts/./tools.sh

# setting hostname to elrond if not SANS SIFT
if [[ "$(hostname)" != *"siftworkstation"* ]]; then
    sudo hostnamectl set-hostname elrond
fi

# installing vmware-tools if applicable
if [[ "$(sudo dmesg | grep -E "DMI|Hypervisor")" == *"VMware"* ]]; then
    # installing vmware_tools
    /opt/elrond/elrond/tools/config/scripts/./VMware.sh
fi

# installing apfs-fuse if architecture is not ARM
if [[ "$(uname -a)" != *"aarch"* ]]; then
    # installing apfs-fuse
    /opt/elrond/elrond/tools/config/scripts/./apfs-fuse.sh
    wget -O /tmp/vscode.deb https://vscode.download.prss.microsoft.com/dbazure/download/stable/b58957e67ee1e712cebf466b995adf4c5307b2bd/code_1.89.0-1714530869_amd64.deb
else
    wget -O /tmp/vscode.deb https://vscode.download.prss.microsoft.com/dbazure/download/stable/b58957e67ee1e712cebf466b995adf4c5307b2bd/code_1.89.0-1714529372_arm64.deb
fi
# installing code
sudo dpkg -i /tmp/vscode.deb

# installing regripper if not installed
if [ -d "/usr/local/src/regripper" ]; then
    # updating regripper
    sudo cp /usr/share/regripper/rip.pl /usr/share/regripper/rip.pl.old
    sudo sed -i 's/my \$VERSION/# Add: Define the variable plugindir\nmy \$plugindir = File::Spec->catfile\(\$scriptdir, "plugins"\);\n\nmy \$VERSION/' /usr/share/regripper/rip.pl
else
    sudo /opt/elrond/elrond/tools/config/scripts/./regrip.sh
fi

/opt/elrond/elrond/tools/config/scripts/./volatility3.sh
printf "\n  -> Downloading MITRE ATT&CK Framework Enterprise v15.1..."
sudo mkdir /opt/elrond/elrond/tools/attack-navigator
sudo chmod -R 744 /opt/elrond/elrond/tools/attack-navigator
sudo chown -R "$USERPROFILE":"$USERPROFILE" /opt/elrond/elrond/tools/attack-navigator
python3 /opt/elrond/elrond/tools/config/mitre.py

# configuring elastic
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable elasticsearch.service
sudo /bin/systemctl enable kibana.service
sudo sysctl -w vm.max_map_count=262144
echo vm.max_map_count=262144 | sudo tee -a /etc/sysctl.conf
sleep 1
sudo sysctl -p

/opt/elrond/elrond/tools/config/scripts/./navigator.sh
/opt/elrond/elrond/tools/config/scripts/./finish.sh
sleep 2

USERPROFILE=$(cat /etc/passwd | grep 1000 | cut -d ":" -f 1)
HOSTNAME=$(hostname)
clear
printf "\n\n  -> '"$(hostname)"' has been successfully configured for elrond; a reboot is required. Press ENTER to continue..."
read answer
echo '' | sudo tee ~/.bash_history
history -c
sudo reboot