#!/bin/bash

USER=$(whoami)
clear
printf "\n\n  +--------- \e[1;31mOPTIONAL\e[m: RDS Hash Sets Download ---------+\n\n   \e[0;36m$ /opt/elrond/elrond/tools/config/scripts/./nsrl.sh\e[m \n\n\n"
sleep 20
clear
sudo apt update
cd /opt/elrond/elrond
sudo chmod -R 744 /opt/elrond/ && sudo chown -R $USER:$USER /opt/elrond
sudo chmod +x /opt/elrond/elrond/elrond.py
sudo chmod +x /opt/elrond/elrond/tools/config/elrond.sh

sudo chmod 777 /etc/sysctl.conf
echo fs.inotify.max_user_watches=1048576 | sudo tee -a /etc/sysctl.conf
sudo chmod 644 /etc/sysctl.conf
# creating linux_swap space
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
HOST=$(hostname)
if [[ "$HOST" != *"siftworkstation"* ]]; then
    sudo hostnamectl set-hostname elrond
fi

# installing vmware-tools if applicable
HYPER=$(sudo dmesg | grep -E "DMI|Hypervisor")
if [[ "$HYPER" == *"VMware"* ]]; then
    # installing vmware_tools
    /opt/elrond/elrond/tools/config/scripts/./VMware.sh
fi

# installing apfs-fuse if architecture is not ARM
UNAME=$(uname -a)
if [[ "$UNAME" != *"aarch"* ]]; then
    # installing apfs-fuse
    /opt/elrond/elrond/tools/config/scripts/./apfs-fuse.sh
    # installing code
    wget -O /tmp/vscode.deb https://vscode.download.prss.microsoft.com/dbazure/download/stable/b58957e67ee1e712cebf466b995adf4c5307b2bd/code_1.89.0-1714530869_amd64.deb
else
    # installing code
    wget -O /tmp/vscode.deb https://vscode.download.prss.microsoft.com/dbazure/download/stable/b58957e67ee1e712cebf466b995adf4c5307b2bd/code_1.89.0-1714529372_arm64.deb
fi
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
/opt/elrond/elrond/tools/config/scripts/./dwarf2json.sh
printf "\n  -> Downloading MITRE ATT&CK Framework Enterprise v15.1..."
python3 /opt/elrond/elrond/tools/config/mitre.py
/opt/elrond/elrond/tools/config/scripts/./elastic.sh
/opt/elrond/elrond/tools/config/scripts/./navigator.sh
USER=$(whoami) && HOST=$(hostname)
sudo chmod -R 744 /opt/elrond/
sudo chown -R $USER:$USER /opt/elrond
sudo chmod +x /opt/elrond/elrond/elrond.py
sleep 2
/opt/elrond/elrond/tools/config/scripts/./finish.sh
sudo chown -R $USER:$USER /opt/
sudo updatedb
clear
printf "\n\n  -> '$HOST' has been successfully configured for elrond; a reboot is required. Press ENTER to continue..."
read answer
echo '' | sudo tee ~/.bash_history
history -c
sudo reboot