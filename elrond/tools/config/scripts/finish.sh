#!/bin/bash

USERPROFILE=$(cat /etc/passwd | grep 1000 | cut -d ":" -f 1)
HOSTNAME=$(hostname)

# configure .bashrc
echo '
export PS1="\e[1;36m\u@\h:\e[m \e[0;32m\w\e[m\n$ "' >> /home/$USERPROFILE/.bashrc
echo "export PATH=$PATH:/opt/elrond/elrond" >> /home/$USERPROFILE/.bashrc
source ~/.bashrc

# configure terminal to launch on login
sudo rm -rf /home/$USERPROFILE/.config/autostart/gnome-terminal.desktop
sudo rm -rf gnome-terminal.desktop
echo "[Desktop Entry]
Type=Application
Exec=gnome-terminal -- /opt/elrond/elrond/elrond.sh
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name[en_NG]=Terminal
Name=Terminal
Comment[en_NG]=Start Terminal On Startup
Comment=Start Terminal On Startup" > gnome-terminal.desktop
sudo chmod 744 gnome-terminal.desktop
sudo chown -R "$USERPROFILE":"$USERPROFILE" gnome-terminal.desktop
mkdir -p /home/$USERPROFILE/.config/autostart
sudo mv gnome-terminal.desktop /home/$USERPROFILE/.config/autostart/
sudo chmod 744 /home/$USERPROFILE/.config/autostart/gnome-terminal.desktop
cp /opt/elrond/elrond/elrond.sh ~/elrond.sh
sudo chmod 744 ~/elrond.sh
sudo chmod +x ~/elrond.sh
sudo chmod 744 /opt/elrond
sudo chown -R "$USERPROFILE":"$USERPROFILE" /opt/elrond
/opt/elrond/elrond/./elrond.sh

# cleaning uneeded applications
sudo unminimize -y
sudo du -sh /var/cache/apt/archives
sudo apt update --allow-insecure-repositories
sudo apt-get clean
sudo apt update --allow-insecure-repositories
sudo updatedb

# making dirs if they do not exist
sudo mkdir /mnt/shadow_mount
sudo mkdir /mnt/vss