#!/bin/bash
sleep 1
sudo apt update
echo fs.inotify.max_user_watches=1048576 | sudo tee -a /etc/sysctl.conf
echo '
export PS1="\e[1;36m\u@\h:\e[m \e[0;32m\w\e[m\n$ "' >> /home/$USER/.bashrc
sudo chmod -R 755 /opt/elrond/
sudo chown -R $USER:$USER /opt/elrond
sudo chmod +x /opt/elrond/elrond/elrond.py
echo "export PATH=$PATH:/opt/elrond/elrond" >> /home/$USER/.bashrc
cd /opt/elrond/elrond/

# removing uneeded applications
sudo chmod 644 /etc/sysctl.conf
sudo du -sh /var/cache/apt/archives > /dev/null 2>&1
sudo apt-get remove --auto-remove --purge thunderbird rhythmbox yelp libreoffice* kdeconnect aisleriot gnome-mines gnome-sudoku gnome-mahjongg cheese ghex simple-scan wxhexeditor scite -y > /dev/null 2>&1
sudo apt-get autoremove --purge > /dev/null 2>&1
sudo apt-get clean > /dev/null 2>&1

# change desktop background
gsettings set org.gnome.desktop.background picture-uri file:///opt/elrond/elrond/images/elrond_background.jpg
gsettings set org.gnome.shell favorite-apps "['org.gnome.seahorse.Application.desktop', 'org.gnome.Nautilus.desktop', 'org.flameshot.Flameshot.desktop', 'firefox_firefox.desktop', 'org.gnome.Terminal.desktop', 'code.desktop', 'bless.desktop', 'wireshark.desktop', 'cutter.desktop', 'sqlitebrowser.desktop', 'maltego.desktop']"

# configure .bashrc
echo "[Desktop Entry]
Type=Application
Exec=gnome-terminal
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name[en_NG]=Terminal
Name=Terminal
Comment[en_NG]=Start Terminal On Startup
Comment=Start Terminal On Startup" > gnome-terminal.desktop
sudo rm -rf /home/$USER/.config/autostart/gnome-terminal.desktop
sudo mv gnome-terminal.desktop /home/$USER/.config/autostart/
sudo chmod 755 /home/$USER/.config/autostart/gnome-terminal.desktop
sudo chown -R $USER:$USER /opt/
sleep 1
clear
printf "\n\n  -> SIFT-Workstation has been successfully configured for elrond; a reboot is required. Press ENTER to continue..."
read answer
sleep 1
sudo updatedb
echo '' | sudo tee ~/.bash_history
history -c
sleep 1
clear
sudo reboot