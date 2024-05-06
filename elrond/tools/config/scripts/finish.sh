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
sleep 2

# removing uneeded applications
sudo chmod 644 /etc/sysctl.conf
sudo du -sh /var/cache/apt/archives
sudo apt update
sudo apt install cutter bless flameshot
sudo apt-get remove --auto-remove --purge thunderbird rhythmbox yelp libreoffice* kdeconnect aisleriot gnome-mines gnome-sudoku gnome-mahjongg cheese ghex simple-scan wxhexeditor scite -y
sudo apt-get autoremove --purge
sudo apt-get clean
sudo apt update
sudo updatedb
sleep 2

# change desktop background
gsettings set org.gnome.desktop.background picture-uri file:///opt/elrond/elrond/images/elrond_background.jpg
gsettings set org.gnome.shell favorite-apps "['org.gnome.seahorse.Application.desktop', 'org.gnome.Nautilus.desktop', 'org.flameshot.Flameshot.desktop', 'firefox_firefox.desktop', 'firefox.desktop', 'org.gnome.Terminal.desktop', 'code.desktop', 'bless.desktop', 'wireshark.desktop', 'cutter.desktop', 'sqlitebrowser.desktop', 'maltego.desktop']"
sleep 2

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
sleep 2

sudo rm -rf /home/$USER/.config/autostart/gnome-terminal.desktop
mkdir /home/parallels/.config/autostart
sudo mv gnome-terminal.desktop /home/$USER/.config/autostart/
sudo chmod 755 /home/$USER/.config/autostart/gnome-terminal.desktop
sudo chown -R $USER:$USER /opt/
sudo updatedb