#!/bin/bash

USERPROFILE=$(cat /etc/passwd | grep 1000 | cut -d ":" -f 1)
HOSTNAME=$(hostname)

# change desktop background
gsettings set org.gnome.desktop.background picture-uri file:///opt/elrond/elrond/images/elrond_background.jpg

# change favourite apps
gsettings set org.gnome.shell favorite-apps "['org.gnome.seahorse.Application.desktop', 'org.gnome.Nautilus.desktop', 'org.flameshot.Flameshot.desktop', 'firefox_firefox.desktop', 'firefox.desktop', 'org.gnome.Terminal.desktop', 'code.desktop', 'bless.desktop', 'cyberchef_cyberchef.desktop', 'wireshark.desktop', 'cutter-re.desktop', 'sqlitebrowser_sqlitebrowser.desktop', 'maltego.desktop']"

# configure terminal to launch on login
sudo rm -rf /home/$USERPROFILE/.config/autostart/gnome-terminal.desktop
sudo rm -rf gnome-terminal.desktop
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
sudo chmod 744 gnome-terminal.desktop
sudo chown -R "$USERPROFILE":"$USERPROFILE" gnome-terminal.desktop
mkdir -p /home/$USERPROFILE/.config/autostart
sudo mv gnome-terminal.desktop /home/$USERPROFILE/.config/autostart/
sudo chmod 744 /home/$USERPROFILE/.config/autostart/gnome-terminal.desktop
sudo chmod -R 744 ~/Desktop/CobaltStrike-Defence

echo '' | sudo tee ~/.bash_history
history -c
clear
sudo reboot