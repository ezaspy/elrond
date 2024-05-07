#!/bin/bash

USER=$(echo $USERNAME)
# change desktop background
gsettings set org.gnome.desktop.background picture-uri file:///opt/elrond/elrond/images/elrond_background.jpg

# change favourite apps
gsettings set org.gnome.shell favorite-apps "['org.gnome.seahorse.Application.desktop', 'org.gnome.Nautilus.desktop', 'org.flameshot.Flameshot.desktop', 'firefox_firefox.desktop', 'firefox.desktop', 'org.gnome.Terminal.desktop', 'code.desktop', 'bless.desktop', 'wireshark.desktop', 'cutter-re.desktop', 'sqlitebrowser_sqlitebrowser.desktop', 'maltego.desktop']"