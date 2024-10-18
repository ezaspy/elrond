#!/bin/bash

USERPROFILE=$(cat /etc/passwd | grep 1000 | cut -d ":" -f 1)
HOSTNAME=$(hostname)

sleep 1
clear
printf "\n  -> Installing and configuring regripper...\n\n"
# downloading regripper for elrond
sudo apt-get install libparse-win32registry-perl -y --fix-missing --allow-unauthenticated
cd /usr/local/src/
sudo rm -r /usr/local/src/regripper/ 2>/dev/null
sudo rm -r /usr/share/regripper/plugins 2>/dev/null
sudo git clone https://github.com/keydet89/RegRipper3.0.git
sudo mv RegRipper3.0 regripper
sudo mkdir /usr/share/regripper
ln -s  /usr/local/src/regripper/plugins /usr/share/regripper/plugins 2>/dev/null
sudo chmod 755 regripper/*
sudo cp regripper/File.pm /usr/share/perl5/Parse/Win32Registry/WinNT/File.pm
sudo cp regripper/Key.pm /usr/share/perl5/Parse/Win32Registry/WinNT/Key.pm
sudo cp regripper/Base.pm /usr/share/perl5/Parse/Win32Registry/Base.pm
set +H
sudo cp regripper/rip.pl regripper/rip.pl.linux
sudo sed -i '77i my \$plugindir \= \"\/usr\/share\/regripper\/plugins\/\"\;' /usr/local/src/regripper/rip.pl.linux 
sudo sed -i '/^#! c:[\]perl[\]bin[\]perl.exe/d' /usr/local/src/regripper/rip.pl.linux
sudo sed -i "1i #!`which perl`" /usr/local/src/regripper/rip.pl.linux
sudo sed -i '2i use lib qw(/usr/lib/perl5/);' /usr/local/src/regripper/rip.pl.linux
sudo cp regripper/rip.pl.linux /usr/local/bin/rip.pl
sudo cp -r /usr/local/src/regripper/ /usr/share/