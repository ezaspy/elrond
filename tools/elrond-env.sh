#!/bin/bash
mkdir ~/tmp
cd ~/tmp
mkdir ~/Desktop/posters
mv ~/Desktop/*.pdf ~/Desktop/posters/
sudo chmod 744 -R ~/Desktop/posters/
sudo chown sansforensics:sansforensics -R ~/Desktop/posters/
sudo chmod -R 744 /opt/elrond/
gsettings set org.gnome.desktop.background picture-uri "file:///opt/elrond/images/elrond_background.jpg"
export PATH=$PATH:/opt/elrond
sudo chmod +x /opt/elrond/elrond.py
sleep 1
sudo apt install libgdbm-dev libreadline-dev libsqlite3-dev libbz2-dev libattr1-dev cmake cmake-curses-gui liblzma-dev john -y --fix-missing
sudo apt install libnss3-dev -y --fix-missing
git clone https://github.com/volatilityfoundation/volatility3.git
sudo mv volatility3/ /usr/lib/python3.8/
sudo chmod -R 755 /usr/lib/python3.8/volatility3/
sudo chown -R root:root /usr/lib/python3.8/volatility3/
wget https://golang.org/dl/go1.15.10.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.15.10.linux-amd64.tar.gz
sudo rm -rf go1.15.10.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
cd /usr/lib/python2.7/distutils/
sudo git clone https://github.com/ezaspy/dwarf2json.git
cd /usr/local/bin
sudo git clone https://github.com/ezaspy/apfs-fuse.git
cd apfs-fuse
sudo git submodule init
sudo git submodule update
sudo mkdir build
cd build
sudo cmake ..
sudo ccmake .
sudo make
sleep 1
sudo chmod 744 -R /opt/elrond/
sudo chown sansforensics:sansforensics -R /opt/elrond/
cd /opt/elrond
printf "\n\n\n    Press ENTER to continue...\n"
read answer
printf "\n    Finished! - enjoy elrond!\n"
sleep 4
gsettings set org.gnome.desktop.background picture-uri "file:///opt/elrond/tools/elrond_background.jpg"
sudo rm -rf ~/tmp
clear