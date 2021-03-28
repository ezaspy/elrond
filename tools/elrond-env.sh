#!/bin/bash
cd ..
mkdir ~/Desktop/posters && mv ~/Desktop/*.pdf ~/Desktop/posters/ && sudo chmod 744 -R ~/Desktop/posters/ && sudo chown sansforensics:sansforensics -R ~/Desktop/posters/
sudo chmod 744 /opt/elrond/tools/elrond_background.jpg
gsettings set org.gnome.desktop.background picture-uri "file:///opt/elrond/images/elrond_background.jpg"
export PATH=$PATH:/opt/elrond && sudo chmod +x /opt/elrond/elrond.py
sudo add-apt-repository ppa:deadsnakes/ppan && sudo apt-get update -y && sudo apt-get install python3.9 -y
sudo git clone https://github.com/volatilityfoundation/volatility3 && sudo mv volatility3/ /usr/lib/python3.9/ && sudo chmod -R 755 /usr/lib/python3.9/volatility3/ && sudo chown -R root:root /usr/lib/python3.9/volatility3/
sudo apt install libimage-exiftool-perl -y && sudo apt install libbz2-dev libattr1-dev cmake cmake-curses-gui -y
sudo rm -r /usr/local/go/ && wget https://golang.org/dl/go1.15.10.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf go1.15.10.linux-amd64.tar.gz && sudo rm -rf go1.15.10.linux-amd64.tar.gz && export PATH=$PATH:/usr/local/go/bin
#sudo git clone https://github.com/ezaspy/dwarf2json.git && cd dwarf2json/
sudo apt install john -y
cd /usr/local/bin
sudo git clone https://github.com/ezaspy/apfs-fuse.git
cd apfs-fuse
sudo git submodule init
sudo git submodule update
sudo mkdir build
cd build
sudo cmake ..
sudo ccmake .
cd /usr/local/bin/apfs-fuse/build/
sudo make
cd /opt/elrond
echo "Press ENTER to continue..."
read answer
echo " Enjoy elrond!"
sleep 5
gsettings set org.gnome.desktop.background picture-uri "file:///opt/elrond/tools/elrond_background.jpg"
clear