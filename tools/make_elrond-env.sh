#!/bin/bash
mkdir /home/sansforensics/Desktop/posters
mv /home/sansforensics/Desktop/*.pdf /home/sansforensics/Desktop/posters/
gsettings set org.gnome.desktop.background picture-uri "file:///home/sansforensics/Downloads/elrond/tools/elrond_background.jpg"
cd ..
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update && sudo apt-get install python3.7
git clone https://github.com/volatilityfoundation/volatility3
sudo mv volatility3/ /usr/lib/python3.7/
sudo chmod -R 755 /usr/lib/python3.7/volatility3/
sudo chown -R root:root /usr/lib/python3.7/volatility3/
sudo apt install libimage-exiftool-perl
sudo apt install libbz2-dev libattr1-dev cmake cmake-curses-gui
sudo apt-get install john -y
cd /usr/local/bin
sudo git clone https://github.com/ezaspy/apfs-fuse.git
cd apfs-fuse
sudo git submodule init
sudo git submodule update
sudo mkdir build
cd build
sudo cmake ..
sudo ccmake .