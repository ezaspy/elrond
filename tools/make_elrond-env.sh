#!/bin/bash
cd ~/Desktop
mkdir posters
mv *.pdf posters/
cd ..
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update && sudo apt-get install python3.7
git clone https://github.com/volatilityfoundation/volatility3
sudo mv volatility3/ /usr/lib/python3.7/
sudo chmod -R 755 /usr/lib/python3.7/volatility3/
sudo chown -R root:root /usr/lib/python3.7/volatility3/
sudo apt-get install -y dwarfdump
sudo apt install libimage-exiftool-perl
sudo apt install libbz2-dev libattr1-dev cmake cmake-curses-gui
cd /usr/local/bin
sudo git clone https://github.com/ezaspy/apfs-fuse.git
cd apfs-fuse
sudo git submodule init
sudo git submodule update
sudo mkdir build
cd build
sudo cmake ..
sudo ccmake .