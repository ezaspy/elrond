#!/bin/bash
printf "\n [+] Installing & configuring apfs-fuse...\n\n"
sleep 2
sudo apt install libbz2-dev libattr1-dev cmake cmake-curses-gui -y --fix-missing
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
clear
sleep 2