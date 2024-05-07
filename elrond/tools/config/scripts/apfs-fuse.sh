#!/bin/bash

USER=$(echo $USERNAME)
sleep 1
clear
printf "\n  -> Installing & configuring apfs-fuse...\n\n"
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
sleep 1