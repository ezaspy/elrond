#!/bin/bash
mkdir ~/Desktop/posters
mv ~/Desktop/*.pdf ~/Desktop/posters/
gsettings set org.gnome.desktop.background picture-uri "file:///opt/elrond/tools/elrond_background.jpg"
cd ..
export PATH=$PATH:/opt/elrond
sudo chmod +x /opt/elrond/elrond.py
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install python3.7
sudo git clone https://github.com/volatilityfoundation/volatility3
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
echo " Now just run the following commands:"
echo "   cd /usr/local/bin/apfs-fuse/build/"
echo "   sudo make"
echo "   cd ~/elrond"
sleep 5
echo " Press ENTER to continue..."
read answer
echo " Enjoy elrond. Bye!"
sleep 2
kill $PPID
