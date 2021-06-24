#!/bin/bash
mkdir ~/tmp
cd ~/tmp
sudo chmod -R 744 /opt/elrond/
gsettings set org.gnome.desktop.background picture-uri "file:///opt/elrond/images/desktop_bkgd_lotr.jpg"
export PATH=$PATH:/opt/elrond
sudo chmod +x /opt/elrond/elrond.py
sleep 1
sudo apt install mlocate build-essential checkinstall libgdbm-dev libreadline-dev libsqlite3-dev libbz2-dev libattr1-dev libncursesw5-dev libssl-dev tk-dev libc6-dev libffi-dev zlib1g-dev cmake cmake-curses-gui liblzma-dev john -y --fix-missing
sudo apt install libnss3-dev -y --fix-missing
#sudo wget https://www.python.org/ftp/python/3.8.7/Python-3.8.7.tgz
#sudo tar xzf Python-3.8.7.tgz
#cd Python-3.8.7
#sudo ./configure --enable-optimizations
#sudo make altinstall
#cd ..
git clone https://github.com/volatilityfoundation/volatility3.git
sudo mv volatility3/ /usr/local/lib/python3.8/dist-packages
sudo chmod -R 755 /usr/local/lib/python3.8/dist-packages/volatility3/
sudo chown -R root:root /usr/local/lib/python3.8/dist-packages/volatility3/
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
cd ~/tmp
#curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
#sudo apt-get install -y nodejs
#npm install -g @angular/cli
#git clone https://github.com/mitre-attack/attack-navigator.git
#cd nav-app
#npm install
#ng serve
sudo chmod 744 -R /opt/elrond/
sudo chown sansforensics:sansforensics -R /opt/elrond/
cd /opt/elrond
printf "\n\n  Press ENTER to continue...\n"
read answer
printf "\n    Finished - enjoy elrond!\n"
sleep 2
cd ..
gsettings set org.gnome.desktop.background picture-uri "file:///opt/elrond/images/desktop_bkgd_lotr.jpg"
sudo rm -rf ~/tmp
clear