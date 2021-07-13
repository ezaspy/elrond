#!/bin/bash
# configuring elrond
mkdir ~/tmp
cd ~/tmp
sudo chmod -R 744 /opt/elrond/
export PATH=$PATH:/opt/elrond
sudo chmod +x /opt/elrond/elrond.py
clear
sleep 2
printf "\n\n  Installing & configuring volatility3 and dependancies...\n"
# installing volatility3
sleep 5
sudo apt install mlocate build-essential checkinstall libgdbm-dev libreadline-dev libsqlite3-dev libbz2-dev libattr1-dev libncursesw5-dev libssl-dev tk-dev libc6-dev libffi-dev zlib1g-dev cmake cmake-curses-gui liblzma-dev john -y --fix-missing
sudo apt install libnss3-dev -y --fix-missing
git clone https://github.com/volatilityfoundation/volatility3.git
sudo mv volatility3/ /usr/local/lib/python3.8/dist-packages
sudo chmod -R 755 /usr/local/lib/python3.8/dist-packages/volatility3/
sudo chown -R root:root /usr/local/lib/python3.8/dist-packages/volatility3/
clear
sleep 5
# installing dwarf2json
wget https://golang.org/dl/go1.15.10.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.15.10.linux-amd64.tar.gz
sudo rm -rf go1.15.10.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
sudo git clone https://github.com/ezaspy/dwarf2json.git
clear
sleep 5
printf "\n\n  Installing & configuring apfs-fuse...\n"
# installing apfs-fuse
sleep 5
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
sleep 5
printf "\n\n  Installing & configuring attack-navigator...\n"
# installing attack-navigator
sleep 5
cd /tmp
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
sudo apt-get install nodejs yarn -y
sudo npm install -g npm@7.19.1
sudo npm install -g @angular/cli
sudo npm install -g pm2
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator/nav-app
npm install
ng build
sudo cp -r dist/ /var/www/html/
sudo mv /var/www/html/dist /var/www/html/attack-navigator
sudo mv /var/www/html/attack-navigator/assets/config.json /var/www/html/attack-navigator/assets/config.json.orig
sudo systemctl start apache2
clear
sleep 5
# finishing
cd /opt/elrond
sudo chmod 744 -R /opt/elrond/
sudo chown sansforensics:sansforensics -R /opt/elrond/
printf "\n\n  SIFT has been successfully configured for elrond. Press ENTER to continue..."
read answer
printf "\n   Enjoy!\n"
sleep 2
cd ..
#gsettings set org.gnome.desktop.background picture-uri "file:///opt/elrond/images/desktop_bkgd_lotr.jpg"
sudo rm -rf ~/tmp
clear