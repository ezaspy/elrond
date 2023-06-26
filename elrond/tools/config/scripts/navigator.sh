#!/bin/bash
sleep 1
clear
printf "\n  -> Installing & configuring attack-navigator...\n\n"
sudo apt-get purge nodejs -y
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | gpg --dearmor | sudo tee /usr/share/keyrings/yarnkey.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/yarnkey.gpg] https://dl.yarnpkg.com/debian stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
sudo apt-get update
sudo apt install npm nodejs yarn gcc g++ make -y --fix-missing
npm cache clean -f
sudo npm install n -g
sudo -E env "PATH=$PATH" n 16
sudo npm install -g @angular/cli
sudo npm install -g pm2
sudo git clone https://github.com/mitre-attack/attack-navigator.git /opt/elrond/elrond/tools/attack-navigator
sudo chmod -R 755 /opt/elrond/
sudo chown -R sansforensics:sansforensics /opt/elrond/
cd /opt/elrond/elrond/tools/attack-navigator/nav-app
sudo npm install
sudo ng build
sudo cp -r dist/ /var/www/html/
sudo mv /var/www/html/dist/ /var/www/html/attack-navigator/
sudo service apache2 restart
sleep 1