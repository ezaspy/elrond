#!/bin/bash
sleep 1
clear
printf "\n  -> Installing & configuring attack-navigator...\n\n"
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | gpg --dearmor | sudo tee /usr/share/keyrings/yarnkey.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/yarnkey.gpg] https://dl.yarnpkg.com/debian stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
sudo apt-get update
sudo apt install nodejs yarn gcc g++ make -y --fix-missing
sudo npm install -g npm@8.6.0
sudo npm install -g @angular/cli
sudo npm install -g pm2
cd /opt/elrond/elrond/tools/ && git clone https://github.com/mitre-attack/attack-navigator.git
sudo chmod -R 744 /opt/elrond/ && cd attack-navigator/nav-app
npm install && npm audit fix --force && ng build && ng build
sudo cp -r dist/ /var/www/html/
sudo mv /var/www/html/dist/ /var/www/html/attack-navigator/
sudo service apache2 restart
sudo updatedb
sleep 1