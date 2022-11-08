#!/bin/bash
sleep 1
clear
printf "\n  -> Installing & configuring attack-navigator...\n\n"
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash - && sleep 1
curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | gpg --dearmor | sudo tee /usr/share/keyrings/yarnkey.gpg >/dev/null && sleep 1
echo "deb [signed-by=/usr/share/keyrings/yarnkey.gpg] https://dl.yarnpkg.com/debian stable main" | sudo tee /etc/apt/sources.list.d/yarn.list && sleep 1
sudo apt-get update
sudo apt install nodejs yarn gcc g++ make -y --fix-missing && sleep 4
sudo npm install -g npm@8.6.0 && sleep 4
sudo npm install -g @angular/cli && sleep 4
sudo npm install -g pm2 && sleep 4
sudo git clone https://github.com/mitre-attack/attack-navigator.git /opt/elrond/elrond/tools/attack-navigator && sleep 1
sudo chmod -R 755 /opt/elrond/ && sleep 1
cd /opt/elrond/elrond/tools/attack-navigator/nav-app && sleep 4
sudo npm install && sleep 4
sudo ng build && sleep 4
sudo cp -r dist/ /var/www/html/
sudo mv /var/www/html/dist/ /var/www/html/attack-navigator/
sudo service apache2 restart
sudo updatedb
sleep 1