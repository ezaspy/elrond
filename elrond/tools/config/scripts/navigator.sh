#!/bin/bash

USER=$(echo $USERNAME)
sleep 1
clear
printf "\n  -> Installing & configuring attack-navigator...\n\n"
sudo apt-get purge nodejs -y
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | gpg --dearmor | sudo tee /usr/share/keyrings/yarnkey.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/yarnkey.gpg] https://dl.yarnpkg.com/debian stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
sudo apt-get update
sudo apt install nodejs yarn -y --fix-missing
npm cache clean -f
sudo npm install n -g
sudo -E env "PATH=$PATH" n 16
sudo npm install -g @angular/cli
sudo npm install -g pm2
sudo git clone https://github.com/mitre-attack/attack-navigator.git /opt/attack-navigator
cd /opt/attack-navigator/nav-app
sudo npm install
sudo pm2 start --time --name="attack-navigator" ng -- serve
sleep 1
curl https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json -o /opt/attack-navigator/nav-app/src/assets/enterprise-attack.json
sudo chmod -R 755 /opt/attack-navigator/
sudo chown -R $USER:$USER /opt/attack-navigator/
# sudo pm2 stop attack-navigator
cd /opt/elrond
sleep 1