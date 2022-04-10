#!/bin/bash
printf "\n [+] Installing & configuring the elastic stack...\n\n"
sudo apt install curl jq openjdk-16-jre-headless -y
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt install apt-transport-https -y
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable elasticsearch.service
sudo sysctl -w vm.max_map_count=262144
sudo apt update
sudo apt install logstash
sudo systemctl enable logstash.service
sudo apt update
sudo apt install kibana
sudo /bin/systemctl daemon-reload
sudo systemctl enable kibana.service
clear
sleep 2