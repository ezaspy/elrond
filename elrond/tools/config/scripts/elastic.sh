#!/bin/bash
sleep 1
clear
printf "\n  -> Installing & configuring the elastic stack...\n\n"
sudo apt install curl jq openjdk-16-jre-headless -y
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt install apt-transport-https -y
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch logstash kibana
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable elasticsearch.service
sudo /bin/systemctl enable logstash.service
sudo /bin/systemctl enable kibana.service
sudo sysctl -w vm.max_map_count=262144
sudo updatedb