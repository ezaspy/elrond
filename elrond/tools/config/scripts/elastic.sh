#!/bin/bash
sleep 1
clear
printf "\n  -> Installing & configuring elasticsearch...\n\n"
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable elasticsearch.service
sudo /bin/systemctl enable kibana.service
sudo sysctl -w vm.max_map_count=262144
echo vm.max_map_count=262144 | sudo tee -a /etc/sysctl.conf
sleep 1
sudo sysctl -p