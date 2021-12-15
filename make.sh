#!/bin/bash
sudo mv ../elrond/elrond /opt/elrond
sleep 1
sudo mv ./LICENSE /opt/elrond
sudo mv ./README.md /opt/elrond
sleep 1
sudo chmod -R 744 /opt/elrond/
export PATH=$PATH:/opt/elrond
sudo chmod +x /opt/elrond/config.sh
sudo chmod +x /opt/elrond/elrond.py
clear
cd /opt/elrond
sleep 4
sudo ./config.sh
