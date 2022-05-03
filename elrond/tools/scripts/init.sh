#!/bin/bash
clear
printf "\n [+] Running initialization script for elrond...\n\n"
sudo apt install mlocate build-essential yara john -y --fix-missing
updatedb
# configuring elrond
sudo chmod -R 744 /opt/elrond/
export PATH=$PATH:/opt/elrond
sudo chmod +x /opt/elrond/elrond.py
sudo updatedb
clear
sleep 2
