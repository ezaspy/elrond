#!/bin/bash
sudo apt install mlocate build-essential john -y --fix-missing
wget https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip > /opt/elrond/elrond/tools/rds_modernm.zip
updatedb
# configuring elrond
clear
printf "\n [+] Running initialization script for elrond...\n\n"
sudo chmod -R 744 /opt/elrond/
export PATH=$PATH:/opt/elrond
sudo chmod +x /opt/elrond/elrond.py
clear
sleep 2
