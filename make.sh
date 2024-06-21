#!/bin/bash

USERPROFILE=$(cat /etc/passwd | grep 1000 | cut -d ":" -f 1)
HOSTNAME=$(hostname)

sudo chmod -R 744 /opt/elrond/
sudo chown -R "$USERPROFILE":"$USERPROFILE" /opt/elrond/
sudo chmod +x /opt/elrond/elrond/config.sh
sudo chmod +x /opt/elrond/elrond/elrond.py
sudo apt install curl -y
sudo /opt/elrond/elrond/./config.sh