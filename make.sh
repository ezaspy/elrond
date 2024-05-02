#!/bin/bash
cd /opt/elrond
sudo chmod 744 -R /opt/elrond/
sudo chown $USER:$USER -R /opt/elrond/
export PATH="/opt/elrond:$PATH"
source ~/.bashrc
sudo chmod +x /opt/elrond/elrond/config.sh
sudo chmod +x /opt/elrond/elrond/elrond.py
clear
sudo /opt/elrond/elrond/./config.sh
