#!/bin/bash
sudo mv ../elrond/elrond/ /opt/elrond
sudo chmod -R 744 /opt/elrond/
export PATH=$PATH:/opt/elrond
sudo chmod +x /opt/elrond/config.sh
sudo chmod +x /opt/elrond/elrond.py
clear
cd /opt/elrond
sudo ./config.sh
