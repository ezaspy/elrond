#!/bin/bash
sudo mv ../elrond /opt/elrond
sudo mv ../LICENSE /opt/elrond
sudo mv ../README.md /opt/elrond
sudo chmod -R 744 /opt/elrond/
export PATH=$PATH:/opt/elrond
sudo chmod +x /opt/elrond/config.sh
sudo chmod +x /opt/elrond/elrond.py
clear
cd /opt/elrond
sudo ./config.sh
