#!/bin/bash
cd /opt/elrond
sudo chmod 744 -R /opt/elrond/
sudo chown sansforensics:sansforensics -R /opt/elrond/
export PATH=$PATH:/opt/elrond
sudo chmod +x /opt/elrond/elrond/config.sh
sudo chmod +x /opt/elrond/elrond/elrond.py
clear
sudo /opt/elrond/elrond/./config.sh
