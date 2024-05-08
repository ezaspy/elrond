#!/bin/bash

sudo chmod -R 744 /opt/elrond/
sudo chown -R $(whoami):$(whoami) /opt/elrond/
sudo chmod +x /opt/elrond/elrond/config.sh
sudo chmod +x /opt/elrond/elrond/elrond.py
sudo cp /opt/elrond/elrond/elrond.sh ~/elrond.sh
#sudo /opt/elrond/elrond/./config.sh
