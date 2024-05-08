#!/bin/bash

sudo chmod 744 -R /opt/elrond/
sudo chown $(whoami):$(whoami) -R /opt/elrond/
sudo chmod +x /opt/elrond/elrond/config.sh
sudo chmod +x /opt/elrond/elrond/elrond.py
sudo cp /opt/elrond/elrond/elrond.sh ~/elrond.sh
sudo /opt/elrond/elrond/./config.sh
