#!/bin/bash
printf "\n [+] Installing & configuring volatility3 and dependancies...\n\n"
sleep 2
sudo apt install build-essential libreadline-dev libncursesw5-dev libssl-dev libc6-dev libffi-dev zlib1g-dev -y --fix-missing
sudo apt-get install checkinstall libgdbm-dev libreadline-dev libnss3-dev libsqlite3-dev tk-dev liblzma-dev -y --fix-missing
git clone https://github.com/volatilityfoundation/volatility3.git
sudo mv volatility3/ /usr/local/lib/python3.8/dist-packages
sudo chmod -R 755 /usr/local/lib/python3.8/dist-packages/volatility3/
sudo chown -R root:root /usr/local/lib/python3.8/dist-packages/volatility3/
clear
sleep 2