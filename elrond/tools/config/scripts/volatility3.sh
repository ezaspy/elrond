#!/bin/bash
sleep 1
clear
printf "\n  -> Installing & configuring volatility3 and dependancies...\n\n"
sudo apt install build-essential libreadline-dev libncursesw5-dev libssl-dev libc6-dev libffi-dev zlib1g-dev -y --fix-missing
sudo apt-get install checkinstall libgdbm-dev libreadline-dev libnss3-dev libsqlite3-dev tk-dev liblzma-dev -y --fix-missing
git clone https://github.com/volatilityfoundation/volatility3.git
sudo mv volatility3/ /usr/local/lib/python3.8/dist-packages
git clone https://github.com/JPCERTCC/Windows-Symbol-Tables.git
sudo mkdir -p /usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/
sudo mkdir -p /usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/windows/tcpip.pdb/
sudo mv Windows-Symbol-Tables/symbols/windows/*.pdb/ /usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/windows/
sudo rm -rf Windows-Symbol-Tables
sudo chmod -R 755 /usr/local/lib/python3.8/dist-packages/volatility3/
sudo chown -R root:root /usr/local/lib/python3.8/dist-packages/volatility3/
sudo updatedb
sleep 1