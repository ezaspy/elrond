#!/bin/bash

USERPROFILE=$(cat /etc/passwd | grep 1000 | cut -d ":" -f 1)
HOSTNAME=$(hostname)

# dwarf2json
sleep 1
clear
printf "\n  -> Installing & configuring dwarf2json...\n\n"
wget https://golang.org/dl/go1.15.10.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.15.10.linux-amd64.tar.gz
sudo rm -rf go1.15.10.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
cd /opt/elrond/elrond/tools/
sudo git clone https://github.com/ezaspy/dwarf2json.git
cd /opt/elrond/elrond
sleep 1

# volatility3
printf "\n  -> Installing & configuring volatility3 and dependancies...\n\n"
# sudo apt install build-essential libreadline-dev libncursesw5-dev libssl-dev libc6-dev libffi-dev zlib1g-dev -y --fix-missing --allow-unauthenticated
# sudo apt-get install checkinstall libgdbm-dev libreadline-dev libnss3-dev libsqlite3-dev tk-dev liblzma-dev -y -y --fix-missing --allow-unauthenticated
sudo git clone https://github.com/volatilityfoundation/volatility3.git /usr/local/lib/python3.8/dist-packages/volatility3 
sudo mkdir -p /usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/
sudo mkdir -p /usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/windows/tcpip.pdb/
sudo git clone https://github.com/JPCERTCC/Windows-Symbol-Tables.git
sudo mv Windows-Symbol-Tables/symbols/windows/*.pdb/ /usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/windows/
sudo rm -rf Windows-Symbol-Tables
sudo chmod -R 755 /usr/local/lib/python3.8/dist-packages/volatility3/
sudo chown -R root:root /usr/local/lib/python3.8/dist-packages/volatility3/
sleep 1