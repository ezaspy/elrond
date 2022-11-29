#!/bin/bash
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