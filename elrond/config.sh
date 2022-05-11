#!/bin/bash
../elrond/tools/scripts/./init.sh
../elrond/tools/scripts/./sift.sh
../elrond/tools/scripts/./volatility3.sh
../elrond/tools/scripts/./dwarf2json.sh
../elrond/tools/scripts/./apfs-fuse.sh
../elrond/tools/scripts/./splunk.sh
../elrond/tools/scripts/./elastic.sh
../elrond/tools/scripts/./navigator.sh
sudo updatedb
sudo apt install mlocate build-essential yara john -y --fix-missing
updatedb
# configuring elrond
sudo chmod -R 744 /opt/elrond/
export PATH=$PATH:/opt/elrond
sudo chmod +x /opt/elrond/elrond.py
sudo updatedb
sleep 2
clear
printf "\n\n [+] SIFT has been successfully configured for elrond. Press ENTER to continue..."
read answer
sleep 2
cd /opt/elrond/elrond/
clear