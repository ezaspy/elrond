#!/bin/bash
sleep 1
clear
sudo apt update
../elrond/tools/config/scripts/./init.sh
../elrond/tools/config/scripts/./sift.sh
../elrond/tools/config/scripts/./apfs-fuse.sh
../elrond/tools/config/scripts/./volatility3.sh
../elrond/tools/config/scripts/./dwarf2json.sh
../elrond/tools/config/scripts/./splunk.sh
#../elrond/tools/config/scripts/./elastic.sh
../elrond/tools/config/scripts/./navigator.sh
updatedb
# configuring elrond
sudo chmod -R 744 /opt/elrond/
export PATH=$PATH:/opt/elrond
sudo chmod +x /opt/elrond/elrond.py
sudo updatedb
sleep 1
clear
printf "\n\n  -> SIFT has been successfully configured for elrond. Press ENTER to continue..."
read answer
cd /opt/elrond/elrond/
clear
sleep 1