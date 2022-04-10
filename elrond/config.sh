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
clear
printf "\n\n [+] SIFT has been successfully configured for elrond. Press ENTER to continue..."
read answer
sleep 2
cd /opt/elrond/elrond/
clear