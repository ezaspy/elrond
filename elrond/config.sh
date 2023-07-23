#!/bin/bash
sleep 1
clear
sudo apt update
cd /opt/elrond/elrond
sudo chmod -R 755 /opt/elrond/
chown -R sansforensics:sansforensics /opt/elrond
/opt/elrond/elrond/tools/config/scripts/./init.sh
/opt/elrond/elrond/tools/config/scripts/./apfs-fuse.sh
/opt/elrond/elrond/tools/config/scripts/./nsrl.sh
/opt/elrond/elrond/tools/config/scripts/./volatility3.sh
/opt/elrond/elrond/tools/config/scripts/./dwarf2json.sh
/opt/elrond/elrond/tools/config/scripts/./splunk.sh
/opt/elrond/elrond/tools/config/scripts/./elastic.sh
/opt/elrond/elrond/tools/config/scripts/./navigator.sh
/opt/elrond/elrond/tools/config/scripts/./finish.sh