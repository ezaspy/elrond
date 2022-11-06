#!/bin/bash
sleep 1
clear
cd /opt/elrond/elrond
/opt/elrond/elrond/tools/config/scripts/./init.sh
/opt/elrond/elrond/tools/config/scripts/./pwsh.sh
/opt/elrond/elrond/tools/config/scripts/./apfs-fuse.sh
/opt/elrond/elrond/tools/config/scripts/./volatility3.sh
/opt/elrond/elrond/tools/config/scripts/./dwarf2json.sh
/opt/elrond/elrond/tools/config/scripts/./splunk.sh
/opt/elrond/elrond/tools/config/scripts/./elastic.sh
/opt/elrond/elrond/tools/config/scripts/./navigator.sh
/opt/elrond/elrond/tools/config/scripts/./nrsl.sh
sudo chmod -R 744 /opt/elrond/ && sudo chmod +x /opt/elrond/elrond.py
echo "export PATH=$PATH:/opt/elrond" > /home/sansforensics/.bashrc
sudo updatedb
sleep 1
/opt/elrond/elrond/tools/config/scripts/./finish.sh