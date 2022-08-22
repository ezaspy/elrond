#!/bin/bash
sudo apt update
../elrond/tools/scripts/./init.sh
../elrond/tools/scripts/./sift.sh
../elrond/tools/scripts/./apfs-fuse.sh
../elrond/tools/scripts/./volatility3.sh
../elrond/tools/scripts/./dwarf2json.sh
../elrond/tools/scripts/./splunk.sh
../elrond/tools/scripts/./elastic.sh
../elrond/tools/scripts/./navigator.sh
sudo updatedb
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.9 python3-pip mlocate build-essential yara john gparted -y --fix-missing
PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring
python3.9 -m pip install setuptools construct==2.10.68
/usr/bin/python3.9 -m pip install --upgrade pip
/usr/bin/python3 -m pip install --upgrade pip
/usr/bin/python -m pip install --upgrade pip
git clone https://github.com/harelsegev/INDXRipper /opt/elrond/elrond/tools/INDXRipper
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