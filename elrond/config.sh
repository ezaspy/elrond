#!/bin/bash
sudo apt update
../elrond/tools/config/scripts/./init.sh
../elrond/tools/config/scripts/./sift.sh
../elrond/tools/config/scripts/./apfs-fuse.sh
../elrond/tools/config/scripts/./volatility3.sh
../elrond/tools/config/scripts/./dwarf2json.sh
../elrond/tools/config/scripts/./splunk.sh
#../elrond/tools/config/scripts/./elastic.sh
../elrond/tools/config/scripts/./navigator.sh
sudo updatedb
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.9 python3-pip mlocate build-essential yara john gparted -y --fix-missing
PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring
git clone https://github.com/harelsegev/INDXRipper /opt/elrond/elrond/tools/INDXRipper
/usr/bin/python3.9 -m pip install --upgrade pip
/usr/bin/python3 -m pip install --upgrade pip
/usr/bin/python -m pip install --upgrade pip
sudo python3.9 -m pip install setuptools
sudo python3.9 -m pip install construct==2.10.68
python3.9 -m pip install setuptools
python3.9 -m pip install construct==2.10.68
#cd /opt/elrond/elrond/tools/INDXRipper
#python3.9 -m pip install virtualenv
#python3.9 -m virtualenv venv
#source venv/bin/activate
#pip install construct==2.10.68
#sudo venv/bin/python INDXRipper.py -V
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