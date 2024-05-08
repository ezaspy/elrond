#!/bin/bash

USERPROFILE=$(cat /etc/passwd | grep 1000 | cut -d ":" -f 1)
HOSTNAME=$(hostname)

sleep 1
clear
printf "\n  -> Configuring python3.9...\n\n"
python3 -m keyring --disable

# installing python libraries
USER=$USERPROFILE
python3 -m pip install --upgrade pip
sudo python3 -m pip install --upgrade pip
python3 -m pip install requests pandas openpyxl jupyterlab notebook voila
sudo python3 -m pip install requests pandas openpyxl jupyterlab notebook voila
sudo chmod -R 744 /opt/elrond/
sudo chown -R "$USERPROFILE":"$USERPROFILE" /opt/elrond
cd /opt/etl-parser
sudo python3 -m pip install -e .
cd /opt/elrond/elrond

PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring
sudo git clone https://github.com/harelsegev/INDXRipper /opt/elrond/elrond/tools/INDXRipper
/usr/bin/python3.9 -m pip install --upgrade pip
/usr/bin/python3.8 -m pip install --upgrade pip
/usr/bin/python3 -m pip install --upgrade pip
/usr/bin/python -m pip install --upgrade pip
python3.9 -m pip install setuptools
python3.9 -m pip install construct==2.10.68
python3.8 -m pip install setuptools
python3.8 -m pip install construct==2.10.68
python3 -m pip install construct
sleep 1