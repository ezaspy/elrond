#!/bin/bash
sleep 1
clear
printf "\n  -> Downloading python libraries...\n\n"
# installing python libraries
python3 -m pip install --upgrade pip
python3 -m pip install requests pandas openpyxl
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install requests pandas openpyxl
# installing additional github tools
cd /opt/elrond/elrond/tools/
sudo git clone https://github.com/PoorBillionaire/USN-Journal-Parser.git
sudo git clone https://github.com/ezaspy/KStrike.git
sudo git clone https://github.com/ezaspy/WMI_Forensics
sudo git clone https://github.com/ezaspy/etl-parser
sudo chmod -R 744 /opt/elrond/
sudo chown -R sansforensics:sansforensics /opt/elrond
cd /opt/elrond/elrond/tools/etl-parser
python3 -m pip install -e .
cd /opt/elrond/elrond
# installing vscode, because I like it
wget -q "https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb"
sudo dpkg -i packages-microsoft-prod.deb
wget -q https://packages.microsoft.com/keys/microsoft.asc -O- | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main"