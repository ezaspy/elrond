#!/bin/bash
sleep 1
clear
printf "\n  -> Downloading python libraries...\n\n"
# installing python libraries
python3 -m pip install --upgrade pip
python3 -m pip install requests pandas openpyxl usnparser
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install requests pandas openpyxl usnparser
# installing additional github tools
cd /opt/elrond/elrond/tools/
sudo git clone https://github.com/PoorBillionaire/USN-Journal-Parser.git

#sudo wget -q https://github.com/libyal/libscca/releases/download/20231203/libscca-alpha-20231203.tar.gz
#sudo tar xfv libscca-alpha-20231203.tar.gz
#cd libscca-20231203
#sudo ./configure --enable-python
#sudo make
#sudo ldconfig
#sudo git clone https://github.com/libyal/libscca.git
#cd /opt/elrond/elrond/tools/libscca
#sudo ./synclibs.sh
#./autogen.sh

#python setup.py build
#sudo python setup.py install
#cd ..
#sudo git clone https://github.com/bromiley/tools.git win10_pf

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