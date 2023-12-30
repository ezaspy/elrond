#!/bin/bash
sleep 1
clear
printf "\n  -> Downloading additional elrond repository components...\n\n"
# downloading additional tools for elrond
cd /tmp
wget --load-cookies /tmp/cookies.txt "https://drive.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://drive.google.com/uc?export=download&id=1mVrkLp84jchHRrAxqXvSpDdZhIKsH9Fi' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1mVrkLp84jchHRrAxqXvSpDdZhIKsH9Fi" -O elrond-archive.zip && rm -rf /tmp/cookies.txt
unzip elrond-archive.zip 1> /dev/null
rm -rf __MACOSX/
#/opt/elrond/elrond/tools/
unzip tools.zip 1> /dev/null
sudo mv avml /opt/elrond/elrond/tools/
sudo mv avml.zip /opt/elrond/elrond/tools/
sudo mv osxpmem.app.zip /opt/elrond/elrond/tools/
sudo mv volatility.zip /opt/elrond/elrond/tools/
sudo mv volatility3.zip /opt/elrond/elrond/tools/
#/opt/elrond/elrond/rivendell/memory/
unzip volatility-sym-prof-plug.zip 1> /dev/null
sudo mv volatility /opt/elrond/elrond/rivendell/memory/
sudo mv volatility3 /opt/elrond/elrond/rivendell/memory/
#/opt/elrond/elrond/rivendell/post/splunk/
unzip apps.zip 1> /dev/null
sudo mkdir /opt/elrond/elrond/rivendell/post/splunk/apps/
sudo mv apps/*.py /opt/elrond/elrond/rivendell/post/splunk/apps/
#/opt/elrond/elrond/tools/config/VMwareTools-10.3.23-16594550.tar.gz
sudo mv VMwareTools-10.3.23-16594550.tar.gz /opt/elrond/elrond/tools/config/
sudo rm -rf /tmp/elrond-archive.zip
cd ~