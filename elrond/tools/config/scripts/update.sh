cd /
sudo rm -rf /opt/elrond
sudo git clone https://github.com/ezaspy/elrond.git /opt/elrond
sudo chmod -R 755 /opt/elrond/
sudo chown -R $USER:$USER /opt/elrond/
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
# installing vmware_tools
/opt/elrond/elrond/tools/config/scripts/./virtual.sh
# pulling down additional github repos
sudo git clone https://github.com/harelsegev/INDXRipper /opt/elrond/elrond/tools/INDXRipper
sudo git clone https://github.com/PoorBillionaire/USN-Journal-Parser.git
sudo git clone https://github.com/ezaspy/KStrike.git
sudo git clone https://github.com/ezaspy/WMI_Forensics
sudo git clone https://github.com/ezaspy/etl-parser
sudo wget -O /opt/elrond/elrond/tools/.splunk.deb "https://download.splunk.com/products/splunk/releases/9.0.5/linux/splunk-9.0.5-e9494146ae5c-linux-2.6-amd64.deb"
# tidying up
sudo apt update
echo fs.inotify.max_user_watches=1048576 | sudo tee -a /etc/sysctl.conf
echo '
export PS1="\e[1;36m\u@\h:\e[m \e[0;32m\w\e[m\n$ "' >> /home/sansforensics/.bashrc
# configuring elrond
sudo chmod -R 755 /opt/elrond/
sudo chown -R $USER:$USER /opt/elrond
sudo chmod +x /opt/elrond/elrond/elrond.py
echo "export PATH=$PATH:/opt/elrond/elrond" >> /home/sansforensics/.bashrc
cd ~
printf "\n\n  -> elrond has been successfully updated. Press ENTER to continue..."
read answer
sleep 1
sudo updatedb
echo '' | sudo tee ~/.bash_history
history -c
sleep 1
clear