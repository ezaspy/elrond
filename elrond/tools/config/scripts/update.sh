#!/bin/bash

USERPROFILE=$(cat /etc/passwd | grep 1000 | cut -d ":" -f 1)
HOSTNAME=$(hostname)

# removing old versions
sudo rm -rf /opt/elrond/elrond/tools/avml*
sudo rm -rf /opt/elrond/elrond/tools/osxpmem.app.zip
sudo rm -rf /opt/elrond/elrond/tools/volatility*
sudo mv /tmp/apps/*.py /opt/elrond/elrond/rivendell/post/splunk/apps/*.py

# downloading latest version
sudo git clone https://github.com/ezaspy/elrond.git

# downloading latest version of additional repos
/opt/elrond/elrond/tools/config/scripts/./repo.sh
/opt/elrond/elrond/tools/config/scripts/./tools.sh
/opt/elrond/elrond/tools/config/scripts/./finish.sh

# finalising update
sudo chmod 744 -R /opt/elrond/
sudo chown "$USERPROFILE":"$USERPROFILE" -R /opt/elrond/
sudo chmod +x /opt/elrond/elrond/config.sh
sudo chmod +x /opt/elrond/elrond/elrond.py
echo "export PATH=$PATH:/opt/elrond/elrond" >> /home/$USERPROFILE/.bashrc
printf "\n\n  -> '"$(hostname)"' has been successfully updated; a reboot is required. Press ENTER to continue..."
read answer
sleep 1
sudo updatedb
# echo '' | sudo tee ~/.bash_history
# history -c
sleep 1
clear