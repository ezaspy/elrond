#!/bin/bash
sleep 1
echo fs.inotify.max_user_watches=1048576 | sudo tee -a /etc/sysctl.conf
echo '
export PS1="\e[1;36m\u@\h:\e[m \e[0;32m\w\e[m\n$ "' >> /home/sansforensics/.bashrc
sudo chmod -R 755 /opt/elrond/
sudo chown -R sansforensics:sansforensics /opt/elrond
sudo chmod +x /opt/elrond/elrond/elrond.py
echo "export PATH=$PATH:/opt/elrond" >> /home/sansforensics/.bashrc
cd /opt/elrond/elrond/
clear
printf "\n\n  -> SIFT has been successfully configured for elrond. Press ENTER to continue..."
read answer
sleep 1
sudo updatedb
echo '' | sudo tee ~/.bash_history
history -c
sleep 1
clear