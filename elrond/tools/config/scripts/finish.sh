#!/bin/bash
sleep 1
echo fs.inotify.max_user_watches=1048576 | sudo tee -a /etc/sysctl.conf
sleep 1
export PATH=$PATH:/opt/elrond/elrond
echo '
export PS1="\e[0;36m\u@\h:\e[m \e[0;32m\W\e[m\n$ "' >> /home/sansforensics/.bashrc
sleep 1
cd /opt/elrond/elrond/
clear
printf "\n\n  -> SIFT has been successfully configured for elrond. Press ENTER to continue..."
read answer
sleep 1
cat /dev/null > ~/.bash_history
history -c
sleep 1
clear