cd /
sudo rm -rf /opt/elrond
sudo git clone https://github.com/ezaspy/elrond.git /opt/elrond
sudo chmod -R 755 /opt/elrond/
sudo chown -R sansforensics:sansforensics /opt/elrond/
cd ~
printf "\n\n  -> elrond has been successfully updated. Press ENTER to continue..."
read answer
sleep 1
sudo updatedb
echo '' | sudo tee ~/.bash_history
history -c
sleep 1
clear