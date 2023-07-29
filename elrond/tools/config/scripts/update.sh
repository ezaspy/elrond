cd /
sudo rm -rf /opt/elrond
sudo git clone https://github.com/ezaspy/elrond.git /opt/elrond
sudo chmod -R 755 /opt/elrond/
sudo chown -R sansforensics:sansforensics /opt/elrond/
cd ~
sudo updatedb
echo '' | sudo tee ~/.bash_history
history -c