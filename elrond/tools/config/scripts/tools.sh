#!/bin/bash

USERPROFILE=$(cat /etc/passwd | grep 1000 | cut -d ":" -f 1)
HOSTNAME=$(hostname)

# purging unwanted software
sudo apt-get remove --auto-remove --purge thunderbird rhythmbox yelp libreoffice* kdeconnect aisleriot gnome-mines gnome-sudoku gnome-mahjongg cheese ghex simple-scan wxhexeditor scite -y
sudo apt-get purge nodejs -y
sudo apt-get autoremove --purge

# downloading additional repo files
sudo add-apt-repository -y ppa:linuxgndu/sqlitebrowser > /dev/null 2>&1 # db browser for sqlite
yes '' | sudo add-apt-repository ppa:deadsnakes/ppa # INDXRipper
echo 'deb http://download.opensuse.org/repositories/home:/RizinOrg/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/home:RizinOrg.list # cutter-re
curl -fsSL https://download.opensuse.org/repositories/home:RizinOrg/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_RizinOrg.gpg > /dev/null # cutter-re
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
#echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
#sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token --scope kibana
#sudo /usr/share/kibana/bin/kibana-verification-code
#sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
# attack-navigator repos
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | gpg --dearmor | sudo tee /usr/share/keyrings/yarnkey.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/yarnkey.gpg] https://dl.yarnpkg.com/debian stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
/opt/elrond/elrond/tools/config/scripts/./repo.sh
sudo wget https://www.netresec.com/?download=NetworkMiner -O /tmp/networkminer.zip
sudo wget -O /tmp/Maltego.v4.7.0.deb https://downloads.maltego.com/maltego-v4/linux/Maltego.v4.7.0.deb
sudo wget -O /opt/elrond/elrond/tools/.splunk.deb "https://download.splunk.com/products/splunk/releases/9.0.5/linux/splunk-9.0.5-e9494146ae5c-linux-2.6-amd64.deb"

# installing additional features for elrond
sudo apt update
sudo apt install libewf-dev ewf-tools mlocate net-tools build-essential libreadline-dev libncursesw5-dev libssl-dev libc6-dev libffi-dev zlib1g-dev qemu apt-transport-https software-properties-common systemd gnupg xz-utils sqlite3 mdbtools yara clamav clamav-daemon john gparted dos2unix sqlitebrowser python3-apt wireshark libguestfs-tools mono-devel openjdk-17-jdk openjdk-17-jre curl jq elasticsearch kibana python3.9 python3.9-venv bless flameshot cutter-re vim nodejs yarn -y --fix-missing
sudo apt-get install checkinstall libgdbm-dev libreadline-dev libnss3-dev libsqlite3-dev tk-dev liblzma-dev -y --fix-missing

# installing additional software via snap
sudo snap install sqlitebrowser
sudo snap install cyberchef
# installing maltego
sudo dpkg -i /tmp/Maltego.v4.7.0.deb

# installing network-miner
sudo unzip /tmp/networkminer.zip -d /opt/
sudo chmod +x /opt/NetworkMiner_2-8-1/NetworkMiner.exe
sudo chmod -R go+w /opt/NetworkMiner_2-8-1/AssembledFiles/
sudo chmod -R go+w /opt/NetworkMiner_2-8-1/Captures/

# initialising clamav
sudo apt update
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam

# installing additional github tools
sudo rm -rf /opt/TZWorks 
sudo rm -rf /opt/BlueTeamPowerShell
sudo rm -rf /opt/Sysmon/SysmonForLinux
sudo rm -rf /home/$USERPROFILE/Desktop/CobaltStrike-Defence/content
sudo git clone https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence /home/$USERPROFILE/Desktop/CobaltStrike-Defence
sudo mkdir -p /home/$USERPROFILE/Desktop/CobaltStrike-Defence/content
sudo mkdir -p /opt/TZWorks /opt/BlueTeamPowerShell /opt/Sysmon/SysmonForLinux

sudo rm -rf /opt/USN-Journal-Parser
sudo git clone https://github.com/PoorBillionaire/USN-Journal-Parser.git /opt/USN-Journal-Parser
sudo rm -rf /opt/KStrike
sudo git clone https://github.com/ezaspy/KStrike.git /opt/KStrike
sudo rm -rf /opt/plaso
sudo git clone https://github.com/log2timeline/plaso.git /opt/plaso
sudo rm -rf /opt/etl-parser
sudo git clone https://github.com/ezaspy/etl-parser /opt/etl-parser
sudo rm -rf /opt/bruce
sudo git clone https://github.com/ezaspy/bruce.git /opt/bruce
sudo rm -rf /opt/bookstack
sudo git clone https://github.com/BookStackApp/BookStack.git /opt/bookstack
sudo rm -rf /opt/gandalf
sudo git clone https://github.com/ezaspy/gandalf.git /opt/gandalf
sudo rm -rf /opt/sigma
sudo git clone https://github.com/SigmaHQ/sigma.git /opt/sigma
sudo rm -rf /opt/DeepBlueCLI
sudo git clone https://github.com/sans-blue-team/DeepBlueCLI.git /opt/DeepBlueCLI
sudo rm -rf /opt/KAPE
sudo git clone https://github.com/EricZimmerman/KapeFiles.git /opt/KAPE
sudo rm -rf /opt/MemProcFS
sudo git clone https://github.com/ufrisk/MemProcFS.git /opt/MemProcFS
sudo rm -rf /opt/WMIExplorer
sudo git clone https://github.com/vinaypamnani/wmie2/ /opt/WMIExplorer
sudo rm -rf /opt/WMI_Forensics
sudo git clone https://github.com/ezaspy/WMI_Forensics /opt/WMI_Forensics
sudo rm -rf /opt/PowerForensics
sudo git clone https://github.com/Invoke-IR/PowerForensics.git /opt/PowerForensics
sudo rm -rf /opt/freq
sudo git clone https://github.com/MarkBaggett/freq.git /opt/freq
sudo rm -rf /opt/dnstwist
sudo git clone https://github.com/elceef/dnstwist.git /opt/dnstwist
sudo rm -rf /opt/rdap
sudo git clone https://github.com/ezaspy/rdap.git /opt/rdap
sudo rm -rf /opt/sherlock
sudo git clone https://github.com/sherlock-project/sherlock.git /opt/sherlock
sudo rm -rf /opt/TweetScraper
sudo git clone https://github.com/jonbakerfish/TweetScraper.git /opt/TweetScraper
sudo rm -rf /opt/karma
sudo git clone https://github.com/Dheerajmadhukar/karma_v2.git /opt/karma
sudo rm -rf /opt/Sysmon/SysmonForLinux
sudo git clone https://github.com/Sysinternals/SysmonForLinux.git /opt/Sysmon/SysmonForLinux
sudo rm -rf /opt/httrack
sudo git clone https://github.com/xroche/httrack.git --recurse /opt/httrack
sudo rm -rf /opt/attack-navigator
sudo git clone https://github.com/mitre-attack/attack-navigator.git /opt/attack-navigator

# downloading indx-parser
/opt/elrond/elrond/tools/config/scripts/./indx.sh