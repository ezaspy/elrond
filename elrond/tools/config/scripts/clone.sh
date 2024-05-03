# install azure cli
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# install aws cli
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
rm awscliv2.zip

# install gcp cli
sudo snap install google-cloud-cli

# installing additional github tools
sudo git clone https://github.com/PoorBillionaire/USN-Journal-Parser.git /opt/USN-Journal-Parser
sudo git clone https://github.com/ezaspy/KStrike.git /opt/KStrike
sudo git clone https://github.com/ezaspy/WMI_Forensics /opt/WMI_Forensics
sudo git clone https://github.com/ezaspy/etl-parser /opt/etl-parser
sudo mkdir -p /opt/TZWorks /opt/BlueTeamPowerShell /opt/Sysmon/SysmonForLinux /home/sansforensics/Desktop/CobaltStrike-Defence/content
sudo git clone https://github.com/ezaspy/bruce.git /opt/bruce
sudo git clone https://github.com/BookStackApp/BookStack.git /opt/bookstack
sudo git clone https://github.com/ezaspy/gandalf.git /opt/gandalf
sudo git clone https://github.com/ezaspy/bruce.git /opt/bruce
sudo git clone https://github.com/SigmaHQ/sigma.git /opt/sigma
sudo git clone https://github.com/sans-blue-team/DeepBlueCLI.git /opt/DeepBlueCLI
sudo git clone https://github.com/EricZimmerman/KapeFiles.git /opt/KAPE
sudo git clone https://github.com/Invoke-IR/PowerForensics.git /opt/PowerForensics
sudo git clone https://github.com/ufrisk/MemProcFS.git /opt/MemProcFS
sudo git clone https://github.com/vinaypamnani/wmie2/ /opt/WMIExplorer
sudo git clone https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence /home/sansforensics/Desktop/CobaltStrike-Defence
sudo git clone https://github.com/MarkBaggett/freq.git /opt/freq
sudo git clone https://github.com/elceef/dnstwist.git /opt/dnstwist
sudo git clone https://github.com/ezaspy/rdap.git /opt/rdap
sudo git clone https://github.com/sherlock-project/sherlock.git /opt/sherlock
sudo git clone https://github.com/jonbakerfish/TweetScraper.git /opt/TweetScraper
sudo git clone https://github.com/Dheerajmadhukar/karma_v2.git /opt/karma
sudo git clone https://github.com/Sysinternals/SysmonForLinux.git /opt/Sysmon/SysmonForLinux
sudo git clone https://github.com/xroche/httrack.git --recurse /opt/httrack