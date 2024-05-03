# install azure cli
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash > /dev/null 2>&1

# install aws cli
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" > /dev/null 2>&1
unzip awscliv2.zip > /dev/null 2>&1
sudo ./aws/install > /dev/null 2>&1
rm awscliv2.zip

# install gcp cli
sudo apt-get install google-cloud-cli

# installing additional github tools
sudo git clone https://github.com/PoorBillionaire/USN-Journal-Parser.git /opt/USN-Journal-Parser > /dev/null 2>&1
sudo git clone https://github.com/ezaspy/KStrike.git /opt/KStrike > /dev/null 2>&1
sudo git clone https://github.com/ezaspy/WMI_Forensics /opt/WMI_Forensics > /dev/null 2>&1
sudo git clone https://github.com/ezaspy/etl-parser /opt/etl-parser > /dev/null 2>&1
sudo mkdir -p /opt/TZWorks /opt/BlueTeamPowerShell /opt/Sysmon/SysmonForLinux /home/sansforensics/Desktop/CobaltStrike-Defence/content
sudo git clone https://github.com/ezaspy/bruce.git /opt/bruce > /dev/null 2>&1
sudo git clone https://github.com/BookStackApp/BookStack.git /opt/bookstack > /dev/null 2>&1
sudo git clone https://github.com/ezaspy/gandalf.git /opt/gandalf > /dev/null 2>&1
sudo git clone https://github.com/ezaspy/bruce.git /opt/bruce > /dev/null 2>&1
sudo git clone https://github.com/SigmaHQ/sigma.git /opt/sigma > /dev/null 2>&1
sudo git clone https://github.com/sans-blue-team/DeepBlueCLI.git /opt/DeepBlueCLI > /dev/null 2>&1
sudo git clone https://github.com/EricZimmerman/KapeFiles.git /opt/KAPE > /dev/null 2>&1
sudo git clone https://github.com/Invoke-IR/PowerForensics.git /opt/PowerForensics > /dev/null 2>&1
sudo git clone https://github.com/ufrisk/MemProcFS.git /opt/MemProcFS > /dev/null 2>&1
sudo git clone https://github.com/vinaypamnani/wmie2/ /opt/WMIExplorer > /dev/null 2>&1
sudo git clone https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence /home/sansforensics/Desktop/CobaltStrike-Defence > /dev/null 2>&1
sudo git clone https://github.com/MarkBaggett/freq.git /opt/freq > /dev/null 2>&1
sudo git clone https://github.com/elceef/dnstwist.git /opt/dnstwist > /dev/null 2>&1
sudo git clone https://github.com/ezaspy/rdap.git /opt/rdap > /dev/null 2>&1
sudo git clone https://github.com/sherlock-project/sherlock.git /opt/sherlock > /dev/null 2>&1
sudo git clone https://github.com/jonbakerfish/TweetScraper.git /opt/TweetScraper > /dev/null 2>&1
sudo git clone https://github.com/Dheerajmadhukar/karma_v2.git /opt/karma > /dev/null 2>&1
sudo git clone https://github.com/Sysinternals/SysmonForLinux.git /opt/Sysmon/SysmonForLinux > /dev/null 2>&1
sudo git clone https://github.com/xroche/httrack.git --recurse /opt/httrack > /dev/null 2>&1