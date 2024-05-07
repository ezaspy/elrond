#!/bin/bash

USER=$(echo $USERNAME)
# installing additional github tools
sudo rm -rf /opt/TZWorks 
sudo rm -rf /opt/BlueTeamPowerShell
sudo rm -rf /opt/Sysmon/SysmonForLinux
sudo rm -rf /home/$USER/Desktop/CobaltStrike-Defence/content
sudo mkdir -p /opt/TZWorks /opt/BlueTeamPowerShell /opt/Sysmon/SysmonForLinux

sudo rm -rf /opt/USN-Journal-Parser
sudo git clone https://github.com/PoorBillionaire/USN-Journal-Parser.git /opt/USN-Journal-Parser
sudo rm -rf /opt/KStrike
sudo git clone https://github.com/ezaspy/KStrike.git /opt/KStrike
sudo rm -rf /opt/WMI_Forensics
sudo git clone https://github.com/ezaspy/WMI_Forensics /opt/WMI_Forensics
sudo rm -rf /opt/etl-parser
sudo git clone https://github.com/ezaspy/etl-parser /opt/etl-parser
sudo rm -rf /opt/bruce
sudo git clone https://github.com/ezaspy/bruce.git /opt/bruce
sudo rm -rf /opt/bookstack
sudo git clone https://github.com/BookStackApp/BookStack.git /opt/bookstack
sudo rm -rf /opt/gandalf
sudo git clone https://github.com/ezaspy/gandalf.git /opt/gandalf
sudo rm -rf /opt/bruce
sudo git clone https://github.com/ezaspy/bruce.git /opt/bruce
sudo rm -rf /opt/sigma
sudo git clone https://github.com/SigmaHQ/sigma.git /opt/sigma
sudo rm -rf /opt/DeepBlueCLI
sudo git clone https://github.com/sans-blue-team/DeepBlueCLI.git /opt/DeepBlueCLI
sudo rm -rf /opt/KAPE
sudo git clone https://github.com/EricZimmerman/KapeFiles.git /opt/KAPE
sudo rm -rf /opt/PowerForensics
sudo git clone https://github.com/Invoke-IR/PowerForensics.git /opt/PowerForensics
sudo rm -rf /opt/MemProcFS
sudo git clone https://github.com/ufrisk/MemProcFS.git /opt/MemProcFS
sudo rm -rf /opt/WMIExplorer
sudo git clone https://github.com/vinaypamnani/wmie2/ /opt/WMIExplorer
sudo git clone https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence /home/$USER/Desktop/CobaltStrike-Defence
sudo mkdir -p /home/$USER/Desktop/CobaltStrike-Defence/content
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