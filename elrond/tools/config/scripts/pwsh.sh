#!/bin/bash
sleep 1
clear
printf "\n  -> Installing & configuring PowerShell...\n\n"
wget -q "https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb"
sudo dpkg -i packages-microsoft-prod.deb
sudo apt update
sudo apt-get install powershell -y --fix-missing
sudo rm -rf packages-microsoft-prod.deb
sudo updatedb
sleep 1