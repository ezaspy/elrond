#!/bin/bash
sleep 1
clear
printf "\n  -> Downloading & Installing PowerShell...\n\n"
wget -q "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb"
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get install powershell -y --fix-missing
sudo rm -rf packages-microsoft-prod.deb
sudo updatedb
sleep 1


