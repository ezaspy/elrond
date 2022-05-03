#!/bin/bash
printf "\n [+] Configuring and updating sift & sift-cli...\n\n"
sift update
sift upgrade
sudo updatedb
clear
sleep 2
