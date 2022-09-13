#!/bin/bash
sleep 1
clear
printf "\n  -> Configuring and updating sift & sift-cli...\n\n"
sift update
sift upgrade
sudo updatedb
sleep 1