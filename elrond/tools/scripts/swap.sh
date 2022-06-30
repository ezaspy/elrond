#!/bin/bash
printf "\n [+] Creating linux_swap space on /dev/sdb...\n\n"
sudo mkswap /dev/sdb
sudo swapon /dev/sdb