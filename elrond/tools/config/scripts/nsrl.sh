#!/bin/bash

USERPROFILE=$(cat /etc/passwd | grep 1000 | cut -d ":" -f 1)
HOSTNAME=$(hostname)

wget -O /opt/elrond/elrond/tools/RDS_2024.03.1_modern.zip https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2024.03.1/RDS_2024.03.1_modern.zip