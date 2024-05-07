#!/bin/bash

USER=$(echo $USERNAME)
# install azure cli
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# install aws cli
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
rm awscliv2.zip

# install gcp cli
sudo snap install google-cloud-cli