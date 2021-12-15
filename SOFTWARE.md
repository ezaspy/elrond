# Configuring SIFT Workstation
## VMware Tools
Download, import (adjust settings such as RAM if desired) and Start SIFT<br>
Shutdown SIFT<br>

### Configuring SIFT Workstation Virtual Machine
#### **Menu Bar -> Virtual Machine -> Settings... ->**
* **'Add Device...' -> 'CD/DVD Drive' -> 'Autodetect'**<br>

Restart SIFT<br>
#### **Menu Bar -> Virtual Machine -> Reinstall VMware Tools... ->**

Copy VMware-<version_number>.tar.gz -> ~/Downloads<br>
`cd ~/Downloads`<br>
`tar -xvf VMware-<version_number>.tar.gz`<br>
`cd vmware-tools-distrib`<br>
`sudo ./vmware-install.pl` (select **ENTER** to all except '...recover wasted disk space...' (last one))<br><br><br>

## Installing & Configuring Software
#### **Menu Bar -> Virtual Machine -> Settings... ->**
* **'Network Adaptor' -> 'Bridged Networking (Autodetect)'**<br>
#### **Menu Bar -> Virtual Machine -> Reinstall VMware Tools... ->**
### Condensed Version
`cd /opt`<br>
`sudo git clone https://github.com/ezaspy/elrond`<br>
`cd elrond/`<br><br>

### SIFT 20.04
`sudo chmod u+x elrond_env.sh`<br>
`sudo ./elrond_env.sh`<br>
**ENTER**<br>
**Y ENTER**<br>
Enter the keys in the following order: **&darr; &darr; c g ENTER**<br><br>

### SIFT 18.04
#### Installing Python3.8.7 (required for volatility3)
`sudo apt install build-essential checkinstall libgdbm-dev libreadline-dev libsqlite3-dev libbz2-dev libattr1-dev libncursesw5-dev libssl-dev tk-dev libc6-dev libffi-dev zlib1g-dev cmake cmake-curses-gui liblzma-dev john -y --fix-missing && sudo apt install libnss3-dev -y --fix-missing`<br>
`sudo wget https://www.python.org/ftp/python/3.8.7/Python-3.8.7.tgz && sudo tar xzf Python-3.8.7.tgz && cd Python-3.8.7 && sudo ./configure --enable-optimizations && sudo make altinstall && cd ..`
#### Installing & Configuring volatility3 (optional)
`git clone https://github.com/volatilityfoundation/volatility3 && sudo mv volatility3/ /usr/lib/python3.8.7/ && sudo chmod -R 755 /usr/lib/python3.8.7/volatility3/ && sudo chown -R root:root /usr/lib/python3.8.7/volatility3/`
#### Installing exiftool
`sudo apt install libimage-exiftool-perl`
#### Installing apfs-fuse (required for macOS disk images)
`sudo apt install libbz2-dev libattr1-dev cmake cmake-curses-gui && cd /usr/local/bin && sudo git clone https://github.com/ezaspy/apfs-fuse.git && cd apfs-fuse && sudo git submodule init && sudo git submodule update && sudo mkdir build && cd build && sudo cmake .. && sudo ccmake .`<br>
Enter the keys in the following order: **&darr; &darr; c g ENTER**<br>
`sudo make`<br>
`cd ~/Downloads/elrond`<br><br><br>

### Reverting SIFT Workstation Virtual Machine
#### **Menu Bar -> Virtual Machine -> Settings... ->**
* **Network Adaptor -> Custom (Private)**<br><br><br>

