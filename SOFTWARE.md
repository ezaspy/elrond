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
`cd elrond/tools/`<br>
`sudo chmod u+x elrond-env.sh`<br>
`sudo ./elrond-env.sh`<br>
**ENTER**<br>
**Y ENTER**<br>
Enter the keys in the following order: **&darr; &darr; c g ENTER**<br>

### Long Version
#### Installing python3.9
`sudo add-apt-repository ppa:deadsnakes/ppa && sudo apt-get update && sudo apt-get install python3.9`
#### Configuring python3.9 (optional)
`sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 1`
#### Installing Volatility3
`git clone https://github.com/volatilityfoundation/volatility3 && sudo mv volatility3/ /usr/lib/python3.9/`
#### Configuring Volatility3
`sudo chmod -R 755 /usr/lib/python3.9/volatility3/ && sudo chown -R root:root /usr/lib/python3.9/volatility3/`
#### Installing exilftool
`sudo apt install libimage-exiftool-perl`
#### Installing apfs-fuse
`sudo apt install libbz2-dev libattr1-dev cmake cmake-curses-gui && cd /usr/local/bin && sudo git clone https://github.com/ezaspy/apfs-fuse.git && cd apfs-fuse && sudo git submodule init && sudo git submodule update && sudo mkdir build && cd build && sudo cmake .. && sudo ccmake .`<br>
Enter the keys in the following order: **&darr; &darr; c g ENTER**<br>
`sudo make`<br>
`cd ~/Downloads/elrond`<br><br><br>

### Reverting SIFT Workstation Virtual Machine
#### **Menu Bar -> Virtual Machine -> Settings... ->**
* **Network Adaptor -> Custom (Private)**<br><br><br>

