# Configuring SIFT Workstation

## VMware Tools

Download, import (adjust settings such as RAM if desired) and Start SIFT<br>
Shutdown SIFT<br>

Start SIFT (and do the next step immediately upon booting)<br>

#### **Menu Bar -> Virtual Machine -> Reinstall VMware Tools... ->**

Copy VMware-<version_number>.tar.gz -> ~/Downloads<br>
>`cd ~/Downloads`<br>
`tar -xvf VMware-<version_number>.tar.gz`<br>
`cd vmware-tools-distrib`<br>
`sudo ./vmware-install.pl` (select **ENTER** to all except '...recover wasted disk space...' (last one))

<br><br>

## Configuration

#### **Menu Bar -> Virtual Machine -> Settings... ->**

- **'Network Adaptor' -> 'Bridged Networking (Autodetect)'**<br>

#### **Menu Bar -> Virtual Machine -> Reinstall VMware Tools... ->**<br><br>

>`cd /opt`<br>
`sudo git clone https://github.com/ezaspy/elrond`<br>
`cd elrond/`<br>
`./make.sh`<br>
Enter the keys in the following order: **&darr; &darr; ENTER c g**

<br>

### Reverting SIFT Workstation Virtual Machine

#### **Menu Bar -> Virtual Machine -> Settings... ->**

- **Network Adaptor -> Custom (Private)**<br><br><br>
