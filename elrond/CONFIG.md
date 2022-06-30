# Configuring SIFT Workstation

- Download, import (adjust settings such as RAM if desired) and Start SIFT
- Shutdown SIFT
<br>

It is **highly recommended** to configure at least 4GB/4096MB RAM and also add another HDD dedicated for linux-swap.<br>
#### **Menu Bar -> Virtual Machine -> Settings... ->**
  - Add Device...
    - New Hard Disk...
      - Add...
        - File name: `Virtual Disk 2.vmdk`
        - Disk Size: `20.00GB` (more, if desired)
        - Advanced options: `None`
        - Apply
- Start SIFT (and do the next step immediately upon booting)<br>
    #### **Menu Bar -> Virtual Machine -> Reinstall VMware Tools... ->**
<br>

Navigate to the newly mounted CD and copy VMware-<version_number>.tar.gz -> ~/Downloads<br>
- Open Terminal<br>
  - `cd ~/Downloads`<br>
  - `tar -xvf VMware-<version_number>.tar.gz`<br>
  - `cd vmware-tools-distrib`<br>
  - `sudo ./vmware-install.pl` (select **ENTER** to all except '...recover wasted disk space...' (last one))<br>
- Reboot SIFT
<br>

`sudo git clone https://github.com/ezaspy/elrond.git /opt/elrond`<br>
`cd /opt/elrond/`<br>
`sudo ./make.sh`<br>
- When prompted, enter the keys in the following order:
  - **&darr; &darr; ENTER c g**

<br>

### Reverting SIFT Workstation Virtual Machine

#### **Menu Bar -> Virtual Machine -> Settings... ->**

- **Network Adaptor -> Custom (Private)**<br><br><br>
