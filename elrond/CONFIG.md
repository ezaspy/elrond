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
- Start SIFT<br>

`sudo git clone https://github.com/ezaspy/elrond.git /opt/elrond`<br>
`sudo /opt/elrond/./make.sh`<br>
- When prompted, enter the keys in the following order:
  - **&darr; &darr; ENTER c g**

<br>

### Reverting SIFT Workstation Virtual Machine

#### **Menu Bar -> Virtual Machine -> Settings... ->**

- **Network Adaptor -> Custom (Private)**<br><br><br>
