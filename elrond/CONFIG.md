# SIFT-elrond

## _Virtual Machine Settings_
Download and import [SANS SIFT Worksation](https://www.sans.org/tools/sift-workstation/) (adjust settings such as RAM if desired)<br>

#### **Menu Bar -> Virtual Machine -> Settings... ->**

- **Network Adaptor -> NAT/Bridged**<br>

#### **Menu Bar -> Virtual Machine -> Settings... ->**
  - Add Device...
    - New Hard Disk...
      - Add...
        - **File name: `Virtual Disk 2.vmdk`**
        - **Disk Size: `20.00GB` (more, if desired)**
        - **Advanced options: `None`**
        - **Apply**
- Start SIFT<br>

---

## _elrond Configuration_
_Note, the following script will partition and format /dev/sdb. If you have not configured the second HDD as recommended above, it may delete data if you have another drive mounted. You can change this location, by editing the [init.sh](https://github.com/ezaspy/elrond/blob/main/elrond/tools/scripts/init.sh) script_<br><br>
`sudo git clone https://github.com/ezaspy/elrond.git /opt/elrond && sudo /opt/elrond/./make.sh && cd /opt/elrond`<br>
  - **&darr; &darr; `ENTER c g`**
<br><br>

---

## _Reverting Virtual Machine_

- #### **Menu Bar -> Virtual Machine -> Settings... ->**
  - **Network Adaptor -> Custom (Private)**<br><br>

---

_If you experience any issues, please try building a new SIFT Workstation VM and then raise an issue inline with the instructions in the [README.md](https://github.com/ezaspy/elrond/blob/main/elrond/README.md)_<br>