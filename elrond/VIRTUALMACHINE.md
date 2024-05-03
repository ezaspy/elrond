# Preparing Virtual Machine

* [Parallels](#Parallels)
* [VMware](#VMware)

## Parallels

Download and import [Ubuntu 22.04](https://ubuntu.com/download/server/arm) (adjust settings such as RAM if desired)<br>

##### **Menu Bar -> Actions -> Configure... ->**
  - Hardware...
    - +...
      - Hard Disk...
        - **Type: `New image file`**
        - **Location: `Ubuntu 22.04-0.hdd`
        - **Size: `20.0GB`** (more, if desired)
        - **OK**
- Start Ubuntu
<br>

### Reverting Virtual Machine

##### **Menu Bar -> Actions -> Configure... ->**

- **Security -> Isolate Linux from ...**
<br><br><br>

## VMware

### _Virtual Machine Settings_
Download and import [SANS SIFT Worksation](https://www.sans.org/tools/sift-workstation/) (adjust settings such as RAM if desired)<br>

##### **Menu Bar -> Virtual Machine -> Settings... ->**

- **Network Adaptor -> NAT/Bridged**<br>

##### **Menu Bar -> Virtual Machine -> Settings... ->**
  - Add Device...
    - New Hard Disk...
      - Add...
        - **File name: `Virtual Disk 2.vmdk`**
        - **Disk Size: `20.00GB`** (more, if desired)
        - **Advanced options: `None`**
        - **Apply**
- Start SIFT
<br>

### Reverting Virtual Machine

- ##### **Menu Bar -> Virtual Machine -> Settings... ->**
  - **Network Adaptor -> Custom (Private)**<br><br>

---

_If you experience any issues, please try building a new SIFT Workstation VM and then raise an issue inline with the instructions in the [README.md](https://github.com/ezaspy/elrond/blob/main/elrond/README.md)_
