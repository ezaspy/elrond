# Additional Tools & Commands to Facilitate elrond Analysis

Additional commands and tools to help get data ready for elrond<br><br>
<!-- TABLE OF CONTENTS -->
# Table of Contents

* [Preparing Disk Images](#Preparing-Disk-Images)
    * [Merging Multiple VMDK Files](#Merging-multiple-VMDK-Files)
    * [Convert DMG to E01](#Convert-DMG-to-E01)
* [Preparing Memory Images](Preparing-Memory-Images)
    * [Capturing Memory](#Capturing-Memory)
    * [Creating Symbol Tables (volatility3)](#Creating-Symbol-Tables-volatility3)
    * [Creating Profiles (volatility2.6)](#Creating-Profiles-volatility26)
* [Appendix](#Appendix)
<br><br>

# Preparing Disk Images

## Merging multiple VMDK Files
* VMware Fusion

`/Applications/VMware\ Fusion.app/Contents/Library/vmware-vdiskmanager -r <location of virtual machine>.vmwarevm/Virtual\ Disk.vmdk -t 0 <new disk name>.vmdk`
* VMware Workstation

`C:\Program Files (x86)\VMware\VMware Player\vmware-vdiskmanager.exe -r <location of virtual machine>.vmwarevm\VirtualDisk.vmdk -t 0 <new disk name>.vmdk`<br><br><br>

## Convert DMG to E01
If you have collected a macOS disk image in the form of a DMG, you can convert it into E01. Note, this can only be done on a macOS device (preferably not the same host where the disk was acquired).<br>
`$ brew install libewf`<br>
`$ hdiutil attach -nomount <filename>.dmg`<br>
`$ diskutil list`
 * Confirm device name which DMG has been mounted<br>

`$ ewfacquire -t evidence -v /dev/diskN`
 * Create evidence.E01 from /dev/diskN (N being the number it has been assigned - usually 3 or 4 but depends on how many additional disks or images are mounted)<br>
 * Adjust 'Evidence segment file size' to a value larger then the size of the DMG - this forces it to create a single E01 file as opposed to multiple<br>

`$ hdiutil detach /dev/disk4`<br><br><br>


# Preparing Memory Images

## Capturing Memory
### macOS
* Download osxpmem from https://github.com/ezaspy/elrond/tree/main/tools/<br>

`$ sudo chown -R root:wheel osxpmem.app/ && sudo osxpmem.app/osxpmem -o mem.aff4 && sudo osxpmem.app/osxpmem -e /dev/pmem -o mem.raw mem.aff4`<br><br>
### Linux
* Download avml from https://github.com/ezaspy/elrond/tree/main/tools/<br>

`$ HOSTNAME=$(uname -r) && sudo chmod +x avml && HOSTNAME=$(uname -r) && sudo ./avml <path/to/directory>/$(uname -r).mem`<br><br><br>

## Creating Symbol Tables (volatility3)
### Linux
#### Analysis Machine
* Download relevant debug symbol and execute the following commands (relevant to your distro):<br>

Obtain the relevant debug symbol
`$ wget <debugsymbol>`
* RHEL: https://access.redhat.com/solutions/9907<br>
`$ yum install <path-to-debug-package> /tmp/`<br>
* Ubuntu: http://ddebs.ubuntu.com/ubuntu/pool/main/l/linux/<br>
`$ dpkg -x <path-to-debug-package> /tmp/`<br>

INSERT ADDITIONAL COMMANDS HERE...

Copy created symbol table to Analysis Machine<br>
`$ ./dwarf2json linux --elf /tmp/usr/lib/debug/boot/<downloaded-ddeb> > .../volatility3/volatility3/symbols/linux/<downloaded-ddeb>.json`<br>

See Appendix for information on additional Linux distros<br><br><br>


## Creating Profiles (volatility2.6)
### macOS
#### Target Machine
* Download the relevant Kernel Debug Kit: http://developer.apple.com/hardwaredrivers<br>
* Download volatility from https://github.com/ezaspy/elrond/tree/main/tools/<br>

`$ unzip volatility.zip`<br>
`$ dwarfdump -arch x86_64 /Library/Developer/KDKs/KDK_<MACOSXVERSION>_16D32.kdk/System/Library/Kernels/kernel.dSYM > <MACOSXVERSION>_x64.dwarfdump`<br>
`$ python tools/mac/convert.py <MACOSXVERSION>.dwarfdump converted-<MACOSXVERSION>_x64.dwarfdump`<br>
`$ python tools/mac/convert.py converted-<MACOSXVERSION>_x64.dwarfdump > 10.12.3.64bit.vtypes`<br>
`$ dsymutil -s -arch x86_64 /Library/Developer/KDKs/KDK_<MACOSXVERSION>_16D32.kdk/System/Library/Kernels/kernel > <MACOSXVERSION>.64bit.symbol.dsymutil`<br>
`$ zip <MACOSXVERSION>.64bit.zip <MACOSXVERSION>.64bit.symbol.dsymutil <MACOSXVERSION>.64bit.vtypes`<br>
Copy created profile to Analysis Machine
#### Analysis Machine
`$ cp <MACOSXVERSION>.64bit.zip volatility/plugins/overlays/mac/`<br><br><br>
### Linux
#### Target Machine
* Download volatility from https://github.com/ezaspy/elrond/tree/main/tools/<br>

`$ sudo apt-get install build-essential && sudo apt-get install dwarfdump`<br>
`$ unzip volatility.zip && sudo rm -rf __MACOSX/ && cd volatility/tools/linux/ && HOSTNAME=$(uname -r)`<br>
`$ sudo make -C /lib/modules/$(uname -r)/build/ CONFIG_DEBUG_INFO=y M=$PWD modules`<br>
`$ sudo rm -rf module.dwarf && sudo dwarfdump -di ./module.o > module.dwarf`<br>
`$ sudo zip [RHEL|Ubuntu]64-$(uname -r).zip module.dwarf /boot/System.map-$(uname -r)`<br>
Copy created profile to Analysis Machine
#### Analysis Machine
`$ cp [RHEL|Ubuntu]64-$(uname -r).zip volatility/plugins/overlays/linux/`<br><br><br><br>


# Appendix
### Additional Linux Distro debuginfo
Required for volatility3 symbol tables, you will need to obain the relevant debuginfo and then install it in accordance with your Linux distro<br>
* CentOS: http://debuginfo.centos.org<br>
* SUSE: http://blog.dynofu.me/post/2015/08/31/linux-kernel-dbuginfo.html<br>
* Debian: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=365349<br>
* Fedora: https://fedoraproject.org/wiki/Packaging:Debuginfo<br>
* Oracle UEK: https://oss.oracle.com/ol6/debuginfo/<br><br>


### Building avml (Analysis Machine)
**Only required if execution of avml fails**

`$ sudo apt-get install musl-dev musl-tools musl && curl https://sh.rustup.rs -sSf | sh -s -- -y && rustup target add x86_64-unknown-linux-musl && cargo build --release --target x86_64-unknown-linux-musl && cargo build --release --target x86_64-unknown-linux-musl --no-default-features`<br>
`$ cd target/x86_64-unknown-linux-musl/release/` (directory path might be slightly different)<br><br>

### Pre-created Profiles (volatility2.6)

For a full list/repository of currently developed profiles for volatility2.6 please visit https://github.com/ezaspy/profiles
Of course, you develop your own, please adhere to the following naming conventions:
* Uploading to GitHub (directory structure):
    * **profiles -> Mac -> 10.11 -> ElCapitan_10.11.1_15B42.zip**
    * **profiles -> Linux -> x64 -> Ubuntu1010[-4.4.0-203-generic].zip**
* Importing into volatility locally (.../volatility/plugins/overlays/[mac|linux]/):
    * **10.11/ElCapitan_10.11.1_15B42.zip**
    * **LinuxUbuntu1010[-4.4.0-203-generic]x64.zip**
