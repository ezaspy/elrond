# Additional Tools & Commands to Facilitate elrond Analysis

Additional commands and tools to help get data ready for elrond<br><br>
<!-- TABLE OF CONTENTS -->
## Table of Contents

* [Multiple VMDK Files](#Merging-multiple-.vmdk-disk-files)
* [Convert DMG to E01](#Convert-DMG-to-E01)
* [Capturing Memory & Creating Profiles](#Capturing-Memory-and-Creating-Profiles-(volatility2.6))
    * [macOS](#macOS-(Target-Machine))
    * [Linux](#Linux-(Target-Machine))
* [Appendix](#Appendix)
    * [Building avml](#Building-avml-(Analysis-Machine))
    * [Pre-created Profiles (volatility2.6)](#Pre-created-Profiles-(volatility2.6))
<br><br>

## Merging multiple .vmdk disk files

* VMware Fusion

`/Applications/VMware\ Fusion.app/Contents/Library/vmware-vdiskmanager -r <location of virtual machine>.vmwarevm/Virtual\ Disk.vmdk -t 0 <new disk name>.vmdk`

* VMware Workstation

`C:\Program Files (x86)\VMware\VMware Player\vmware-vdiskmanager.exe -r <location of virtual machine>.vmwarevm\VirtualDisk.vmdk -t 0 <new disk name>.vmdk`
<br><br><br>

## Convert DMG to E01

If you have collected artefacts into a DMG file (using option "dmg" or "ro-dmg"), you can convert it into E01.<br>
`$ brew install libewf`<br>
`$ hdiutil attach -nomount xxxxxx_YYYYMMDD_hhmmss.dmg`<br>
`$ diskutil list    -> confirm device name which DMG has been mounted`<br>
`$ ewfacquire -t evidence -v /dev/disk4s1    -> create evidence.E01 from /dev/disk4s1`<br>
`$ hdiutil detach /dev/disk4`
<br><br><br>

## Capturing Memory and Creating Profiles (volatility2.6)

### macOS (Target Machine)

#### Capturing Memory
* Download osxpmem from https://github.com/ezaspy/elrond/tree/main/tools/<br>

`sudo chown -R root:wheel osxpmem.app/ && sudo osxpmem.app/osxpmem -o mem.aff4 && sudo osxpmem.app/osxpmem -e /dev/pmem -o mem.raw mem.aff4`<br>

#### Creating Profile
* Download the relevant Kernel Debug Kit: http://developer.apple.com/hardwaredrivers<br>
* Download volatility3 from https://github.com/ezaspy/elrond/tree/main/tools/<br>

`unzip volatility3.zip`<br>
`dwarfdump -arch x86_64 /Library/Developer/KDKs/KDK_<MACOSXVERSION>_16D32.kdk/System/Library/Kernels/kernel.dSYM > <MACOSXVERSION>_x64.dwarfdump`<br>
`python tools/mac/convert.py <MACOSXVERSION>.dwarfdump converted-<MACOSXVERSION>_x64.dwarfdump`<br>
`python tools/mac/convert.py converted-<MACOSXVERSION>_x64.dwarfdump > 10.12.3.64bit.vtypes`<br>
`dsymutil -s -arch x86_64 /Library/Developer/KDKs/KDK_<MACOSXVERSION>_16D32.kdk/System/Library/Kernels/kernel > <MACOSXVERSION>.64bit.symbol.dsymutil`<br>
`zip <MACOSXVERSION>.64bit.zip <MACOSXVERSION>.64bit.symbol.dsymutil <MACOSXVERSION>.64bit.vtypes`<br>
`cp <MACOSXVERSION>.64bit.zip volatility/plugins/overlays/mac/`<br>
<br><br>

### Linux (Target Machine)

#### Capturing Memory
* Download avml from https://github.com/ezaspy/elrond/tree/main/tools/<br>

`HOSTNAME=$(uname -r) && sudo chmod +x avml && HOSTNAME=$(uname -r) && sudo ./avml <path/to/directory>/$(uname -r).mem`<br><br>
#### Creating Profile
* Download volatility from https://github.com/ezaspy/elrond/tree/main/tools/<br>

`sudo apt-get install build-essential && sudo apt-get install dwarfdump`<br>
`unzip volatility.zip && sudo rm -rf __MACOSX/ && cd volatility/tools/linux/ && HOSTNAME=$(uname -r)`<br>
`sudo make -C /lib/modules/$(uname -r)/build/ CONFIG_DEBUG_INFO=y M=$PWD modules`<br>
`sudo rm -rf module.dwarf && sudo dwarfdump -di ./module.o > module.dwarf`<br>
`sudo zip [RHEL|Ubuntu]64-$(uname -r).zip module.dwarf /boot/System.map-$(uname -r)`<br><br>
Copy **[RHEL|Ubuntu]64-$(uname -r).zip** to **/usr/lib/python2.7/dist-packages/volatility/plugins/overlays/linux/** on analysis machine<br><br><br><br>


## Appendix

### Building avml (Analysis Machine)
**Only required if execution of avml fails**

`sudo apt-get install musl-dev musl-tools musl && curl https://sh.rustup.rs -sSf | sh -s -- -y && rustup target add x86_64-unknown-linux-musl && cargo build --release --target x86_64-unknown-linux-musl && cargo build --release --target x86_64-unknown-linux-musl --no-default-features`<br>
`cd target/x86_64-unknown-linux-musl/release/` (directory path might be slightly different)<br><br>

### Pre-created Profiles (volatility2.6)

For a full list/repository of currently developed profiles for volatility2.6 please visit https://github.com/ezaspy/profiles
Of course, you develop your own, please adhere to the following naming conventions:
* Uploading to GitHub (directory structure):
    * **profiles -> Mac -> 10.11 -> ElCapitan_10.11.1_15B42.zip**
    * **profiles -> Linux -> x64 -> Ubuntu1010[-4.4.0-203-generic].zip**
* Importing into volatility locally (.../volatility/plugins/overlays/[mac|linux]/):
    * **10.11/ElCapitan_10.11.1_15B42.zip**
    * **LinuxUbuntu1010[-4.4.0-203-generic]x64.zip**
