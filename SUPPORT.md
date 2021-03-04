# Additional Tools & Commands to Facilitate elrond Analysis

Additional commands and tools to help get data ready for elrond
<!-- TABLE OF CONTENTS -->
## Table of Contents

* [Multiple VMDK Files](#Merging-multiple-.vmdk-disk-files)
* [Convert DMG to E01](#Convert-DMG-to-E01)
* [Capturing Memory & Creating Profiles](#Capturing-Memory-and-Creating-Profiles-(volatility2.6))
    * [macOS](#macOS-(Target-Machine))
    * [Linux](#Linux-(Target-Machine))
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

`sudo chown -R root:wheel osxpmem.app/`<br>
`sudo osxpmem.app/osxpmem -o /tmp/mem.aff4`<br>
`sudo osxpmem.app/osxpmem -e /dev/pmem -o /tmp/mem.raw /tmp/mem.aff4`<br>
`sudo osxpmem.app/osxpmem -u`

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

`sudo chmod +x avml && HOSTNAME=$(uname -r) && sudo ./avml <path/to/directory>/$(uname -r).mem`<br><br>
#### Creating Profile
* Download volatility from https://github.com/ezaspy/elrond/tree/main/tools/<br>

`sudo apt-get install build-essential && sudo apt-get install dwarfdump`
`mkdir volatility && cd volatility && unzip ../volatility.zip && cd tools/linux/ && HOSTNAME=$(uname -r)`<br>
`sudo make -C /lib/modules/$(uname -r)/build/ CONFIG_DEBUG_INFO=y M=$PWD modules`<br>
`sudo rm -rf module.dwarf && sudo dwarfdump -di ./module.o > module.dwarf`<br>
`sudo zip [RHEL|Ubuntu]64-$(uname -r).zip module.dwarf /boot/System.map-$(uname -r)`<br>
Copy **[RHEL|Ubuntu]64-$(uname -r).zip** to **/usr/lib/python2.7/dist-packages/volatility/plugins/overlays/linux/** on analysis machine<br>
