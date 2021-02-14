# Additional Tools & Commands to facilitate elrond

Additional commands and tools to help support with getting data ready for elrond
<br><br>

## Merging multiple .vmdk disk files

* VMware Fusion
<br>

`/Applications/VMware\ Fusion.app/Contents/Library/vmware-vdiskmanager -r <location of virtual machine>.vmwarevm/Virtual\ Disk.vmdk -t 0 <new disk name>.vmdk`

* VMware Workstation
<br>

`C:\Program Files (x86)\VMware\VMware Player\vmware-vdiskmanager.exe -r <location of virtual machine>.vmwarevm\VirtualDisk.vmdk -t 0 <new disk name>.vmdk`
<br><br><br><br>

## Convert DMG to E01

If you have collected artefacts into a DMG file (using option "dmg" or "ro-dmg"), you can convert it into E01.<br>
`$ brew install libewf`<br>
`$ hdiutil attach -nomount xxxxxx_YYYYMMDD_hhmmss.dmg`<br>
`$ diskutil list    -> confirm device name which DMG has been mounted`<br>
`$ ewfacquire -t evidence -v /dev/disk4s1    -> create evidence.E01 from /dev/disk4s1`<br>
`$ hdiutil detach /dev/disk4`
<br><br><br><br>

## Capturing and Converting memory

### macOS

* Analysis Machine

Download osxpmem from https://github.com/ezaspy/elrond/tools/<br>

* Target Machine

Copy osxpmem to the host and run the following commands:<br>
`sudo chown -R root:wheel osxpmem.app/`<br>
`sudo osxpmem.app/osxpmem -o /tmp/mem.aff4`<br>
`sudo osxpmem.app/osxpmem -e /dev/pmem -o /tmp/mem.raw /tmp/mem.aff4`<br>
`sudo osxpmem.app/osxpmem -u`
<br><br>

### Linux

* Analysis Machine

Download avml from https://github.com/ezaspy/elrond/tools/<br>
`sudo apt-get install musl-dev musl-tools musl && curl https://sh.rustup.rs -sSf | sh -s -- -y && rustup target add x86_64-unknown-linux-musl && cargo build --release --target x86_64-unknown-linux-musl && cargo build --release --target x86_64-unknown-linux-musl --no-default-features`<br>
`cd target/x86_64-unknown-linux-musl/release/` (directory path might be slightly different)<br>

 * Target Machine<br>

Copy avml directory to the host and run the following command:<br>
`HOSTNAME=$(uname -r) && sudo ./avml <path/to/directory>/$(uname -r).mem`
<br><br><br>

## Creating memory Profiles

### macOS

Download the relevant Kernel Debug Kit: http://developer.apple.com/hardwaredrivers<br>
`dwarfdump -arch x86_64 /Library/Developer/KDKs/KDK_MACOSXVERSION_16D32.kdk/System/Library/Kernels/kernel.dSYM > MACOSXVERSION_x64.dwarfdump`<br>
`python tools/mac/convert.py MACOSXVERSION.dwarfdump converted-MACOSXVERSION_x64.dwarfdump`<br>
`python tools/mac/convert.py converted-MACOSXVERSION_x64.dwarfdump > 10.12.3.64bit.vtypes`<br>
`dsymutil -s -arch x86_64 /Library/Developer/KDKs/KDK_MACOSXVERSION_16D32.kdk/System/Library/Kernels/kernel > MACOSXVERSION.64bit.symbol.dsymutil`<br>
`zip MACOSXVERSION.64bit.zip MACOSXVERSION.64bit.symbol.dsymutil MACOSXVERSION.64bit.vtypes`<br>
`cp MACOSXVERSION.64bit.zip volatility/plugins/overlays/mac/`<br>

### Linux

Download volatility from https://github.com/ezaspy/elrond/tools/<br>
`cd volatility/tools/linux/`<br>
`sudo make -C /lib/modules/HOSTNAME/build/ CONFIG_DEBUG_INFO=y M=$PWD modules`<br>
`sudo rm -rf module.dwarf`<br>
`sudo dwarfdump -di ./module.o > module.dwarf`<br>
`sudo zip Ubuntu64-HOSTNAME.zip module.dwarf /boot/System.map-HOSTNAME`<br>
`sudo cp Ubuntu64-HOSTNAME.zip /usr/lib/python2.7/dist-packages/volatility/plugins/overlays/linux/`<br>
<br><br>
