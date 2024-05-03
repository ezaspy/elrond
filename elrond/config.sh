#!/bin/bash
sleep 1
clear
sudo apt update
cd /opt/elrond/elrond
sudo chmod -R 755 /opt/elrond/
chown -R $USER:$USER /opt/elrond
/opt/elrond/elrond/tools/config/scripts/./init.sh

# installing vmware-tools if applicable
HYPER=$(sudo dmesg | grep -E "DMI|Hypervisor")
if [[ "$HYPER" == *"VMware"* ]]; then
    # installing vmware_tools
    /opt/elrond/elrond/tools/config/scripts/./virtual.sh
    # change desktop background
    gsettings set org.gnome.desktop.background picture-uri file:///opt/elrond/elrond/images/elrond_background.jpg
fi

# installing apfs-fuse if architecture is not ARM
UNAME=$(uname -a)
if [[ "$UNAME" != *"aarch"* ]]; then
    # installing apfs-fuse
    /opt/elrond/elrond/tools/config/scripts/./apfs-fuse.sh
fi

# installing regripper if not installed
if [ -d "/usr/local/src/regripper" ]; then
    # updating regripper
    sudo cp /usr/share/regripper/rip.pl /usr/share/regripper/rip.pl.old
    sudo sed -i 's/my \$VERSION/# Add: Define the variable plugindir\nmy \$plugindir = File::Spec->catfile\(\$scriptdir, "plugins"\);\n\nmy \$VERSION/' /usr/share/regripper/rip.pl
else
    /opt/elrond/elrond/tools/config/scripts/./regrip.sh
fi

/opt/elrond/elrond/tools/config/scripts/./nsrl.sh
/opt/elrond/elrond/tools/config/scripts/./volatility3.sh
/opt/elrond/elrond/tools/config/scripts/./dwarf2json.sh
/opt/elrond/elrond/tools/config/scripts/./python.sh
/opt/elrond/elrond/tools/config/scripts/./mitre.sh
/opt/elrond/elrond/tools/config/scripts/./splunk.sh
/opt/elrond/elrond/tools/config/scripts/./elastic.sh #E: Unable to locate package openjdk-16-jre-headless
/opt/elrond/elrond/tools/config/scripts/./navigator.sh
/opt/elrond/elrond/tools/config/scripts/./finish.sh