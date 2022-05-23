#!/usr/bin/env python3 -tt
# disk-based IOCs
def create_default_transforms(transformsconf):
    start, prefix, suffix, end = "if(match(", ',"(', ')"), "', '", '
    assignment_pairings = {
        "Artefact_|_/etc/profile|/etc/zshenv|/etc/zprofile|/etc/zlogin|profile\\.d|bash_profile|bashrc|bash_login|bash_logout|zshrc|zshenv|zlogout|zlogin|profile": "T1546.004 - Unix Shell Configuration Modification",  # usb, timeline
        "Artefact_|_/print processors/|/print_processors/": "T1547.012 - Print Processors",  # usb, timeline
        "Artefact_|_/security/policy/secrets": "T1003.004 - LSA Secrets",  # usb, timeline
        "Artefact_|_/special/perf": "T1337.002 - Office Test",  # usb, timeline
        "Artefact_|_/var/log": "T1070.002 - Clear Linux or Mac System Logs",  # usb, timeline
        "Artefact_|_\\.7z|\\.arj|\\.tar|\\.tgz|\\.zip": "T1560.001 - Archive via Utility",  # usb, timeline
        "Artefact_|_\\.asc|\\.cer|\\.gpg|\\.key|\\.p12|\\.p7b|\\.pem|\\.pfx|\\.pgp|\\.ppk": "T1552.004 - Private Keys",  # usb, timeline
        "Artefact_|_\\.chm|\\.hh": "T1218.001 - Compiled HTML File",  # usb, timeline
        "Artefact_|_\\.cpl|panel/cpls": "T1218.002 - Control Panel",  # usb, timeline
        "Artefact_|_\\.doc|\\.xls|\\.ppt|\\.pdf| winword| excel| powerpnt| acrobat| acrord32|winword\\.|excel\\.|powerpnt\\.|acrobat\\.|acrord32\\.": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File",  # usb, timeline
        "Artefact_|_\\.docm|\\.xlsm|\\.pptm": "T1137.001 - Office Template Macros | T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1559.001 - Component Object Model Hijacking",  # usb, timeline
        "Artefact_|_\\.docx|\\.xlsx|\\.pptx": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1221.000 - Template Injection",  # usb, timeline
        "Artefact_|_\\.eml": "T1114.001 - Local Email Collection",  # usb, timeline
        "Artefact_|_\\.job|schtask": "T1053.005 - Scheduled Task",  # usb, timeline
        "Artefact_|_\\.lnk": "T1547.009 - Shortcut Modification",  # usb, timeline
        "Artefact_|_\\.local|\\.manifest": "T1574.001 - DLL Search Order Hijacking",  # usb, timeline
        "Artefact_|_\\.mobileconfig|profiles": "T1176.000 - Browser Extensions",  # usb, timeline
        "Artefact_|_\\.mp3|\\.wav|\\.aac|\\.m4a|microphone": "T1123.000 - Audio Capture",  # usb, timeline
        "Artefact_|_\\.mp4|\\.mkv|\\.avi|\\.mov|\\.wmv|\\.mpg|\\.mpeg|\\.m4v|\\.flv": "T1125.000 - Video Capture",  # usb, timeline
        "Artefact_|_\\.msg|\\.eml": "T1203.000 - Exploitation for Client Execution | T1204.001 - Malicious Link | T1204.002 - Malicious File | T1114.001 - Local Email Collection | T1566.001 - Spearphishing Attachment | T1566.002 - Spearphishing Link",  # usb, timeline
        "Artefact_|_\\.ost|\\.pst": "T1114.001 - Local Email Collection",  # usb, timeline
        "Artefact_|_\\.ps1": "T1059.001 - PowerShell",  # usb, timeline
        "Artefact_|_\\.service|services\\.exe|sc\\.exe": "T1007.000 - System Service Discovery | T1489.000 - Service Stop | T1543.003 - Windows Service | T1569.002 - Service Execution",  # usb, timeline
        "Artefact_|_active setup/installed components|active_setup/installed_components": "T1547.014 - Active Setup",  # usb, timeline
        "Artefact_|_add-trusted-cert|trustroot|certmgr": "T1553.004 - Install Root Certificate",  # usb, timeline
        "Artefact_|_admin%24|admin\\$|admin$|c%24|c\\$|c$": "T1021.002 - SMB/Windows Admin Shares | T1570.000 - Lateral Tool Transfer",  # usb, timeline
        "Artefact_|_appcmd\\.exe|inetsrv/config/applicationhost\\.config": "T1505.004 - IIS Components",  # usb, timeline
        "Artefact_|_ascii|unicode|hex|base64|mime": "T1132.001 - Standard Encoding",  # usb, timeline
        "Artefact_|_at\\.": "T1053.002 - At",  # usb, timeline
        "Artefact_|_atbroker|displayswitch|magnify|narrator|osk\\.|sethc|utilman": "T1546.008 - Accessibility Features",  # usb, timeline
        "Artefact_|_authorizationexecutewithprivileges|security_authtrampoline": "T1548.004 - Elevated Execution with Prompt",  # usb, timeline
        "Artefact_|_authorized_keys|sshd_config|ssh-keygen": "T1098.004 - SSH Authorized Keys",  # usb, timeline
        "Artefact_|_autoruns|reg |reg\\.exe": "T1112.000 - Modify Registry",  # usb, timeline
        "Artefact_|_backgrounditems\\.btm": "T1547.015 - Login Items",  # usb, timeline
        "Artefact_|_bash_history": "T1552.003 - Bash History",  # usb, timeline
        "Artefact_|_bcdedit": "T1553.006 - Code Signing Policy Modification | T1562.009 - Safe Mode Boot",  # usb, timeline
        "Artefact_|_bcdedit|csrutil": "T1553.006 - Code Signing Policy Modification",  # usb, timeline
        "Artefact_|_bluetooth": "T1011.001 - Exfiltration over Bluetooth",  # usb, timeline
        "Artefact_|_bootcfg": "T1562.009 - Safe Mode Boot",  # usb, timeline
        "Artefact_|_certutil": "T1036.003 - Rename System Utilities | T1140.000 - Deobfuscate/Decode Files or Information | T1553.004 - Install Root Certificate",  # usb, timeline
        "Artefact_|_chage|common-password|pwpolicy|getaccountpolicies": "T1201.000 - Password Policy Discovery",  # usb, timeline
        "Artefact_|_chmod": "T1222.002 - Linux and Mac File and Directory Permissions Modification | T1548.001 - Setuid and Setgid",  # usb, timeline
        "Artefact_|_chown|chgrp": "T1222.002 - Linux and Mac File and Directory Permissions Modification",  # usb, timeline
        "Artefact_|_clipboard|pbpaste": "T1115.000 - Clipboard Data",  # usb, timeline
        "Artefact_|_cmd |cmd_|cmd\\.": "T1059.003 - Windows Command Shell | T1106.000 - Native API",  # usb, timeline
        "Artefact_|_cmmgr32|cmstp|cmlua": "T1218.003 - CMSTP",  # usb, timeline
        "Artefact_|_com\\.apple\\.quarantine|xattr|xttr": "T1553.001 - Gatekeeper Bypass | T1564.009 - Resource Forking",  # usb, timeline
        "Artefact_|_contentsofdirectoryatpath|pathextension|fork |fork_": "T1106.000 - Native API",  # usb, timeline
        "Artefact_|_csc\\.exe|gcc |gcc_": "T1027.004 - Compile After Delivery",  # usb, timeline
        "Artefact_|_cscript|pubprn": "T1216.001 - PubPrn",  # usb, timeline
        "Artefact_|_csrutil": "T1553.006 - Code Signing Policy Modification",  # usb, timeline
        "Artefact_|_curl |curl_|wget |wget_": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1553.001 - Gatekeeper Bypass",  # usb, timeline
        "Artefact_|_currentcontrolset/control/lsa": "T1003.001 - LSASS Memory | T1547.002 - Authentication Package | T1547.005 - Security Support Provider | T1556.002 - Password Filter DLL",  # usb, timeline
        "Artefact_|_currentcontrolset/control/nls/language": "T1614.001 - System Language Discovery",  # usb, timeline
        "Artefact_|_currentcontrolset/control/print/monitors": "T1547.010 - Port Monitors",  # usb, timeline
        "Artefact_|_currentcontrolset/control/safeboot/minimal": "T1562.009 - Safe Mode Boot",  # usb, timeline
        "Artefact_|_currentcontrolset/control/session manager|currentcontrolset/control/session_manager": "T1546.009 - AppCert DLLs | T1547.001 - Registry Run Keys / Startup Folder",  # usb, timeline
        "Artefact_|_currentcontrolset/services/": "T1574.011 - Services Registry Permissions Weakness",  # usb, timeline
        "Artefact_|_currentcontrolset/services/termservice/parameters": "T1505.005 - Terminal Services DLL",  # usb, timeline
        "Artefact_|_currentcontrolset/services/w32time/timeproviders": "T1547.003 - Time Providers",  # usb, timeline
        "Artefact_|_currentversion/app paths|software/classes/ms-settings/shell/open/command|currentversion/app_paths|software/classes/mscfile/shell/open/command|software/classes/exefile/shell/runas/command/isolatedcommand|eventvwr|sdclt": "T1548.002 - Bypass User Account Control",  # usb, timeline
        "Artefact_|_currentversion/appcompatflags/installedsdb": "T1546.011 - Application Shimming",  # usb, timeline
        "Artefact_|_currentversion/explorer/fileexts": "T1546.001 - Change Default File Association",  # usb, timeline
        "Artefact_|_currentversion/image file execution options|currentversion/image_file_execution_options": "T1546.008 - Accessibility Features | T1546.012 - Image File Execution Options Injection | T1547.002 - Authentication Package | T1547.005 - Security Support Provider",  # usb, timeline
        "Artefact_|_currentversion/policies/credui/enumerateadministrators": "T1087.001 - Local Account | T1087.002 - Domain Account",  # usb, timeline
        "Artefact_|_currentversion/run|currentversion/policies/explorer/run|currentversion/explorer/user/|currentversion/explorer/shell": "T1547.001 - Registry Run Keys / Startup Folder",  # usb, timeline
        "Artefact_|_currentversion/windows|nt/currentversion/windows": "T1546.010 - AppInit DLLs",  # usb, timeline
        "Artefact_|_currentversion/winlogon/notify|currentversion/winlogon/userinit|currentversion/winlogon/shell": "T1547.001 - Registry Run Keys / Startup Folder | T1547.004 - Winlogon Helper DLL",  # usb, timeline
        "Artefact_|_DISPLAY|display|HID|hid|PCI|pci|UMB|umb|FDC|fdc|SCSI|scsi|STORAGE|storage|USB|usb": "T1025.000 - Data from Removable Media | T1052.001 - Exfiltration over USB | T1056.001 - Keylogging | T1091.000 - Replication through Removable Media | T1200.000 - Hardware Additions | T1570.000 - Lateral Tool Transfer",  # usb, timeline
        "Artefact_|_docker build|docker build|docker_build|docker__build": "T1612.000 - Build Image on Host",  # usb, timeline
        "Artefact_|_docker create|docker create|docker start|docker start|docker_create|docker__create|docker_start|docker_start": "T1610.000 - Deploy Container",  # usb, timeline
        "Artefact_|_docker exec|docker exec|docker run|docker run|kubectl exec|kubectl exec|kubectl run|kubectl run|docker_exec|docker__exec|docker_run|docker__run|kubectl_exec|kubectl__exec|kubectl_run|kubectl__run": "T1609.000 - Container Administration Command",  # usb, timeline
        "Artefact_|_dscacheutil|ldapsearch": "T1069.002 - Domain Groups | T1087.002 - Domain Accounts",  # usb, timeline
        "Artefact_|_dscl": "T1069.001 - Local Groups | T1564.002 - Hidden Users",  # usb, timeline
        "Artefact_|_emond": "T1546.014 - Emond | T1547.015 - Login Items",  # usb, timeline
        "Artefact_|_encrypt": "T1573.001 - Symmetric Cryptography | T1573.002 - Asymmetric Cryptography",  # usb, timeline
        "Artefact_|_environment/userinitmprlogonscript": "T1037.001 - Logon Script (Windows)",  # usb, timeline
        "Artefact_|_etc/passwd|etc/shadow": "T1003.008 - /etc/passwd and /etc/shadow | T1087.001 - Local Account | T1556.003 - Pluggable Authentication Modules",  # usb, timeline
        "Artefact_|_find |locate |find_|locate_": "T1083.000 - File and Directory Discovery",  # usb, timeline
        "Artefact_|_forwardingsmtpaddress|x-forwarded-to|x-mailfwdby|x-ms-exchange-organization-autoforwarded": "T1114.003 - Email Forwarding Rule",  # usb, timeline
        "Artefact_|_fsutil|fsinfo": "T1120.000 - Peripheral Device Discovery",  # usb, timeline
        "Artefact_|_gcc |gcc_": "T1027.004 - Compile After Delivery",  # usb, timeline
        "Artefact_|_github|gitlab|bitbucket": "T1567.001 - Exfiltration to Code Repository",  # usb, timeline
        "Artefact_|_gpttmpl\\.inf|scheduledtasks\\.xml": "T1484.001 - Group Policy Modification",  # usb, timeline
        "Artefact_|_group": "T1069.001 - Local Groups | T1069.002 - Domain Groups",  # usb, timeline
        "Artefact_|_gsecdump|mimikatz|pwdumpx|secretsdump|reg save|reg save|net user|net user|net\\.exe user|net\\.exe user|net1 user|net1 user|net1\\.exe user|net1\\.exe user|reg_save|reg_save|net user|net user|net\\.exe user|net\\.exe user|net1 user|net1 user|net1\\.exe user|net1\\.exe user|reg_save|reg__save|net_user|net__user|net\\.exe_user|net\\.exe__user|net1_user|net1__user|net1\\.exe_user|net1\\.exe__user": "T1003.002 - Security Account Manager",  # usb, timeline
        "Artefact_|_halt": "T1529.000 - System Shutdown/Reboot",  # usb, timeline
        "Artefact_|_hidden|uielement": "T1564.003 - Hidden Window",  # usb, timeline
        "Artefact_|_histcontrol": "T1562.003 - Impair Command History Logging",  # usb, timeline
        "Artefact_|_history|histfile": "T1070.003 - Clear Command History | T1552.003 - Bash History | T1562.003 - Impair Command History Logging",  # usb, timeline
        "Artefact_|_hostname |systeminfo|whoami": "T1033.000 - System Owner/User Discovery",  # usb, timeline
        "Artefact_|_ifconfig|ipconfig|dig ": "T1016.001 - Internet Connection Discovery",  # usb, timeline
        "Artefact_|_ipc%24|ipc\\$|ipc$": "T1021.002 - SMB/Windows Admin Shares | T1559.001 - Component Object Model Hijacking",  # usb, timeline
        "Artefact_|_is_debugging|sysctl|ptrace": "T1497.001 - System Checks | T1622 - Debugger Evasion",  # usb, timeline
        "Artefact_|_keychain": "T1555.001 - Keychain",  # usb, timeline
        "Artefact_|_kill ": "T1489.000 - Service Stop | T1548.003 - Sudo and Sudo Caching | T1562.001 - Disable or Modify Tools",  # usb, timeline
        "Artefact_|_launchagents|systemctl": "T1543.001 - Launch Agent",  # usb, timeline
        "Artefact_|_launchctl": "T1569.001 - Launchctl",  # usb, timeline
        "Artefact_|_launchdaemons": "T1543.004 - Launch Daemon",  # usb, timeline
        "Artefact_|_lc_code_signature|lc_load_dylib": "T1546.006 - LC_LOAD_DYLIB Addition | T1574.004 - Dylib Hijacking",  # usb, timeline
        "Artefact_|_lc_load_weak_dylib|rpath|loader_path|executable_path|ottol": "T1547.004 - Dylib Hijacking",  # usb, timeline
        "Artefact_|_ld_preload|dyld_insert_libraries|export|setenv|putenv|os\\.environ|ld\\.so\\.preload|dlopen|mmap|failure": "T1547.006 - Dynamic Linker Hijacking",  # usb, timeline
        "Artefact_|_libzip|zlib|rarfile|bzip2": "T1560.002 - Archive via Library",  # usb, timeline
        "Artefact_|_loginitems|loginwindow|smloginitemsetenabled|uielement|quarantine": "T1547.015 - Login Items",  # usb, timeline
        "Artefact_|_loginwindow|hide500users|dscl|uniqueid": "T1564.002 - Hidden Users",  # usb, timeline
        "Artefact_|_lsof|route|dig ": "T1049.000 - System Network Connections Discovery",  # usb, timeline
        "Artefact_|_lsof|who": "T1049.000 - System Network Connections Discovery",  # usb, timeline
        "Artefact_|_malloc|ptrace_setregs|ptrace_poketext|ptrace_pokedata": "T1055.008 - Ptrace System Calls",  # usb, timeline
        "Artefact_|_manager/safedllsearchmode|security/policy/secrets": "T1003.001 - LSASS Memory | T1547.008 - LSASS Driver",  # usb, timeline
        "Artefact_|_mavinject\\.exe": "T1218.013 - Mavinject",  # usb, timeline
        "Artefact_|_microphone": "T1123.000 - Audio Capture",  # usb, timeline
        "Artefact_|_microsoft/windows/softwareprotectionplatform/eventcachemanager|scvhost|svchast|svchust|svchest|lssas|lsasss|lsaas|cssrs|canhost|conhast|connhost|connhst|iexplorer|iexploror|iexplorar": "T1036.004 - Masquerade Task or Service",  # usb, timeline
        "Artefact_|_mmc\\.exe|wbadmin\\.msc": "T1218.014 - MMC",  # usb, timeline
        "Artefact_|_modprobe|insmod|lsmod|rmmod|modinfo|kextload|kextunload|autostart": "T1547.006 - Kernel Modules and Extensions",  # usb, timeline
        "Artefact_|_mscor\\.dll|mscoree\\.dll|clr\\.dll|assembly\\.load": "T1620 - Reflective Code Loading",  # usb, timeline
        "Artefact_|_mshta": "T1218.005 - Mshta",  # usb, timeline
        "Artefact_|_msiexec": "T1218.007 - Msiexec",  # usb, timeline
        "Artefact_|_msxml": "T1220.000 - XSL Script Processing",  # usb, timeline
        "Artefact_|_netsh": "T1049.000 - System Network Connections Discovery | T1090.001 - Internal Proxy | T1135.000 - Network Share Discovery | T1518.001 - Security Software Discovery",  # usb, timeline
        "Artefact_|_normal\\.dotm|personal\\.xlsb": "T1137.001 - Office Template Macros",  # usb, timeline
        "Artefact_|_nt/dnsclient": "T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",  # usb, timeline
        "Artefact_|_ntds|ntdsutil|secretsdump": "T1003.003 - NTDS",  # usb, timeline
        "Artefact_|_odbcconf": "T1218.008 - Odbcconf",  # usb, timeline
        "Artefact_|_onedrive|1drv|azure|icloud|cloudrive|dropbox|drive\\.google|\\.box\\.com|egnyte|mediafire|zippyshare|megaupload|4shared": "T1537.000 - Transfer Data to Cloud Account | T1567.002 - Exfiltration to Cloud Storage",  # usb, timeline
        "Artefact_|_pam_unix\\.so": "T1556.003 - Pluggable Authentication Modules",  # usb, timeline
        "Artefact_|_panel/cpls": "T1218.002 - Control Panel",  # usb, timeline
        "Artefact_|_password|pwd|login|secure|credentials": "T1552.001 - Credentials in Files | T1555.005 - Password Managers",  # usb, timeline
        "Artefact_|_ping\\.|ping |traceroute|dig |etc/host|etc/hosts|bonjour": "T1016.001 - Internet Connection Discovery | T1018.000 - Remote System Discovery",  # usb, timeline
        "Artefact_|_policy\\.vpol|vaultcmd|vcrd": "T1555.004 - Windows Credential Manager",  # usb, timeline
        "Artefact_|_portopening": "T1090.001 - Internal Proxy",  # usb, timeline
        "Artefact_|_powershell\\.": "T1059.001 - PowerShell | T1106.000 - Native API",  # usb, timeline
        "Artefact_|_profile\\.d|bash_profile|bashrc|bash_login|bash_logout": "T1546.004 - Unix Shell Configuration Modification",  # usb, timeline
        "Artefact_|_ps -|ps_-": "T1057.000 - Process Discovery",  # usb, timeline
        "Artefact_|_psexec": "T1003.001 - LSASS Memory | T1569.002 - Service Execution | T1570.000 - Lateral Tool Transfer",  # usb, timeline
        "Artefact_|_pubprn": "T1216.001 - PubPrn",  # usb, timeline
        "Artefact_|_python|\\.py |\\.py_": "T1059.006 - Python",  # usb, timeline
        "Artefact_|_rassfm\\.dll": "T1556.005 - Reversible Encryption",  # usb, timeline
        "Artefact_|_rc\\.local|rc\\.common": "T1037.004 - RC Scripts",  # usb, timeline
        "Artefact_|_rm -|rm  -|rm_-": "T1070.004 - File Deletion | T1485.000 - Data Destruction",  # usb, timeline
        "Artefact_|_rundll32": "T1218.011 - Rundll32",  # usb, timeline
        "Artefact_|_scp|rsync|sftp": "T1105.000 - Ingress Tool Transfer",  # usb, timeline
        "Artefact_|_scrnsave": "T1546.002 - Screensaver",  # usb, timeline
        "Artefact_|_sdelete": "T1070.004 - File Deletion | T1485.000 - Data Destruction",  # usb, timeline
        "Artefact_|_services": "T1489.000 - Service Stop",  # usb, timeline
        "Artefact_|_software/microsoft/netsh": "T1546.007 - Netsh Helper DLL",  # usb, timeline
        "Artefact_|_software/microsoft/ole": "T1546.015 - Component Object Model Hijacking",  # usb, timeline
        "Artefact_|_software/policies/microsoft/previousversions/disablelocalpage": "T1490.000 - Inhibit System Recovery",  # usb, timeline
        "Artefact_|_startupitems": "T1037.002 - Logon Script (Mac)",  # usb, timeline
        "Artefact_|_startupparameters": "T1037.002 - Logon Script (Mac) | T1037.005 - Startup Items | T1547.015 - Login Items",  # usb, timeline
        "Artefact_|_sudo|timestamp_timeout|tty_tickets": "T1548.003 - Sudo and Sudo Caching",  # usb, timeline
        "Artefact_|_systemctl": "T1543.001 - Launch Agent",  # usb, timeline
        "Artefact_|_systemsetup": "T1082.000 - System Information Discovery",  # usb, timeline
        "Artefact_|_sysvol/policies": "T1615 - Group Policy Discovery",  # usb, timeline
        "Artefact_|_tasklist": "T1007.000 - System Service Discovery | T1518.001 - Security Software Discovery",  # usb, timeline
        "Artefact_|_time |sleep": "T1497.003 - Time Based Evasion",  # usb, timeline
        "Artefact_|_timer": "T1053.006 - Systemd Timers",  # usb, timeline
        "Artefact_|_trap": "T1546.005 - Trap",  # usb, timeline
        "Artefact_|_tscon": "T1563.002 - RDP Hijacking",  # usb, timeline
        "Artefact_|_u202e": "T1036.002 - Right-to-Left Override",  # usb, timeline
        "Artefact_|_uielement": "T1564.003 - Hidden Window",  # usb, timeline
        "Artefact_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",  # usb, timeline
        "Artefact_|_vbscript|wscript": "T1059.005 - Visual Basic | T1059.007 - JavaScript",  # usb, timeline
        "Artefact_|_verclsid": "T1218.012 - Verclsid",  # usb, timeline
        "Artefact_|_winrm": "T1021.006 - Windows Remote Management",  # usb, timeline
        "Artefact_|_wmic|msxsl": "T1047.000 - Windows Management Instrumentation | T1220.000 - XSL Script Processing",  # usb, timeline
        "Artefact_|_xattr|xttr": "T1553.001 - Gatekeeper Bypass | T1564.009 - Resource Forking",  # usb, timeline
        "Artefact_|_xdg|autostart": "T1547.013 - XDG Autostart Entries",  # usb, timeline
        "Artefact_|_xwd|screencapture": "T1113.000 - Screen Capture",  # usb, timeline
        "Artefact_|_zshrc|zshenv|zlogout|zlogin|profile": "T1546.004 - Unix Shell Configuration Modification",  # usb, timeline
        "Artefact_|_zwqueryeafile|zwseteafile": "T1564.004 - NTFS File Attributes",  # usb, timeline
        "EventID_|_^10|12|13$": "T1218.003 - CMSTP",  # evt
        "EventID_|_^1020$": "T1557.003 - DHCP Spoofing",  # evt
        "EventID_|_^1063$": "T1557.003 - DHCP Spoofing",  # evt
        "EventID_|_^1074|6006$": "T1529.000 - System Shutdown/Reboot",  # evt
        "EventID_|_^1102$": "T1070.001 - Clear Windows Event Logs",  # evt
        "EventID_|_^1341$": "T1557.003 - DHCP Spoofing",  # evt
        "EventID_|_^1342$": "T1557.003 - DHCP Spoofing",  # evt
        "EventID_|_^17|18$": "T1055.002 - Portable Execution Injection",  # evt
        "EventID_|_^3033|3063$": "T1547.008 - LSASS Driver | T1553.003 - SIP and Trust Provider Hijacking",  # evt
        "EventID_|_^307|510$": "T1484.002 - Domain Trust Modification",  # evt
        "EventID_|_^400$": "T1562.010 - Downgrade Attack",  # evt
        "EventID_|_^4624|4634$": "T1558.001 - Golden Ticket | T1558.002 - Silver Ticket",  # evt
        "EventID_|_^4625|4648|4771$": "T1110.003 - Password Spraying",  # evt
        "EventID_|_^4657$": "T1112.000 - Modify Registry | T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",  # evt
        "EventID_|_^4670$": "T1098.000 - Account Manipulation | T1222.001 - Windows File and Directory Permissions Modification",  # evt
        "EventID_|_^4672$": "T1484.001 - Group Policy Modification | T1558.001 - Golden Ticket",  # evt
        "EventID_|_^4697|7045$": "T1021.003 - Windows Service",  # evt
        "EventID_|_^4704|5136|5137|5138|5139|5141$": "T1484.001 - Group Policy Modification",  # evt
        "EventID_|_^4720$": "T1136.001 - Local Account | T1136.002 - Domain Account",  # evt
        "EventID_|_^4723|4724|4726|4740$": "T1531.000 - Account Access Removal",  # evt
        "EventID_|_^4728|4738$": "T1098.000 - Account Manipulation",  # evt
        "EventID_|_^4768|4769$": "T1550.002 - Pass the Hash | T1550.003 - Pass the Ticket | T1558.003 - Kerberoasting",  # evt
        "EventID_|_^4928|4929$": "T1207.000 - Rogue Domain Controller",  # evt
        "EventID_|_^524$": "T1490.000 - Inhibit System Recovery",  # evt
        "EventID_|_^5861$": "T1546.003 - Windows Management Instrumentation Event Subscription",  # evt
        "EventID_|_^7045$": "T1021.003 - Windows Service | T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",  # evt
        "EventID_|_^81$": "T1553.003 - SIP and Trust Provider Hijacking",  # evt
        "Filename_|_\\.7z|\\.arj|\\.tar|\\.tgz|\\.zip": "T1560.001 - Archive via Utility",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.asc|\\.cer|\\.gpg|\\.key|\\.p12|\\.p7b|\\.pem|\\.pfx|\\.pgp|\\.ppk": "T1552.004 - Private Keys",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.chm|\\.hh": "T1218.001 - Compiled HTML File",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.cpl": "T1218.002 - Control Panel",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.doc|\\.xls|\\.ppt|\\.pdf": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.docm|\\.xlsm|\\.pptm": "T1137.001 - Office Template Macros | T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1559.001 - Component Object Model Hijacking",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.docx|\\.xlsx|\\.pptx": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1221.000 - Template Injection",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.job": "T1053.005 - Scheduled Task",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.lnk": "T1547.009 - Shortcut Modification",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.local|\\.manifest": "T1574.001 - DLL Search Order Hijacking",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.mobileconfig|profiles": "T1176.000 - Browser Extensions",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.mp3|\\.wav|\\.aac|\\.m4a": "T1123.000 - Audio Capture",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.mp4|\\.mkv|\\.avi|\\.mov|\\.wmv|\\.mpg|\\.mpeg|\\.m4v|\\.flv": "T1125.000 - Video Capture",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.msg|\\.eml": "T1203.000 - Exploitation for Client Execution | T1204.001 - Malicious Link | T1204.002 - Malicious File | T1566.001 - Spearphishing Attachment | T1566.002 - Spearphishing Link",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.ost|\\.pst|\\.msg|\\.eml": "T1114.001 - Local Email Collection",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.ps1": "T1059.001 - PowerShell",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_\\.service|services\\.exe|sc\\.exe": "T1007.000 - System Service Discovery | T1489.000 - Service Stop | T1543.003 - Windows Service | T1569.002 - Service Execution",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_appcmd\\.exe|inetsrv/config/applicationhost\\.config": "T1505.004 - IIS Components",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_at\\.": "T1053.002 - At",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_atbroker|displayswitch|magnify|narrator|osk\\.|sethc|utilman": "T1546.008 - Accessibility Features",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_autoruns": "T1112.000 - Modify Registry",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_backgrounditems\\.btm": "T1547.015 - Login Items",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_bash_history": "T1552.003 - Bash History",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_bcdedit": "T1553.006 - Code Signing Policy Modification | T1562.009 - Safe Mode Boot",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_bcdedit|csrutil": "T1553.006 - Code Signing Policy Modification",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_bluetooth": "T1011.001 - Exfiltration over Bluetooth",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_bootcfg": "T1562.009 - Safe Mode Boot",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_certmgr": "T1553.004 - Install Root Certificate",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_certutil": "T1036.003 - Rename System Utilities | T1140.000 - Deobfuscate/Decode Files or Information | T1553.004 - Install Root Certificate",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_cmd |cmd_|cmd\\.": "T1059.003 - Windows Command Shell | T1106.000 - Native API",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_com\\.apple\\.quarantine": "T1553.001 - Gatekeeper Bypass",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_csc\\.exe": "T1027.004 - Compile After Delivery",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_cscript": "T1216.001 - PubPrn",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_csrutil": "T1553.006 - Code Signing Policy Modification",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_etc/passwd|etc/shadow": "T1003.008 - /etc/passwd and /etc/shadow | T1087.001 - Local Account | T1556.003 - Pluggable Authentication Modules",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_eventvwr|sdclt": "T1548.002 - Bypass User Account Control",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_fsutil|fsinfo": "T1120.000 - Peripheral Device Discovery",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_github|gitlab|bitbucket": "T1567.001 - Exfiltration to Code Repository",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_gpttmpl\\.inf|scheduledtasks\\.xml": "T1484.001 - Group Policy Modification",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_keychain": "T1555.001 - Keychain",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_mavinject\\.exe": "T1218.013 - Mavinject",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_microphone": "T1123.000 - Audio Capture",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_mmc\\.exe|wbadmin\\.msc": "T1218.014 - MMC",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_mscor\\.dll|mscoree\\.dll|clr\\.dll|assembly\\.load": "T1620 - Reflective Code Loading",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_mshta": "T1218.005 - Mshta",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_msiexec": "T1218.007 - Msiexec",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_normal\\.dotm|personal\\.xlsb": "T1137.001 - Office Template Macros",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_odbcconf": "T1218.008 - Odbcconf",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_pam_unix\\.so": "T1556.003 - Pluggable Authentication Modules",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_policy\\.vpol|vaultcmd|vcrd": "T1555.004 - Windows Credential Manager",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_powershell\\.": "T1059.001 - PowerShell | T1106.000 - Native API",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_profile\\.d|bash_profile|bashrc|bash_login|bash_logout": "T1546.004 - Unix Shell Configuration Modification",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_psexec": "T1003.001 - LSASS Memory | T1569.002 - Service Execution | T1570.000 - Lateral Tool Transfer",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_pubprn": "T1216.001 - PubPrn",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_python|\\.py": "T1059.006 - Python",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_rassfm\\.dll": "T1556.005 - Reversible Encryption",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_rc\\.local|rc\\.common": "T1037.004 - RC Scripts",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_reg\\.exe": "T1112.000 - Modify Registry",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_scrnsave": "T1546.002 - Screensaver",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_sdelete": "T1070.004 - File Deletion | T1485.000 - Data Destruction",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_sudo|timestamp_timeout|tty_tickets": "T1548.003 - Sudo and Sudo Caching",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_sysvol/policies": "T1615 - Group Policy Discovery",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_tscon": "T1563.002 - RDP Hijacking",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",  # journal, LastAccessTime, metadata & iocs
        "Filename_|_wmic|msxsl": "T1047.000 - Windows Management Instrumentation | T1220.000 - XSL Script Processing",  # journal, LastAccessTime, metadata & iocs
        "Message_|_/etc/profile|/etc/zshenv|/etc/zprofile|/etc/zlogin|profile\\.d|bash_profile|bashrc|bash_login|bash_logout|zshrc|zshenv|zlogout|zlogin|profile": "T1546.004 - Unix Shell Configuration Modification",  # unix-logs, timeline
        "Message_|_/print processors/|/print_processors/": "T1547.012 - Print Processors",  # unix-logs, timeline
        "Message_|_/security/policy/secrets": "T1003.004 - LSA Secrets",  # unix-logs, timeline
        "Message_|_/special/perf": "T1337.002 - Office Test",  # unix-logs, timeline
        "Message_|_/var/log": "T1070.002 - Clear Linux or Mac System Logs",  # unix-logs, timeline
        "Message_|_\\.7z|\\.arj|\\.tar|\\.tgz|\\.zip": "T1560.001 - Archive via Utility",  # unix-logs, timeline
        "Message_|_\\.asc|\\.cer|\\.gpg|\\.key|\\.p12|\\.p7b|\\.pem|\\.pfx|\\.pgp|\\.ppk": "T1552.004 - Private Keys",  # unix-logs, timeline
        "Message_|_\\.chm|\\.hh": "T1218.001 - Compiled HTML File",  # unix-logs, timeline
        "Message_|_\\.cpl|panel/cpls": "T1218.002 - Control Panel",  # unix-logs, timeline
        "Message_|_\\.doc|\\.xls|\\.ppt|\\.pdf| winword| excel| powerpnt| acrobat| acrord32|winword\\.|excel\\.|powerpnt\\.|acrobat\\.|acrord32\\.": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File",  # unix-logs, timeline
        "Message_|_\\.docm|\\.xlsm|\\.pptm": "T1137.001 - Office Template Macros | T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1559.001 - Component Object Model Hijacking",  # unix-logs, timeline
        "Message_|_\\.docx|\\.xlsx|\\.pptx": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1221.000 - Template Injection",  # unix-logs, timeline
        "Message_|_\\.eml": "T1114.001 - Local Email Collection",  # unix-logs, timeline
        "Message_|_\\.job|schtask": "T1053.005 - Scheduled Task",  # unix-logs, timeline
        "Message_|_\\.lnk": "T1547.009 - Shortcut Modification",  # unix-logs, timeline
        "Message_|_\\.local|\\.manifest": "T1574.001 - DLL Search Order Hijacking",  # unix-logs, timeline
        "Message_|_\\.mobileconfig|profiles": "T1176.000 - Browser Extensions",  # unix-logs, timeline
        "Message_|_\\.mp3|\\.wav|\\.aac|\\.m4a|microphone": "T1123.000 - Audio Capture",  # unix-logs, timeline
        "Message_|_\\.mp4|\\.mkv|\\.avi|\\.mov|\\.wmv|\\.mpg|\\.mpeg|\\.m4v|\\.flv": "T1125.000 - Video Capture",  # unix-logs, timeline
        "Message_|_\\.msg|\\.eml": "T1203.000 - Exploitation for Client Execution | T1204.001 - Malicious Link | T1204.002 - Malicious File | T1114.001 - Local Email Collection | T1566.001 - Spearphishing Attachment | T1566.002 - Spearphishing Link",  # unix-logs, timeline
        "Message_|_\\.ost|\\.pst": "T1114.001 - Local Email Collection",  # unix-logs, timeline
        "Message_|_\\.ps1": "T1059.001 - PowerShell",  # unix-logs, timeline
        "Message_|_\\.service|services\\.exe|sc\\.exe": "T1007.000 - System Service Discovery | T1489.000 - Service Stop | T1543.003 - Windows Service | T1569.002 - Service Execution",  # unix-logs, timeline
        "Message_|_active setup/installed components|active_setup/installed_components": "T1547.014 - Active Setup",  # unix-logs, timeline
        "Message_|_add-trusted-cert|trustroot|certmgr": "T1553.004 - Install Root Certificate",  # unix-logs, timeline
        "Message_|_admin%24|admin\\$|admin$|c%24|c\\$|c$": "T1021.002 - SMB/Windows Admin Shares | T1570.000 - Lateral Tool Transfer",  # unix-logs, timeline
        "Message_|_appcmd\\.exe|inetsrv/config/applicationhost\\.config": "T1505.004 - IIS Components",  # unix-logs, timeline
        "Message_|_ascii|unicode|hex|base64|mime": "T1132.001 - Standard Encoding",  # unix-logs, timeline
        "Message_|_at\\.": "T1053.002 - At",  # unix-logs, timeline
        "Message_|_atbroker|displayswitch|magnify|narrator|osk\\.|sethc|utilman": "T1546.008 - Accessibility Features",  # unix-logs, timeline
        "Message_|_authorizationexecutewithprivileges|security_authtrampoline": "T1548.004 - Elevated Execution with Prompt",  # unix-logs, timeline
        "Message_|_authorized_keys|sshd_config|ssh-keygen": "T1098.004 - SSH Authorized Keys",  # unix-logs, timeline
        "Message_|_autoruns|reg |reg\\.exe": "T1112.000 - Modify Registry",  # unix-logs, timeline
        "Message_|_backgrounditems\\.btm": "T1547.015 - Login Items",  # unix-logs, timeline
        "Message_|_bash_history": "T1552.003 - Bash History",  # unix-logs, timeline
        "Message_|_bcdedit": "T1553.006 - Code Signing Policy Modification | T1562.009 - Safe Mode Boot",  # unix-logs, timeline
        "Message_|_bcdedit|csrutil": "T1553.006 - Code Signing Policy Modification",  # unix-logs, timeline
        "Message_|_bluetooth": "T1011.001 - Exfiltration over Bluetooth",  # unix-logs, timeline
        "Message_|_bootcfg": "T1562.009 - Safe Mode Boot",  # unix-logs, timeline
        "Message_|_certutil": "T1036.003 - Rename System Utilities | T1140.000 - Deobfuscate/Decode Files or Information | T1553.004 - Install Root Certificate",  # unix-logs, timeline
        "Message_|_chage|common-password|pwpolicy|getaccountpolicies": "T1201.000 - Password Policy Discovery",  # unix-logs, timeline
        "Message_|_chmod": "T1222.002 - Linux and Mac File and Directory Permissions Modification | T1548.001 - Setuid and Setgid",  # unix-logs, timeline
        "Message_|_chown|chgrp": "T1222.002 - Linux and Mac File and Directory Permissions Modification",  # unix-logs, timeline
        "Message_|_clipboard|pbpaste": "T1115.000 - Clipboard Data",  # unix-logs, timeline
        "Message_|_cmd |cmd_|cmd\\.": "T1059.003 - Windows Command Shell | T1106.000 - Native API",  # unix-logs, timeline
        "Message_|_cmmgr32|cmstp|cmlua": "T1218.003 - CMSTP",  # unix-logs, timeline
        "Message_|_com\\.apple\\.quarantine|xattr|xttr": "T1553.001 - Gatekeeper Bypass | T1564.009 - Resource Forking",  # unix-logs, timeline
        "Message_|_contentsofdirectoryatpath|pathextension|fork |fork_": "T1106.000 - Native API",  # unix-logs, timeline
        "Message_|_csc\\.exe|gcc |gcc_": "T1027.004 - Compile After Delivery",  # unix-logs, timeline
        "Message_|_cscript|pubprn": "T1216.001 - PubPrn",  # unix-logs, timeline
        "Message_|_csrutil": "T1553.006 - Code Signing Policy Modification",  # unix-logs, timeline
        "Message_|_curl |curl_|wget |wget_": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1553.001 - Gatekeeper Bypass",  # unix-logs, timeline
        "Message_|_currentcontrolset/control/lsa": "T1003.001 - LSASS Memory | T1547.002 - Authentication Package | T1547.005 - Security Support Provider | T1556.002 - Password Filter DLL",  # unix-logs, timeline
        "Message_|_currentcontrolset/control/nls/language": "T1614.001 - System Language Discovery",  # unix-logs, timeline
        "Message_|_currentcontrolset/control/print/monitors": "T1547.010 - Port Monitors",  # unix-logs, timeline
        "Message_|_currentcontrolset/control/safeboot/minimal": "T1562.009 - Safe Mode Boot",  # unix-logs, timeline
        "Message_|_currentcontrolset/control/session manager|currentcontrolset/control/session_manager": "T1546.009 - AppCert DLLs | T1547.001 - Registry Run Keys / Startup Folder",  # unix-logs, timeline
        "Message_|_currentcontrolset/services/": "T1574.011 - Services Registry Permissions Weakness",  # unix-logs, timeline
        "Message_|_currentcontrolset/services/termservice/parameters": "T1505.005 - Terminal Services DLL",  # unix-logs, timeline
        "Message_|_currentcontrolset/services/w32time/timeproviders": "T1547.003 - Time Providers",  # unix-logs, timeline
        "Message_|_currentversion/app paths|software/classes/ms-settings/shell/open/command|currentversion/app_paths|software/classes/mscfile/shell/open/command|software/classes/exefile/shell/runas/command/isolatedcommand|eventvwr|sdclt": "T1548.002 - Bypass User Account Control",  # unix-logs, timeline
        "Message_|_currentversion/appcompatflags/installedsdb": "T1546.011 - Application Shimming",  # unix-logs, timeline
        "Message_|_currentversion/explorer/fileexts": "T1546.001 - Change Default File Association",  # unix-logs, timeline
        "Message_|_currentversion/image file execution options|currentversion/image_file_execution_options": "T1546.008 - Accessibility Features | T1546.012 - Image File Execution Options Injection | T1547.002 - Authentication Package | T1547.005 - Security Support Provider",  # unix-logs, timeline
        "Message_|_currentversion/policies/credui/enumerateadministrators": "T1087.001 - Local Account | T1087.002 - Domain Account",  # unix-logs, timeline
        "Message_|_currentversion/run|currentversion/policies/explorer/run|currentversion/explorer/user/|currentversion/explorer/shell": "T1547.001 - Registry Run Keys / Startup Folder",  # unix-logs, timeline
        "Message_|_currentversion/windows|nt/currentversion/windows": "T1546.010 - AppInit DLLs",  # unix-logs, timeline
        "Message_|_currentversion/winlogon/notify|currentversion/winlogon/userinit|currentversion/winlogon/shell": "T1547.001 - Registry Run Keys / Startup Folder | T1547.004 - Winlogon Helper DLL",  # unix-logs, timeline
        "Message_|_DISPLAY|display|HID|hid|PCI|pci|UMB|umb|FDC|fdc|SCSI|scsi|STORAGE|storage|USB|usb": "T1025.000 - Data from Removable Media | T1052.001 - Exfiltration over USB | T1056.001 - Keylogging | T1091.000 - Replication through Removable Media | T1200.000 - Hardware Additions | T1570.000 - Lateral Tool Transfer",  # unix-logs, timeline
        "Message_|_docker build|docker build|docker_build|docker__build": "T1612.000 - Build Image on Host",  # unix-logs, timeline
        "Message_|_docker create|docker create|docker start|docker start|docker_create|docker__create|docker_start|docker_start": "T1610.000 - Deploy Container",  # unix-logs, timeline
        "Message_|_docker exec|docker exec|docker run|docker run|kubectl exec|kubectl exec|kubectl run|kubectl run|docker_exec|docker__exec|docker_run|docker__run|kubectl_exec|kubectl__exec|kubectl_run|kubectl__run": "T1609.000 - Container Administration Command",  # unix-logs, timeline
        "Message_|_dscacheutil|ldapsearch": "T1069.002 - Domain Groups | T1087.002 - Domain Accounts",  # unix-logs, timeline
        "Message_|_dscl": "T1069.001 - Local Groups | T1564.002 - Hidden Users",  # unix-logs, timeline
        "Message_|_emond": "T1546.014 - Emond | T1547.015 - Login Items",  # unix-logs, timeline
        "Message_|_encrypt": "T1573.001 - Symmetric Cryptography | T1573.002 - Asymmetric Cryptography",  # unix-logs, timeline
        "Message_|_environment/userinitmprlogonscript": "T1037.001 - Logon Script (Windows)",  # unix-logs, timeline
        "Message_|_etc/passwd|etc/shadow": "T1003.008 - /etc/passwd and /etc/shadow | T1087.001 - Local Account | T1556.003 - Pluggable Authentication Modules",  # unix-logs, timeline
        "Message_|_find |locate |find_|locate_": "T1083.000 - File and Directory Discovery",  # unix-logs, timeline
        "Message_|_forwardingsmtpaddress|x-forwarded-to|x-mailfwdby|x-ms-exchange-organization-autoforwarded": "T1114.003 - Email Forwarding Rule",  # unix-logs, timeline
        "Message_|_fsutil|fsinfo": "T1120.000 - Peripheral Device Discovery",  # unix-logs, timeline
        "Message_|_gcc |gcc_": "T1027.004 - Compile After Delivery",  # unix-logs, timeline
        "Message_|_github|gitlab|bitbucket": "T1567.001 - Exfiltration to Code Repository",  # unix-logs, timeline
        "Message_|_gpttmpl\\.inf|scheduledtasks\\.xml": "T1484.001 - Group Policy Modification",  # unix-logs, timeline
        "Message_|_group": "T1069.001 - Local Groups | T1069.002 - Domain Groups",  # unix-logs, timeline
        "Message_|_gsecdump|mimikatz|pwdumpx|secretsdump|reg save|reg save|net user|net user|net\\.exe user|net\\.exe user|net1 user|net1 user|net1\\.exe user|net1\\.exe user|reg_save|reg_save|net user|net user|net\\.exe user|net\\.exe user|net1 user|net1 user|net1\\.exe user|net1\\.exe user|reg_save|reg__save|net_user|net__user|net\\.exe_user|net\\.exe__user|net1_user|net1__user|net1\\.exe_user|net1\\.exe__user": "T1003.002 - Security Account Manager",  # unix-logs, timeline
        "Message_|_halt": "T1529.000 - System Shutdown/Reboot",  # unix-logs, timeline
        "Message_|_hidden|uielement": "T1564.003 - Hidden Window",  # unix-logs, timeline
        "Message_|_histcontrol": "T1562.003 - Impair Command History Logging",  # unix-logs, timeline
        "Message_|_history|histfile": "T1070.003 - Clear Command History | T1552.003 - Bash History | T1562.003 - Impair Command History Logging",  # unix-logs, timeline
        "Message_|_hostname |systeminfo|whoami": "T1033.000 - System Owner/User Discovery",  # unix-logs, timeline
        "Message_|_ifconfig|ipconfig|dig ": "T1016.001 - Internet Connection Discovery",  # unix-logs, timeline
        "Message_|_ipc%24|ipc\\$|ipc$": "T1021.002 - SMB/Windows Admin Shares | T1559.001 - Component Object Model Hijacking",  # unix-logs, timeline
        "Message_|_is_debugging|sysctl|ptrace": "T1497.001 - System Checks | T1622 - Debugger Evasion",  # unix-logs, timeline
        "Message_|_keychain": "T1555.001 - Keychain",  # unix-logs, timeline
        "Message_|_kill ": "T1489.000 - Service Stop | T1548.003 - Sudo and Sudo Caching | T1562.001 - Disable or Modify Tools",  # unix-logs, timeline
        "Message_|_launchagents|systemctl": "T1543.001 - Launch Agent",  # unix-logs, timeline
        "Message_|_launchctl": "T1569.001 - Launchctl",  # unix-logs, timeline
        "Message_|_launchdaemons": "T1543.004 - Launch Daemon",  # unix-logs, timeline
        "Message_|_lc_code_signature|lc_load_dylib": "T1546.006 - LC_LOAD_DYLIB Addition | T1574.004 - Dylib Hijacking",  # unix-logs, timeline
        "Message_|_lc_load_weak_dylib|rpath|loader_path|executable_path|ottol": "T1547.004 - Dylib Hijacking",  # unix-logs, timeline
        "Message_|_ld_preload|dyld_insert_libraries|export|setenv|putenv|os\\.environ|ld\\.so\\.preload|dlopen|mmap|failure": "T1547.006 - Dynamic Linker Hijacking",  # unix-logs, timeline
        "Message_|_libzip|zlib|rarfile|bzip2": "T1560.002 - Archive via Library",  # unix-logs, timeline
        "Message_|_loginitems|loginwindow|smloginitemsetenabled|uielement|quarantine": "T1547.015 - Login Items",  # unix-logs, timeline
        "Message_|_loginwindow|hide500users|dscl|uniqueid": "T1564.002 - Hidden Users",  # unix-logs, timeline
        "Message_|_lsof|route|dig ": "T1049.000 - System Network Connections Discovery",  # unix-logs, timeline
        "Message_|_lsof|who": "T1049.000 - System Network Connections Discovery",  # unix-logs, timeline
        "Message_|_malloc|ptrace_setregs|ptrace_poketext|ptrace_pokedata": "T1055.008 - Ptrace System Calls",  # unix-logs, timeline
        "Message_|_manager/safedllsearchmode|security/policy/secrets": "T1003.001 - LSASS Memory | T1547.008 - LSASS Driver",  # unix-logs, timeline
        "Message_|_mavinject\\.exe": "T1218.013 - Mavinject",  # unix-logs, timeline
        "Message_|_microphone": "T1123.000 - Audio Capture",  # unix-logs, timeline
        "Message_|_microsoft/windows/softwareprotectionplatform/eventcachemanager|scvhost|svchast|svchust|svchest|lssas|lsasss|lsaas|cssrs|canhost|conhast|connhost|connhst|iexplorer|iexploror|iexplorar": "T1036.004 - Masquerade Task or Service",  # unix-logs, timeline
        "Message_|_mmc\\.exe|wbadmin\\.msc": "T1218.014 - MMC",  # unix-logs, timeline
        "Message_|_modprobe|insmod|lsmod|rmmod|modinfo|kextload|kextunload|autostart": "T1547.006 - Kernel Modules and Extensions",  # unix-logs, timeline
        "Message_|_mscor\\.dll|mscoree\\.dll|clr\\.dll|assembly\\.load": "T1620 - Reflective Code Loading",  # unix-logs, timeline
        "Message_|_mshta": "T1218.005 - Mshta",  # unix-logs, timeline
        "Message_|_msiexec": "T1218.007 - Msiexec",  # unix-logs, timeline
        "Message_|_msxml": "T1220.000 - XSL Script Processing",  # unix-logs, timeline
        "Message_|_netsh": "T1049.000 - System Network Connections Discovery | T1090.001 - Internal Proxy | T1135.000 - Network Share Discovery | T1518.001 - Security Software Discovery",  # unix-logs, timeline
        "Message_|_normal\\.dotm|personal\\.xlsb": "T1137.001 - Office Template Macros",  # unix-logs, timeline
        "Message_|_nt/dnsclient": "T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",  # unix-logs, timeline
        "Message_|_ntds|ntdsutil|secretsdump": "T1003.003 - NTDS",  # unix-logs, timeline
        "Message_|_odbcconf": "T1218.008 - Odbcconf",  # unix-logs, timeline
        "Message_|_onedrive|1drv|azure|icloud|cloudrive|dropbox|drive\\.google|\\.box\\.com|egnyte|mediafire|zippyshare|megaupload|4shared": "T1537.000 - Transfer Data to Cloud Account | T1567.002 - Exfiltration to Cloud Storage",  # unix-logs, timeline
        "Message_|_pam_unix\\.so": "T1556.003 - Pluggable Authentication Modules",  # unix-logs, timeline
        "Message_|_panel/cpls": "T1218.002 - Control Panel",  # unix-logs, timeline
        "Message_|_password|pwd|login|secure|credentials": "T1552.001 - Credentials in Files | T1555.005 - Password Managers",  # unix-logs, timeline
        "Message_|_ping\\.|ping |traceroute|dig |etc/host|etc/hosts|bonjour": "T1016.001 - Internet Connection Discovery | T1018.000 - Remote System Discovery",  # unix-logs, timeline
        "Message_|_policy\\.vpol|vaultcmd|vcrd": "T1555.004 - Windows Credential Manager",  # unix-logs, timeline
        "Message_|_portopening": "T1090.001 - Internal Proxy",  # unix-logs, timeline
        "Message_|_powershell\\.": "T1059.001 - PowerShell | T1106.000 - Native API",  # unix-logs, timeline
        "Message_|_profile\\.d|bash_profile|bashrc|bash_login|bash_logout": "T1546.004 - Unix Shell Configuration Modification",  # unix-logs, timeline
        "Message_|_ps -|ps_-": "T1057.000 - Process Discovery",  # unix-logs, timeline
        "Message_|_psexec": "T1003.001 - LSASS Memory | T1569.002 - Service Execution | T1570.000 - Lateral Tool Transfer",  # unix-logs, timeline
        "Message_|_pubprn": "T1216.001 - PubPrn",  # unix-logs, timeline
        "Message_|_python|\\.py |\\.py_": "T1059.006 - Python",  # unix-logs, timeline
        "Message_|_rassfm\\.dll": "T1556.005 - Reversible Encryption",  # unix-logs, timeline
        "Message_|_rc\\.local|rc\\.common": "T1037.004 - RC Scripts",  # unix-logs, timeline
        "Message_|_rm -|rm  -|rm_-": "T1070.004 - File Deletion | T1485.000 - Data Destruction",  # unix-logs, timeline
        "Message_|_rundll32": "T1218.011 - Rundll32",  # unix-logs, timeline
        "Message_|_scp|rsync|sftp": "T1105.000 - Ingress Tool Transfer",  # unix-logs, timeline
        "Message_|_scrnsave": "T1546.002 - Screensaver",  # unix-logs, timeline
        "Message_|_sdelete": "T1070.004 - File Deletion | T1485.000 - Data Destruction",  # unix-logs, timeline
        "Message_|_services": "T1489.000 - Service Stop",  # unix-logs, timeline
        "Message_|_software/microsoft/netsh": "T1546.007 - Netsh Helper DLL",  # unix-logs, timeline
        "Message_|_software/microsoft/ole": "T1546.015 - Component Object Model Hijacking",  # unix-logs, timeline
        "Message_|_software/policies/microsoft/previousversions/disablelocalpage": "T1490.000 - Inhibit System Recovery",  # unix-logs, timeline
        "Message_|_startupitems": "T1037.002 - Logon Script (Mac)",  # unix-logs, timeline
        "Message_|_startupparameters": "T1037.002 - Logon Script (Mac) | T1037.005 - Startup Items | T1547.015 - Login Items",  # unix-logs, timeline
        "Message_|_sudo|timestamp_timeout|tty_tickets": "T1548.003 - Sudo and Sudo Caching",  # unix-logs, timeline
        "Message_|_systemctl": "T1543.001 - Launch Agent",  # unix-logs, timeline
        "Message_|_systemsetup": "T1082.000 - System Information Discovery",  # unix-logs, timeline
        "Message_|_sysvol/policies": "T1615 - Group Policy Discovery",  # unix-logs, timeline
        "Message_|_tasklist": "T1007.000 - System Service Discovery | T1518.001 - Security Software Discovery",  # unix-logs, timeline
        "Message_|_time |sleep": "T1497.003 - Time Based Evasion",  # unix-logs, timeline
        "Message_|_timer": "T1053.006 - Systemd Timers",  # unix-logs, timeline
        "Message_|_trap": "T1546.005 - Trap",  # unix-logs, timeline
        "Message_|_tscon": "T1563.002 - RDP Hijacking",  # unix-logs, timeline
        "Message_|_u202e": "T1036.002 - Right-to-Left Override",  # unix-logs, timeline
        "Message_|_uielement": "T1564.003 - Hidden Window",  # unix-logs, timeline
        "Message_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",  # unix-logs, timeline
        "Message_|_vbscript|wscript": "T1059.005 - Visual Basic | T1059.007 - JavaScript",  # unix-logs, timeline
        "Message_|_verclsid": "T1218.012 - Verclsid",  # unix-logs, timeline
        "Message_|_winrm": "T1021.006 - Windows Remote Management",  # unix-logs, timeline
        "Message_|_wmic|msxsl": "T1047.000 - Windows Management Instrumentation | T1220.000 - XSL Script Processing",  # unix-logs, timeline
        "Message_|_xattr|xttr": "T1553.001 - Gatekeeper Bypass | T1564.009 - Resource Forking",  # unix-logs, timeline
        "Message_|_xdg|autostart": "T1547.013 - XDG Autostart Entries",  # unix-logs, timeline
        "Message_|_xwd|screencapture": "T1113.000 - Screen Capture",  # unix-logs, timeline
        "Message_|_zshrc|zshenv|zlogout|zlogin|profile": "T1546.004 - Unix Shell Configuration Modification",  # unix-logs, timeline
        "Message_|_zwqueryeafile|zwseteafile": "T1564.004 - NTFS File Attributes",  # unix-logs, timeline
        "Plist_|_loginitems|loginwindow|smloginitemsetenabled|uielement|quarantine": "T1547.015 - Login Items",  # plists
        "Plist_|_rulesactivestate|syncedrules|unsyncedrules|messagerules": "T1564.008 - Email Hiding Rules",  # plists
        "Plist_|_startupitems": "T1037.002 - Logon Script (Mac)",  # plists
        "Plist_|_startupparameters": "T1037.002 - Logon Script (Mac) | T1037.005 - Startup Items | T1547.015 - Login Items",  # plists
        "Plist_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",  # plists
        "Registry_|_/print processors/|/print_processors/": "T1547.012 - Print Processors",  # registry
        "Registry_|_/security/policy/secrets": "T1003.004 - LSA Secrets",  # registry
        "Registry_|_/special/perf": "T1337.002 - Office Test",  # registry
        "Registry_|_active setup/installed components|active_setup/installed_components": "T1547.014 - Active Setup",  # registry
        "Registry_|_currentcontrolset/control/lsa": "T1003.001 - LSASS Memory | T1547.002 - Authentication Package | T1547.005 - Security Support Provider | T1556.002 - Password Filter DLL",  # registry
        "Registry_|_currentcontrolset/control/nls/language": "T1614.001 - System Language Discovery",  # registry
        "Registry_|_currentcontrolset/control/print/monitors": "T1547.010 - Port Monitors",  # registry
        "Registry_|_currentcontrolset/control/safeboot/minimal": "T1562.009 - Safe Mode Boot",  # registry
        "Registry_|_currentcontrolset/control/session manager|currentcontrolset/control/session_manager": "T1547.001 - Registry Run Keys / Startup Folder | T1546.009 - AppCert DLLs",  # registry
        "Registry_|_currentcontrolset/services/": "T1574.011 - Services Registry Permissions Weakness",  # registry
        "Registry_|_currentcontrolset/services/termservice/parameters": "T1505.005 - Terminal Services DLL",  # registry
        "Registry_|_currentcontrolset/services/w32time/timeproviders": "T1547.003 - Time Providers",  # registry
        "Registry_|_currentversion/app paths|software/classes/ms-settings/shell/open/command|currentversion/app_paths|software/classes/mscfile/shell/open/command|software/classes/exefile/shell/runas/command/isolatedcommand": "T1548.002 - Bypass User Account Control",  # registry
        "Registry_|_currentversion/appcompatflags/installedsdb": "T1546.011 - Application Shimming",  # registry
        "Registry_|_currentversion/explorer/fileexts": "T1546.001 - Change Default File Association",  # registry
        "Registry_|_currentversion/image file execution options|currentversion/image_file_execution_options": "T1546.008 - Accessibility Features | T1546.012 - Image File Execution Options Injection | T1547.002 - Authentication Package | T1547.005 - Security Support Provider",  # registry
        "Registry_|_currentversion/policies/credui/enumerateadministrators": "T1087.001 - Local Account | T1087.002 - Domain Account",  # registry
        "Registry_|_currentversion/run|currentversion/policies/explorer/run|currentversion/explorer/user/|currentversion/explorer/shell": "T1547.001 - Registry Run Keys / Startup Folder",  # registry
        "Registry_|_currentversion/windows|nt/currentversion/windows": "T1546.010 - AppInit DLLs",  # registry
        "Registry_|_currentversion/winlogon/notify|currentversion/winlogon/userinit|currentversion/winlogon/shell": "T1547.001 - Registry Run Keys / Startup Folder | T1547.004 - Winlogon Helper DLL",  # registry
        "Registry_|_environment/userinitmprlogonscript": "T1037.001 - Logon Script (Windows)",  # registry
        "Registry_|_manager/safedllsearchmode|security/policy/secrets": "T1003.001 - LSASS Memory | T1547.008 - LSASS Driver",  # registry
        "Registry_|_microsoft/windows/softwareprotectionplatform/eventcachemanager": "T1036.004 - Masquerade Task or Service",  # registry
        "Registry_|_nt/dnsclient": "T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",  # registry
        "Registry_|_panel/cpls": "T1218.002 - Control Panel",  # registry
        "Registry_|_software/microsoft/netsh": "T1546.007 - Netsh Helper DLL",  # registry
        "Registry_|_software/microsoft/ole": "T1175.001 - Component Object Model Hijacking",  # registry
        "Registry_|_software/policies/microsoft/previousversions/disablelocalpage": "T1490.000 - Inhibit System Recovery",  # registry
        "Registry_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",  # registry
        "url_|_github|gitlab|bitbucket|sourceforge": "T1213.003 - Code Repositories | T1567.001 - Exfiltration to Code Repository",  # urls
        "url_|_linkedin\\.|facebook\\.|twitter\\.|instagram\\.|snapchat\\.|tiktok\\.|vk\\.|telegram\\.|whatsapp\\.": "T1566.003 - Spearphishing via Service",  # urls
        "url_|_onedrive|1drv|azure|icloud|cloudrive|clouddrive|dropbox|drive\\.google|\\.box\\.com|egnyte|mediafire|zippyshare|megaupload|4shared": "T1537.000 - Transfer Data to Cloud Account | T1567.002 - Exfiltration to Cloud Storage",  # urls
        "ForeignPort_|_^110|143|465|993|995$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.003 - Mail Protocols",  # memory
        "ForeignPort_|_^135$": "T1047.000 - Windows Management Instrumentation | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol",  # memory
        "ForeignPort_|_^137$": "T1187.000 - Forced Authentication | T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",  # memory
        "ForeignPort_|_^139$": "T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1133.000 - External Remote Services | T1187.000 - Forced Authentication",  # memory
        "ForeignPort_|_^20|21$": "T1041.000 - Exfiltration over C2 Channel | T1071.002 - File Transfer Protocols | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol",  # memory
        "ForeignPort_|_^22|23$": "T1021.004 - SSH | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1133.000 - External Remote Services",  # memory
        "ForeignPort_|_^2375|2376$": "T1612.000 - Build Image on Host",  # memory
        "ForeignPort_|_^25$": "T1041.000 - Exfiltration over C2 Channel | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.003 - Mail Protocols",  # memory
        "ForeignPort_|_^3389$": "T1021.001 - Remote Desktop Protocol | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1210.000 - Exploitation of Remote Services",  # memory
        "ForeignPort_|_^389|88|1433|1521|3306$": "T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing",  # memory
        "ForeignPort_|_^443$": "T1041.000 - Exfiltration over C2 Channel  | T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol | T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | T1071.001 - Web Protocols | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1187.000 - Forced Authentication | T1189.000 - Drive-by Compromise",  # memory
        "ForeignPort_|_^445$": "T1021.002 - SMB/Windows Admin Shares | T1041.000 - Exfiltration over C2 Channel | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1133.000 - External Remote Services | T1187.000 - Forced Authentication | T1210.000 - Exploitation of Remote Services",  # memory
        "ForeignPort_|_^53$": "T1041.000 - Exfiltration over C2 Channel | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.002 - DNS",  # memory
        "ForeignPort_|_^5355$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",  # memory
        "ForeignPort_|_^5800|5895|5938|5984|5986|8200$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1219.000 - Remote Access Software",  # memory
        "ForeignPort_|_^5900$": "T1021.005 - VNC | T1219.000 - Remote Access Software | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol",  # memory
        "ForeignPort_|_^69|989|990$": "T1071.002 - File Transfer Protocols | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol",  # memory
        "ForeignPort_|_^80$": "T1041.000 - Exfiltration over C2 Channel | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.001 - Web Protocols | T1110.004 - Credential Stuffing | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1187.000 - Forced Authentication | T1189.000 - Drive-by Compromise",  # memory
        "LocalPort_|_^135$": "T1047.000 - Windows Management Instrumentation | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol",  # memory
        "LocalPort_|_^137$": "T1187.000 - Forced Authentication | T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",  # memory
        "LocalPort_|_^139$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1133.000 - External Remote Services | T1187.000 - Forced Authentication",  # memory
        "LocalPort_|_^20|21$": "T1041.000 - Exfiltration over C2 Channel | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.002 - File Transfer Protocols",  # memory
        "LocalPort_|_^22|23$": "T1021.004 - SSH | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1133.000 - External Remote Services",  # memory
        "LocalPort_|_^2375|2376$": "T1612.000 - Build Image on Host",  # memory
        "LocalPort_|_^25$": "T1041.000 - Exfiltration over C2 Channel | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.003 - Mail Protocols",  # memory
        "LocalPort_|_^3389$": "T1021.001 - Remote Desktop Protocol | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1210.000 - Exploitation of Remote Services",  # memory
        "LocalPort_|_^389|88|1433|1521|3306$": "T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing",  # memory
        "LocalPort_|_^443$": "T1041.000 - Exfiltration over C2 Channel  | T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol | T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | T1071.001 - Web Protocols | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1187.000 - Forced Authentication | T1189.000 - Drive-by Compromise",  # memory
        "LocalPort_|_^445$": "T1021.002 - SMB/Windows Admin Shares | T1041.000 - Exfiltration over C2 Channel | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1133.000 - External Remote Services | T1187.000 - Forced Authentication | T1210.000 - Exploitation of Remote Services",  # memory
        "LocalPort_|_^53$": "T1041.000 - Exfiltration over C2 Channel | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.002 - DNS",  # memory
        "LocalPort_|_^5355$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",  # memory
        "LocalPort_|_^5800|5895|5938|5984|5986|8200$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1219.000 - Remote Access Software",  # memory
        "LocalPort_|_^5900$": "T1021.005 - VNC | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1219.000 - Remote Access Software",  # memory
        "LocalPort_|_^69|989|990$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.002 - File Transfer Protocols",  # memory
        "LocalPort_|_^80$": "T1041.000 - Exfiltration over C2 Channel | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.001 - Web Protocols | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1187.000 - Forced Authentication | T1189.000 - Drive-by Compromise",  # memory
        "nixCommand_|_/var/log": "T1070.002 - Clear Linux or Mac System Logs",  # memory, unix-logs
        "nixCommand_|_\\.7z|\\.arj|\\.tar|\\.tgz|\\.zip": "T1560.001 - Archive via Utility",  # memory, unix-logs
        "nixCommand_|_\\.eml": "T1114.001 - Local Email Collection",  # memory, unix-logs
        "nixCommand_|_\\.lnk": "T1547.009 - Shortcut Modification",  # memory, unix-logs
        "nixCommand_|_\\.mobileconfig|profiles": "T1176.000 - Browser Extensions",  # memory, unix-logs
        "nixCommand_|_add-trusted-cert|trustroot": "T1553.004 - Install Root Certificate",  # memory, unix-logs
        "nixCommand_|_ascii|unicode|hex|base64|mime": "T1132.001 - Standard Encoding",  # memory, unix-logs
        "nixCommand_|_at\\.": "T1053.002 - At",  # memory, unix-logs
        "nixCommand_|_authorizationexecutewithprivileges|security_authtrampoline": "T1548.004 - Elevated Execution with Prompt",  # memory, unix-logs
        "nixCommand_|_authorized_keys|sshd_config|ssh-keygen": "T1098.004 - SSH Authorized Keys",  # memory, unix-logs
    }
    transformsconf.write("[mitre_assign]\nINGEST_EVAL = mitre_techniques=")
    for ioc, mitre in assignment_pairings.items():
        transformsconf.write(
            "{}{}{}{}{}{}{}".format(
                start,
                ioc.split("_|_")[0],
                prefix,
                ioc.split("_|_")[1],
                suffix,
                mitre,
                end,
            )
        )
    transformsconf.write(
        '"-")))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))), '
    )
    transformsconf.write('mitre_technique=split(mitre_techniques," | ")\n\n')
