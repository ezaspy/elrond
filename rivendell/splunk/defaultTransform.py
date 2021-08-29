#!/usr/bin/env python3 -tt
def doTransform(transformsconf):
    start, prefix, suffix, end = "if(match(", ",\"(", ")\"), \"", "\", "
    assignment_pairings = {
        "Artefact_|_/etc/profile|/etc/zshenv|/etc/zprofile|/etc/zlogin|profile\\.d|bash_profile|bashrc|bash_login|bash_logout|zshrc|zshenv|zlogout|zlogin|profile": "T1546.004 - Unix Shell Configuration Modification",# timeline
        "Artefact_|_/print processors/|/print_processors/": "T1547.012 - Print Processors",# timeline
        "Artefact_|_/security/policy/secrets": "T1003.004 - LSA Secrets",# timeline
        "Artefact_|_/special/perf": "T1337.002 - Office Test",# timeline
        "Artefact_|_/var/log": "T1070.002 - Clear Linux or Mac System Logs",# timeline
        "Artefact_|_\\.7z|\\.arj|\\.cab|\\.tar|\\.tgz|\\.zip": "T1560.001 - Archive via Utility",# timeline
        "Artefact_|_\\.asc|\\.cer|\\.gpg|\\.key|\\.p12|\\.p7b|\\.pem|\\.pfx|\\.pgp|\\.ppk": "T1552.004 - Private Keys",# timeline
        "Artefact_|_\\.chm|\\.hh": "T1218.001 - Compiled HTML File",# timeline
        "Artefact_|_\\.cpl|panel/cpls": "T1218.002 - Control Panel",# timeline
        "Artefact_|_\\.doc|\\.xls|\\.ppt|\\.pdf|winword|excel|powerpnt|acrobat|acrord32": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File",# timeline
        "Artefact_|_\\.docm|\\.xlsm|\\.pptm": "T1137.001 - Office Template Macros | T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1559.001 - Component Object Model",# timeline
        "Artefact_|_\\.docx|\\.xlsx|\\.pptx": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1221.000 - Template Injection | ",# timeline
        "Artefact_|_\\.job|schtask": "T1053.005 - Scheduled Task",# timeline
        "Artefact_|_\\.lnk": "T1547.009 - Shortcut Modification",# timeline
        "Artefact_|_\\.local|\\.manifest": "T1574.001 - DLL Search Order Hijacking",# timeline
        "Artefact_|_\\.mobileconfig|profiles": "T1176.000 - Browser Extensions",# timeline
        "Artefact_|_\\.mp3|\\.wav|\\.aac|\\.m4a|microphone": "T1123.000 - Audio Capture",# timeline
        "Artefact_|_\\.mp4|\\.mkv|\\.avi|\\.mov|\\.wmv|\\.mpg|\\.mpeg|\\.m4v|\\.flv": "T1125.000 - Video Capture",# timeline
        "Artefact_|_\\.msg|\\.eml": " | T1203.000 - Exploitation for Client Execution | T1204.001 - Malicious Link | T1204.002 - Malicious File | T1566.001 - Spearphishing Attachment | T1566.002 - Spearphishing Link",# timeline
        "Artefact_|_\\.ost|\\.pst|\\.msg|\\.eml": "T1114.001 - Local Email Collection",# timeline
        "Artefact_|_\\.ps1": "T1059.001 - PowerShell",# timeline
        "Artefact_|_\\.service|services\\.exe|sc\\.exe": "T1007.000 - System Service Discovery | T1489.000 - Service Stop | T1543.003 - Windows Service | T1569.002 - Service Execution",# timeline
        "Artefact_|_active setup/installed components|active_setup/installed_components": "T1547.014 - Active Setup",# timeline
        "Artefact_|_add-trusted-cert|trustroot|certmgr": "T1553.004 - Install Root Certificate",# timeline
        "Artefact_|_admin%24|admin\\$|admin$|c%24|c\\$|c$": "T1021.002 - SMB/Windows Admin Shares | T1570.000 - Lateral Tool Transfer",# timeline
        "Artefact_|_ascii|unicode|hex|base64|mime": "T1132.001 - Standard Encoding",# timeline
        "Artefact_|_at\\.": "T1053.001 - At (Linux)",# timeline
        "Artefact_|_atbroker|displayswitch|magnify|narrator|osk|sethc|utilman": "T1546.008 - Accessibility Features",# timeline
        "Artefact_|_authorizationexecutewithprivileges|security_authtrampoline": "T1548.004 - Elevated Execution with Prompt",# timeline
        "Artefact_|_authorized_keys|sshd_config|ssh-keygen": "T1098.004 - SSH Authorized Keys",# timeline
        "Artefact_|_autoruns|reg |reg\\.exe": "T1112.000 - Modify Registry",# timeline
        "Artefact_|_bash_history": "T1552.003 - Bash History",# timeline
        "Artefact_|_bcdedit|csrutil": "T1553.006 - Code Signing Policy Modification",# timeline
        "Artefact_|_bluetooth": "T1011.001 - Exfiltration over Bluetooth",# timeline
        "Artefact_|_certutil": "T1036.003 - Rename System Utilities | T1140.000 - Deobfuscate/Decode Files or Information | T1553.004 - Install Root Certificate",# timeline
        "Artefact_|_chage|common-password|pwpolicy|getaccountpolicies": "T1201.000 - Password Policy Discovery",# timeline
        "Artefact_|_chmod": "T1222.002 - Linux and Mac File and Directory Permissions Modification | T1548.001 - Setuid and Setgid",# timeline
        "Artefact_|_chown|chgrp": "T1222.002 - Linux and Mac File and Directory Permissions Modification",# timeline
        "Artefact_|_clipboard|pbpaste": "T1115.000 - Clipboard Data",# timeline
        "Artefact_|_cmd |cmd_|cmd\\.": "T1059.003 - Windows Command Shell | T1106.000 - Native API",# timeline
        "Artefact_|_cmmgr32|cmstp|cmlua": "T1218.003 - CMSTP",# timeline
        "Artefact_|_com\\.apple\\.quarantine|xattr|xttr": "T1553.001 - Gatekeeper Bypass",# timeline
        "Artefact_|_contentsofdirectoryatpath|pathextension|compare|fork |fork_": "T1106.000 - Native API",# timeline
        "Artefact_|_csc\\.exe|gcc |gcc_": "T1027.004 - Compile After Delivery",# timeline
        "Artefact_|_cscript|pubprn": "T1216.001 - PubPrn",# timeline
        "Artefact_|_curl |curl_": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1553.001 - Gatekeeper Bypass",# timeline
        "Artefact_|_currentcontrolset/control/lsa": "T1003.001 - LSASS Memory | T1547.002 - Authentication Package | T1547.005 - Security Support Provider | T1556.002 - Password Filter DLL",# timeline
        "Artefact_|_currentcontrolset/control/print/monitors": "T1547.010 - Port Monitors",# timeline
        "Artefact_|_currentcontrolset/control/session manager|currentcontrolset/control/session_manager": "T1546.009 - AppCert DLLs | T1547.001 - Registry Run Keys / Startup Folder",# timeline
        "Artefact_|_currentcontrolset/services/": "T1574.011 - Services Registry Permissions Weakness",# timeline
        "Artefact_|_currentcontrolset/services/w32time/timeproviders": "T1547.003 - Time Providers",# timeline
        "Artefact_|_currentversion/app paths|software/classes/ms-settings/shell/open/command|currentversion/app_paths|software/classes/mscfile/shell/open/command|software/classes/exefile/shell/runas/command/isolatedcommand|eventvwr|sdclt": "T1548.002 - Bypass User Account Control",# timeline
        "Artefact_|_currentversion/appcompatflags/installedsdb": "T1546.011 - Application Shimming",# timeline
        "Artefact_|_currentversion/explorer/fileexts": "T1546.001 - Change Default File Association",# timeline
        "Artefact_|_currentversion/image file execution options|currentversion/image_file_execution_options": "T1546.008 - Accessibility Features | T1546.012 - Image File Execution Options Injection | T1547.002 - Authentication Package | T1547.005 - Security Support Provider",# timeline
        "Artefact_|_currentversion/policies/credui/enumerateadministrators": "T1087.001 - Local Account | T1087.002 - Domain Account",# timeline
        "Artefact_|_currentversion/run|currentversion/policies/explorer/run|currentversion/explorer/user|currentversion/explorer/shell": "T1547.001 - Registry Run Keys / Startup Folder",# timeline
        "Artefact_|_currentversion/windows|nt/currentversion/windows": "T1546.010 - AppInit DLLs",# timeline
        "Artefact_|_currentversion/winlogon/notify|currentversion/winlogon/userinit|currentversion/winlogon/shell": "T1547.001 - Registry Run Keys / Startup Folder | T1547.004 - Winlogon Helper DLL",# timeline
        "Artefact_|_DISPLAY|display|HID|hid|PCI|pci|IDE|ide|ROOT|root|UMB|umb|FDC|fdc|IDE|ide|SCSI|scsi|STORAGE|storage|USBSTOR|usbstor|USB|usb": "T1025.000 - Data from Removable Media | T1052.001 - Exfiltration over USB | T1056.001 - Keylogging | T1091.000 - Replication through Removable Media | T1200.000 - Hardware Additions | T1570.000 - Lateral Tool Transfer",# timeline, usb
        "Artefact_|_docker build|docker build|docker_build|docker__build": "T1612.000 - Build Image on Host",# timeline
        "Artefact_|_docker create|docker create|docker start|docker start|docker_create|docker__create|docker_start|docker_start": "T1610.000 - Deploy Container",# timeline
        "Artefact_|_docker exec|docker exec|docker run|docker run|kubectl exec|kubectl exec|kubectl run|kubectl run|docker_exec|docker__exec|docker_run|docker__run|kubectl_exec|kubectl__exec|kubectl_run|kubectl__run": "T1609.000 - Container Administration Command",# timeline
        "Artefact_|_dscacheutil|ldapsearch": "T1069.002 - Domain Groups | T1087.002 - Domain Accounts",# timeline
        "Artefact_|_dscl": "T1069.001 - Local Groups | T1564.002 - Hidden Users",# timeline
        "Artefact_|_emond": "T1546.014 - Emond | T1547.011 - Plist Modification",# timeline
        "Artefact_|_encrypt": "T1573.001 - Symmetric Cryptography | T1573.002 - Asymmetric Cryptography",# timeline
        "Artefact_|_environment/userinitmprlogonscript": "T1037.001 - Logon Script (Windows)",# timeline
        "Artefact_|_find |locate |find_|locate_": "T1083.000 - File and Directory Discovery",# timeline
        "Artefact_|_forwardingsmtpaddress|x-forwarded-to|x-mailfwdby|x-ms-exchange-organization-autoforwarded": "T1114.003 - Email Forwarding Rule",# timeline
        "Artefact_|_fsutil|fsinfo": "T1120.000 - Peripheral Device Discovery",# timeline
        "Artefact_|_github|gitlab|bitbucket": "T1567.001 - Exfiltration to Code Repository",# timeline
        "Artefact_|_gpttmpl\\.inf|scheduledtasks\\.xml": "T1484.001 - Group Policy Modification",# timeline
        "Artefact_|_group": "T1069.001 - Local Groups | T1069.002 - Domain Groups",# timeline
        "Artefact_|_gsecdump|mimikatz|pwdumpx|secretsdump|reg save|reg save|net user|net user|net\\.exe user|net\\.exe user|net1 user|net1 user|net1\\.exe user|net1\\.exe user|reg_save|reg_save|net user|net user|net\\.exe user|net\\.exe user|net1 user|net1 user|net1\\.exe user|net1\\.exe user|reg_save|reg__save|net_user|net__user|net\\.exe_user|net\\.exe__user|net1_user|net1__user|net1\\.exe_user|net1\\.exe__user": "T1003.002 - Security Account Manager",# timeline
        "Artefact_|_halt": "T1529.000 - System Shutdown/Reboot",# timeline
        "Artefact_|_hidden|uielement": "T1564.003 - Hidden Window",# timeline
        "Artefact_|_histcontrol": "T1562.003 - Impair Command History Logging",# timeline
        "Artefact_|_history|histfile": "T1070.003 - Clear Command History | T1552.003 - Bash History | T1562.003 - Impair Command History Logging",# timeline
        "Artefact_|_hostname|systeminfo|whoami": "T1033.000 - System Owner/User Discovery",# timeline
        "Artefact_|_ifconfig": "T1016.001 - Internet Connection Discovery",# timeline
        "Artefact_|_ipc%24|ipc\\$|ipc$": "T1021.002 - SMB/Windows Admin Shares | T1559.001 - Component Object Model",# timeline
        "Artefact_|_is_debugging|sysctl|ptrace": "T1497.001 - System Checks",# timeline
        "Artefact_|_keychain": "T1555.001 - Keychain",# timeline
        "Artefact_|_kill": "T1489.000 - Service Stop | T1548.003 - Sudo and Sudo Caching | T1562.001 - Disable or Modify Tools",# timeline
        "Artefact_|_launchagents|systemctl": "T1543.001 - Launch Agent",# timeline
        "Artefact_|_launchctl": "T1569.001 - Launchctl",# timeline
        "Artefact_|_launchdaemons": "T1543.004 - Launch Daemon",# timeline
        "Artefact_|_lc_code_signature|lc_load_dylib": "T1546.006 - LC_LOAD_DYLIB Addition | T1574.004 - Dylib Hijacking",# timeline
        "Artefact_|_lc_load_weak_dylib|rpath|loader_path|executable_path|ottol": "T1547.004 - Dylib Hijacking",# timeline
        "Artefact_|_ld_preload|dyld_insert_libraries|export|setenv|putenv|os\\.environ|ld\\.so\\.preload|dlopen|mmap|failure": "T1547.006 - Dynamic Linker Hijacking",# timeline
        "Artefact_|_libzip|zlib|rarfile|bzip2": "T1560.002 - Archive via Library",# timeline
        "Artefact_|_loginitems|loginwindow|smloginitemsetenabled|uielement|quarantine": "T1547.011 - Plist Modification",# timeline
        "Artefact_|_loginwindow|hide500users|dscl|uniqueid": "T1564.002 - Hidden Users",# timeline
        "Artefact_|_lsof|who": "T1049.000 - System Network Connections Discovery",# timeline
        "Artefact_|_malloc|ptrace_setregs|ptrace_poketext|ptrace_pokedata": "T1055.008 - Ptrace System Calls",# timeline
        "Artefact_|_manager/safedllsearchmode|security/policy/secrets": "T1003.001 - LSASS Memory | T1547.008 - LSASS Driver",# timeline
        "Artefact_|_microsoft/windows/softwareprotectionplatform/eventcachemanager|scvhost|svchast|svchust|svchest|lssas|lsasss|lsaas|cssrs|canhost|conhast|connhost|connhst|iexplorer|iexploror|iexplorar": "T1036.004 - Masquerade Task or Service",# timeline
        "Artefact_|_modprobe|insmod|lsmod|rmmod|modinfo|kextload|kextunload|autostart": "T1547.006 - Kernel Modules and Extensions",# timeline
        "Artefact_|_mshta": "T1218.005 - Mshta",# timeline
        "Artefact_|_msiexec": "T1218.007 - Msiexec",# timeline
        "Artefact_|_msxml": "T1220.000 - XSL Script Processing",# timeline
        "Artefact_|_net |net\\.exe |net1 |net1\\.exe |net_|net\\.exe_|net1_|net1\\.exe_": "T1070.005 - Network Share Connection Removal | T1018.000 - Remote System Discovery | T1569.002 - Service Execution | T1574.008 - Path Interception by Search Order Hijacking",# timeline
        "Artefact_|_netsh": "T1049.000 - System Network Connections Discovery | T1090.001 - Internal Proxy | T1135.000 - Network Share Discovery | T1518.001 - Security Software Discovery",# timeline
        "Artefact_|_normal\\.dotm|personal\\.xlsb": "T1137.001 - Office Template Macros",# timeline
        "Artefact_|_nt/dnsclient": "T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",# timeline
        "Artefact_|_ntds|ntdsutil|secretsdump": "T1003.003 - NTDS",# timeline
        "Artefact_|_odbcconf": "T1218.008 - Odbcconf",# timeline
        "Artefact_|_onedrive|1drv|azure|icloud|cloudrive|dropbox|drive\\.google|fileshare|mediafire|zippyshare|megaupload|4shared": "T1537.000 - Transfer Data to Cloud Account | T1567.002 - Exfiltration to Cloud Storage",# timeline
        "Artefact_|_pam_unix\\.so": "T1556.003 - Pluggable Authentication Modules",# timeline
        "Artefact_|_passwd|shadow": "T1003.008 - /etc/passwd and /etc/shadow | T1087.001 - Local Account | T1556.003 - Pluggable Authentication Modules",# timeline
        "Artefact_|_password|pwd|login|store|secure|credentials": "T1552.001 - Credentials in Files | T1555.005 - Password Managers",# timeline
        "Artefact_|_ping|traceroute|etc/host|etc/hosts|bonjour": "T1016.001 - Internet Connection Discovery | T1018.000 - Remote System Discovery",# timeline
        "Artefact_|_policy\\.vpol|vaultcmd|vcrd": "T1555.004 - Windows Credential Manager",# timeline
        "Artefact_|_portopening": "T1090.001 - Internal Proxy",# timeline
        "Artefact_|_powershell": "T1059.001 - PowerShell | T1106.000 - Native API",# timeline
        "Artefact_|_ps |ps_": "T1057.000 - Process Discovery",# timeline
        "Artefact_|_psexec": "T1003.001 - LSASS Memory | T1569.002 - Service Execution | T1570.000 - Lateral Tool Transfer",# timeline
        "Artefact_|_python|\\.py |\\.py_": "T1059.006 - Python",# timeline
        "Artefact_|_rc\\.local|rc\\.common": "T1037.004 - RC Scripts",# timeline
        "Artefact_|_rm |rm_": "T1070.004 - File Deletion | T1485.000 - Data Destruction",# timeline
        "Artefact_|_rundll32": "T1218.011 - Rundll32",# timeline
        "Artefact_|_scp|rsync|sftp": "T1105.000 - Ingress Tool Transfer",# timeline
        "Artefact_|_scrnsave": "T1546.002 - Screensaver",# timeline
        "Artefact_|_sdelete": "T1070.004 - File Deletion | T1485.000 - Data Destruction",# timeline
        "Artefact_|_services": "T1489.000 - Service Stop",# timeline
        "Artefact_|_software/microsoft/netsh": "T1546.007 - Netsh Helper DLL",# timeline
        "Artefact_|_software/microsoft/ole": "T1175.001 - Component Object Model",# timeline
        "Artefact_|_software/policies/microsoft/previousversions/disablelocalpage": "T1490.000 - Inhibit System Recovery",# timeline
        "Artefact_|_startupitems|startupparameters": "T1037.002 - Logon Script (Mac)",# timeline
        "Artefact_|_startupparameters": "T1037.005 - Startup Items | T1547.011 - Plist Modification",# timeline
        "Artefact_|_sudo|timestamp_timeout|tty_tickets": "T1548.003 - Sudo and Sudo Caching",# timeline
        "Artefact_|_systemsetup": "T1082.000 - System Information Discovery",# timeline
        "Artefact_|_tasklist": "T1007.000 - System Service Discovery | T1518.001 - Security Software Discovery",# timeline
        "Artefact_|_time|sleep": "T1497.003 - Time Based Evasion",# timeline
        "Artefact_|_timer": "T1053.006 - Systemd Timers",# timeline
        "Artefact_|_trap": "T1546.005 - Trap",# timeline
        "Artefact_|_tscon": "T1563.002 - RDP Hijacking",# timeline
        "Artefact_|_u202e": "T1036.002 - Right-to-Left Override",# timeline
        "Artefact_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",# timeline, usb
        "Artefact_|_vbscript|wscript": "T1059.005 - Visual Basic | T1059.007 - JavaScript",# timeline
        "Artefact_|_verclsid": "T1218.012 - Verclsid",# timeline
        "Artefact_|_winrm": "T1021.006 - Windows Remote Management",# timeline
        "Artefact_|_wmic|msxsl": "T1047.000 - Windows Management Instrumentation | T1220.000 - XSL Script Processing",# timeline
        "Artefact_|_xdg|autostart": "T1547.013 - XDG Autostart Entries",# timeline
        "Artefact_|_xwd|screencapture": "T1113.000 - Screen Capture",# timeline
        "Artefact_|_zwqueryeafile|zwseteafile": "T1564.004 - NTFS File Attributes",# timeline
        "EventID_|_^10|12|13$": "T1218.003 - CMSTP",# evt
        "EventID_|_^1074|6006$": "T1529.000 - System Shutdown/Reboot",# evt
        "EventID_|_^1102$": "T1070.001 - Clear Windows Event Logs",# evt
        "EventID_|_^17|18$": "T1055.002 - Portable Execution Injection",# evt
        "EventID_|_^3033|3063$": "T1547.008 - LSASS Driver | T1553.003 - SIP and Trust Provider Hijacking",# evt
        "EventID_|_^307|510$": "T1484.002 - Domain Trust Modification",# evt
        "EventID_|_^4624|4634$": "T1558.001 - Golden Ticket | T1558.002 - Silver Ticket",# evt
        "EventID_|_^4625|4648|4771$": "T1110.003 - Password Spraying",# evt
        "EventID_|_^4657$": "T1112.000 - Modify Registry | T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",# evt
        "EventID_|_^4670$": "T1098.000 - Account Manipulation | T1222.001 - Windows File and Directory Permissions Modification",# evt
        "EventID_|_^4672$": "T1484.001 - Group Policy Modification | T1558.001 - Golden Ticket",# evt
        "EventID_|_^4697|7045$": "T1021.003 - Windows Service",# evt
        "EventID_|_^4704|5136|5137|5138|5139|5141$": "T1484.001 - Group Policy Modification",# evt
        "EventID_|_^4720$": "T1136.001 - Local Account | T1136.002 - Domain Account",# evt
        "EventID_|_^4723|4724|4726|4740$": "T1531.000 - Account Access Removal",# evt
        "EventID_|_^4728|4738$": "T1098.000 - Account Manipulation",# evt
        "EventID_|_^4768|4769$": "T1550.002 - Pass the Hash | T1550.003 - Pass the Ticket | T1558.003 - Kerberoasting",# evt
        "EventID_|_^4928|4929$": "T1207.000 - Rogue Domain Controller",# evt
        "EventID_|_^524$": "T1490.000 - Inhibit System Recovery",# evt
        "EventID_|_^5861$": "T1546.003 - Windows Management Instrumentation Event Subscription",# evt
        "EventID_|_^7045$": "T1021.003 - Windows Service | T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",# evt
        "EventID_|_^81$": "T1553.003 - SIP and Trust Provider Hijacking",# evt
        "Filename_|_\\.7z|\\.arj|\\.tar|\\.tgz|\\.zip": "T1560.001 - Archive via Utility",# LastAccessTime, metadata & iocs
        "Filename_|_\\.asc|\\.cer|\\.gpg|\\.key|\\.p12|\\.p7b|\\.pem|\\.pfx|\\.pgp|\\.ppk": "T1552.004 - Private Keys",# LastAccessTime, metadata & iocs
        "Filename_|_\\.chm|\\.hh": "T1218.001 - Compiled HTML File",# LastAccessTime, metadata & iocs
        "Filename_|_\\.cpl": "T1218.002 - Control Panel",# LastAccessTime, metadata & iocs
        "Filename_|_\\.doc|\\.xls|\\.ppt|\\.pdf": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File",# LastAccessTime, metadata & iocs
        "Filename_|_\\.docm|\\.xlsm|\\.pptm": "T1137.001 - Office Template Macros | T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1559.001 - Component Object Model",# LastAccessTime, metadata & iocs
        "Filename_|_\\.docx|\\.xlsx|\\.pptx": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1221.000 - Template Injection",# LastAccessTime, metadata & iocs
        "Filename_|_\\.job": "T1053.005 - Scheduled Task",# LastAccessTime, metadata & iocs
        "Filename_|_\\.lnk": "T1547.009 - Shortcut Modification",# LastAccessTime, metadata & iocs
        "Filename_|_\\.local|\\.manifest": "T1574.001 - DLL Search Order Hijacking",# LastAccessTime, metadata & iocs
        "Filename_|_\\.mobileconfig|profiles": "T1176.000 - Browser Extensions",# LastAccessTime, metadata & iocs
        "Filename_|_\\.mp3|\\.wav|\\.aac|\\.m4a": "T1123.000 - Audio Capture",# LastAccessTime, metadata & iocs
        "Filename_|_\\.mp4|\\.mkv|\\.avi|\\.mov|\\.wmv|\\.mpg|\\.mpeg|\\.m4v|\\.flv": "T1125.000 - Video Capture",# LastAccessTime, metadata & iocs
        "Filename_|_\\.msg|\\.eml": "T1203.000 - Exploitation for Client Execution | T1204.001 - Malicious Link | T1204.002 - Malicious File | T1566.001 - Spearphishing Attachment | T1566.002 - Spearphishing Link",# LastAccessTime, metadata & iocs
        "Filename_|_\\.ost|\\.pst|\\.msg|\\.eml": "T1114.001 - Local Email Collection",# LastAccessTime, metadata & iocs
        "Filename_|_\\.ps1": "T1059.001 - PowerShell",# LastAccessTime, metadata & iocs
        "Filename_|_\\.service|services\\.exe|sc\\.exe": "T1007.000 - System Service Discovery | T1489.000 - Service Stop | T1543.003 - Windows Service | T1569.002 - Service Execution",# LastAccessTime, metadata & iocs
        "Filename_|_at\\.": "T1053.001 - At (Linux)",# LastAccessTime, metadata & iocs
        "Filename_|_atbroker|displayswitch|magnify|narrator|osk|sethc|utilman": "T1546.008 - Accessibility Features",# LastAccessTime, metadata & iocs
        "Filename_|_autoruns": "T1112.000 - Modify Registry",# LastAccessTime, metadata & iocs
        "Filename_|_bash_history": "T1552.003 - Bash History",# LastAccessTime, metadata & iocs
        "Filename_|_bcdedit|csrutil": "T1553.006 - Code Signing Policy Modification",# LastAccessTime, metadata & iocs
        "Filename_|_bluetooth": "T1011.001 - Exfiltration over Bluetooth",# LastAccessTime, metadata & iocs
        "Filename_|_certmgr": "T1553.004 - Install Root Certificate",# LastAccessTime, metadata & iocs
        "Filename_|_certutil": "T1036.003 - Rename System Utilities | T1140.000 - Deobfuscate/Decode Files or Information | T1553.004 - Install Root Certificate",# LastAccessTime, metadata & iocs
        "Filename_|_cmd |cmd_|cmd\\.": "T1059.003 - Windows Command Shell | T1106.000 - Native API",# LastAccessTime, metadata & iocs
        "Filename_|_com\\.apple\\.quarantine": "T1553.001 - Gatekeeper Bypass",# LastAccessTime, metadata & iocs
        "Filename_|_csc\\.exe": "T1027.004 - Compile After Delivery",# LastAccessTime, metadata & iocs
        "Filename_|_cscript": "T1216.001 - PubPrn",# LastAccessTime, metadata & iocs
        "Filename_|_eventvwr|sdclt": "T1548.002 - Bypass User Account Control",# LastAccessTime, metadata & iocs
        "Filename_|_fsutil|fsinfo": "T1120.000 - Peripheral Device Discovery",# LastAccessTime, metadata & iocs
        "Filename_|_github|gitlab|bitbucket": "T1567.001 - Exfiltration to Code Repository",# LastAccessTime, metadata & iocs
        "Filename_|_gpttmpl\\.inf|scheduledtasks\\.xml": "T1484.001 - Group Policy Modification",# LastAccessTime, metadata & iocs
        "Filename_|_keychain": "T1555.001 - Keychain",# LastAccessTime, metadata & iocs
        "Filename_|_microphone": "T1123.000 - Audio Capture",# LastAccessTime, metadata & iocs
        "Filename_|_mshta": "T1218.005 - Mshta",# LastAccessTime, metadata & iocs
        "Filename_|_msiexec": "T1218.007 - Msiexec",# LastAccessTime, metadata & iocs
        "Filename_|_normal\\.dotm|personal\\.xlsb": "T1137.001 - Office Template Macros",# LastAccessTime, metadata & iocs
        "Filename_|_odbcconf": "T1218.008 - Odbcconf",# LastAccessTime, metadata & iocs
        "Filename_|_pam_unix\\.so": "T1556.003 - Pluggable Authentication Modules",# LastAccessTime, metadata & iocs
        "Filename_|_passwd|shadow": "T1003.008 - /etc/passwd and /etc/shadow | T1087.001 - Local Account | T1556.003 - Pluggable Authentication Modules",# LastAccessTime, metadata & iocs
        "Filename_|_policy\\.vpol|vaultcmd|vcrd": "T1555.004 - Windows Credential Manager",# LastAccessTime, metadata & iocs
        "Filename_|_powershell": "T1059.001 - PowerShell | T1106.000 - Native API",# LastAccessTime, metadata & iocs
        "Filename_|_profile\\.d|bash_profile|bashrc|bash_login|bash_logout": "T1546.004 - Unix Shell Configuration Modification",# LastAccessTime, metadata & iocs
        "Filename_|_psexec": "T1003.001 - LSASS Memory | T1569.002 - Service Execution | T1570.000 - Lateral Tool Transfer",# LastAccessTime, metadata & iocs
        "Filename_|_pubprn": "T1216.001 - PubPrn",# LastAccessTime, metadata & iocs
        "Filename_|_python|\\.py": "T1059.006 - Python",# LastAccessTime, metadata & iocs
        "Filename_|_rc\\.local|rc\\.common": "T1037.004 - RC Scripts",# LastAccessTime, metadata & iocs
        "Filename_|_reg\\.exe": "T1112.000 - Modify Registry",# LastAccessTime, metadata & iocs
        "Filename_|_scrnsave": "T1546.002 - Screensaver",# LastAccessTime, metadata & iocs
        "Filename_|_sdelete": "T1070.004 - File Deletion | T1485.000 - Data Destruction",# LastAccessTime, metadata & iocs
        "Filename_|_sudo|timestamp_timeout|tty_tickets": "T1548.003 - Sudo and Sudo Caching",# LastAccessTime, metadata & iocs
        "Filename_|_tscon": "T1563.002 - RDP Hijacking",# LastAccessTime, metadata & iocs
        "Filename_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",# LastAccessTime, metadata & iocs
        "Filename_|_wmic|msxsl": "T1047.000 - Windows Management Instrumentation | T1220.000 - XSL Script Processing",# LastAccessTime, metadata & iocs
        "Filename1_|_\\.7z|\\.arj|\\.tar|\\.tgz|\\.zip": "T1560.001 - Archive via Utility",# mft
        "Filename1_|_\\.asc|\\.cer|\\.gpg|\\.key|\\.p12|\\.p7b|\\.pem|\\.pfx|\\.pgp|\\.ppk": "T1552.004 - Private Keys",# mft
        "Filename1_|_\\.chm|\\.hh": "T1218.001 - Compiled HTML File",# mft
        "Filename1_|_\\.cpl": "T1218.002 - Control Panel",# mft
        "Filename1_|_\\.doc|\\.xls|\\.ppt|\\.pdf": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File",# mft
        "Filename1_|_\\.docm|\\.xlsm|\\.pptm": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1137.001 - Office Template Macros | T1559.001 - Component Object Model",# mft
        "Filename1_|_\\.docx|\\.xlsx|\\.pptx": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1221.000 - Template Injection",# mft
        "Filename1_|_\\.job": "T1053.005 - Scheduled Task",# mft
        "Filename1_|_\\.lnk": "T1547.009 - Shortcut Modification",# mft
        "Filename1_|_\\.local|\\.manifest": "T1574.001 - DLL Search Order Hijacking",# mft
        "Filename1_|_\\.mp3|\\.wav|\\.aac|\\.m4a": "T1123.000 - Audio Capture",# mft
        "Filename1_|_\\.mp4|\\.mkv|\\.avi|\\.mov|\\.wmv|\\.mpg|\\.mpeg|\\.m4v|\\.flv": "T1125.000 - Video Capture",# mft
        "Filename1_|_\\.msg|\\.eml": "T1203.000 - Exploitation for Client Execution | T1204.001 - Malicious Link | T1204.002 - Malicious File | T1566.001 - Spearphishing Attachment | T1566.002 - Spearphishing Link",# mft
        "Filename1_|_\\.ost|\\.pst|\\.msg": "T1114.001 - Local Email Collection",# mft
        "Filename1_|_\\.ps1": "T1059.001 - PowerShell",# mft
        "Filename1_|_\\.service|services\\.exe|sc\\.exe": "T1007.000 - System Service Discovery | T1489.000 - Service Stop | T1543.003 - Windows Service | T1569.002 - Service Execution",# mft
        "Filename1_|_atbroker|displayswitch|magnify|narrator|osk|sethc|utilman": "T1546.008 - Accessibility Features",# mft
        "Filename1_|_autoruns": "T1112.000 - Modify Registry",# mft
        "Filename1_|_bcdedit|csrutil": "T1553.006 - Code Signing Policy Modification",# mft
        "Filename1_|_certmgr": "T1553.004 - Install Root Certificate",# mft
        "Filename1_|_certutil": "T1036.003 - Rename System Utilities | T1140.000 - Deobfuscate/Decode Files or Information | T1553.004 - Install Root Certificate",# mft
        "Filename1_|_cmd |cmd_|cmd\\.": "T1059.003 - Windows Command Shell | T1106.000 - Native API",# mft
        "Filename1_|_csc\\.exe": "T1027.004 - Compile After Delivery",# mft
        "Filename1_|_cscript": "T1216.001 - PubPrn",# mft
        "Filename1_|_eventvwr|sdclt": "T1548.002 - Bypass User Account Control",# mft
        "Filename1_|_github|gitlab|bitbucket": "T1567.001 - Exfiltration to Code Repository",# mft
        "Filename1_|_gpttmpl\\.inf|scheduledtasks\\.xml": "T1484.001 - Group Policy Modification",# mft
        "Filename1_|_mshta": "T1218.005 - Mshta",# mft
        "Filename1_|_msiexec": "T1218.007 - Msiexec",# mft
        "Filename1_|_normal\\.dotm|personal\\.xlsb": "T1137.001 - Office Template Macros",# mft
        "Filename1_|_odbcconf": "T1218.008 - Odbcconf",# mft
        "Filename1_|_onedrive|1drv|azure|icloud|cloudrive|dropbox|drive\\.google|fileshare|mediafire|zippyshare|megaupload|4shared": "T1537.000 - Transfer Data to Cloud Account | T1567.002 - Exfiltration to Cloud Storage",# mft
        "Filename1_|_policy\\.vpol|vaultcmd|vcrd": "T1555.004 - Windows Credential Manager",# mft
        "Filename1_|_powershell": "T1059.001 - PowerShell | T1106.000 - Native API",# mft
        "Filename1_|_psexec": "T1003.001 - LSASS Memory | T1569.002 - Service Execution | T1570.000 - Lateral Tool Transfer",# mft
        "Filename1_|_pubprn": "T1216.001 - PubPrn",# mft
        "Filename1_|_reg\\.exe": "T1112.000 - Modify Registry",# mft
        "Filename1_|_scrnsave": "T1546.002 - Screensaver",# mft
        "Filename1_|_scvhost|svchast|svchust|svchest|lssas|lsasss|lsaas|cssrs|canhost|conhast|connhost|connhst|iexplorer|iexploror|iexplorar": "T1036.004 - Masquerade Task or Service",# mft
        "Filename1_|_sdelete": "T1070.004 - File Deletion | T1485.000 - Data Destruction",# mft
        "Filename1_|_tscon": "T1563.002 - RDP Hijacking",# mft
        "Filename1_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",# mft
        "Filename1_|_wmic|msxsl": "T1047.000 - Windows Management Instrumentation | T1220.000 - XSL Script Processing",# mft
        "Filename2_|_\\.7z|\\.arj|\\.tar|\\.tgz|\\.zip": "T1560.001 - Archive via Utility",# mft
        "Filename2_|_\\.asc|\\.cer|\\.gpg|\\.key|\\.p12|\\.p7b|\\.pem|\\.pfx|\\.pgp|\\.ppk": "T1552.004 - Private Keys",# mft
        "Filename2_|_\\.chm|\\.hh": "T1218.001 - Compiled HTML File",# mft
        "Filename2_|_\\.cpl": "T1218.002 - Control Panel",# mft
        "Filename2_|_\\.doc|\\.xls|\\.ppt|\\.pdf": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File",# mft
        "Filename2_|_\\.docm|\\.xlsm|\\.pptm": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1137.001 - Office Template Macros | T1559.001 - Component Object Model",# mft
        "Filename2_|_\\.docx|\\.xlsx|\\.pptx": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1221.000 - Template Injection",# mft
        "Filename2_|_\\.job": "T1053.005 - Scheduled Task",# mft
        "Filename2_|_\\.lnk": "T1547.009 - Shortcut Modification",# mft
        "Filename2_|_\\.local|\\.manifest": "T1574.001 - DLL Search Order Hijacking",# mft
        "Filename2_|_\\.mp3|\\.wav|\\.aac|\\.m4a": "T1123.000 - Audio Capture",# mft
        "Filename2_|_\\.mp4|\\.mkv|\\.avi|\\.mov|\\.wmv|\\.mpg|\\.mpeg|\\.m4v|\\.flv": "T1125.000 - Video Capture",# mft
        "Filename2_|_\\.msg|\\.eml": "T1203.000 - Exploitation for Client Execution | T1204.001 - Malicious Link | T1204.002 - Malicious File | T1566.001 - Spearphishing Attachment | T1566.002 - Spearphishing Link",# mft
        "Filename2_|_\\.ost|\\.pst|\\.msg": "T1114.001 - Local Email Collection",# mft
        "Filename2_|_\\.ps1": "T1059.001 - PowerShell",# mft
        "Filename2_|_\\.service|services\\.exe|sc\\.exe": "T1007.000 - System Service Discovery | T1489.000 - Service Stop | T1543.003 - Windows Service | T1569.002 - Service Execution",# mft
        "Filename2_|_atbroker|displayswitch|magnify|narrator|osk|sethc|utilman": "T1546.008 - Accessibility Features",# mft
        "Filename2_|_autoruns": "T1112.000 - Modify Registry",# mft
        "Filename2_|_bcdedit|csrutil": "T1553.006 - Code Signing Policy Modification",# mft
        "Filename2_|_certmgr": "T1553.004 - Install Root Certificate",# mft
        "Filename2_|_certutil": "T1036.003 - Rename System Utilities | T1140.000 - Deobfuscate/Decode Files or Information | T1553.004 - Install Root Certificate",# mft
        "Filename2_|_cmd |cmd_|cmd\\.": "T1059.003 - Windows Command Shell | T1106.000 - Native API",# mft
        "Filename2_|_csc\\.exe": "T1027.004 - Compile After Delivery",# mft
        "Filename2_|_cscript": "T1216.001 - PubPrn",# mft
        "Filename2_|_eventvwr|sdclt": "T1548.002 - Bypass User Account Control",# mft
        "Filename2_|_github|gitlab|bitbucket": "T1567.001 - Exfiltration to Code Repository",# mft
        "Filename2_|_gpttmpl\\.inf|scheduledtasks\\.xml": "T1484.001 - Group Policy Modification",# mft
        "Filename2_|_mshta": "T1218.005 - Mshta",# mft
        "Filename2_|_msiexec": "T1218.007 - Msiexec",# mft
        "Filename2_|_normal\\.dotm|personal\\.xlsb": "T1137.001 - Office Template Macros",# mft
        "Filename2_|_odbcconf": "T1218.008 - Odbcconf",# mft
        "Filename2_|_onedrive|1drv|azure|icloud|cloudrive|dropbox|drive\\.google|fileshare|mediafire|zippyshare|megaupload|4shared": "T1537.000 - Transfer Data to Cloud Account | T1567.002 - Exfiltration to Cloud Storage",# mft
        "Filename2_|_policy\\.vpol|vaultcmd|vcrd": "T1555.004 - Windows Credential Manager",# mft
        "Filename2_|_powershell": "T1059.001 - PowerShell | T1106.000 - Native API",# mft
        "Filename2_|_psexec": "T1003.001 - LSASS Memory | T1569.002 - Service Execution | T1570.000 - Lateral Tool Transfer",# mft
        "Filename2_|_pubprn": "T1216.001 - PubPrn",# mft
        "Filename2_|_reg\\.exe": "T1112.000 - Modify Registry",# mft
        "Filename2_|_scrnsave": "T1546.002 - Screensaver",# mft
        "Filename2_|_scvhost|svchast|svchust|svchest|lssas|lsasss|lsaas|cssrs|canhost|conhast|connhost|connhst|iexplorer|iexploror|iexplorar": "T1036.004 - Masquerade Task or Service",# mft
        "Filename2_|_sdelete": "T1070.004 - File Deletion | T1485.000 - Data Destruction",# mft
        "Filename2_|_tscon": "T1563.002 - RDP Hijacking",# mft
        "Filename2_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",# mft
        "Filename2_|_wmic|msxsl": "T1047.000 - Windows Management Instrumentation | T1220.000 - XSL Script Processing",# mft
        "Filename3_|_\\.7z|\\.arj|\\.tar|\\.tgz|\\.zip": "T1560.001 - Archive via Utility",# mft
        "Filename3_|_\\.asc|\\.cer|\\.gpg|\\.key|\\.p12|\\.p7b|\\.pem|\\.pfx|\\.pgp|\\.ppk": "T1552.004 - Private Keys",# mft
        "Filename3_|_\\.chm|\\.hh": "T1218.001 - Compiled HTML File",# mft
        "Filename3_|_\\.cpl": "T1218.002 - Control Panel",# mft
        "Filename3_|_\\.doc|\\.xls|\\.ppt|\\.pdf": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File",# mft
        "Filename3_|_\\.docm|\\.xlsm|\\.pptm": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1137.001 - Office Template Macros | T1559.001 - Component Object Model",# mft
        "Filename3_|_\\.docx|\\.xlsx|\\.pptx": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1221.000 - Template Injection",# mft
        "Filename3_|_\\.job": "T1053.005 - Scheduled Task",# mft
        "Filename3_|_\\.lnk": "T1547.009 - Shortcut Modification",# mft
        "Filename3_|_\\.local|\\.manifest": "T1574.001 - DLL Search Order Hijacking",# mft
        "Filename3_|_\\.mp3|\\.wav|\\.aac|\\.m4a": "T1123.000 - Audio Capture",# mft
        "Filename3_|_\\.mp4|\\.mkv|\\.avi|\\.mov|\\.wmv|\\.mpg|\\.mpeg|\\.m4v|\\.flv": "T1125.000 - Video Capture",# mft
        "Filename3_|_\\.msg|\\.eml": "T1203.000 - Exploitation for Client Execution | T1204.001 - Malicious Link | T1204.002 - Malicious File | T1566.001 - Spearphishing Attachment | T1566.002 - Spearphishing Link",# mft
        "Filename3_|_\\.ost|\\.pst|\\.msg": "T1114.001 - Local Email Collection",# mft
        "Filename3_|_\\.ps1": "T1059.001 - PowerShell",# mft
        "Filename3_|_\\.service|services\\.exe|sc\\.exe": "T1007.000 - System Service Discovery | T1489.000 - Service Stop | T1543.003 - Windows Service | T1569.002 - Service Execution",# mft
        "Filename3_|_atbroker|displayswitch|magnify|narrator|osk|sethc|utilman": "T1546.008 - Accessibility Features",# mft
        "Filename3_|_autoruns": "T1112.000 - Modify Registry",# mft
        "Filename3_|_bcdedit|csrutil": "T1553.006 - Code Signing Policy Modification",# mft
        "Filename3_|_certmgr": "T1553.004 - Install Root Certificate",# mft
        "Filename3_|_certutil": "T1036.003 - Rename System Utilities | T1140.000 - Deobfuscate/Decode Files or Information | T1553.004 - Install Root Certificate",# mft
        "Filename3_|_cmd |cmd_|cmd\\.": "T1059.003 - Windows Command Shell | T1106.000 - Native API",# mft
        "Filename3_|_csc\\.exe": "T1027.004 - Compile After Delivery",# mft
        "Filename3_|_cscript": "T1216.001 - PubPrn",# mft
        "Filename3_|_eventvwr|sdclt": "T1548.002 - Bypass User Account Control",# mft
        "Filename3_|_github|gitlab|bitbucket": "T1567.001 - Exfiltration to Code Repository",# mft
        "Filename3_|_gpttmpl\\.inf|scheduledtasks\\.xml": "T1484.001 - Group Policy Modification",# mft
        "Filename3_|_mshta": "T1218.005 - Mshta",# mft
        "Filename3_|_msiexec": "T1218.007 - Msiexec",# mft
        "Filename3_|_normal\\.dotm|personal\\.xlsb": "T1137.001 - Office Template Macros",# mft
        "Filename3_|_odbcconf": "T1218.008 - Odbcconf",# mft
        "Filename3_|_onedrive|1drv|azure|icloud|cloudrive|dropbox|drive\\.google|fileshare|mediafire|zippyshare|megaupload|4shared": "T1537.000 - Transfer Data to Cloud Account | T1567.002 - Exfiltration to Cloud Storage",# mft
        "Filename3_|_policy\\.vpol|vaultcmd|vcrd": "T1555.004 - Windows Credential Manager",# mft
        "Filename3_|_powershell": "T1059.001 - PowerShell | T1106.000 - Native API",# mft
        "Filename3_|_psexec": "T1003.001 - LSASS Memory | T1569.002 - Service Execution | T1570.000 - Lateral Tool Transfer",# mft
        "Filename3_|_pubprn": "T1216.001 - PubPrn",# mft
        "Filename3_|_reg\\.exe": "T1112.000 - Modify Registry",# mft
        "Filename3_|_scrnsave": "T1546.002 - Screensaver",# mft
        "Filename3_|_scvhost|svchast|svchust|svchest|lssas|lsasss|lsaas|cssrs|canhost|conhast|connhost|connhst|iexplorer|iexploror|iexplorar": "T1036.004 - Masquerade Task or Service",# mft
        "Filename3_|_sdelete": "T1070.004 - File Deletion | T1485.000 - Data Destruction",# mft
        "Filename3_|_tscon": "T1563.002 - RDP Hijacking",# mft
        "Filename3_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",# mft
        "Filename3_|_wmic|msxsl": "T1047.000 - Windows Management Instrumentation | T1220.000 - XSL Script Processing",# mft
        "Filename4_|_\\.7z|\\.arj|\\.tar|\\.tgz|\\.zip": "T1560.001 - Archive via Utility",# mft
        "Filename4_|_\\.asc|\\.cer|\\.gpg|\\.key|\\.p12|\\.p7b|\\.pem|\\.pfx|\\.pgp|\\.ppk": "T1552.004 - Private Keys",# mft
        "Filename4_|_\\.chm|\\.hh": "T1218.001 - Compiled HTML File",# mft
        "Filename4_|_\\.cpl": "T1218.002 - Control Panel",# mft
        "Filename4_|_\\.doc|\\.xls|\\.ppt|\\.pdf": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File",# mft
        "Filename4_|_\\.docm|\\.xlsm|\\.pptm": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1137.001 - Office Template Macros | T1559.001 - Component Object Model",# mft
        "Filename4_|_\\.docx|\\.xlsx|\\.pptx": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File | T1221.000 - Template Injection",# mft
        "Filename4_|_\\.job": "T1053.005 - Scheduled Task",# mft
        "Filename4_|_\\.lnk": "T1547.009 - Shortcut Modification",# mft
        "Filename4_|_\\.local|\\.manifest": "T1574.001 - DLL Search Order Hijacking",# mft
        "Filename4_|_\\.mp3|\\.wav|\\.aac|\\.m4a": "T1123.000 - Audio Capture",# mft
        "Filename4_|_\\.mp4|\\.mkv|\\.avi|\\.mov|\\.wmv|\\.mpg|\\.mpeg|\\.m4v|\\.flv": "T1125.000 - Video Capture",# mft
        "Filename4_|_\\.msg|\\.eml": "T1203.000 - Exploitation for Client Execution | T1204.001 - Malicious Link | T1204.002 - Malicious File | T1566.001 - Spearphishing Attachment | T1566.002 - Spearphishing Link",# mft
        "Filename4_|_\\.ost|\\.pst|\\.msg": "T1114.001 - Local Email Collection",# mft
        "Filename4_|_\\.ps1": "T1059.001 - PowerShell",# mft
        "Filename4_|_\\.service|services\\.exe|sc\\.exe": "T1007.000 - System Service Discovery | T1489.000 - Service Stop | T1543.003 - Windows Service | T1569.002 - Service Execution",# mft
        "Filename4_|_atbroker|displayswitch|magnify|narrator|osk|sethc|utilman": "T1546.008 - Accessibility Features",# mft
        "Filename4_|_autoruns": "T1112.000 - Modify Registry",# mft
        "Filename4_|_bcdedit|csrutil": "T1553.006 - Code Signing Policy Modification",# mft
        "Filename4_|_certmgr": "T1553.004 - Install Root Certificate",# mft
        "Filename4_|_certutil": "T1036.003 - Rename System Utilities | T1140.000 - Deobfuscate/Decode Files or Information | T1553.004 - Install Root Certificate",# mft
        "Filename4_|_cmd |cmd_|cmd\\.": "T1059.003 - Windows Command Shell | T1106.000 - Native API",# mft
        "Filename4_|_csc\\.exe": "T1027.004 - Compile After Delivery",# mft
        "Filename4_|_cscript": "T1216.001 - PubPrn",# mft
        "Filename4_|_eventvwr|sdclt": "T1548.002 - Bypass User Account Control",# mft
        "Filename4_|_github|gitlab|bitbucket": "T1567.001 - Exfiltration to Code Repository",# mft
        "Filename4_|_gpttmpl\\.inf|scheduledtasks\\.xml": "T1484.001 - Group Policy Modification",# mft
        "Filename4_|_mshta": "T1218.005 - Mshta",# mft
        "Filename4_|_msiexec": "T1218.007 - Msiexec",# mft
        "Filename4_|_normal\\.dotm|personal\\.xlsb": "T1137.001 - Office Template Macros",# mft
        "Filename4_|_odbcconf": "T1218.008 - Odbcconf",# mft
        "Filename4_|_onedrive|1drv|azure|icloud|cloudrive|dropbox|drive\\.google|fileshare|mediafire|zippyshare|megaupload|4shared": "T1537.000 - Transfer Data to Cloud Account | T1567.002 - Exfiltration to Cloud Storage",# mft
        "Filename4_|_policy\\.vpol|vaultcmd|vcrd": "T1555.004 - Windows Credential Manager",# mft
        "Filename4_|_powershell": "T1059.001 - PowerShell | T1106.000 - Native API",# mft
        "Filename4_|_psexec": "T1003.001 - LSASS Memory | T1569.002 - Service Execution | T1570.000 - Lateral Tool Transfer",# mft
        "Filename4_|_pubprn": "T1216.001 - PubPrn",# mft
        "Filename4_|_reg\\.exe": "T1112.000 - Modify Registry",# mft
        "Filename4_|_scrnsave": "T1546.002 - Screensaver",# mft
        "Filename4_|_scvhost|svchast|svchust|svchest|lssas|lsasss|lsaas|cssrs|canhost|conhast|connhost|connhst|iexplorer|iexploror|iexplorar": "T1036.004 - Masquerade Task or Service",# mft
        "Filename4_|_sdelete": "T1070.004 - File Deletion | T1485.000 - Data Destruction",# mft
        "Filename4_|_tscon": "T1563.002 - RDP Hijacking",# mft
        "Filename4_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",# mft
        "Filename4_|_wmic|msxsl": "T1047.000 - Windows Management Instrumentation | T1220.000 - XSL Script Processing",# mft
        "ForeignPort_|_^110|143|465|993|995$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.003 - Mail Protocols",# memory
        "ForeignPort_|_^135$": "T1047.000 - Windows Management Instrumentation | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol",# memory
        "ForeignPort_|_^137$": "T1187.000 - Forced Authentication | T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",# memory
        "ForeignPort_|_^139$": "T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1133.000 - External Remote Services | T1187.000 - Forced Authentication",# memory
        "ForeignPort_|_^20|21$": "T1041.000 - Exfiltration over C2 Channel | T1071.002 - File Transfer Protocols | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol",# memory
        "ForeignPort_|_^22|23$": "T1021.004 - SSH | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1133.000 - External Remote Services",# memory
        "ForeignPort_|_^2375|2376$": "T1612.000 - Build Image on Host",# memory
        "ForeignPort_|_^25$": "T1041.000 - Exfiltration over C2 Channel | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.003 - Mail Protocols",# memory
        "ForeignPort_|_^3389$": "T1021.001 - Remote Desktop Protocol | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1210.000 - Exploitation of Remote Services",# memory
        "ForeignPort_|_^389|88|1433|1521|3306$": "T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing",# memory
        "ForeignPort_|_^443$": "T1041.000 - Exfiltration over C2 Channel  | T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol | T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | T1071.001 - Web Protocols | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1187.000 - Forced Authentication | T1189.000 - Drive-by Compromise",# memory
        "ForeignPort_|_^445$": "T1021.002 - SMB/Windows Admin Shares | T1041.000 - Exfiltration over C2 Channel | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1133.000 - External Remote Services | T1187.000 - Forced Authentication | T1210.000 - Exploitation of Remote Services",# memory
        "ForeignPort_|_^53$": "T1041.000 - Exfiltration over C2 Channel | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.002 - DNS",# memory
        "ForeignPort_|_^5355$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",# memory
        "ForeignPort_|_^5800|5895|5938|5984|5986|8200$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1219.000 - Remote Access Software",# memory
        "ForeignPort_|_^5900$": "T1021.005 - VNC | T1219.000 - Remote Access Software | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol",# memory
        "ForeignPort_|_^69|989|990$": "T1071.002 - File Transfer Protocols | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol",# memory
        "ForeignPort_|_^80$": "T1041.000 - Exfiltration over C2 Channel | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.001 - Web Protocols | T1110.004 - Credential Stuffing | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1187.000 - Forced Authentication | T1189.000 - Drive-by Compromise",# memory
        "LocalPort_|_^110|143|465|993|995$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.003 - Mail Protocols",# memory
        "LocalPort_|_^135$": "T1047.000 - Windows Management Instrumentation | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol",# memory
        "LocalPort_|_^137$": "T1187.000 - Forced Authentication | T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",# memory
        "LocalPort_|_^139$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1133.000 - External Remote Services | T1187.000 - Forced Authentication",# memory
        "LocalPort_|_^20|21$": "T1041.000 - Exfiltration over C2 Channel | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.002 - File Transfer Protocols",# memory
        "LocalPort_|_^22|23$": "T1021.004 - SSH | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1133.000 - External Remote Services",# memory
        "LocalPort_|_^2375|2376$": "T1612.000 - Build Image on Host",# memory
        "LocalPort_|_^25$": "T1041.000 - Exfiltration over C2 Channel | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.003 - Mail Protocols",# memory
        "LocalPort_|_^3389$": "T1021.001 - Remote Desktop Protocol | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1210.000 - Exploitation of Remote Services",# memory
        "LocalPort_|_^389|88|1433|1521|3306$": "T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing",# memory
        "LocalPort_|_^443$": "T1041.000 - Exfiltration over C2 Channel  | T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol | T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | T1071.001 - Web Protocols | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1187.000 - Forced Authentication | T1189.000 - Drive-by Compromise",# memory
        "LocalPort_|_^445$": "T1021.002 - SMB/Windows Admin Shares | T1041.000 - Exfiltration over C2 Channel | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1133.000 - External Remote Services | T1187.000 - Forced Authentication | T1210.000 - Exploitation of Remote Services",# memory
        "LocalPort_|_^53$": "T1041.000 - Exfiltration over C2 Channel | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.002 - DNS",# memory
        "LocalPort_|_^5355$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",# memory
        "LocalPort_|_^5800|5895|5938|5984|5986|8200$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1219.000 - Remote Access Software",# memory
        "LocalPort_|_^5900$": "T1021.005 - VNC | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1219.000 - Remote Access Software",# memory
        "LocalPort_|_^69|989|990$": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.002 - File Transfer Protocols",# memory
        "LocalPort_|_^80$": "T1041.000 - Exfiltration over C2 Channel | T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1071.001 - Web Protocols | T1110.001 - Password Guessing | T1110.003 - Password Spraying | T1110.004 - Credential Stuffing | T1187.000 - Forced Authentication | T1189.000 - Drive-by Compromise",# memory
        "Message_|_/etc/profile|/etc/zshenv|/etc/zprofile|/etc/zlogin": "T1546.004 - Unix Shell Configuration Modification",# unix-logs
        "Message_|_/var/log": "T1070.002 - Clear Linux or Mac System Logs",# unix-logs
        "Message_|_\\.7z|\\.arj|\\.tar|\\.tgz|\\.zip": "T1560.001 - Archive via Utility",# unix-logs
        "Message_|_\\.asc|\\.cer|\\.gpg|\\.key|\\.p12|\\.p7b|\\.pem|\\.pfx|\\.pgp|\\.ppk": "T1552.004 - Private Keys",# unix-logs
        "Message_|_\\.chm|\\.hh": "T1218.001 - Compiled HTML File",# unix-logs
        "Message_|_\\.eml": "T1114.001 - Local Email Collection",# unix-logs
        "Message_|_\\.job": "T1053.005 - Scheduled Task",# unix-logs
        "Message_|_\\.lnk": "T1547.009 - Shortcut Modification",# unix-logs
        "Message_|_\\.mobileconfig|profiles": "T1176.000 - Browser Extensions",# unix-logs
        "Message_|_\\.mp3|\\.wav|\\.aac|\\.m4a": "T1123.000 - Audio Capture",# unix-logs
        "Message_|_\\.mp4|\\.mkv|\\.avi|\\.mov|\\.wmv|\\.mpg|\\.mpeg|\\.m4v|\\.flv": "T1125.000 - Video Capture",# unix-logs
        "Message_|_\\.msg|\\.eml": "T1203.000 - Exploitation for Client Execution | T1204.001 - Malicious Link | T1204.002 - Malicious File | T1566.001 - Spearphishing Attachment | T1566.002 - Spearphishing Link",# unix-logs
        "Message_|_add-trusted-cert|trustroot": "T1553.004 - Install Root Certificate",# unix-logs
        "Message_|_ascii|unicode|hex|base64|mime": "T1132.001 - Standard Encoding",# unix-logs
        "Message_|_at\\.": "T1053.001 - At (Linux)",# unix-logs
        "Message_|_authorizationexecutewithprivileges|security_authtrampoline": "T1548.004 - Elevated Execution with Prompt",# unix-logs
        "Message_|_authorized_keys|sshd_config|ssh-keygen": "T1098.004 - SSH Authorized Keys",# unix-logs
        "Message_|_bash_history": "T1552.003 - Bash History",# unix-logs
        "Message_|_bluetooth": "T1011.001 - Exfiltration over Bluetooth",# unix-logs
        "Message_|_chage|common-password|pwpolicy|getaccountpolicies": "T1201.000 - Password Policy Discovery",# unix-logs
        "Message_|_chmod": "T1222.002 - Linux and Mac File and Directory Permissions Modification | T1548.001 - Setuid and Setgid",# unix-logs
        "Message_|_chown|chgrp": "T1222.002 - Linux and Mac File and Directory Permissions Modification",# unix-logs
        "Message_|_clipboard|pbpaste": "T1115.000 - Clipboard Data",# unix-logs
        "Message_|_com\\.apple\\.quarantine": "T1553.001 - Gatekeeper Bypass",# unix-logs
        "Message_|_contentsofdirectoryatpath|pathextension|compare|fork |fork_": "T1106.000 - Native API",# unix-logs
        "Message_|_curl |curl_": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1553.001 - Gatekeeper Bypass",# unix-logs
        "Message_|_DISPLAY|display|HID|hid|PCI|pci|IDE|ide|ROOT|root|UMB|umb|FDC|fdc|IDE|ide|SCSI|scsi|STORAGE|storage|USBSTOR|usbstor|USB|usb": "T1025.000 - Data from Removable Media | T1052.001 - Exfiltration over USB | T1056.001 - Keylogging | T1091.000 - Replication through Removable Media | T1200.000 - Hardware Additions | T1570.000 - Lateral Tool Transfer",# unix-logs
        "Message_|_dscacheutil|ldapsearch": "T1069.002 - Domain Groups | T1087.002 - Domain Accounts",# unix-logs
        "Message_|_dscl": "T1069.001 - Local Groups | T1564.002 - Hidden Users",# unix-logs
        "Message_|_emond": "T1546.014 - Emond | T1547.011 - Plist Modification",# unix-logs
        "Message_|_encrypt": "T1573.001 - Symmetric Cryptography | T1573.002 - Asymmetric Cryptography",# unix-logs
        "Message_|_find |locate |find_|locate_": "T1083.000 - File and Directory Discovery",# unix-logs
        "Message_|_forwardingsmtpaddress|x-forwarded-to|x-mailfwdby|x-ms-exchange-organization-autoforwarded": "T1114.003 - Email Forwarding Rule",# unix-logs
        "Message_|_fsutil|fsinfo": "T1120.000 - Peripheral Device Discovery",# unix-logs
        "Message_|_gcc |gcc_": "T1027.004 - Compile After Delivery",# unix-logs
        "Message_|_github|gitlab|bitbucket": "T1567.001 - Exfiltration to Code Repository",# unix-logs
        "Message_|_group": "T1069.001 - Local Groups | T1069.002 - Domain Groups",# unix-logs
        "Message_|_halt": "T1529.000 - System Shutdown/Reboot",# unix-logs
        "Message_|_hidden": "T1564.003 - Hidden Window",# unix-logs
        "Message_|_histcontrol": "T1562.003 - Impair Command History Logging",# unix-logs
        "Message_|_history|histfile": "T1070.003 - Clear Command History | T1552.003 - Bash History | T1562.003 - Impair Command History Logging",# unix-logs
        "Message_|_hostname|systeminfo|whoami": "T1033.000 - System Owner/User Discovery",# unix-logs
        "Message_|_ifconfig": "T1016.001 - Internet Connection Discovery",# unix-logs
        "Message_|_is_debugging|sysctl|ptrace": "T1497.001 - System Checks",# unix-logs
        "Message_|_keychain": "T1555.001 - Keychain",# unix-logs
        "Message_|_kill|kill ": "T1489.000 - Service Stop | 1548.003 - Sudo and Sudo Caching | T1562.001 - Disable or Modify Tools",# unix-logs
        "Message_|_launchagents": "T1543.001 - Launch Agent",# unix-logs
        "Message_|_launchctl": "T1569.001 - Launchctl",# unix-logs
        "Message_|_launchdaemons": "T1543.004 - Launch Daemon",# unix-logs
        "Message_|_lc_code_signature|lc_load_dylib": "T1546.006 - LC_LOAD_DYLIB Addition | T1574.004 - Dylib Hijacking",# unix-logs
        "Message_|_lc_load_weak_dylib|rpath|loader_path|executable_path|ottol": "T1547.004 - Dylib Hijacking",# unix-logs
        "Message_|_ld_preload|dyld_insert_libraries|export|setenv|putenv|os\\.environ|ld\\.so\\.preload|dlopen|mmap|failure": "T1547.006 - Dynamic Linker Hijacking",# unix-logs
        "Message_|_libzip|zlib|rarfile|bzip2": "T1560.002 - Archive via Library",# unix-logs
        "Message_|_loginitems|loginwindow|smloginitemsetenabled|uielement|quarantine": "T1547.011 - Plist Modification",# unix-logs
        "Message_|_loginwindow|hide500users|dscl|uniqueid": "T1564.002 - Hidden Users",# unix-logs
        "Message_|_lsof|route|dig": "T1049.000 - System Network Connections Discovery",# unix-logs
        "Message_|_malloc|ptrace_setregs|ptrace_poketext|ptrace_pokedata": "T1055.008 - Ptrace System Calls",# unix-logs
        "Message_|_microphone": "T1123.000 - Audio Capture",# unix-logs
        "Message_|_modprobe|insmod|lsmod|rmmod|modinfo|kextload|kextunload|autostart": "T1547.006 - Kernel Modules and Extensions",# unix-logs
        "Message_|_onedrive|1drv|azure|icloud|cloudrive|dropbox|drive\\.google|fileshare|mediafire|zippyshare|megaupload|4shared": "T1537.000 - Transfer Data to Cloud Account | T1567.002 - Exfiltration to Cloud Storage",# unix-logs
        "Message_|_pam_unix\\.so": "T1556.003 - Pluggable Authentication Modules",# unix-logs
        "Message_|_passwd|shadow": "T1003.008 - /etc/passwd and /etc/shadow | T1087.001 - Local Account | T1556.003 - Pluggable Authentication Modules",# unix-logs
        "Message_|_password|pwd|login|store|secure|credentials": "T1552.001 - Credentials in Files | T1555.005 - Password Managers",# unix-logs
        "Message_|_ping|traceroute|etc/host|etc/hosts|bonjour": "T1016.001 - Internet Connection Discovery | T1018.000 - Remote System Discovery",# unix-logs
        "Message_|_portopening": "T1090.001 - Internal Proxy",# unix-logs
        "Message_|_profile\\.d|bash_profile|bashrc|bash_login|bash_logout": "T1546.004 - Unix Shell Configuration Modification",# unix-logs
        "Message_|_ps |ps_": "T1057.000 - Process Discovery",# unix-logs
        "Message_|_pubprn": "T1216.001 - PubPrn",# unix-logs
        "Message_|_python|\\.py |\\.py_": "T1059.006 - Python",# unix-logs
        "Message_|_rc\\.local|rc\\.common": "T1037.004 - RC Scripts",# unix-logs
        "Message_|_rm |rm_": "T1070.004 - File Deletion | T1485.000 - Data Destruction",# unix-logs
        "Message_|_scp|rsync|sftp": "T1105.000 - Ingress Tool Transfer",# unix-logs
        "Message_|_services": "T1489.000 - Service Stop",# unix-logs
        "Message_|_startupitems": "T1037.002 - Logon Script (Mac)",# unix-logs
        "Message_|_startupparameters": "T1037.002 - Logon Script (Mac) | T1037.005 - Startup Items | T1547.011 - Plist Modification",# unix-logs
        "Message_|_sudo|timestamp_timeout|tty_tickets": "T1548.003 - Sudo and Sudo Caching",# unix-logs
        "Message_|_systemctl": "T1543.001 - Launch Agent",# unix-logs
        "Message_|_systemsetup": "T1082.000 - System Information Discovery",# unix-logs
        "Message_|_time|sleep": "T1497.003 - Time Based Evasion",# unix-logs
        "Message_|_timer": "T1053.006 - Systemd Timers",# unix-logs
        "Message_|_trap": "T1546.005 - Trap",# unix-logs
        "Message_|_u202e": "T1036.002 - Right-to-Left Override",# unix-logs
        "Message_|_uielement": "T1564.003 - Hidden Window",# unix-logs
        "Message_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",# unix-logs
        "Message_|_xattr|xttr": "T1553.001 - Gatekeeper Bypass",# unix-logs
        "Message_|_xdg|autostart": "T1547.013 - XDG Autostart Entries",# unix-logs
        "Message_|_xwd|screencapture": "T1113.000 - Screen Capture",# unix-logs
        "Message_|_zshrc|zshenv|zlogout|zlogin|profile": "T1546.004 - Unix Shell Configuration Modification",# unix-logs
        "nixCommand_|_/var/log": "T1070.002 - Clear Linux or Mac System Logs",# memory, unix-logs
        "nixCommand_|_\\.7z|\\.arj|\\.tar|\\.tgz|\\.zip": "T1560.001 - Archive via Utility",# memory, unix-logs
        "nixCommand_|_\\.eml": "T1114.001 - Local Email Collection",# memory, unix-logs
        "nixCommand_|_\\.lnk": "T1547.009 - Shortcut Modification",# memory, unix-logs
        "nixCommand_|_\\.mobileconfig|profiles": "T1176.000 - Browser Extensions",# memory, unix-logs
        "nixCommand_|_add-trusted-cert|trustroot": "T1553.004 - Install Root Certificate",# memory, unix-logs
        "nixCommand_|_ascii|unicode|hex|base64|mime": "T1132.001 - Standard Encoding",# memory, unix-logs
        "nixCommand_|_at\\.": "T1053.001 - At (Linux)",# memory, unix-logs
        "nixCommand_|_authorizationexecutewithprivileges|security_authtrampoline": "T1548.004 - Elevated Execution with Prompt",# memory, unix-logs
        "nixCommand_|_authorized_keys|sshd_config|ssh-keygen": "T1098.004 - SSH Authorized Keys",# memory, unix-logs
        "nixCommand_|_bash_history": "T1552.003 - Bash History",# memory, unix-logs
        "nixCommand_|_bluetooth": "T1011.001 - Exfiltration over Bluetooth",# memory, unix-logs
        "nixCommand_|_chage|common-password|pwpolicy|getaccountpolicies": "T1201.000 - Password Policy Discovery",# memory, unix-logs
        "nixCommand_|_chmod": "T1222.002 - Linux and Mac File and Directory Permissions Modification | T1548.001 - Setuid and Setgid",# memory, unix-logs
        "nixCommand_|_chown|chgrp": "T1222.002 - Linux and Mac File and Directory Permissions Modification",# memory, unix-logs
        "nixCommand_|_clipboard|pbpaste": "T1115.000 - Clipboard Data",# memory, unix-logs
        "nixCommand_|_com\\.apple\\.quarantine": "T1553.001 - Gatekeeper Bypass",# memory, unix-logs
        "nixCommand_|_contentsofdirectoryatpath|pathextension|compare|fork |fork_": "T1106.000 - Native API",# memory, unix-logs
        "nixCommand_|_curl |curl_": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1553.001 - Gatekeeper Bypass",# memory, unix-logs
        "nixCommand_|_docker build|docker  build|docker_build|docker__build": "T1612.000 - Build Image on Host",# memory, unix-logs
        "nixCommand_|_docker create|docker  create|docker start|docker  start|docker_create|docker__create|docker_start|docker_start": "T1610.000 - Deploy Container",# memory, unix-logs
        "nixCommand_|_docker exec|docker  exec|docker run|docker  run|kubectl exec|kubectl  exec|kubectl run|kubectl  run|docker_exec|docker__exec|docker_run|docker__run|kubectl_exec|kubectl__exec|kubectl_run|kubectl__run": "T1609.000 - Container Administration Command",# memory, unix-logs
        "nixCommand_|_dscacheutil|ldapsearch": "T1069.002 - Domain Groups | T1087.002 - Domain Accounts",# memory, unix-logs
        "nixCommand_|_dscl": "T1069.001 - Local Groups | T1564.002 - Hidden Users",# memory, unix-logs
        "nixCommand_|_emond": "T1546.014 - Emond | T1547.011 - Plist Modification",# memory, unix-logs
        "nixCommand_|_encrypt": "T1573.001 - Symmetric Cryptography | T1573.002 - Asymmetric Cryptography",# memory, unix-logs
        "nixCommand_|_find |locate |find_|locate_": "T1083.000 - File and Directory Discovery",# memory, unix-logs
        "nixCommand_|_forwardingsmtpaddress|x-forwarded-to|x-mailfwdby|x-ms-exchange-organization-autoforwarded": "T1114.003 - Email Forwarding Rule",# memory, unix-logs
        "nixCommand_|_fsutil|fsinfo": "T1120.000 - Peripheral Device Discovery",# memory, unix-logs
        "nixCommand_|_gcc |gcc_": "T1027.004 - Compile After Delivery",# memory, unix-logs
        "nixCommand_|_github|gitlab|bitbucket": "T1567.001 - Exfiltration to Code Repository",# memory, unix-logs
        "nixCommand_|_group |group_": "T1069.001 - Local Groups | T1069.002 - Domain Groups",# memory, unix-logs
        "nixCommand_|_halt": "T1529.000 - System Shutdown/Reboot",# memory, unix-logs
        "nixCommand_|_hidden": "T1564.003 - Hidden Window",# memory, unix-logs
        "nixCommand_|_histcontrol": "T1562.003 - Impair Command History Logging",# memory, unix-logs
        "nixCommand_|_history|histfile": "T1070.003 - Clear Command History | T1552.003 - Bash History | T1562.003 - Impair Command History Logging",# memory, unix-logs
        "nixCommand_|_hostname|systeminfo|whoami": "T1033.000 - System Owner/User Discovery",# memory, unix-logs
        "nixCommand_|_ifconfig": "T1016.001 - Internet Connection Discovery",# memory, unix-logs
        "nixCommand_|_is_debugging|sysctl|ptrace": "T1497.001 - System Checks",# memory, unix-logs
        "nixCommand_|_keychain": "T1555.001 - Keychain",# memory, unix-logs
        "nixCommand_|_kill": "T1489.000 - Service Stop | T1548.003 - Sudo and Sudo Caching | T1562.001 - Disable or Modify Tools",# memory, unix-logs
        "nixCommand_|_launchagents": "T1543.001 - Launch Agent",# memory, unix-logs
        "nixCommand_|_launchctl": "T1569.001 - Launchctl",# memory, unix-logs
        "nixCommand_|_launchdaemons": "T1543.004 - Launch Daemon",# memory, unix-logs
        "nixCommand_|_lc_code_signature|lc_load_dylib": "T1546.006 - LC_LOAD_DYLIB Addition | T1574.004 - Dylib Hijacking",# memory, unix-logs
        "nixCommand_|_lc_load_weak_dylib|rpath|loader_path|executable_path|ottol": "T1547.004 - Dylib Hijacking",# memory, unix-logs
        "nixCommand_|_ld_preload|dyld_insert_libraries|export|setenv|putenv|os\\.environ|ld\\.so\\.preload|dlopen|mmap|failure": "T1547.006 - Dynamic Linker Hijacking",# memory, unix-logs
        "nixCommand_|_libzip|zlib|rarfile|bzip2": "T1560.002 - Archive via Library",# memory, unix-logs
        "nixCommand_|_loginwindow|hide500users|dscl|uniqueid": "T1564.002 - Hidden Users",# memory, unix-logs
        "nixCommand_|_lsof|route|dig": "T1049.000 - System Network Connections Discovery",# memory, unix-logs
        "nixCommand_|_malloc|ptrace_setregs|ptrace_poketext|ptrace_pokedata": "T1055.008 - Ptrace System Calls",# memory, unix-logs
        "nixCommand_|_microphone": "T1123.000 - Audio Capture",# memory, unix-logs
        "nixCommand_|_modprobe|insmod|lsmod|rmmod|modinfo|kextload|kextunload|autostart": "T1547.006 - Kernel Modules and Extensions",# memory, unix-logs
        "nixCommand_|_onedrive|1drv|azure|icloud|cloudrive|dropbox|drive\\.google|fileshare|mediafire|zippyshare|megaupload|4shared": "T1537.000 - Transfer Data to Cloud Account | T1567.002 - Exfiltration to Cloud Storage",# memory, unix-logs
        "nixCommand_|_pam_unix\\.so": "T1556.003 - Pluggable Authentication Modules",# memory, unix-logs
        "nixCommand_|_passwd|shadow": "T1003.008 - /etc/passwd and /etc/shadow | T1087.001 - Local Account | T1556.003 - Pluggable Authentication Modules",# memory, unix-logs
        "nixCommand_|_password|pwd|login|store|secure|credentials": "T1552.001 - Credentials in Files | T1555.005 - Password Managers",# memory, unix-logs
        "nixCommand_|_ping|traceroute|etc/host|etc/hosts|bonjour": "T1016.001 - Internet Connection Discovery | T1018.000 - Remote System Discovery",# memory, unix-logs
        "nixCommand_|_portopening": "T1090.001 - Internal Proxy",# memory, unix-logs
        "nixCommand_|_profile\\.d|bash_profile|bashrc|bash_login|bash_logout": "T1546.004 - Unix Shell Configuration Modification",# memory, unix-logs
        "nixCommand_|_ps |ps_": "T1057.000 - Process Discovery",# memory, unix-logs
        "nixCommand_|_pubprn": "T1216.001 - PubPrn",# memory, unix-logs
        "nixCommand_|_python|\\.py": "T1059.006 - Python",# memory, unix-logs
        "nixCommand_|_rc\\.local|rc\\.common": "T1037.004 - RC Scripts",# memory, unix-logs
        "nixCommand_|_rm |rm_": "T1070.004 - File Deletion | T1485.000 - Data Destruction",# memory, unix-logs
        "nixCommand_|_scp|rsync|sftp": "T1105.000 - Ingress Tool Transfer",# memory, unix-logs
        "nixCommand_|_services": "T1489.000 - Service Stop",# memory, unix-logs
        "nixCommand_|_startupitems|startupparameters": "T1037.002 - Logon Script (Mac)",# memory, unix-logs
        "nixCommand_|_sudo|timestamp_timeout|tty_tickets": "T1548.003 - Sudo and Sudo Caching",# memory, unix-logs
        "nixCommand_|_systemctl": "T1543.001 - Launch Agent",# memory, unix-logs
        "nixCommand_|_systemsetup": "T1082.000 - System Information Discovery",# memory, unix-logs
        "nixCommand_|_time|sleep": "T1497.003 - Time Based Evasion",# memory, unix-logs
        "nixCommand_|_timer": "T1053.006 - Systemd Timers",# memory, unix-logs
        "nixCommand_|_trap": "T1546.005 - Trap",# memory, unix-logs
        "nixCommand_|_u202e": "T1036.002 - Right-to-Left Override",# memory, unix-logs
        "nixCommand_|_uielement": "T1564.003 - Hidden Window",# memory, unix-logs
        "nixCommand_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",# memory, unix-logs
        "nixCommand_|_xattr|xttr": "T1553.001 - Gatekeeper Bypass",# memory, unix-logs
        "nixCommand_|_xdg|autostart": "T1547.013 - XDG Autostart Entries",# memory, unix-logs
        "nixCommand_|_xwd|screencapture": "T1113.000 - Screen Capture",# memory, unix-logs
        "nixCommand_|_zshrc|zshenv|zlogout|zlogin|profile": "T1546.004 - Unix Shell Configuration Modification",# memory, unix-logs
        "nixProcess_|_\\.mobileconfig|profiles": "T1176.000 - Browser Extensions",# unix-logs
        "nixProcess_|_bluetooth": "T1011.001 - Exfiltration over Bluetooth",# memory, unix-logs
        "nixProcess_|_fsutil|fsinfo": "T1120.000 - Peripheral Device Discovery",# memory, unix-logs
        "nixProcess_|_is_debugging|sysctl|ptrace": "T1497.001 - System Checks",# unix-logs
        "nixProcess_|_keychain": "T1555.001 - Keychain",# unix-logs
        "nixProcess_|_launchagents": "T1543.001 - Launch Agent",# unix-logs
        "nixProcess_|_launchctl": "T1569.001 - Launchctl",# unix-logs
        "nixProcess_|_launchdaemons": "T1543.004 - Launch Daemon",# unix-logs
        "nixProcess_|_loginitems|loginwindow|smloginitemsetenabled|uielement|quarantine": "T1547.011 - Plist Modification",# unix-logs
        "nixProcess_|_malloc|ptrace_setregs|ptrace_poketext|ptrace_pokedata": "T1055.008 - Ptrace System Calls",# unix-logs
        "nixProcess_|_microphone": "T1123.000 - Audio Capture",# unix-logs
        "nixProcess_|_modprobe|insmod|lsmod|rmmod|modinfo|kextload|kextunload|autostart": "T1547.006 - Kernel Modules and Extensions",# unix-logs
        "nixProcess_|_onedrive|1drv|azure|icloud|cloudrive|dropbox|drive\\.google|fileshare|mediafire|zippyshare|megaupload|4shared": "T1537.000 - Transfer Data to Cloud Account | T1567.002 - Exfiltration to Cloud Storage",# memory
        "nixProcess_|_pam_unix\\.so": "T1556.003 - Pluggable Authentication Modules",# unix-logs
        "nixProcess_|_ping|traceroute|etc/host|etc/hosts|bonjour": "T1016.001 - Internet Connection Discovery | T1018.000 - Remote System Discovery",# unix-logs
        "nixProcess_|_python|\\.py |\\.py_": "T1059.006 - Python",# memory, unix-logs
        "nixProcess_|_rc\\.local|rc\\.common": "T1037.004 - RC Scripts",# unix-logs
        "nixProcess_|_scp|rsync|sftp": "T1105.000 - Ingress Tool Transfer",# memory, unix-logs
        "nixProcess_|_services": "T1489.000 - Service Stop",# memory, unix-logs
        "nixProcess_|_startupitems": "T1037.002 - Logon Script (Mac)",# unix-logs
        "nixProcess_|_startupparameters": "T1037.002 - Logon Script (Mac) | T1037.005 - Startup Items | T1547.011 - Plist Modification",# unix-logs
        "nixProcess_|_sudo|timestamp_timeout|tty_tickets": "T1548.003 - Sudo and Sudo Caching",# unix-logs
        "nixProcess_|_systemctl": "T1543.001 - Launch Agent",# unix-logs
        "nixProcess_|_systemsetup": "T1082.000 - System Information Discovery",# unix-logs
        "nixProcess_|_time|sleep": "T1497.003 - Time Based Evasion",# unix-logs
        "nixProcess_|_timer": "T1053.006 - Systemd Timers",# memory, unix-logs
        "nixProcess_|_trap": "T1546.005 - Trap",# unix-logs
        "nixProcess_|_uielement": "T1564.003 - Hidden Window",# unix-logs
        "nixProcess_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",# memory, unix-logs
        "nixProcess_|_xattr|xttr": "T1553.001 - Gatekeeper Bypass",# unix-logs
        "nixProcess_|_xdg|autostart": "T1547.013 - XDG Autostart Entries",# unix-logs
        "nixProcess_|_xwd|screencapture": "T1113.000 - Screen Capture",# unix-logs
        "Plist_|_loginitems|loginwindow|smloginitemsetenabled|uielement|quarantine": "T1547.011 - Plist Modification",# plists
        "Plist_|_startupparameters": "T1037.005 - Startup Items | T1547.011 - Plist Modification",# plists
        "Plist_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",# plists
        "Registry_|_/print processors/|/print_processors/": "T1547.012 - Print Processors",# registry
        "Registry_|_/security/policy/secrets": "T1003.004 - LSA Secrets",# registry
        "Registry_|_/special/perf": "T1337.002 - Office Test",# registry
        "Registry_|_active setup/installed components|active_setup/installed_components": "T1547.014 - Active Setup",# registry
        "Registry_|_currentcontrolset/control/lsa": "T1003.001 - LSASS Memory | T1547.002 - Authentication Package | T1547.005 - Security Support Provider | T1556.002 - Password Filter DLL",# registry
        "Registry_|_currentcontrolset/control/print/monitors": "T1547.010 - Port Monitors",# registry
        "Registry_|_currentcontrolset/control/session manager|currentcontrolset/control/session_manager": "T1547.001 - Registry Run Keys / Startup Folder | T1546.009 - AppCert DLLs",# registry
        "Registry_|_currentcontrolset/services/": "T1574.011 - Services Registry Permissions Weakness",# registry
        "Registry_|_currentcontrolset/services/w32time/timeproviders": "T1547.003 - Time Providers",# registry
        "Registry_|_currentversion/app paths|software/classes/ms-settings/shell/open/command|currentversion/app_paths|software/classes/mscfile/shell/open/command|software/classes/exefile/shell/runas/command/isolatedcommand": "T1548.002 - Bypass User Account Control",# registry
        "Registry_|_currentversion/appcompatflags/installedsdb": "T1546.011 - Application Shimming",# registry
        "Registry_|_currentversion/explorer/fileexts": "T1546.001 - Change Default File Association",# registry
        "Registry_|_currentversion/image file execution options|currentversion/image_file_execution_options": "T1546.008 - Accessibility Features | T1546.012 - Image File Execution Options Injection | T1547.002 - Authentication Package | T1547.005 - Security Support Provider | ",# registry
        "Registry_|_currentversion/policies/credui/enumerateadministrators": "T1087.001 - Local Account | T1087.002 - Domain Account",# registry
        "Registry_|_currentversion/run|currentversion/policies/explorer/run|currentversion/explorer/user|currentversion/explorer/shell": "T1547.001 - Registry Run Keys / Startup Folder",# registry
        "Registry_|_currentversion/windows|nt/currentversion/windows": "T1546.010 - AppInit DLLs",# registry
        "Registry_|_currentversion/winlogon/notify|currentversion/winlogon/userinit|currentversion/winlogon/shell": "T1547.001 - Registry Run Keys / Startup Folder | T1547.004 - Winlogon Helper DLL",# registry
        "Registry_|_environment/userinitmprlogonscript": "T1037.001 - Logon Script (Windows)",# registry
        "Registry_|_manager/safedllsearchmode|security/policy/secrets": "T1003.001 - LSASS Memory | T1547.008 - LSASS Driver",# registry
        "Registry_|_microsoft/windows/softwareprotectionplatform/eventcachemanager": "T1036.004 - Masquerade Task or Service",# registry
        "Registry_|_nt/dnsclient": "T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",# registry
        "Registry_|_panel/cpls": "T1218.002 - Control Panel",# registry
        "Registry_|_software/microsoft/netsh": "T1546.007 - Netsh Helper DLL",# registry
        "Registry_|_software/microsoft/ole": "T1175.001 - Component Object Model",# registry
        "Registry_|_software/policies/microsoft/previousversions/disablelocalpage": "T1490.000 - Inhibit System Recovery",# registry
        "Registry_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",# registry
        "url_|_github|gitlab|bitbucket": "T1567.001 - Exfiltration to Code Repository",# urls
        "url_|_onedrive|1drv|azure|icloud|cloudrive|dropbox|drive\\.google|fileshare|mediafire|zippyshare|megaupload|4shared": "T1537.000 - Transfer Data to Cloud Account | T1567.002 - Exfiltration to Cloud Storage",# urls
        "WinCommand_|_-create|dscl|hide500users": "T1564.002 - Hidden Users",# memory, evt
        "WinCommand_|_-decode|openssl": "T1140.000 - Deobfuscate/Decode Files or Information",# memory, evt
        "WinCommand_|_-noprofile": "T1547.013 - PowerShell Profile",# memory, evt
        "WinCommand_|_/add": "T1136.001 - Local Account | T1136.002 - Domain Account",# memory, evt
        "WinCommand_|_/delete": "T1070.005 - Network Share Connection Removal",# memory, evt
        "WinCommand_|_/domain": "T1087.002 - Domain Account | T1136.002 - Domain Account",# memory, evt
        "WinCommand_|_\\.7z|\\.arj|\\.cab|\\.tar|\\.tgz|\\.zip|winzip|winrar": "T1560.001 - Archive via Utility",# memory, evt
        "WinCommand_|_\\.cpl": "T1218.002 - Control Panel",# memory, evt
        "WinCommand_|_\\.lnk": "T1547.009 - Shortcut Modification",# memory, evt
        "WinCommand_|_\\.local|\\.manifest": "T1574.001 - DLL Search Order Hijacking",# memory, evt
        "WinCommand_|_\\.ost|\\.pst|\\.msg": "T1114.001 - Local Email Collection",# memory, evt
        "WinCommand_|_\\.ps1|invoke-command|start-process|system\\.management\\.automation": "T1059.001 - PowerShell",# memory, evt
        "WinCommand_|_\\.service|services\\.exe|sc\\.exe": "T1007.000 - System Service Discovery | T1489.000 - Service Stop | T1543.003 - Windows Service | T1569.002 - Service Execution",# memory, evt
        "WinCommand_|_add-mailboxpermission|set-casmailbox": "T1098.002 - Exchange Email Delegate Permissions",# memory, evt
        "WinCommand_|_addfile|bits|setnotifyflags|setnotifycmdline|transfer": "T1197.000 - BITS Jobs",# memory, evt
        "WinCommand_|_addmonitor": "T1547.010 - Port Monitors",# memory, evt
        "WinCommand_|_addprintprocessor|getprintprocessordirectory|seloaddriverprivilege": "T1547.012 - Print Processors",# memory, evt
        "WinCommand_|_addsid|get-aduser|dsaddsidhistory": "T1134.005 - SID-History Injection",# memory, evt
        "WinCommand_|_admin%24|admin\\$|admin$|c%24|c\\$|c$": "T1021.002 - SMB/Windows Admin Shares | T1570.000 - Lateral Tool Transfer",# memory, evt
        "WinCommand_|_ascii|unicode|hex|base64|mime": "T1132.001 - Standard Encoding",# memory, evt
        "WinCommand_|_at\\.": "T1053.002 - At (Windows)",# memory, evt
        "WinCommand_|_atbroker|displayswitch|magnify|narrator|osk|sethc|utilman": "T1546.008 - Accessibility Features",# memory, evt
        "WinCommand_|_attrib": "T1564.001 - Hidden Files and Directories",# memory, evt
        "WinCommand_|_auditpol": "T1562.002 - Disable Windows Event Logging",# memory, evt
        "WinCommand_|_authentication packages|authentication_packages": "T1547.002 - Authentication Package",# memory, evt
        "WinCommand_|_autoruns|regdelnull": "T1112.000 - Modify Registry",# memory, evt
        "WinCommand_|_bcdedit|vssadmin|wbadmin|shadows|shadowcopy": "T1490.000 - Inhibit System Recovery | T1553.006 - Code Signing Policy Modification",# memory, evt
        "WinCommand_|_bluetooth": "T1011.001 - Exfiltration over Bluetooth",# memory, evt
        "WinCommand_|_bootexecute|autocheck|autochk": "T1547.001 - Registry Run Keys / Startup Folder",# memory, evt
        "WinCommand_|_certmgr": "T1553.004 - Install Root Certificate",# memory, evt
        "WinCommand_|_certutil": "T1036.003 - Rename System Utilities | T1140.000 - Deobfuscate/Decode Files or Information | T1553.004 - Install Root Certificate",# memory, evt
        "WinCommand_|_clear-history": "T1070.003 - Clear Command History",# memory, evt
        "WinCommand_|_clipboard|pbpaste": "T1115.000 - Clipboard Data",# memory, evt
        "WinCommand_|_cmd |cmd_|cmd\\.": "T1059.003 - Windows Command Shell | T1106.000 - Native API",# memory, evt
        "WinCommand_|_cmmgr32|cmstp|cmlua": "T1218.003 - CMSTP",# memory, evt
        "WinCommand_|_cmsadcs|ntds": "T1003.003 - NTDS",# memory, evt
        "WinCommand_|_consolehost|clear-history|historysavestyle|savenothing": "T1562.003 - Impair Command History Logging",# memory, evt
        "WinCommand_|_copyfromscreen": "T1113.000 - Screen Capture_",# memory, evt
        "WinCommand_|_cor_profiler": "T1547.012 - COR_PROFILER",# memory, evt
        "WinCommand_|_createfiletransacted|createtransaction|ntcreatethreadex|ntunmapviewofsection|rollbacktransaction|virtualprotectex": "T1055.013 - Process Doppelganging",# memory, evt
        "WinCommand_|_createprocess": "T1055.012 - Process Hollowing | T1055.013 - Process Doppelganging | T1106.000 - Native API | T1134.002 - Create Process with Token | T1134.004 - Parent PID Spoofing | T1546.009 - AppCert DLLs",# memory, evt
        "WinCommand_|_createremotethread": "T1055.001 - Dynamic-link Library Injection | T1055.011 - Extra Window Memory Injection | T1055.002 - Portable Executable Injection | T1055.005 - Thread Local Storage | T1106.000 - Native API",# memory, evt
        "WinCommand_|_createtoolhelp32snapshot|get-process": "T1424.000 - Process Discovery",# memory, evt
        "WinCommand_|_csc\\.exe": "T1027.004 - Compile After Delivery",# memory, evt
        "WinCommand_|_cscript": "T1216.001 - PubPrn",# memory, evt
        "WinCommand_|_csrutil|g_cioptions|requiresigned": "T1553.006 - Code Signing Policy Modification",# memory, evt
        "WinCommand_|_curl |curl_": "T1048.003 - Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol | T1553.001 - Gatekeeper Bypass",# memory, evt
        "WinCommand_|_dcsync": "T1550.003 - Pass the Ticket",# memory, evt
        "WinCommand_|_debug only this process|debug  only  this  process|debug process|debug  process|debug_only_this_process|debug__only__this__process|debug_process|debug__process|ntsd": "T1546.012 - Image File Execution Options Injection",# memory, evt
        "WinCommand_|_del|rm|/delete|sdelete": "T1070.004 - File Deletion | T1485.000 - Data Destruction",# memory, evt
        "WinCommand_|_dir|tree|ls": "T1083.000 - File and Directory Discovery",# memory, evt
        "WinCommand_|_docker build|docker  build|docker_build|docker__build": "T1612.000 - Build Image on Host",# memory, evt
        "WinCommand_|_docker create|docker  create|docker start|docker  start|docker_create|docker__create|docker_start|docker_start": "T1610.000 - Deploy Container",# memory, evt
        "WinCommand_|_docker exec|docker  exec|docker run|docker  run|kubectl exec|kubectl  exec|kubectl run|kubectl  run|docker_exec|docker__exec|docker_run|docker__run|kubectl_exec|kubectl__exec|kubectl_run|kubectl__run": "T1609.000 - Container Administration Command",# memory, evt
        "WinCommand_|_dsaddsidhistory|get-aduser": "T1134.005 - SID-History Injection",# memory, evt
        "WinCommand_|_dscl": "T1069.001 - Local Groups",# memory, evt
        "WinCommand_|_dsenumeratedomaintrusts|getalltrustrelationships|get-accepteddomain|nltest|dsquery|get-netdomaintrust|get-netforesttrust": "T1482.000 - Domain Trust Discovery",# memory, evt
        "WinCommand_|_duo-sid": "T1550.004 - Web Session Cookie",# memory, evt
        "WinCommand_|_duplicatetoken": "T1134.001 - Token Impersonation/Theft | T1134.002 - Create Process with Token",# memory, evt
        "WinCommand_|_enablemulticast": "T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",# memory, evt
        "WinCommand_|_encrypt": "T1573.001 - Symmetric Cryptography | T1573.002 - Asymmetric Cryptography",# memory, evt
        "WinCommand_|_eventvwr|sdclt": "T1548.002 - Bypass User Account Control",# memory, evt
        "WinCommand_|_failure": "T1547.011 - Services Registry Permissions Weakness",# memory, evt
        "WinCommand_|_filerecvwriterand": "T1027.001 - Binary Padding",# memory, evt
        "WinCommand_|_find-avsignature": "T1027.005 - Indicator Removal from Tools",# memory, evt
        "WinCommand_|_forwardingsmtpaddress|x-forwarded-to|x-mailfwdby|x-ms-exchange-organization-autoforwarded": "T1114.003 - Email Forwarding Rule",# memory, evt
        "WinCommand_|_gcc|mingw|microsoft\\.csharp\\.csharpcodeprovider": "T1027.004 - Compile After Delivery",# memory, evt
        "WinCommand_|_get-addefaultdomainpasswordpolicy": "T1201.000 - Password Policy Discovery",# memory, evt
        "WinCommand_|_get-globaladdresslist": "T1087.003 - Email Account",# memory, evt
        "WinCommand_|_get-process|createtoolhelp32snapshot": "T1057.000 - Process Discovery",# memory, evt
        "WinCommand_|_get-unattendedinstallfile|get-webconfig|get-applicationhost|get-sitelistpassword|get-cachedgpppassword|get-registryautologon": "T1552.002 - Credentials in Registry",# memory, evt
        "WinCommand_|_getasynckeystate|getkeystate|setwindowshook": "T1056.001 - Keylogging",# memory, evt
        "WinCommand_|_getlocaleinfow": "T1614.000 - System Location Discovery",# memory, evt
        "WinCommand_|_getprintprocessordirectory": "T1547.012 - Print Processors",# memory, evt
        "WinCommand_|_getwindowlong|setwindowlong": "T1055.011 - Extra Window Memory Injection",# memory, evt
        "WinCommand_|_github|gitlab|bitbucket": "T1567.001 - Exfiltration to Code Repository",# memory, evt
        "WinCommand_|_gsecdump|mimikatz|pwdumpx|secretsdump|reg save|reg  save|net user|net  user|net\\.exe user|net\\.exe  user|net1 user|net1  user|net1\\.exe user|net1\\.exe  user|reg_save|reg__save|net_user|net__user|net\\.exe_user|net\\.exe__user|net1_user|net1__user|net1\\.exe_user|net1\\.exe__user": "T1003.002 - Security Account Manager",# memory, evt
        "WinCommand_|_hidden": "T1564.003 - Hidden Window",# memory, evt
        "WinCommand_|_hklm/sam|hklm/system": "T1003.002 - Security Account Manager",# memory, evt
        "WinCommand_|_hostname|net config|net  config|net\\.exe config|net\\.exe  config|net1 config|net1  config|net1\\.exe config|net1\\.exe  config|netuser-getinfo|query user|query  user|net_config|net__config|net\\.exe_config|net\\.exe__config|net1_config|net1__config|net1\\.exe_config|net1\\.exe__config|query_user|query__user|quser|systeminfo|whoami": "T1033.000 - System Owner/User Discovery",# memory, evt
        "WinCommand_|_icacls|cacls|takeown|attrib": "T1222.001 - Windows File and Directory Permissions Modification",# memory, evt
        "WinCommand_|_ifconfig": "T1016.001 - Internet Connection Discovery",# memory, evt
        "WinCommand_|_impersonateloggedonuser|impersonateloggedonuser|runas|setthreadtoken|impersonatenamedpipeclient": "T1134.001 - Token Impersonation/Theft",# memory, evt
        "WinCommand_|_impersonateloggedonuser|logonuser|runas|setthreadtoken|impersonatenamedpipeclient": "T1134.001 - Token Impersonation/Theft",# memory, evt
        "WinCommand_|_installutil": "T1218.004 - InstallUtil",# memory, evt
        "WinCommand_|_invoke-psimage": "T1001.002 - Steganography",# memory, evt
        "WinCommand_|_ipc%24|ipc\\$|ipc$": "T1021.002 - SMB/Windows Admin Shares | T1559.001 - Component Object Model | T1570.000 - Lateral Tool Transfer",# memory, evt
        "WinCommand_|_itaskservice|itaskdefinition|itasksettings": "T1559.001 - Component Object Model",# memory, evt
        "WinCommand_|_libzip|zlib": "T1560.002 - Archive via Library",# memory, evt
        "WinCommand_|_loadlibrary": "T1055.001 - Dynamic-link Library Injection | T1055.002 - Portable Executable Injection | T1055.004 - Asynchronous Procedure Call | T1106.000 - Native API",# memory, evt
        "WinCommand_|_logonuser|runas|setthreadtoken": "T1134.003 - Make and Impersonate Token",# memory, evt
        "WinCommand_|_lsadump|dcshadow": "T1207.000 - Rogue Domain Controller",# memory, evt
        "WinCommand_|_lsass": "T1003.001 - LSASS Memory | T1547.008 - LSASS Driver | T1556.001 - Domain Controller Authentication",# memory, evt
        "WinCommand_|_lsof|route|dig": "T1033.000 - System Owner/User Discovery | T1049.000 - System Network Connections Discovery",# memory, evt
        "WinCommand_|_mailboxexportrequest|x-ms-exchange-organization-autoforwarded|x-mailfwdby|x-forwarded-to|forwardingsmtpaddress": "T1114.003 - Email Forwarding Rule",# memory, evt
        "WinCommand_|_microphone": "T1123.000 - Audio Capture",# memory, evt
        "WinCommand_|_microsoft\\.office\\.interop": "T1559.001 - Component Object Model",# memory, evt
        "WinCommand_|_mof|register-wmievent|wmiprvse|eventfilter|eventconsumer|filtertoconsumerbinding": "T1546.003 - Windows Management Instrumentation Event Subscription",# memory, evt
        "WinCommand_|_msbuild": "T1127.001 - MSBuild | T1569.002 - Service Execution",# memory, evt
        "WinCommand_|_mshta|alwaysinstallelevated": "T1218.005 - Mshta",# memory, evt
        "WinCommand_|_msiexec|alwaysinstallelevated": "T1218.007 - Msiexec",# memory, evt
        "WinCommand_|_msxml": "T1220.000 - XSL Script Processing",# memory, evt
        "WinCommand_|_net accounts|net  accounts|net\\.exe accounts|net\\.exe  accounts|net1 accounts|net1  accounts|net1\\.exe accounts|net1\\.exe  accounts|net_accounts|net__accounts|net\\.exe_accounts|net\\.exe__accounts|net1_accounts|net1__accounts|net1\\.exe_accounts|net1\\.exe__accounts": "T1201.000 - Password Policy Discovery",# memory, evt
        "WinCommand_|_net share|net  share|net\\.exe share|net\\.exe  share|net1 share|net1  share|net1\\.exe share|net1\\.exe  share|net_share|net__share|net\\.exe_share|net\\.exe__share|net1_share|net1__share|net1\\.exe_share|net1\\.exe__share": "T1135.000 - Network Share Discovery",# memory, evt
        "WinCommand_|_net start|net  start|net\\.exe start|net\\.exe  start|net1 start|net1  start|net1\\.exe start|net1\\.exe  start|net stop|net  stop|net\\.exe stop|net\\.exe  stop|net1 stop|net1  stop|net1\\.exe stop|net1\\.exe  stop|net_start|net__start|net\\.exe_start|net\\.exe__start|net1_start|net1__start|net1\\.exe_start|net1\\.exe__start|net_stop|net__stop|net\\.exe_stop|net\\.exe__stop|net1_stop|net1__stop|net1\\.exe_stop|net1\\.exe__stop": "T1007.000 - System Service Discovery | T1569.002 - Service Execution",# memory, evt
        "WinCommand_|_net stop|net  stop|net\\.exe stop|net\\.exe  stop|net1 stop|net1  stop|net1\\.exe stop|net1\\.exe  stop|net_stop|net__stop|net\\.exe_stop|net\\.exe__stop|net1_stop|net1__stop|net1\\.exe_stop|net1\\.exe__stop|msexchangeis|changeserviceconfigw": "T1489.000 - Service Stop | T1569.002 - Service Execution",# memory, evt
        "WinCommand_|_net time|net  time|net\\.exe time|net\\.exe  time|net1 time|net1  time|net1\\.exe time|net1\\.exe  time|net_time|net__time|net\\.exe_time|net\\.exe__time|net1_time|net1__time|net1\\.exe_time|net1\\.exe__time": "T1124.000 - System Time Discovery",# memory, evt
        "WinCommand_|_net use|net  use|net\\.exe use|net\\.exe  use|net1 use|net1  use|net1\\.exe use|net1\\.exe  use|net_use|net__use|net\\.exe_use|net\\.exe__use|net1_use|net1__use|net1\\.exe_use|net1\\.exe__use": "T1049.000 - System Network Connections Discovery | T1070.005 - Network Share Connection Removal | T1136.001 - Local Account | T1136.002 - Domain Account | T1574.008 - Path Interception by Search Order Hijacking",# memory, evt
        "WinCommand_|_net view|net  view|net_view|net__view": "T1018.000 - Remote System Discovery | T1135.000 - Network Share Discovery",# memory, evt
        "WinCommand_|_netsh": "T1049.000 - System Network Connections Discovery | T1090.001 - Internal Proxy | T1135.000 - Network Share Discovery | T1518.001 - Security Software Discovery",# memory, evt
        "WinCommand_|_netstat|net session|net  session|net\\.exe session|net\\.exe  session|net1 session|net1  session|net1\\.exe session|net1\\.exe  session|net_session|net__session|net\\.exe_session|net\\.exe__session|net1_session|net1__session|net1\\.exe_session|net1\\.exe__session": "T1049.000 - System Network Connections Discovery",# memory, evt
        "WinCommand_|_new-gpoimmediatetask": "T1484.001 - Group Policy Modification",# memory, evt
        "WinCommand_|_nltest": "T1482.000 - Domain Trust Discovery",# memory, evt
        "WinCommand_|_notonorafter|accesstokenlifetime|lifetimetokenpolicy": "T1606.002 - SAML Tokens",# memory, evt
        "WinCommand_|_ntds|ntdsutil|secretsdump": "T1003.003 - NTDS",# memory, evt
        "WinCommand_|_ntsd": "T1546.012 - Image File Execution Options Injection",# memory, evt
        "WinCommand_|_ntunmapviewofsection": "T1055.012 - Process Hollowing | T1055.013 - Process Doppelganging",# memory, evt
        "WinCommand_|_odbcconf": "T1218.008 - Odbcconf",# memory, evt
        "WinCommand_|_onedrive|1drv|azure|icloud|cloudrive|dropbox|drive\\.google|fileshare|mediafire|zippyshare|megaupload|4shared": "T1537.000 - Transfer Data to Cloud Account | T1567.002 - Exfiltration to Cloud Storage",# memory, evt
        "WinCommand_|_openprocess": "T1556.001 - Domain Controller Authentication",# memory, evt
        "WinCommand_|_openthread": "T1055.004 - Asynchronous Procedure Call | T1055.003 - Thread Execution Hijacking",# memory, evt
        "WinCommand_|_password|secure|credentials|security": "T1552.001 - Credentials in Files | T1555.004 - Windows Credential Manager | T1555.005 - Password Managers",# memory, evt
        "WinCommand_|_performancecache|_vba_project": "T1564.007 - VBA Stomping",# memory, evt
        "WinCommand_|_ping|tracert": "T1016.001 - Internet Connection Discovery | T1018.000 - Remote System Discovery",# memory, evt
        "WinCommand_|_policy\\.vpol|vaultcmd|vcrd|listcreds|credenumeratea": "T1555.004 - Windows Credential Manager",# memory, evt
        "WinCommand_|_powershell": "T1059.001 - PowerShell | T1106.000 - Native API",# memory, evt
        "WinCommand_|_procdump|sekurlsa": "T1003.001 - LSASS Memory",# memory, evt
        "WinCommand_|_psexec": "T1003.001 - LSASS Memory | T1569.002 - Service Execution | T1570.000 - Lateral Tool Transfer",# memory, evt
        "WinCommand_|_psinject|peinject|ntqueueapcthread|queueuserapc": "T1055.004 - Asynchronous Procedure Call",# memory, evt
        "WinCommand_|_psreadline|set-psreadlineoption": "T1070.003 - Clear Command History | T1562.003 - Impair Command History Logging",# memory, evt
        "WinCommand_|_pubprn": "T1216.001 - PubPrn",# memory, evt
        "WinCommand_|_python|\\.py": "T1059.006 - Python",# memory, evt
        "WinCommand_|_queueuserapc": "T1055.004 - Asynchronous Procedure Call",# memory, evt
        "WinCommand_|_quser|query user|query  user|query_user|query__user|hostname": "T1033.000 - System Owner/User Discovery",# memory, evt
        "WinCommand_|_reg |reg_|reg\\.exe": "T1112.000 - Modify Registry",# memory, evt
        "WinCommand_|_reg query|reg  query|reg_query|reg__query": "T1012.000 - Query Registry | T1518.001 - Security Software Discovery",# memory, evt
        "WinCommand_|_regsvcs|regasm|comregisterfunction|comunregisterfunction": "T1218.009 - Regsvcs/Regasm",# memory, evt
        "WinCommand_|_regsvr": "T1218.008 - Odbcconf | T1218.010 - Regsvr32",# memory, evt
        "WinCommand_|_resumethread": "T1055.003 - Thread Execution Hijacking | T1055.004 - Asynchronous Procedure Call | T1055.005 - Thread Local Storage | T1055.012 - Process Hollowing",# memory, evt
        "WinCommand_|_rundll32": "T1218.010 - Regsvr32",# memory, evt
        "WinCommand_|_rundll32|cplapplet|dllentrypoint|control_rundll|controlrundllasuser": "T1036.003 - Rename System Utilities | T1218.011 - Rundll32",# memory, evt
        "WinCommand_|_schtask|\\.job": "T1053.005 - Scheduled Task",# memory, evt
        "WinCommand_|_scp|rsync|sftp": "T1105.000 - Ingress Tool Transfer",# memory, evt
        "WinCommand_|_scrnsave": "T1546.002 - Screensaver",# memory, evt
        "WinCommand_|_scvhost|svchast|svchust|svchest|lssas|lsasss|lsaas|cssrs|canhost|conhast|connhost|connhst|iexplorer|iexploror|iexplorar": "T1036.004 - Masquerade Task or Service",# memory, evt
        "WinCommand_|_set-etwtraceprovider|zwopenprocess|getextendedtcptable": "T1562.006 - Indicator Blocking",# memory, evt
        "WinCommand_|_setthreadcontext": "T1055.003 - Thread Execution Hijacking | T1055.004 - Asynchronous Procedure Call | T1055.005 - Thread Local Storage | T1055.012 - Process Hollowing | T1055.013 - Process Doppelganging | T1106.000 - Native API",# memory, evt
        "WinCommand_|_setwindowshook|setwineventhook": "T1056.004 - Credential API Hooking",# memory, evt
        "WinCommand_|_shellexecute|isdebuggerpresent|outputdebugstring|setlasterror|httpopenrequesta|createpipe|getusernamew|callwindowproc|enumresourcetypesa|connectnamedpipe|wnetaddconnection2|zwwritevirtualmemory|zwprotectvirtualmemory|zwqueueapcthread|ntresumethread|terminateprocess|getmodulefilename|lstrcat|createfile|readfile|getprocessbyid|writefile|closehandle|getcurrenthwprofile|getprocaddress|dwritecreatefactory|findnexturlcacheentrya|findfirsturlcacheentrya|getwindowsdirectoryw|movefileex|ntqueryinformationprocess|regenumkeyw": "T1106.000 - Native API",# memory, evt
        "WinCommand_|_shutdown": "T1529.000 - System Shutdown/Reboot",# memory, evt
        "WinCommand_|_startupitems": "T1037.005 - Startup Items",# memory, evt
        "WinCommand_|_suspendthread": "T1055.003 - Thread Execution Hijacking | T1055.004 - Asynchronous Procedure Call | T1055.005 - Thread Local Storage",# memory, evt
        "WinCommand_|_sysmain\\.sdb|profile": "T1546.013 - PowerShell Profile",# memory, evt
        "WinCommand_|_systemdiskclean|getwindowsdirectoryw": "T1036.005 - Match Legitimate Name or Location",# memory, evt
        "WinCommand_|_tasklist": "T1007.000 - System Service Discovery | T1518.001 - Security Software Discovery",# memory, evt
        "WinCommand_|_testsigning": "T1553.006 - Code Signing Policy Modification",# memory, evt
        "WinCommand_|_time|sleep": "T1497.003 - Time Based Evasion",# memory, evt
        "WinCommand_|_tscon": "T1563.002 - RDP Hijacking",# memory, evt
        "WinCommand_|_u202e": "T1036.002 - Right-to-Left Override",# memory, evt
        "WinCommand_|_update-msolfederateddomain|set federation|domain authentication|set  federation|domain  authentication|set_federation|domain_authentication|set__federation|domain__authentication": "T1484.002 - Domain Trust Modification",# memory, evt
        "WinCommand_|_updateprocthreadattribute": "T1134.003 - Make and Impersonate Token | T1134.004 - Parent PID Spoofing",# memory, evt
        "WinCommand_|_useradd": "T1136.001 - Local Account",# memory, evt
        "WinCommand_|_vboxmanage|virtualbox|vmplayer|vmprocess|vmware|hyper-v|qemu": "T1564.006 - Run Virtual Instance",# memory, evt
        "WinCommand_|_vbscript": "T1059.005 - Visual Basic",# memory, evt
        "WinCommand_|_verclsid": "T1218.012 - Verclsid",# memory, evt
        "WinCommand_|_virtualalloc": "T1055.001 - Dynamic-link Library Injection | T1055.002 - Portable Executable Injection | T1055.003 - Thread Execution Hijacking | T1055.004 - Asynchronous Procedure Call | T1055.005 - Thread Local Storage | T1055.012 - Process Hollowing | T1106.000 - Native API",# memory, evt
        "WinCommand_|_vpcext|vmtoolsd|msacpi_thermalzonetemperature": "T1497.001 - System Checks",# memory, evt
        "WinCommand_|_vssadmin|wbadmin|shadows|shadowcopy": "T1490.000 - Inhibit System Recovery",# memory, evt
        "WinCommand_|_wevtutil|openeventlog|cleareventlog": "T1070.001 - Clear Windows Event Logs",# memory, evt
        "WinCommand_|_windowstyle|hidden": "T1564.003 - Hidden Window",# memory, evt
        "WinCommand_|_winexec": "T1106.000 - Native API | T1543.003 - Windows Service | T1546.009 - AppCert DLLs",# memory, evt
        "WinCommand_|_winrm": "T1021.006 - Windows Remote Management",# memory, evt
        "WinCommand_|_winword|excel|powerpnt|acrobat|acrord32": "T1203.000 - Exploitation for Client Execution | T1204.002 - Malicious File",# memory, evt
        "WinCommand_|_wmic|invoke-wmi": "T1047.000 - Windows Management Instrumentation | T1220.000 - XSL Script Processing",# memory, evt
        "WinCommand_|_writeprocessmemory": "T1055.001 - Dynamic-link Library Injection | T1055.002 - Portable Executable Injection | T1055.003 - Thread Execution Hijacking | T1055.004 - Asynchronous Procedure Call | T1055.005 - Thread Local Storage | T1055.011 - Extra Window Memory Injection | T1055.012 - Process Hollowing | T1055.013 - Process Doppelganging | T1106.000 - Native API",# memory, evt
        "WinCommand_|_wscript": "T1059.005 - Visual Basic | T1059.007 - JavaScript",# memory, evt
        "WinCommand_|_zwseteafile|zwqueryeafile|:ads|stream": "T1564.004 - NTFS File Attributes",# memory, evt
        "WinCommand_|_zwunmapviewofsection": "T1055.012 - Process Hollowing"# memory, evt
    }
    transformsconf.write("[mitre_assign]\nINGEST_EVAL = mitre_techniques=")
    for ioc, mitre in assignment_pairings.items():
        transformsconf.write("{}{}{}{}{}{}{}".format(start, ioc.split("_|_")[0], prefix, ioc.split("_|_")[1], suffix, mitre, end))
    transformsconf.write("\"-\")))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))), ")
    transformsconf.write("mitre_technique=split(mitre_techniques,\" | \")\n\n")

  ##ForeignPort_|_^NEGATE_STANDARD_PORTS_-_(ALL_PORTS_LISTED_ABOVE)$": "T1571.00 - Non-Standard Port
  ##LocalPort_|_^NEGATE_STANDARD_PORTS_-_(ALL_PORTS_LISTED_ABOVE)$": "T1571.00 - Non-Standard Port
  ## Spearphishing via Service sites - Facebook, Instagram etc.
