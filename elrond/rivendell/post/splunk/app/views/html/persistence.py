#!/usr/bin/env python3 -tt


def create_persistence_html(sd, header, headings, iocs, related, insert, mitigations, footer):
    with open(sd + "t1098.html", "w") as t1098html:
        # description
        t1098html.write(
            "{}Adversaries may manipulate accounts to maintain access to victim systems. Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups.<br>".format(
                header
            )
        )
        t1098html.write(
            "These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials.<br>"
        )
        t1098html.write(
            "In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain."
        )
        # information
        t1098html.write("{}T1098</td>\n        <td>".format(headings))  # id
        t1098html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP, Office 365</td>\n        <td>"
        )  # platforms
        t1098html.write("Persistence</td>\n        <td>")  # tactics
        t1098html.write(
            "T1098.001: Additional Cloud Credentials<br>T1098.002: Exchange Email Delegate Permissions<br>T1098.003: Add Office 365 Global Administrator Role<br>T1098.004: SSH Authorized Keys"
        )  # sub-techniques
        # indicator regex assignments
        t1098html.write("{}authorized_keys</li>\n        <li>".format(iocs))
        t1098html.write("sshd_config</li>\n        <li>")
        t1098html.write("ssh-keygen</li>")
        # related techniques
        t1098html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t0078 target="_blank"">T0078</a></td>\n        <td>'.format(
                related
            )
        )
        t1098html.write("Valid Accounts")
        # mitigations
        t1098html.write(
            "{}Multi-factor Authentication</td>\n        <td>".format(mitigations)
        )
        t1098html.write(
            "Use multi-factor authentication for user and privileged accounts.{}".format(
                insert
            )
        )
        t1098html.write("Network Segmentation</td>\n        <td>")
        t1098html.write(
            "Configure access controls and firewalls to limit access to critical systems and domain controllers. Most cloud environments support separate virtual private cloud (VPC) instances that enable further segmentation of cloud systems.{}".format(
                insert
            )
        )
        t1098html.write("Operating System Configuration</td>\n        <td>")
        t1098html.write(
            "Protect domain controllers by ensuring proper security configuration for critical servers to limit access by potentially unnecessary protocols and services, such as SMB file sharing.{}".format(
                insert
            )
        )
        t1098html.write("Privileged Account Management</td>\n        <td>")
        t1098html.write(
            "Do not allow domain administrator accounts to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.{}".format(
                footer
            )
        )
    with open(sd + "t1197.html", "w") as t1197html:
        # description
        t1197html.write(
            "{}Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM).<br>".format(
                header
            )
        )
        t1197html.write(
            "BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.<br>"
        )
        t1197html.write(
            "The interface to create and manage BITS jobs is accessible through PowerShell and the BITSAdmin tool.<br>"
        )
        t1197html.write(
            "Adversaries may abuse BITS to download, execute, and even clean up after running malicious code. BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls.<br>"
        )
        t1197html.write(
            "BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots).<br>"
        )
        t1197html.write(
            "BITS upload functionalities can also be used to perform Exfiltration Over Alternative Protocol."
        )
        # information
        t1197html.write("{}T1197</td>\n        <td>".format(headings))  # id
        t1197html.write("Windows</td>\n        <td>")  # platforms
        t1197html.write("Persistence, Defense Evasion</td>\n        <td>")  # tactics
        t1197html.write("-")  # sub-techniques
        # indicator regex assignments
        t1197html.write("{}addfile</li>\n        <li>".format(iocs))
        t1197html.write("bits</li>\n        <li>")
        t1197html.write("setnotifyflags</li>\n        <li>")
        t1197html.write("setnotifycmdline</li>\n        <li>")
        t1197html.write("transfer</li>")
        # related techniques
        t1197html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1559 target="_blank"">T1559</a></td>\n        <td>'.format(
                related
            )
        )
        t1197html.write("Inter-Process Communication: Component Object Model")
        t1197html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1059 target="_blank"">T1059</a></td>\n        <td>'.format(
                insert
            )
        )
        t1197html.write("Command and Scripting Interpreter: PowerShell")
        t1197html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1048 target="_blank"">T1048</a></td>\n        <td>'.format(
                insert
            )
        )
        t1197html.write("Exfiltration Over Alternative Protocol")
        # mitigations
        t1197html.write(
            "{}Filter Network Traffic</td>\n        <td>".format(mitigations)
        )
        t1197html.write(
            "Modify network and/or host firewall rules, as well as other network controls, to only allow legitimate BITS traffic.{}".format(
                insert
            )
        )
        t1197html.write("Operating System Configuration</td>\n        <td>")
        t1197html.write(
            "Consider reducing the default BITS job lifetime in Group Policy or by editing the JobInactivityTimeout and MaxDownloadTime Registry values in HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\BITS.{}".format(
                insert
            )
        )
        t1197html.write("User Account Management</td>\n        <td>")
        t1197html.write(
            "Consider limiting access to the BITS interface to specific users or groups.{}".format(
                footer
            )
        )
    with open(sd + "t1547.html", "w") as t1547html:
        # description
        t1547html.write(
            "{}Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon.<br>".format(
                header
            )
        )
        t1547html.write(
            "These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.<br>"
        )
        t1547html.write(
            "Since some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges."
        )
        # information
        t1547html.write("{}T1547</td>\n        <td>".format(headings))  # id
        t1547html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1547html.write(
            "Persistence, Privilege Escalation</td>\n        <td>"
        )  # tactics
        t1547html.write(
            "T1547.001: Registry Run Keys/Startup Folder<br>T1547.002: Authentication Package<br>T1547.003: Time Providers<br>T1547.004: Winlogon Helper DLL<br>T1547.005: Security Support Provider<br>T1547.006: Kernel Modules and Extensions<br>T1547.007: Re-opened Applications<br>T1547.008: LSASS Driver<br>T1547.009: Shortcut Modification<br>T1547.010: Port Monitors<br>T1547.011: Plist Modification<br>T1547.012: Print Processors<br>T1547.013: XDG Autostart Entries<br>T1547.014: Active Setup"
        )  # sub-techniques
        # indicator regex assignments
        t1547html.write("{}Event IDs: 3033, 3063</li>\n        <li>".format(iocs))
        t1547html.write("-noprofile</li>\n        <li>")
        t1547html.write("AddMonitor</li>\n        <li>")
        t1547html.write("AddPrintProcessor</li>\n        <li>")
        t1547html.write("GetPrintProcessorDirectory</li>\n        <li>")
        t1547html.write("SeLoadDriverPrivilege</li>\n        <li>")
        t1547html.write("BootExecute</li>\n        <li>")
        t1547html.write("autocheck</li>\n        <li>")
        t1547html.write("autochk</li>\n        <li>")
        t1547html.write("COR_PROFILER</li>\n        <li>")
        t1547html.write("failure</li>\n        <li>")
        t1547html.write("lsass</li>\n        <li>")
        t1547html.write(".lnk</li>\n        <li>")
        t1547html.write("Authentication Packages</li>\n        <li>")
        t1547html.write("Print Processors</li>\n        <li>")
        t1547html.write("Active Setup/Installed Components</li>\n        <li>")
        t1547html.write("CurrentControlSet/Control/Lsa</li>\n        <li>")
        t1547html.write("CurrentControlSet/Control/Print/Monitors</li>\n        <li>")
        t1547html.write("CurrentControlSet/Control/Session Manager</li>\n        <li>")
        t1547html.write(
            "CurrentControlSet/Services/W32Time/TimeProviders</li>\n        <li>"
        )
        t1547html.write(
            "CurrentVersion/Image File Execution Options</li>\n        <li>"
        )
        t1547html.write("CurrentVersion/WinLogon/Notify</li>\n        <li>")
        t1547html.write("CurrentVersion/WinLogon/UserInit</li>\n        <li>")
        t1547html.write("CurrentVersion/WinLogon/Shell</li>\n        <li>")
        t1547html.write("Manager/SafeDllSearchMode</li>\n        <li>")
        t1547html.write("Security/Policy/Secrets</li>\n        <li>")
        t1547html.write("emond</li>\n        <li>")
        t1547html.write("lc_load_weak_dylib</li>\n        <li>")
        t1547html.write("rpath</li>\n        <li>")
        t1547html.write("loader_path</li>\n        <li>")
        t1547html.write("executable_path</li>\n        <li>")
        t1547html.write("ottol</li>\n        <li>")
        t1547html.write("LD_PRELOAD</li>\n        <li>")
        t1547html.write("DYLD_INSERT_LIBRARIES</li>\n        <li>")
        t1547html.write("export</li>\n        <li>")
        t1547html.write("setenv</li>\n        <li>")
        t1547html.write("putenv</li>\n        <li>")
        t1547html.write("os.environ</li>\n        <li>")
        t1547html.write("ld.so.preload</li>\n        <li>")
        t1547html.write("dlopen</li>\n        <li>")
        t1547html.write("mmap</li>\n        <li>")
        t1547html.write("failure</li>\n        <li>")
        t1547html.write("modprobe</li>\n        <li>")
        t1547html.write("insmod</li>\n        <li>")
        t1547html.write("lsmod</li>\n        <li>")
        t1547html.write("rmmod</li>\n        <li>")
        t1547html.write("modinfo</li>\n        <li>")
        t1547html.write("kextload</li>\n        <li>")
        t1547html.write("kextunload</li>\n        <li>")
        t1547html.write("autostart</li>\n        <li>")
        t1547html.write("xdg</li>\n        <li>")
        t1547html.write("autostart</li>\n        <li>")
        t1547html.write("loginitems</li>\n        <li>")
        t1547html.write("loginwindow</li>\n        <li>")
        t1547html.write("SMLoginItemSetEnabled</li>\n        <li>")
        t1547html.write("uielement</li>\n        <li>")
        t1547html.write("quarantine</li>\n        <li>")
        t1547html.write("startupparameters</li>")
        # related techniques
        t1547html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1037 target="_blank"">T1037</a></td>\n        <td>'.format(
                related
            )
        )
        t1547html.write("Boot or Logon Initialization Scripts")
        # mitigations
        t1547html.write("{}-</td>\n        <td>".format(mitigations))
        t1547html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1037.html", "w") as t1037html:
        # description
        t1037html.write(
            "{}Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence.<br>".format(
                header
            )
        )
        t1037html.write(
            "Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.<br>"
        )
        t1037html.write(
            "Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.<br>"
        )
        t1037html.write(
            "An adversary may also be able to escalate their privileges since some boot or logon initialization scripts run with higher privileges."
        )
        # information
        t1037html.write("{}T1037</td>\n        <td>".format(headings))  # id
        t1037html.write("Windows, macOS</td>\n        <td>")  # platforms
        t1037html.write(
            "Persistence, Privilege Escalation</td>\n        <td>"
        )  # tactics
        t1037html.write(
            "T1037.001: Logon Script (Windows)<br>T1037.002: Logon Script (Mac)<br>T1037.003: Network Logon Script<br>T1037.004: Rc.common<br>T1037.005: Startup Items"
        )  # sub-techniques
        # indicator regex assignments
        t1037html.write("{}StartupItems</li>\n        <li>".format(iocs))
        t1037html.write("StartupParameters</li>\n        <li>")
        t1037html.write("init.d</li>\n        <li>")
        t1037html.write("rc.local</li>\n        <li>")
        t1037html.write("rc.common</li>\n        <li>")
        t1037html.write("Environment/UserInitMprLogonScript</li>")
        # related techniques
        t1037html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1555 target="_blank"">T1555</a></td>\n        <td>'.format(
                related
            )
        )
        t1037html.write(
            "Credentials from Password Stores: Credentials from Web Browsers"
        )
        # mitigations
        t1037html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1037html.write(
            "Ensure extensions that are installed are the intended ones as many malicious extensions will masquerade as legitimate ones.{}".format(
                insert
            )
        )
        t1037html.write("Execution Prevention</td>\n        <td>")
        t1037html.write(
            "Set a browser extension allow or deny list as appropriate for your security policy.{}".format(
                insert
            )
        )
        t1037html.write("Limit Software Installation</td>\n        <td>")
        t1037html.write(
            "Only install browser extensions from trusted sources that can be verified. Browser extensions for some browsers can be controlled through Group Policy. Change settings to prevent the browser from installing extensions without sufficient permissions.{}".format(
                insert
            )
        )
        t1037html.write("Update Software</td>\n        <td>")
        t1037html.write(
            "Ensure operating systems and browsers are using the most current version.{}".format(
                insert
            )
        )
        t1037html.write("User Training</td>\n        <td>")
        t1037html.write(
            "Close out all browser sessions when finished using them to prevent any potentially malicious extensions from continuing to run.{}".format(
                footer
            )
        )
    with open(sd + "t1176.html", "w") as t1176html:
        # description
        t1176html.write(
            "{}Adversaries may abuse Internet browser extensions to establish persistence access to victim systems. Browser extensions or plugins are small programs that can add functionality and customize aspects of Internet browsers.<br>".format(
                header
            )
        )
        t1176html.write(
            "They can be installed directly or through a browser's app store and generally have access and permissions to everything that the browser can access.<br>"
        )
        t1176html.write(
            "Malicious extensions can be installed into a browser through malicious app store downloads masquerading as legitimate extensions, through social engineering, or by an adversary that has already compromised a system.<br>"
        )
        t1176html.write(
            "Security can be limited on browser app stores so it may not be difficult for malicious extensions to defeat automated scanners. Once the extension is installed, it can browse to websites in the background, steal all information that a user enters into a browser (including credentials) and be used as an installer for a RAT for persistence.<br>"
        )
        t1176html.write(
            "There have also been instances of botnets using a persistent backdoor through malicious Chrome extensions. There have also been similar examples of extensions being used for command & control."
        )
        # information
        t1176html.write("{}T1176</td>\n        <td>".format(headings))  # id
        t1176html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1176html.write("Persistence</td>\n        <td>")  # tactics
        t1176html.write("-")  # sub-techniques
        # indicator regex assignments
        t1176html.write("{}.mobileconfig</li>\n        <li>".format(iocs))
        t1176html.write("profiles</li>")
        # related techniques
        t1176html.write("{}T1554</td>\n        <td>".format(related))
        t1176html.write("-")
        # mitigations
        t1176html.write("{}Code Signing</td>\n        <td>".format(mitigations))
        t1176html.write(
            "Ensure all application component binaries are signed by the correct application developers.{}".format(
                footer
            )
        )
    with open(sd + "t1554.html", "w") as t1554html:
        # description
        t1554html.write(
            "{}Adversaries may modify client software binaries to establish persistent access to systems. Client software enables users to access services provided by a server.<br>".format(
                header
            )
        )
        t1554html.write(
            "Common client software types are SSH clients, FTP clients, email clients, and web browsers.<br>"
        )
        t1554html.write(
            "Adversaries may make modifications to client software binaries to carry out malicious tasks when those applications are in use. For example, an adversary may copy source code for the client software, add a backdoor, compile for the target, and replace the legitimate application binary (or support files) with the backdoored one.<br>"
        )
        t1554html.write(
            "Since these applications may be routinely executed by the user, the adversary can leverage this for persistent access to the host."
        )
        # information
        t1554html.write("{}T1554</td>\n        <td>".format(headings))  # id
        t1554html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1554html.write("Persistence</td>\n        <td>")  # tactics
        t1554html.write("-")  # sub-techniques
        # indicator regex assignments
        t1554html.write("{}-".format(iocs))
        # related techniques
        t1554html.write("{}--</a></td>\n        <td>".format(related))
        t1554html.write("-")
        # mitigations
        t1554html.write(
            "{}Multi-factor Authentication</td>\n        <td>".format(mitigations)
        )
        t1554html.write(
            "Use multi-factor authentication for user and privileged accounts.{}".format(
                insert
            )
        )
        t1554html.write("Network Segmentation</td>\n        <td>")
        t1554html.write(
            "Configure access controls and firewalls to limit access to domain controllers and systems used to create and manage accounts.{}".format(
                insert
            )
        )
        t1554html.write("Operating System Configuration</td>\n        <td>")
        t1554html.write(
            "Protect domain controllers by ensuring proper security configuration for critical servers.{}".format(
                insert
            )
        )
        t1554html.write("Privileged Account Management</td>\n        <td>")
        t1554html.write(
            "Do not allow domain administrator accounts to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.{}".format(
                footer
            )
        )
    with open(sd + "t1136.html", "w") as t1136html:
        # description
        t1136html.write(
            "{}Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.<br>".format(
                header
            )
        )
        t1136html.write(
            "Accounts may be created on the local system or within a domain or cloud tenant. In cloud environments, adversaries may create accounts that only have access to specific services, which can reduce the chance of detection."
        )
        # information
        t1136html.write("{}T1136</td>\n        <td>".format(headings))  # id
        t1136html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP, Office 365</td>\n        <td>"
        )  # platforms
        t1136html.write("Persistence</td>\n        <td>")  # tactics
        t1136html.write(
            "T1136.001: Local Account<br>T1136.002: Domain Account<br>T1136.003: Cloud Account"
        )  # sub-techniques
        # indicator regex assignments
        t1136html.write("{}net.exe user /add</li>\n        <li>".format(iocs))
        t1136html.write("net.exe user /domain</li>\n        <li>")
        t1136html.write("net1.exe user /add</li>\n        <li>")
        t1136html.write("net1.exe user /domain</li>")
        # related techniques
        t1136html.write("{}-</a></td>\n        <td>".format(related))
        t1136html.write("-")
        # mitigations
        t1136html.write(
            "{}Multi-factor Authentication</td>\n        <td>".format(mitigations)
        )
        t1136html.write(
            "Use multi-factor authentication for user and privileged accounts.{}".format(
                insert
            )
        )
        t1136html.write("Network Segmentation</td>\n        <td>")
        t1136html.write(
            "Configure access controls and firewalls to limit access to domain controllers and systems used to create and manage accounts.{}".format(
                insert
            )
        )
        t1136html.write("Operating System Configuration</td>\n        <td>")
        t1136html.write(
            "Protect domain controllers by ensuring proper security configuration for critical servers.{}".format(
                insert
            )
        )
        t1136html.write("Privileged Account Management</td>\n        <td>")
        t1136html.write(
            "Do not allow domain administrator accounts to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.{}".format(
                footer
            )
        )
    with open(sd + "t1543.html", "w") as t1543html:
        # description
        t1543html.write(
            "{}Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions.<br>".format(
                header
            )
        )
        t1543html.write(
            "On Windows and Linux, these system processes are referred to as services. On macOS, launchd processes known as Launch Daemon and Launch Agent are run to finish system initialization and load user specific parameters.<br>"
        )
        t1543html.write(
            "Adversaries may install new services, daemons, or agents that can be configured to execute at startup or a repeatable interval in order to establish persistence. Similarly, adversaries may modify existing services, daemons, or agents to achieve the same effect.<br>"
        )
        t1543html.write(
            "Services, daemons, or agents may be created with administrator privileges but executed under root/SYSTEM privileges. Adversaries may leverage this functionality to create or modify system processes in order to escalate privileges."
        )
        # information
        t1543html.write("{}T1543</td>\n        <td>".format(headings))  # id
        t1543html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1543html.write(
            "Persistence, Privilege Escalation</td>\n        <td>"
        )  # tactics
        t1543html.write(
            "T1543.001: Launch Agent<br>T1543.002: Systemd Service<br>T1543.003: Windows Service<br>T1543.004: Launch Daemon"
        )  # sub-techniques
        # indicator regex assignments
        t1543html.write("{}services.exe</li>\n        <li>".format(iocs))
        t1543html.write("sc.exe</li>\n        <li>")
        t1543html.write("WinExec</li>\n        <li>")
        t1543html.write(".services</li>\n        <li>")
        t1543html.write("LaunchAgent</li>\n        <li>")
        t1543html.write("LaunchDaemon</li>\n        <li>")
        t1543html.write("systemctl</li>")
        # related techniques
        t1543html.write("{}-</a></td>\n        <td>".format(related))
        t1543html.write("-")
        # mitigations
        t1543html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1543html.write(
            "Use auditing tools capable of detecting privilege and service abuse opportunities on systems within an enterprise and correct them.{}".format(
                insert
            )
        )
        t1543html.write("Limit Software Installation</td>\n        <td>")
        t1543html.write(
            "Restrict software installation to trusted repositories only and be cautious of orphaned software packages.{}".format(
                insert
            )
        )
        t1543html.write("Restrict File and Directory Permissions</td>\n        <td>")
        t1543html.write(
            "Restrict read/write access to system-level process files to only select privileged users who have a legitimate need to manage system services.{}".format(
                insert
            )
        )
        t1543html.write("User Account Management</td>\n        <td>")
        t1543html.write(
            "Limit privileges of user accounts and groups so that only authorized administrators can interact with system-level process changes and service configurations.{}".format(
                footer
            )
        )
    with open(sd + "t1546.html", "w") as t1546html:
        # description
        t1546html.write(
            "{}Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries.<br>".format(
                header
            )
        )
        t1546html.write(
            "Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via repeatedly executing malicious code. After gaining access to a victim system, adversaries may create/modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked.<br>"
        )
        t1546html.write(
            "Since the execution can be proxied by an account with higher permissions, such as SYSTEM or service accounts, an adversary may be able to abuse these triggered execution mechanisms to escalate their privileges."
        )
        # information
        t1546html.write("{}T1546</td>\n        <td>".format(headings))  # id
        t1546html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1546html.write(
            "Persistence, Privilege Escalation</td>\n        <td>"
        )  # tactics
        t1546html.write(
            "T1546.001: Change Default File Association<br>T1546.002: Screensaver<br>T1546.003: Windows Management Instrumentation Event Subscription<br>T1546.004: .bash_profile and .bashrc<br>T1546.005: Trap<br>T1546.006: LC_LOAD_DYLIB Addition<br>T1546.007: Netsh Helper DLL<br>T1546.008: Accessibility Features<br>T1546.009: AppCert DLLs<br>T1546.010: AppInit DLLs<br>T1546.011: Application Shimming<br>T1546.012: Image File Execution Options Injection<br>T1546.013: PowerShell Profile<br>T1546.014: emond<br>T1546.015: Component Object Model Hijacking"
        )  # sub-techniques
        # indicator regex assignments
        t1546html.write("{}Event IDs: 5861</li>\n        <li>".format(iocs))
        t1546html.write("atbroker</li>\n        <li>")
        t1546html.write("displayswitch</li>\n        <li>")
        t1546html.write("magnify</li>\n        <li>")
        t1546html.write("narrator</li>\n        <li>")
        t1546html.write("osk</li>\n        <li>")
        t1546html.write("sethc</li>\n        <li>")
        t1546html.write("utilman</li>\n        <li>")
        t1546html.write("scrnsave</li>\n        <li>")
        t1546html.write("ntsd</li>\n        <li>")
        t1546html.write("WmiPrvSe</li>\n        <li>")
        t1546html.write("sysmain.sdb</li>\n        <li>")
        t1546html.write("profile</li>\n        <li>")
        t1546html.write("CreateProcess</li>\n        <li>")
        t1546html.write("WinExec</li>\n        <li>")
        t1546html.write("Register-WmiEvent</li>\n        <li>")
        t1546html.write("EventFilter</li>\n        <li>")
        t1546html.write("EventConsumer</li>\n        <li>")
        t1546html.write("FilterToConsumerBinding</li>\n        <li>")
        t1546html.write(".mof</li>\n        <li>")
        t1546html.write("debug only this process</li>\n        <li>")
        t1546html.write("debug process</li>\n        <li>")
        t1546html.write("CurrentControlSet/Control/Session Manager</li>\n        <li>")
        t1546html.write("CurrentVersion/AppCompatFlags/InstalledSDB</li>\n        <li>")
        t1546html.write("CurrentVersion/Explorer/FileExts</li>\n        <li>")
        t1546html.write(
            "CurrentVersion/Image File Execution Options</li>\n        <li>"
        )
        t1546html.write("CurrentVersion/Windows</li>\n        <li>")
        t1546html.write("Software/Microsoft/Netsh</li>\n        <li>")
        t1546html.write("emond</li>\n        <li>")
        t1546html.write("lc_code_signature</li>\n        <li>")
        t1546html.write("lc_load_dylib</li>\n        <li>")
        t1546html.write("profile\\.d</li>\n        <li>")
        t1546html.write("bash_profile</li>\n        <li>")
        t1546html.write("bashrc</li>\n        <li>")
        t1546html.write("bash_login</li>\n        <li>")
        t1546html.write("bash_logout</li>\n        <li>")
        t1546html.write("trap</li>\n        <li>")
        t1546html.write("zshrc</li>\n        <li>")
        t1546html.write("zshenv</li>\n        <li>")
        t1546html.write("zlogout</li>\n        <li>")
        t1546html.write("zlogin</li>")
        # related techniques
        t1546html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1222 target="_blank"">T1222</a></td>\n        <td>'.format(
                related
            )
        )
        t1546html.write("File and Directory Permissions Modification")
        # mitigations
        t1546html.write("{}-</td>\n        <td>".format(mitigations))
        t1546html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1574.html", "w") as t1574html:
        # description
        t1574html.write(
            "{}Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time.<br>".format(
                header
            )
        )
        t1574html.write(
            "Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.<br>"
        )
        t1574html.write(
            "There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted.<br>"
        )
        t1574html.write(
            "Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads."
        )
        # information
        t1574html.write("{}T1574</td>\n        <td>".format(headings))  # id
        t1574html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1574html.write(
            "Persistence, Privilege Escalation, Defense Evasion</td>\n        <td>"
        )  # tactics
        t1574html.write(
            "T1574.001: DLL Search Order Hijacking<br>T1574.002: DLL Side-Loading<br>T1574.004: Dylib Hijacking<br>T1574.005: Executable Installer File Permissions Weakness<br>T1574.006: LD_PRELOAD<br>T1574.007: Path Interception by PATH Environment Variable<br>T1574.008: Path Interception by Search Order Hijacking<br>T1574.009: Path Interception by Unquoted Path<br>T1574.010: Services File Permissions Weakness<br>T1574.011: Services Registry Permissions Weakness<br>T1574.012: COR_PROFILER"
        )  # sub-techniques
        # indicator regex assignments
        t1574html.write("{}.local</li>\n        <li>".format(iocs))
        t1574html.write(".manifest</li>\n        <li>")
        t1574html.write("net.exe use</li>\n        <li>")
        t1574html.write("net1.exe use</li>\n        <li>")
        t1574html.write("CurrentControlSet/Services/</li>\n        <li>")
        t1574html.write("LC_CODE_SIGNATURE</li>\n        <li>")
        t1574html.write("LC_LOAD_DYLIB</li>")
        # related techniques
        t1574html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1548 target="_blank"">T1548.002</a></td>\n        <td>'.format(
                related
            )
        )
        t1574html.write(
            "Abuse Elevation Control Mechanism: Bypass User Account Control"
        )
        # mitigations
        t1574html.write(
            "{}Application Developer Guidance</td>\n        <td>".format(mitigations)
        )
        t1574html.write(
            "When possible, include hash values in manifest files to help prevent side-loading of malicious libraries.{}".format(
                insert
            )
        )
        t1574html.write("Audit</td>\n        <td>")
        t1574html.write(
            "Use auditing tools capable of detecting hijacking opportunities on systems within an enterprise and correct them. Toolkits like the PowerSploit framework contain PowerUp modules that can be used to explore systems for hijacking weaknesses. Use the program sxstrace.exe that is included with Windows along with manual inspection to check manifest files for side-loading vulnerabilities in software. Find and eliminate path interception weaknesses in program configuration files, scripts, the PATH environment variable, services, and in shortcuts by surrounding PATH variables with quotation marks when functions allow for them. Be aware of the search order Windows uses for executing or loading binaries and use fully qualified paths wherever appropriate. Clean up old Windows Registry keys when software is uninstalled to avoid keys with no associated legitimate binaries. Periodically search for and correct or report path interception weaknesses on systems that may have been introduced using custom or available tools that report software using insecure path configurations.{}".format(
                insert
            )
        )
        t1574html.write("Execution Prevention</td>\n        <td>")
        t1574html.write(
            "Adversaries may use new payloads to execute this technique. Identify and block potentially malicious software executed through hijacking by using application control solutions also capable of blocking libraries loaded by legitimate software.{}".format(
                insert
            )
        )
        t1574html.write("Restrict File and Directory Permissions</td>\n        <td>")
        t1574html.write(
            "Install software in write-protected locations. Set directory access controls to prevent file writes to the search paths for applications, both in the folders where applications are run from and the standard library folders.{}".format(
                insert
            )
        )
        t1574html.write("Restrict Library Loading</td>\n        <td>")
        t1574html.write(
            "Disallow loading of remote DLLs. This is included by default in Windows Server 2012+ and is available by patch for XP+ and Server 2003+. Enable Safe DLL Search Mode to force search for system DLLs in directories with greater restrictions (e.g. %SYSTEMROOT%)to be used before local directory DLLs (e.g. a user's home directory)<br>The Safe DLL Search Mode can be enabled via Group Policy at Computer Configuration > [Policies] > Administrative Templates > MSS (Legacy): MSS: (SafeDllSearchMode) Enable Safe DLL search mode. The associated Windows Registry key for this is located at HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SafeDLLSearchMode{}".format(
                insert
            )
        )
        t1574html.write("Restrict Registry Permissions</td>\n        <td>")
        t1574html.write(
            "Ensure proper permissions are set for Registry hives to prevent users from modifying keys for system components that may lead to privilege escalation.{}".format(
                insert
            )
        )
        t1574html.write("Update Software</td>\n        <td>")
        t1574html.write(
            "Update software regularly to include patches that fix DLL side-loading vulnerabilities.{}".format(
                insert
            )
        )
        t1574html.write("User Account Control</td>\n        <td>")
        t1574html.write(
            'Turn off UAC\'s privilege elevation for standard users [HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System] to automatically deny elevation requests, add: "ConsentPromptBehaviorUser"=dword:00000000. Consider enabling installer detection for all users by adding: "EnableInstallerDetection"=dword:00000001. This will prompt for a password for installation and also log the attempt. To disable installer detection, instead add: "EnableInstallerDetection"=dword:00000000. This may prevent potential elevation of privileges through exploitation during the process of UAC detecting the installer, but will allow the installation process to continue without being logged.{}'.format(
                insert
            )
        )
        t1574html.write("User Account Management</td>\n        <td>")
        t1574html.write(
            "Limit privileges of user accounts and groups so that only authorized administrators can interact with service changes and service binary target path locations. Deny execution from user directories such as file download directories and temp directories where able.<>Ensure that proper permissions and directory access control are set to deny users the ability to write files to the top-level directory C: and system directories, such as C:\\Windows\\, to reduce places where malicious files could be placed for execution.{}".format(
                footer
            )
        )
    with open(sd + "t1525.html", "w") as t1525html:
        # description
        t1525html.write(
            "{}Adversaries may implant cloud container images with malicious code to establish persistence. Amazon Web Service (AWS) Amazon Machine Images (AMI), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be implanted or backdoored.<br>".format(
                header
            )
        )
        t1525html.write(
            "Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image.<br>"
        )
        t1525html.write(
            "A tool has been developed to facilitate planting backdoors in cloud container images. If an attacker has access to a compromised AWS instance, and permissions to list the available container images, they may implant a backdoor such as a Web Shell.<br>"
        )
        t1525html.write(
            "Adversaries may also implant Docker images that may be inadvertently used in cloud deployments, which has been reported in some instances of cryptomining botnets."
        )
        # information
        t1525html.write("{}T1525</td>\n        <td>".format(headings))  # id
        t1525html.write("AWS, Azure, GCP</td>\n        <td>")  # platforms
        t1525html.write("Persistence</td>\n        <td>")  # tactics
        t1525html.write("-")  # sub-techniques
        # indicator regex assignments
        t1525html.write("{}-".format(iocs))
        # related techniques
        t1525html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1505 target="_blank"">T1505</a></td>\n        <td>'.format(
                related
            )
        )
        t1525html.write("Server Software Component: Web Shell")
        # mitigations
        t1525html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1525html.write(
            "Periodically check the integrity of images and containers used in cloud deployments to ensure they have not been modified to include malicious software.{}".format(
                insert
            )
        )
        t1525html.write("Code Signing</td>\n        <td>")
        t1525html.write(
            "Several cloud service providers support content trust models that require container images be signed by trusted sources.{}".format(
                insert
            )
        )
        t1525html.write("Privileged Account Management</td>\n        <td>")
        t1525html.write(
            "Limit permissions associated with creating and modifying platform images or containers based on the principle of least privilege.{}".format(
                footer
            )
        )
    with open(sd + "t1556.html", "w") as t1556html:
        # description
        t1556html.write(
            "{}Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts.<br>".format(
                header
            )
        )
        t1556html.write(
            "The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows or pluggable authentication modules (PAM) on Unix-based systems, responsible for gathering, storing, and validating credentials.<br>"
        )
        t1556html.write(
            "Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms.<br>"
        )
        t1556html.write(
            "Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop."
        )
        # information
        t1556html.write("{}T1556</td>\n        <td>".format(headings))  # id
        t1556html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1556html.write(
            "Defense Evasion, Credential Access</td>\n        <td>"
        )  # tactics
        t1556html.write(
            "T1556.001: Domain Controller Authentication<br>T1556.002: Password Filter DLL<br>T1556.003: Pluggable Authentication Modules<br>T1556.004: Network Device Authenticiation"
        )  # sub-techniques
        # indicator regex assignments
        t1556html.write("{}OpenProcess</li>\n        <li>".format(iocs))
        t1556html.write("lsass</li>\n        <li>")
        t1556html.write("CurrentControlSet/Control/Lsa</li>\n        <li>")
        t1556html.write("pam_unix.so</li>\n        <li>")
        t1556html.write("etc/passwd</li>\n        <li>")
        t1556html.write("etc/shadow</li>")
        # related techniques
        t1556html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1078 target="_blank"">T1078</a></td>\n        <td>'.format(
                related
            )
        )
        t1556html.write("Valid Accounts")
        # mitigations
        t1556html.write(
            "{}Multi-factor Authentication</td>\n        <td>".format(mitigations)
        )
        t1556html.write(
            "Integrating multi-factor authentication (MFA) as part of organizational policy can greatly reduce the risk of an adversary gaining control of valid credentials that may be used for additional tactics such as initial access, lateral movement, and collecting information. MFA can also be used to restrict access to cloud resources and APIs.{}".format(
                insert
            )
        )
        t1556html.write("Operating System Configuration</td>\n        <td>")
        t1556html.write(
            "Ensure only valid password filters are registered. Filter DLLs must be present in Windows installation directory (C:\\Windows\\System32\\ by default) of a domain controller and/or local computer with a corresponding entry in HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages.{}".format(
                insert
            )
        )
        t1556html.write("Privileged Account Management</td>\n        <td>")
        t1556html.write(
            "Audit domain and local accounts as well as their permission levels routinely to look for situations that could allow an adversary to gain wide access by obtaining credentials of a privileged account. These audits should also include if default accounts have been enabled, or if new local accounts are created that have not be authorized. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers. Limit access to the root account and prevent users from modifying protected components through proper privilege separation (ex SELinux, grsecurity, AppArmor, etc.) and limiting Privilege Escalation opportunities.{}".format(
                insert
            )
        )
        t1556html.write("Privileged Process Integrity</td>\n        <td>")
        t1556html.write(
            "Enabled features, such as Protected Process Light (PPL), for LSA.{}".format(
                insert
            )
        )
        t1556html.write("Restrict File and Directory Permissions</td>\n        <td>")
        t1556html.write(
            "Restrict write access to the /Library/Security/SecurityAgentPlugins directory.{}".format(
                footer
            )
        )
    with open(sd + "t1137.html", "w") as t1137html:
        # description
        t1137html.write(
            "{}Adversaries may leverage Microsoft Office-based applications for persistence between startups. Microsoft Office is a fairly common application suite on Windows-based operating systems within an enterprise network.<br>".format(
                header
            )
        )
        t1137html.write(
            "There are multiple mechanisms that can be used with Office for persistence when an Office-based application is started; this can include the use of Office Template Macros and add-ins.<br>"
        )
        t1137html.write(
            "A variety of features have been discovered in Outlook that can be abused to obtain persistence, such as Outlook rules, forms, and Home Page. These persistence mechanisms can work within Outlook or be used through Office 365."
        )
        # information
        t1137html.write("{}T1137</td>\n        <td>".format(headings))  # id
        t1137html.write("Windows, Office 365</td>\n        <td>")  # platforms
        t1137html.write("Persistence</td>\n        <td>")  # tactics
        t1137html.write(
            "T1137.001: Office Template Macros<br>T1137.002: Office Test<br>T1137.003: Outlook Forms<br>T1137.004: Outlook Home Page<br>T1137.005: Outlook Rules<br>T1137.006: Add-ins"
        )  # sub-techniques
        # indicator regex assignments
        t1137html.write("{}.docm</li>\n        <li>".format(iocs))
        t1137html.write(".xlsm</li>\n        <li>")
        t1137html.write("pptm</li>\n        <li>")
        t1137html.write("Normal.dotm</li>\n        <li>")
        t1137html.write("PERSONAL.xlsb</li>")
        # related techniques
        t1137html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1203 target="_blank"">T1203</a></td>\n        <td>'.format(
                related
            )
        )
        t1137html.write("Exploitation for Client Execution")
        t1137html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1204 target="_blank"">T1204</a></td>\n        <td>'.format(
                insert
            )
        )
        t1137html.write("User Execution")
        # mitigations
        t1137html.write(
            "{}Disable or Remove Feature or Program</td>\n        <td>".format(
                mitigations
            )
        )
        t1137html.write(
            "Follow Office macro security best practices suitable for your environment. Disable Office VBA macros from executing. Disable Office add-ins. If they are required, follow best practices for securing them by requiring them to be signed and disabling user notification for allowing add-ins. For some add-ins types (WLL, VBA) additional mitigation is likely required as disabling add-ins in the Office Trust Center does not disable WLL nor does it prevent VBA code from executing.{}".format(
                insert
            )
        )
        t1137html.write("Software Configuration</td>\n        <td>")
        t1137html.write(
            'For the Office Test method, create the Registry key used to execute it and set the permissions to "Read Control" to prevent easy access to the key without administrator permissions or requiring Privilege Escalation.{}'.format(
                insert
            )
        )
        t1137html.write("Update Software</td>\n        <td>")
        t1137html.write(
            "For the Outlook methods, blocking macros may be ineffective as the Visual Basic engine used for these features is separate from the macro scripting engine. Microsoft has released patches to try to address each issue. Ensure KB3191938 which blocks Outlook Visual Basic and displays a malicious code warning, KB4011091 which disables custom forms by default, and KB4011162 which removes the legacy Home Page feature, are applied to systems.{}".format(
                footer
            )
        )
    with open(sd + "t1542.html", "w") as t1542html:
        # description
        t1542html.write(
            "{}Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system.<br>".format(
                header
            )
        )
        t1542html.write(
            "These programs control flow of execution before the operating system takes control.<br>"
        )
        t1542html.write(
            "Adversaries may overwrite data in boot drivers or firmware such as BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) to persist on systems at a layer below the operating system.<br>"
        )
        t1542html.write(
            "This can be particularly difficult to detect as malware at this level will not be detected by host software-based defenses."
        )
        # information
        t1542html.write("{}T1542</td>\n        <td>".format(headings))  # id
        t1542html.write("Windows, Linux</td>\n        <td>")  # platforms
        t1542html.write("Persistence, Defense Evasion</td>\n        <td>")  # tactics
        t1542html.write(
            "T1542.001: System Firmware<br>T1542.002: Component Firmware<br>T1542.003: Bootkit<br>T1542.004: ROMMONkit<br>T1542.005: TFTP Boot"
        )  # sub-techniques
        # indicator regex assignments
        t1542html.write("{}-".format(iocs))
        # related techniques
        t1542html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1200 target="_blank"">T1200</a></td>\n        <td>'.format(
                related
            )
        )
        t1542html.write("Hardware Additions")
        # mitigations
        t1542html.write("{}Boot Integrity</td>\n        <td>".format(mitigations))
        t1542html.write(
            "Use Trusted Platform Module technology and a secure or trusted boot process to prevent system integrity from being compromised. Check the integrity of the existing BIOS or EFI to determine if it is vulnerable to modification.{}".format(
                insert
            )
        )
        t1542html.write("Privileged Account Management</td>\n        <td>")
        t1542html.write(
            "Ensure proper permissions are in place to help prevent adversary access to privileged accounts necessary to perform these actions.{}".format(
                insert
            )
        )
        t1542html.write("Update Software</td>\n        <td>")
        t1542html.write("Patch the BIOS and EFI as necessary.{}".format(footer))
    with open(sd + "t1505.html", "w") as t1505html:
        # description
        t1505html.write(
            "{}Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems.<br>".format(
                header
            )
        )
        t1505html.write(
            "Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application.<br>"
        )
        t1505html.write(
            "Adversaries may install malicious components to extend and abuse server applications."
        )
        # information
        t1505html.write("{}T1505</td>\n        <td>".format(headings))  # id
        t1505html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1505html.write("Persistence</td>\n        <td>")  # tactics
        t1505html.write(
            "T1505.001: SQL Stored Procedures<br>T1505.002: Transport Agent<br>T1505.003: Web Shell"
        )  # sub-techniques
        # indicator regex assignments
        t1505html.write("{}-".format(iocs))
        # related techniques
        t1505html.write("{}-</a></td>\n        <td>".format(related))
        t1505html.write("-")
        # mitigations
        t1505html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1505html.write(
            "Regularly check component software on critical services that adversaries may target for persistence to verify the integrity of the systems and identify if unexpected changes have been made.{}".format(
                insert
            )
        )
        t1505html.write("Code Signing</td>\n        <td>")
        t1505html.write(
            "Ensure all application component binaries are signed by the correct application developers.{}".format(
                insert
            )
        )
        t1505html.write("Privileged Account Management</td>\n        <td>")
        t1505html.write(
            "Do not allow administrator accounts that have permissions to add component software on these services to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.{}".format(
                footer
            )
        )
    with open(sd + "t1205.html", "w") as t1205html:
        # description
        t1205html.write(
            "{}Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control.<br>".format(
                header
            )
        )
        t1205html.write(
            "Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task.<br>"
        )
        t1205html.write(
            "This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control.<br>"
        )
        t1205html.write(
            "Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. Port Knocking), but can involve unusual flags, specific strings, or other unique characteristics.<br>"
        )
        t1205html.write(
            "After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.<br>"
        )
        t1205html.write(
            "Adversaries may also communicate with an already open port, but the service listening on that port will only respond to commands or trigger other malicious functionality if passed the appropriate magic value(s).<br>"
        )
        t1205html.write(
            "The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r, is to use the libpcap libraries to sniff for the packets in question.<br>"
        )
        t1205html.write(
            "Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs."
        )
        # information
        t1205html.write("{}T1205</td>\n        <td>".format(headings))  # id
        t1205html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1205html.write(
            "Persistence, Defense Evasion, Command &amp; Control</td>\n        <td>"
        )  # tactics
        t1205html.write("T1205.001: Port Knocking")  # sub-techniques
        # indicator regex assignments
        t1205html.write("{}-".format(iocs))
        # related techniques
        t1205html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1556 target="_blank"">T1556.004</a></td>\n        <td>'.format(
                related
            )
        )
        t1205html.write("Modify Authentication Process: Network Device Authentication")
        t1205html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1601 target="_blank"">T1601.001</a></td>\n        <td>'.format(
                insert
            )
        )
        t1205html.write("Modify System Image: Patch System Image")
        # mitigations
        t1205html.write(
            "{}Disable or Remove Feature or Program</td>\n        <td>".format(
                mitigations
            )
        )
        t1205html.write(
            "Disable Wake-on-LAN if it is not needed within an environment.{}".format(
                insert
            )
        )
        t1205html.write("Filter Network Traffic</td>\n        <td>")
        t1205html.write(
            "Mitigation of some variants of this technique could be achieved through the use of stateful firewalls, depending upon how it is implemented.{}".format(
                footer
            )
        )
