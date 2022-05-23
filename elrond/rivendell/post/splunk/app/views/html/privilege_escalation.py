#!/usr/bin/env python3 -tt


def create_privilege_escalation_html(sd, header, headings, iocs, related, insert, mitigations, footer):
    with open(sd + "t1548.html", "w") as t1548html:
        # description
        t1548html.write(
            "{}Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine.<br>".format(
                header
            )
        )
        t1548html.write(
            "Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system."
        )
        # information
        t1548html.write("{}T1574</td>\n        <td>".format(headings))  # id
        t1548html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1548html.write(
            "Privilege Escalation, Defense Evasion</td>\n        <td>"
        )  # tactics
        t1548html.write(
            "T1574.001: Setuid and Setgid<br>T1574.002: Bypass User Access Control<br>T1574.003: Sudo and Sudo Caching<br>T1574.004: Elevated Execution with Prompt"
        )  # sub-techniques
        # indicator regex assignments
        t1548html.write("{}eventvwr.exe</li>\n        <li>".format(iocs))
        t1548html.write("sdclt.exe</li>\n        <li>")
        t1548html.write("CurrentVersion/App Paths</li>\n        <li>")
        t1548html.write(
            "Software/Classes/ms-settings/shell/open/command</li>\n        <li>"
        )
        t1548html.write("CurrentVersion/App Paths</li>\n        <li>")
        t1548html.write(
            "Software/Classes/mscfile/shell/open/command</li>\n        <li>"
        )
        t1548html.write(
            "Software/Classes/exefile/shell/runas/command/isolatedcommand</li>\n        <li>"
        )
        t1548html.write("AuthorizationExecuteWithPrivileges</li>\n        <li>")
        t1548html.write("security_authtrampoline</li>\n        <li>")
        t1548html.write("chmod</li>\n        <li>")
        t1548html.write("kill</li>\n        <li>")
        t1548html.write("sudo</li>\n        <li>")
        t1548html.write("timestamp_timeout</li>\n        <li>")
        t1548html.write("tty_tickets</li>")
        # related techniques
        t1548html.write("{}-</a></td>\n        <td>".format(related))
        t1548html.write("-")
        # mitigations
        t1548html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1548html.write(
            "Check for common UAC bypass weaknesses on Windows systems to be aware of the risk posture and address issues where appropriate.{}".format(
                insert
            )
        )
        t1548html.write("Execution Prevention</td>\n        <td>")
        t1548html.write(
            "System settings can prevent applications from running that haven't been downloaded from legitimate repositories which may help mitigate some of these issues. Not allowing unsigned applications from being run may also mitigate some risk.{}".format(
                insert
            )
        )
        t1548html.write("Operating System Configuration</td>\n        <td>")
        t1548html.write(
            "Applications with known vulnerabilities or known shell escapes should not have the setuid or setgid bits set to reduce potential damage if an application is compromised. Additionally, the number of programs with setuid or setgid bits set should be minimized across a system. Ensuring that the sudo tty_tickets setting is enabled will prevent this leakage across tty sessions.{}".format(
                insert
            )
        )
        t1548html.write("Privileged Account Management</td>\n        <td>")
        t1548html.write(
            "Remove users from the local administrator group on systems. By requiring a password, even if an adversary can get terminal access, they must know the password to run anything in the sudoers file. Setting the timestamp_timeout to 0 will require the user to input their password every time sudo is executed.{}".format(
                insert
            )
        )
        t1548html.write("Restrict File and Directory Permissions</td>\n        <td>")
        t1548html.write(
            "The sudoers file should be strictly edited such that passwords are always required and that users can't spawn risky processes as users with higher privilege.{}".format(
                insert
            )
        )
        t1548html.write("User Account Control</td>\n        <td>")
        t1548html.write(
            "Although UAC bypass techniques exist, it is still prudent to use the highest enforcement level for UAC when possible and mitigate bypass opportunities that exist with techniques such as DLL Search Order Hijacking.{}".format(
                footer
            )
        )
    with open(sd + "t1134.html", "w") as t1134html:
        # description
        t1134html.write(
            "{}Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process.<br>".format(
                header
            )
        )
        t1134html.write(
            "A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.<br>"
        )
        t1134html.write(
            "An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. These token can then be applied to an existing process (i.e. Token Impersonation/Theft) or used to spawn a new process (i.e. Create Process with Token).<br>"
        )
        t1134html.write(
            "An adversary must already be in a privileged user context (i.e. administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to the SYSTEM level. An adversary can then use a token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system.<br>"
        )
        t1134html.write(
            "Any standard user can use the runas command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account. There are also other mechanisms, such as Active Directory fields, that can be used to modify access tokens."
        )
        # information
        t1134html.write("{}T1134</td>\n        <td>".format(headings))  # id
        t1134html.write("Windows</td>\n        <td>")  # platforms
        t1134html.write(
            "Privilege Escalation, Defense Evasion</td>\n        <td>"
        )  # tactics
        t1134html.write(
            "T1134.001: Token Impersonation/Theft<br>T1134.002: Create Process with Token<br>T1134.003: Make and Impersonate Token<br>T1134.004: Parent PID Spoofing<br>T1134.005: SID-History Injection"
        )  # sub-techniques
        # indicator regex assignments
        t1134html.write("{}Get-ADUser</li>\n        <li>".format(iocs))
        t1134html.write("DsAddSidHistory</li>\n        <li>")
        t1134html.write("CreateProcess</li>\n        <li>")
        t1134html.write("DuplicateToken</li>\n        <li>")
        t1134html.write("ImpersonateLoggedOnUser</li>\n        <li>")
        t1134html.write("runas</li>\n        <li>")
        t1134html.write("SetThreadToken</li>\n        <li>")
        t1134html.write("ImpersonateNamedPipeClient</li>\n        <li>")
        t1134html.write("UpdateProcThreadAttribute</li>\n        <li>")
        t1134html.write("LogonUser</li>")
        # related techniques
        t1134html.write("{}--</a></td>\n        <td>".format(related))
        t1134html.write("-")
        # mitigations
        t1134html.write(
            "{}Privileged Account Management</td>\n        <td>".format(mitigations)
        )
        t1134html.write(
            "Limit permissions so that users and user groups cannot create tokens. This setting should be defined for the local system account only. GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Create a token object. Also define who can create a process level token to only the local and network service through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Replace a process level token. Administrators should log in as a standard user but run their tools with administrator privileges using the built-in access token manipulation command runas.{}".format(
                insert
            )
        )
        t1134html.write("User Account Management</td>\n        <td>")
        t1134html.write(
            "An adversary must already have administrator level access on the local system to make full use of this technique; be sure to restrict users and accounts to the least privileges they require.{}".format(
                footer
            )
        )
    with open(sd + "t1484.html", "w") as t1484html:
        # description
        t1484html.write(
            "{}Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary access controls for a domain, usually with the intention of escalating privileges on the domain. Group policy allows for centralized management of user and computer settings in Active Directory (AD).<br>".format(
                header
            )
        )
        t1484html.write(
            "GPOs are containers for group policy settings made up of files stored within a predicable network path \\<DOMAIN>\\SYSVOL\\<DOMAIN>\\Policies\\.<br>"
        )
        t1484html.write(
            "Like other objects in AD, GPOs have access controls associated with them. By default all user accounts in the domain have permission to read GPOs. It is possible to delegate GPO access control permissions, e.g. write access, to specific users or groups in the domain.<br>"
        )
        t1484html.write(
            "Malicious GPO modifications can be used to implement many other malicious behaviors such as Scheduled Task/Job, Disable or Modify Tools, Ingress Tool Transfer, Create Account, Service Execution, and more.<br>"
        )
        t1484html.write(
            "Since GPOs can control so many user and machine settings in the AD environment, there are a great number of potential attacks that can stem from this GPO abuse.<br>"
        )
        t1484html.write(
            "For example, publicly available scripts such as New-GPOImmediateTask can be leveraged to automate the creation of a malicious Scheduled Task/Job by modifying GPO settings, in this case modifying <GPO_PATH>\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml.<br>"
        )
        t1484html.write(
            "In some cases an adversary might modify specific user rights like SeEnableDelegationPrivilege, set in <GPO_PATH>\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf, to achieve a subtle AD backdoor with complete control of the domain because the user account under the adversary's control would then be able to modify GPOs."
        )
        # information
        t1484html.write("{}T1484</td>\n        <td>".format(headings))  # id
        t1484html.write("Windows</td>\n        <td>")  # platforms
        t1484html.write(
            "Privilege Escalation, Defense Evasion</td>\n        <td>"
        )  # tactics
        t1484html.write(
            "T1484.001: Group Policy Modification<br>T1484.002: Domain Trust Modification"
        )  # sub-techniques
        # indicator regex assignments
        t1484html.write(
            "{}Event IDs: 307, 510, 4672, 4704, 5136, 5137, 5138, 5139, 5141</li>\n        <li>".format(
                iocs
            )
        )
        t1484html.write("GptTmpl.inf</li>\n        <li>")
        t1484html.write("ScheduledTasks.xml</li>\n        <li>")
        t1484html.write("New-GPOImmediateTask</li>")
        # related techniques
        t1484html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1053 target="_blank"">T1053</a></td>\n        <td>'.format(
                related
            )
        )
        t1484html.write("Scheduled Task/Job")
        t1484html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1562 target="_blank"">T1562.001</a></td>\n        <td>'.format(
                insert
            )
        )
        t1484html.write("Impair Defenses: Disable or Modify Tools")
        t1484html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1105 target="_blank"">T1105</a></td>\n        <td>'.format(
                insert
            )
        )
        t1484html.write("Ingress Tool Transfer")
        t1484html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1136 target="_blank"">T1136</a></td>\n        <td>'.format(
                insert
            )
        )
        t1484html.write("Create Account")
        t1484html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1569 target="_blank"">T1569</a></td>\n        <td>'.format(
                insert
            )
        )
        t1484html.write("System Services: Service Execution")
        t1484html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1207 target="_blank"">T1207</a></td>\n        <td>'.format(
                insert
            )
        )
        t1484html.write("Rogue Domain Controller")
        # mitigations
        t1484html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1484html.write(
            "Identify and correct GPO permissions abuse opportunities (ex: GPO modification privileges) using auditing tools such as BloodHound (version 1.5.1 and later){}".format(
                insert
            )
        )
        t1484html.write("Privileged Account Management</td>\n        <td>")
        t1484html.write(
            "Use least privilege and protect administrative access to the Domain Controller and Active Directory Federation Services (AD FS) server. Do not create service accounts with administrative privileges.{}".format(
                insert
            )
        )
        t1484html.write("User Account Management</td>\n        <td>")
        t1484html.write(
            "Consider implementing WMI and security filtering to further tailor which users and computers a GPO will apply to.{}".format(
                footer
            )
        )
    with open(sd + "t1611.html", "w") as t1611html:
        # description
        t1611html.write(
            "{}Adversaries may break out of a container to gain access to the underlying host. This can allow an adversary access to other containerized resources from the host level or to the host itself. In principle, containerized resources should provide a clear separation of application functionality and be isolated from the host environment.<br>".format(
                header
            )
        )
        t1611html.write(
            "There are multiple ways an adversary may escape to a host environment. Examples include creating a container configured to mount the host’s filesystem using the bind parameter, which allows the adversary to drop payloads and execute control utilities such as cron on the host, and utilizing a privileged container to run commands on the underlying host. Gaining access to the host may provide the adversary with the opportunity to achieve follow-on objectives, such as establishing persistence, moving laterally within the environment, or setting up a command and control channel on the host."
        )
        # information
        t1611html.write("{}T1611</td>\n        <td>".format(headings))  # id
        t1611html.write("Windows, Linux, Containers</td>\n        <td>")  # platforms
        t1611html.write("Privilege Escalation</td>\n        <td>")  # tactics
        t1611html.write("-")  # sub-techniques
        # indicator regex assignments
        t1611html.write("{}-".format(iocs))
        # related techniques
        t1611html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1612 target="_blank"">T1612</a></td>\n        <td>'.format(
                related
            )
        )
        t1611html.write("Build Image on Host")
        # mitigations
        t1611html.write(
            "{}Application Isolation and Sandboxing</td>\n        <td>".format(
                mitigations
            )
        )
        t1611html.write(
            "Ensure all COM alerts and Protected View are enabled.{}".format(insert)
        )
        t1611html.write("Behavior Prevention on Endpoint</td>\n        <td>")
        t1611html.write(
            "Consider utilizing seccomp, seccomp-bpf, or a similar solution that restricts certain system calls such as mount.{}".format(
                insert
            )
        )
        t1611html.write("Execution Prevention</td>\n        <td>")
        t1611html.write(
            "Use read-only containers and minimal images when possible to prevent the running of commands.{}".format(
                insert
            )
        )
        t1611html.write("Privileged Account Management</td>\n        <td>")
        t1611html.write("Ensure containers are not running as root by default.")
    with open(sd + "t1068.html", "w") as t1068html:
        # description
        t1068html.write(
            "{}Adversaries may exploit software vulnerabilities in an attempt to collect elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.<br>".format(
                header
            )
        )
        t1068html.write(
            "Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions.<br>"
        )
        t1068html.write(
            "When initially gaining access to a system, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system.<br>"
        )
        t1068html.write(
            "Vulnerabilities may exist, usually in operating system components and software commonly running at higher permissions, that can be exploited to gain higher levels of access on the system. This could enable someone to move from unprivileged or user level permissions to SYSTEM or root permissions depending on the component that is vulnerable.<br>"
        )
        t1068html.write(
            "This may be a necessary step for an adversary compromising a endpoint system that has been properly configured and limits other privilege escalation methods."
        )
        # information
        t1068html.write("{}T1068</td>\n        <td>".format(headings))  # id
        t1068html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1068html.write("Privilege Escalation</td>\n        <td>")  # tactics
        t1068html.write("-")  # sub-techniques
        # indicator regex assignments
        t1068html.write("{}-".format(iocs))
        # related techniques
        t1068html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1105 target="_blank"">T1105</a></td>\n        <td>'.format(
                related
            )
        )
        t1068html.write("Ingress Tool Transfer")
        t1068html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1570 target="_blank"">T1570</a></td>\n        <td>'.format(
                insert
            )
        )
        t1068html.write("Lateral Tool Transfer")
        # mitigations
        t1068html.write(
            "{}Application Isolation and Sandboxing</td>\n        <td>".format(
                mitigations
            )
        )
        t1068html.write(
            "Make it difficult for adversaries to advance their operation through exploitation of undiscovered or unpatched vulnerabilities by using sandboxing. Other types of virtualization and application microsegmentation may also mitigate the impact of some types of exploitation. Risks of additional exploits and weaknesses in these systems may still exist.{}".format(
                insert
            )
        )
        t1068html.write("Execution Prevention</td>\n        <td>")
        t1068html.write(
            "Consider blocking the execution of known vulnerable drivers that adversaries may exploit to execute code in kernel mode. Validate driver block rules in audit mode to ensure stability prior to production deployment.{}".format(
                insert
            )
        )
        t1068html.write("Exploit Protection</td>\n        <td>")
        t1068html.write(
            "Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility and may not work for software components targeted for privilege escalation.{}".format(
                insert
            )
        )
        t1068html.write("Threat Intelligence Program</td>\n        <td>")
        t1068html.write(
            "Develop a robust cyber threat intelligence capability to determine what types and levels of threat may use software exploits and 0-days against a particular organization.{}".format(
                insert
            )
        )
        t1068html.write("Update Software</td>\n        <td>")
        t1068html.write(
            "Update software regularly by employing patch management for internal enterprise endpoints and servers.{}".format(
                footer
            )
        )
    with open(sd + "t1055.html", "w") as t1055html:
        # description
        t1055html.write(
            "{}Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process.<br>".format(
                header
            )
        )
        t1055html.write(
            "Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.<br>"
        )
        t1055html.write(
            "There are many different ways to inject code into a process, many of which abuse legitimate functionalities. These implementations exist for every major OS but are typically platform specific.<br>"
        )
        t1055html.write(
            "More sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel."
        )
        # information
        t1055html.write("{}T1055</td>\n        <td>".format(headings))  # id
        t1055html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1055html.write(
            "Privilege Escalation, Defense Evasion</td>\n        <td>"
        )  # tactics
        t1055html.write(
            "T1574.001: Dynamic-link Library Injection<br>T1574.002: Portable Execution Injection<br>T1574.003: Thread Execution Hijacking<br>T1574.004: Asynchronous Procedure Call<br>T1574.005: Thread Local Storage<br>T1574.008: Ptrace System Calls<br>T1574.009: Proc Memory<br>T1574.011: Extra Windows Memory Injection<br>T1574.012: Process Hollowing<br>T1574.013: Process Doppelganging<br>T1574.014: VDSO Hijacking"
        )  # sub-techniques
        # indicator regex assignments
        t1055html.write("{}Event IDs: 17, 18</li>\n        <li>".format(iocs))
        t1055html.write("CreateFileTransacted</li>\n        <li>")
        t1055html.write("CreateTransaction</li>\n        <li>")
        t1055html.write("NtCreateThreadEx</li>\n        <li>")
        t1055html.write("NtUnmapViewOfSection</li>\n        <li>")
        t1055html.write("RollbackTransaction</li>\n        <li>")
        t1055html.write("VirtualProtectEx</li>\n        <li>")
        t1055html.write("CreateRemoteThread</li>\n        <li>")
        t1055html.write("GetWindowLong</li>\n        <li>")
        t1055html.write("SetWindowLong</li>\n        <li>")
        t1055html.write("LoadLibrary</li>\n        <li>")
        t1055html.write("NtUnmapViewOfSection</li>\n        <li>")
        t1055html.write("NtQueueApcThread</li>\n        <li>")
        t1055html.write("QueueUserApc</li>\n        <li>")
        t1055html.write("ResumeThread</li>\n        <li>")
        t1055html.write("SetThreadContext</li>\n        <li>")
        t1055html.write("SuspendThread</li>\n        <li>")
        t1055html.write("VirtualAlloc</li>\n        <li>")
        t1055html.write("ZwUnmapViewOfSection</li>\n        <li>")
        t1055html.write("malloc</li>\n        <li>")
        t1055html.write("ptrace_setregs</li>\n        <li>")
        t1055html.write("ptrace_poketext</li>\n        <li>")
        t1055html.write("ptrace_pokedata</li>")
        # related techniques
        t1055html.write("{}-</a></td>\n        <td>".format(related))
        t1055html.write("-")
        # mitigations
        t1055html.write(
            "{}Behavior Prevention on Endpoint</td>\n        <td>".format(mitigations)
        )
        t1055html.write(
            "Some endpoint security solutions can be configured to block some types of process injection based on common sequences of behavior that occur during the injection process.{}".format(
                insert
            )
        )
        t1055html.write("Privileged Account Management</td>\n        <td>")
        t1055html.write(
            "Utilize Yama (ex: /proc/sys/kernel/yama/ptrace_scope) to mitigate ptrace based process injection by restricting the use of ptrace to privileged users only. Other mitigation controls involve the deployment of security kernel modules that provide advanced access control and process restrictions such as SELinux, grsecurity, and AppArmor.{}".format(
                footer
            )
        )
