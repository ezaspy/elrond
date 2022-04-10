#!/usr/bin/env python3 -tt


def create_defence_evasion_html(
    sd, header, headings, iocs, related, insert, mitigations, footer
):
    with open(sd + "t1612.html", "w") as t1612html:
        # description
        t1612html.write(
            "{}Adversaries may build a container image directly on a host to bypass defenses that monitor for the retrieval of malicious images from a public registry. A remote build request may be sent to the Docker API that includes a Dockerfile that pulls a vanilla base image, such as alpine, from a public or local registry and then builds a custom image upon it.<br>".format(
                header
            )
        )
        t1612html.write(
            "An adversary may take advantage of that build API to build a custom image on the host that includes malware downloaded from their C2 server, and then they then may utilize Deploy Container using that custom image. If the base image is pulled from a public registry, defenses will likely not detect the image as malicious since it’s a vanilla image. If the base image already resides in a local registry, the pull may be considered even less suspicious since the image is already in the environment."
        )
        # information
        t1612html.write("{}T1610</td>\n        <td>".format(headings))  # id
        t1612html.write("Containers</td>\n        <td>")  # platforms
        t1612html.write("Execution</td>\n        <td>")  # tactics
        t1612html.write("-")  # sub-techniques
        # indicator regex assignments
        t1612html.write("{}Ports: 2375, 2376</li>\n        <li>".format(iocs))
        t1612html.write("docker build</li>")
        # related techniques
        t1612html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1610 target="_blank"">T1610</a></td>\n        <td>'.format(
                related
            )
        )
        t1612html.write("Deploy Container")
        t1612html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1609 target="_blank"">T1609</a></td>\n        <td>'.format(
                insert
            )
        )
        t1612html.write("Container Administration Command")
        # mitigations
        t1612html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1612html.write(
            "Audit images deployed within the environment to ensure they do not contain any malicious components.{}".format(
                insert
            )
        )
        t1612html.write("Limit Access to Resource Over Network</td>\n        <td>")
        t1612html.write(
            "Limit communications with the container service to local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API on port 2375. Instead, communicate with the Docker API over TLS on port 2376.{}".format(
                insert
            )
        )
        t1612html.write("Network Segmentation</td>\n        <td>")
        t1612html.write(
            "Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.{}".format(
                insert
            )
        )
        t1612html.write("Privileged Account Management</td>\n        <td>")
        t1612html.write(
            "Ensure containers are not running as root by default.{}".format(footer)
        )
    with open(sd + "t1140.html", "w") as t1140html:
        # description
        t1140html.write(
            "{}Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it.<br>".format(
                header
            )
        )
        t1140html.write(
            "Methods for doing that include built-in functionality of malware or by using utilities present on the system.<br>"
        )
        t1140html.write(
            "One such example is use of certutil to decode a remote access tool portable executable file that has been hidden inside a certificate file. Another example is using the Windows copy /b command to reassemble binary fragments into a malicious payload.<br>"
        )
        t1140html.write(
            "Sometimes a user's action may be required to open it for deobfuscation or decryption as part of User Execution. The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary."
        )
        # information
        t1140html.write("{}T1140</td>\n        <td>".format(headings))  # id
        t1140html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1140html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1140html.write("-")  # sub-techniques
        # indicator regex assignments
        t1140html.write("{}certutil</li>\n        <li>".format(iocs))
        t1140html.write("-decode</li>\n        <li>")
        t1140html.write("openssl</li>")
        # related techniques
        t1140html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1027 target="_blank"">T1027</a></td>\n        <td>'.format(
                related
            )
        )
        t1140html.write("Obfuscated Files or Information")
        t1140html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1204 target="_blank"">T1204</a></td>\n        <td>'.format(
                insert
            )
        )
        t1140html.write("User Execution")
        # mitigations
        t1140html.write("{}-</td>\n        <td>".format(mitigations))
        t1140html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1006.html", "w") as t1006html:
        # description
        t1006html.write(
            "{}Adversaries may directly access a volume to bypass file access controls and file system monitoring.<br>".format(
                header
            )
        )
        t1006html.write(
            "Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures.<br>"
        )
        t1006html.write(
            "This technique bypasses Windows file access controls as well as file system monitoring tools.<br>"
        )
        t1006html.write(
            "Utilities, such as NinjaCopy, exist to perform these actions in PowerShell."
        )
        # information
        t1006html.write("{}T1006</td>\n        <td>".format(headings))  # id
        t1006html.write("Windows</td>\n        <td>")  # platforms
        t1006html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1006html.write("-")  # sub-techniques
        # indicator regex assignments
        t1006html.write("{}-".format(iocs))
        # related techniques
        t1006html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1059 target="_blank"">T1059.001</a></td>\n        <td>'.format(
                related
            )
        )
        t1006html.write("Command and Scripting Interpreter: PowerShell")
        # mitigations
        t1006html.write("{}-</td>\n        <td>".format(mitigations))
        t1006html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1480.html", "w") as t1480html:
        # description
        t1480html.write(
            "{}Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target.<br>".format(
                header
            )
        )
        t1480html.write(
            "Guardrails ensure that a payload only executes against an intended target and reduces collateral damage from an adversary’s campaign.<br>"
        )
        t1480html.write(
            "Values an adversary can provide about a target system or environment to use as guardrails may include specific network share names, attached physical devices, files, joined Active Directory (AD) domains, and local/external IP addresses.<br>"
        )
        t1480html.write(
            "Guardrails can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. This use of guardrails is distinct from typical Virtualization/Sandbox Evasion.<br>"
        )
        t1480html.write(
            "While use of Virtualization/Sandbox Evasion may involve checking for known sandbox values and continuing with execution only if there is no match, the use of guardrails will involve checking for an expected target-specific value and only continuing with execution if there is such a match."
        )
        # information
        t1480html.write("{}T1480</td>\n        <td>".format(headings))  # id
        t1480html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1480html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1480html.write("T1480.001: Environmental Keying")  # sub-techniques
        # indicator regex assignments
        t1480html.write("{}-".format(iocs))
        # related techniques
        t1480html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1487 target="_blank"">T1487</a></td>\n        <td>'.format(
                related
            )
        )
        t1480html.write("Virtualization/Sandbox Evasion")
        # mitigations
        t1480html.write("{}Do Not Mitigate</td>\n        <td>".format(mitigations))
        t1480html.write(
            "Execution Guardrails likely should not be mitigated with preventative controls because it may protect unintended targets from being compromised. If targeted, efforts should be focused on preventing adversary tools from running earlier in the chain of activity and on identifying subsequent malicious behavior if compromised.{}".format(
                footer
            )
        )
    with open(sd + "t1211.html", "w") as t1211html:
        # description
        t1211html.write(
            "{}Adversaries may exploit software vulnerabilities in an attempt to collect credentials.<br>".format(
                header
            )
        )
        t1211html.write(
            "Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.<br>"
        )
        t1211html.write(
            "Credentialing and authentication mechanisms may be targeted for exploitation by adversaries as a means to gain access to useful credentials or circumvent the process to gain access to systems.<br>"
        )
        t1211html.write(
            "One example of this is MS14-068, which targets Kerberos and can be used to forge Kerberos tickets using domain user permissions.<br>"
        )
        t1211html.write(
            "Exploitation for credential access may also result in Privilege Escalation depending on the process targeted or credentials obtained."
        )
        # information
        t1211html.write("{}T1212</td>\n        <td>".format(headings))  # id
        t1211html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1211html.write("Credential Access</td>\n        <td>")  # tactics
        t1211html.write("-")  # sub-techniques
        # indicator regex assignments
        t1211html.write("{}-".format(iocs))
        # related techniques
        t1211html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1518 target="_blank"">T1518</a></td>\n        <td>'.format(
                related
            )
        )
        t1211html.write("Security Software Discovery")
        # mitigations
        t1211html.write(
            "{}Application Isolation and Sandboxing</td>\n        <td>".format(
                mitigations
            )
        )
        t1211html.write(
            "Make it difficult for adversaries to advance their operation through exploitation of undiscovered or unpatched vulnerabilities by using sandboxing. Other types of virtualization and application microsegmentation may also mitigate the impact of some types of exploitation. Risks of additional exploits and weaknesses in these systems may still exist.{}".format(
                insert
            )
        )
        t1211html.write("Exploit Protection</td>\n        <td>")
        t1211html.write(
            "Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility and may not work for software targeted for defense evasion.{}".format(
                insert
            )
        )
        t1211html.write("Threat Intelligence Program</td>\n        <td>")
        t1211html.write(
            "Develop a robust cyber threat intelligence capability to determine what types and levels of threat may use software exploits and 0-days against a particular organization.{}".format(
                insert
            )
        )
        t1211html.write("Update Software</td>\n        <td>")
        t1211html.write(
            "Update software regularly by employing patch management for internal enterprise endpoints and servers.{}".format(
                footer
            )
        )
    with open(sd + "t1222.html", "w") as t1222html:
        # description
        t1222html.write(
            "{}Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions.<br>".format(
                header
            )
        )
        t1222html.write(
            "File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).<br>"
        )
        t1222html.write(
            "Modifications may include changing specific access rights, which may require taking ownership of a file or directory and/or elevated permissions depending on the file or directory’s existing permissions. This may enable malicious activity such as modifying, replacing, or deleting specific files or directories.<br>"
        )
        t1222html.write(
            "Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via Accessibility Features, Boot or Logon Initialization Scripts, .bash_profile and .bashrc, or tainting/hijacking other instrumental binary/configuration files via Hijack Execution Flow."
        )
        # information
        t1222html.write("{}T1222</td>\n        <td>".format(headings))  # id
        t1222html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1222html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1222html.write(
            "T1222.001: Windows File and Directory Permissions Modification<br>T1222.002: Linux and Mac File and Directory Permissions Modification"
        )  # sub-techniques
        # indicator regex assignments
        t1222html.write("{}Event IDs: 4670</li>\n        <li>".format(iocs))
        t1222html.write("icacls</li>\n        <li>")
        t1222html.write("cacls</li>\n        <li>")
        t1222html.write("takeown</li>\n        <li>")
        t1222html.write("attrib</li>\n        <li>")
        t1222html.write("chmod</li>\n        <li>")
        t1222html.write("chown</li>\n        <li>")
        t1222html.write("chgrp</li>")
        # related
        t1222html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1546 target="_blank"">T1546.008</a></td>\n        <td>'.format(
                insert
            )
        )
        t1222html.write("Event Triggered Execution: Accessibility Features")
        t1222html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1037 target="_blank"">T1037</a></td>\n        <td>'.format(
                insert
            )
        )
        t1222html.write("Boot or Logon Initialization Scripts")
        t1222html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1546 target="_blank"">T1546.004</a></td>\n        <td>'.format(
                insert
            )
        )
        t1222html.write(
            "Event Triggered Execution: Unix Shell Configuration Modification"
        )
        t1222html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1574 target="_blank"">T1574</a></td>\n        <td>'.format(
                insert
            )
        )
        t1222html.write("Hijack Execution Flow")
        # mitigations
        t1222html.write(
            "{}Privileged Account Management</td>\n        <td>".format(mitigations)
        )
        t1222html.write(
            "Ensure critical system files as well as those known to be abused by adversaries have restrictive permissions and are owned by an appropriately privileged account, especially if access is not required by users nor will inhibit system functionality.{}".format(
                insert
            )
        )
        t1222html.write("Restrict File and Directory Permissions</td>\n        <td>")
        t1222html.write(
            "Applying more restrictive permissions to files and directories could prevent adversaries from modifying the access control lists.{}".format(
                footer
            )
        )
    with open(sd + "t1564.html", "w") as t1564html:
        # description
        t1564html.write(
            "{}Adversaries may attempt to hide artifacts associated with their behaviors to evade detection. Operating systems may have features to hide various artifacts, such as important system files and administrative task execution, to avoid disrupting user work environments and prevent users from changing files or features on the system.<br>".format(
                header
            )
        )
        t1564html.write(
            "Adversaries may abuse these features to hide artifacts such as files, directories, user accounts, or other system activity to evade detection.<br>"
        )
        t1564html.write(
            "Adversaries may also attempt to hide artifacts associated with malicious behavior by creating computing regions that are isolated from common security instrumentation, such as through the use of virtualization technology."
        )
        # information
        t1564html.write("{}T1564</td>\n        <td>".format(headings))  # id
        t1564html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1564html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1564html.write(
            "T1564.001: Hidden Files and Directories<br>T1564.002: Hidden Users<br>T1564.003: Hidden Window<br>T1564.004: NTFS File Attributes<br>T1564.005: Hidden File System<br>T1564.006: Run Virtual Instance<br>T1564.007: VBA Stomping"
        )  # sub-techniques
        # indicator regex assignments
        t1564html.write("{}-create</li>\n        <li>".format(iocs))
        t1564html.write("attrib</li>\n        <li>")
        t1564html.write("dscl</li>\n        <li>")
        t1564html.write("windowstyle</li>\n        <li>")
        t1564html.write("hidden</li>\n        <li>")
        t1564html.write("vboxmanage</li>\n        <li>")
        t1564html.write("virtualbox</li>\n        <li>")
        t1564html.write("vmplayer</li>\n        <li>")
        t1564html.write("vmprocess</li>\n        <li>")
        t1564html.write("vmware</li>\n        <li>")
        t1564html.write("hyper-v</li>\n        <li>")
        t1564html.write("qemu</li>\n        <li>")
        t1564html.write("performancecache</li>\n        <li>")
        t1564html.write("_vba_project</li>\n        <li>")
        t1564html.write("zwqueryeafile</li>\n        <li>")
        t1564html.write("zwseteafile</li>\n        <li>")
        t1564html.write("stream</li>\n        <li>")
        t1564html.write(":ads</li>\n        <li>")
        t1564html.write("LoginWindow</li>\n        <li>")
        t1564html.write("Hide500Users</li>\n        <li>")
        t1564html.write("UniqueID</li>\n        <li>")
        t1564html.write("UIElement</li>")
        # related techniques
        t1564html.write("{}-</a></td>\n        <td>".format(related))
        t1564html.write("-")
        # mitigations
        t1564html.write("{}-</td>\n        <td>".format(mitigations))
        t1564html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1562.html", "w") as t1562html:
        # description
        t1562html.write(
            "{}Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior.<br>".format(
                header
            )
        )
        t1562html.write(
            "This may also span both native defenses as well as supplemental capabilities installed by users and administrators.<br>"
        )
        t1562html.write(
            "Adversaries could also target event aggregation and analysis mechanisms, or otherwise disrupt these procedures by altering other system components."
        )
        # information
        t1562html.write("{}T1562</td>\n        <td>".format(headings))  # id
        t1562html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>"
        )  # platforms
        t1562html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1562html.write(
            "T1562.001: Disable or Modify Tools<br>T1562.002: Disable Windows Event Logging<br>T1562.003: HISTCONTROL<br>T1562.004: Disable or Modify System Firewall<br>T1562.006: Indicator Blocking<br>T1562.007: Disable or Modify Cloud Firewall<br>T1562.008: Disable Cloud Logs"
        )  # sub-techniques
        # indicator regex assignments
        t1562html.write("{}AUDITPOL</li>\n        <li>".format(iocs))
        t1562html.write("history</li>\n        <li>")
        t1562html.write("ConsoleHost</li>\n        <li>")
        t1562html.write("Clear-History</li>\n        <li>")
        t1562html.write("HistorySaveStyle</li>\n        <li>")
        t1562html.write("SaveNothing</li>\n        <li>")
        t1562html.write("PSReadLine</li>\n        <li>")
        t1562html.write("Set-PSReadLinePption</li>\n        <li>")
        t1562html.write("Set-EtwTraceProvider</li>\n        <li>")
        t1562html.write("ZwOpenProcess</li>\n        <li>")
        t1562html.write("GetExtendedTcpTable</li>\n        <li>")
        t1562html.write("HISTCONTROL</li>\n        <li>")
        t1562html.write("HISTFILE</li>\n        <li>")
        t1562html.write("kill</li>")
        # related techniques
        t1562html.write("{}-</a></td>\n        <td>".format(related))
        t1562html.write("-")
        # mitigations
        t1562html.write(
            "{}Restrict File and Directory Permissions</td>\n        <td>".format(
                mitigations
            )
        )
        t1562html.write(
            "Ensure proper process and file permissions are in place to prevent adversaries from disabling or interfering with security/logging services.{}".format(
                insert
            )
        )
        t1562html.write("Restrict Registry Permissions</td>\n        <td>")
        t1562html.write(
            "Ensure proper Registry permissions are in place to prevent adversaries from disabling or interfering with security/logging services.{}".format(
                insert
            )
        )
        t1562html.write("User Account Management</td>\n        <td>")
        t1562html.write(
            "Ensure proper user permissions are in place to prevent adversaries from disabling or interfering with security/logging services.{}".format(
                footer
            )
        )
    with open(sd + "t1070.html", "w") as t1070html:
        # description
        t1070html.write(
            "{}Adversaries may delete or alter generated artifacts on a host system, including logs or captured files such as quarantined malware.<br>".format(
                header
            )
        )
        t1070html.write(
            "Locations and format of logs are platform or product-specific, however standard operating system logs are captured as Windows events or Linux/macOS files such as Bash History and /var/log/*.<br>"
        )
        t1070html.write(
            "These actions may interfere with event collection, reporting, or other notifications used to detect intrusion activity. This that may compromise the integrity of security solutions by causing notable events to go unreported.<br>"
        )
        t1070html.write(
            "This activity may also impede forensic analysis and incident response, due to lack of sufficient data to determine what occurred."
        )
        # information
        t1070html.write("{}T1070</td>\n        <td>".format(headings))  # id
        t1070html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1070html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1070html.write(
            "T1070.001: Clear Windows Event Logs<br>T1070.002: Clear Linux or Mac System Logs<br>T1070.003: Clear Command History<br>T1070.004: File Deletion<br>T1070.005: Network Share Connection Removal<br>T1070.006: Timestomp"
        )  # sub-techniques
        # indicator regex assignments
        t1070html.write("{}Event IDs: 1102</li>\n        <li>".format(iocs))
        t1070html.write("/delete</li>\n        <li>")
        t1070html.write("sdelete</li>\n        <li>")
        t1070html.write("del</li>\n        <li>")
        t1070html.write("rm</li>\n        <li>")
        t1070html.write("clear-history</li>\n        <li>")
        t1070html.write("PSReadLine</li>\n        <li>")
        t1070html.write("Set-PSReadLineOption</li>\n        <li>")
        t1070html.write("wevtutil</li>\n        <li>")
        t1070html.write("OpenEventLog ClearEventLog</li>\n        <li>")
        t1070html.write("net.exe use</li>\n        <li>")
        t1070html.write("net1.exe use</li>\n        <li>")
        t1070html.write("/var/log</li>")
        # related techniques
        t1070html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1552 target="_blank"">T1552</a></td>\n        <td>'.format(
                related
            )
        )
        t1070html.write("Unsecured Credentials: Bash History")
        # mitigations
        t1070html.write(
            "{}Encrypt Sensitive Information</td>\n        <td>".format(mitigations)
        )
        t1070html.write(
            "Obfuscate/encrypt event files locally and in transit to avoid giving feedback to an adversary.{}".format(
                insert
            )
        )
        t1070html.write("Remote Data Storage</td>\n        <td>")
        t1070html.write(
            "Automatically forward events to a log server or data repository to prevent conditions in which the adversary can locate and manipulate data on the local system. When possible, minimize time delay on event reporting to avoid prolonged storage on the local system.{}".format(
                insert
            )
        )
        t1070html.write("Restrict File and Directory Permissions</td>\n        <td>")
        t1070html.write(
            "Protect generated event files that are stored locally with proper permissions and authentication and limit opportunities for adversaries to increase privileges by preventing Privilege Escalation opportunities.{}".format(
                footer
            )
        )
    with open(sd + "t1202.html", "w") as t1202html:
        # description
        t1202html.write(
            "{}Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters. Various Windows utilities may be used to execute commands, possibly without invoking cmd.<br>".format(
                header
            )
        )
        t1202html.write(
            "For example, Forfiles, the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a Command and Scripting Interpreter, Run window, or via scripts.<br>"
        )
        t1202html.write(
            "Adversaries may abuse these features for Defense Evasion, specifically to perform arbitrary execution while subverting detections and/or mitigation controls (such as Group Policy) that limit/prevent the usage of cmd or file extensions more commonly associated with malicious payloads."
        )
        # information
        t1202html.write("{}T1202</td>\n        <td>".format(headings))  # id
        t1202html.write("Windows</td>\n        <td>")  # platforms
        t1202html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1202html.write("-")  # sub-techniques
        # indicator regex assignments
        t1202html.write("{}-".format(iocs))
        # related techniques
        t1202html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1059 target="_blank"">T1059</a></td>\n        <td>'.format(
                related
            )
        )
        t1202html.write("Command and Scripting Interpreter")
        # mitigations
        t1202html.write("{}-</td>\n        <td>".format(mitigations))
        t1202html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1036.html", "w") as t1036html:
        # description
        t1036html.write(
            "{}Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools.<br>".format(
                header
            )
        )
        t1036html.write(
            "Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation.<br>"
        )
        t1036html.write(
            "This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.<br>"
        )
        t1036html.write(
            "Renaming abusable system utilities to evade security monitoring is also a form of Masquerading."
        )
        # information
        t1036html.write("{}T1036</td>\n        <td>".format(headings))  # id
        t1036html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1036html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1036html.write(
            "T1036.001: Invalid Code Signature<br>T1036.002: Right-to-Left Override<br>T1036.003: Rename System Utilities<br>T1036.004: Masquerade Task or Service<br>T1036.005: Match Legitimate Name or Location<br>T1036.006: Space after Filename"
        )  # sub-techniques
        # indicator regex assignments
        t1036html.write("{}certutil</li>\n        <li>".format(iocs))
        t1036html.write("PubPrn</li>\n        <li>")
        t1036html.write("rundll32.exe</li>\n        <li>")
        t1036html.write("CPlApplet</li>\n        <li>")
        t1036html.write("DllEntryPoint</li>\n        <li>")
        t1036html.write("Control_RunDLL</li>\n        <li>")
        t1036html.write("ControlRunDLLAsUser</li>\n        <li>")
        t1036html.write("GetWindowsDirectoryW</li>\n        <li>")
        t1036html.write("u202E</li>\n        <li>")
        t1036html.write("scvhost</li>\n        <li>")
        t1036html.write("svchast</li>\n        <li>")
        t1036html.write("svchust</li>\n        <li>")
        t1036html.write("svchest</li>\n        <li>")
        t1036html.write("lssas</li>\n        <li>")
        t1036html.write("lsasss</li>\n        <li>")
        t1036html.write("lsaas</li>\n        <li>")
        t1036html.write("cssrs</li>\n        <li>")
        t1036html.write("canhost</li>\n        <li>")
        t1036html.write("conhast</li>\n        <li>")
        t1036html.write("connhost</li>\n        <li>")
        t1036html.write("connhst</li>\n        <li>")
        t1036html.write("iexplorer</li>\n        <li>")
        t1036html.write("iexploror</li>\n        <li>")
        t1036html.write("iexplorar</li>")
        # related techniques
        t1036html.write("{}-</a></td>\n        <td>".format(related))
        t1036html.write("-")
        # mitigations
        t1036html.write("{}Code Signing</td>\n        <td>".format(mitigations))
        t1036html.write("Require signed binaries.{}".format(insert))
        t1036html.write("Execution Prevention</td>\n        <td>")
        t1036html.write(
            "Use tools that restrict program execution via application control by attributes other than file name for common operating system utilities that are needed.{}".format(
                insert
            )
        )
        t1036html.write("Restrict File and Directory Permissions</td>\n        <td>")
        t1036html.write(
            "Use file system access controls to protect folders such as C:\\Windows\\System32.{}".format(
                footer
            )
        )
    with open(sd + "t1578.html", "w") as t1578html:
        # description
        t1578html.write(
            "{}An adversary may attempt to modify a cloud account's compute service infrastructure to evade defenses.<br>".format(
                header
            )
        )
        t1578html.write(
            "A modification to the compute service infrastructure can include the creation, deletion, or modification of one or more components such as compute instances, virtual machines, and snapshots.<br>"
        )
        t1578html.write(
            "Permissions gained from the modification of infrastructure components may bypass restrictions that prevent access to existing infrastructure.<br>"
        )
        t1578html.write(
            "Modifying infrastructure components may also allow an adversary to evade detection and remove evidence of their presence."
        )
        # information
        t1578html.write("{}T1578</td>\n        <td>".format(headings))  # id
        t1578html.write("AWS, Azure, GCP</td>\n        <td>")  # platforms
        t1578html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1578html.write(
            "T1578.001: Create Snapshot<br>T1578.002: Create Cloud Instance<br>T1578: Delete Cloud Instance<br>T1578.003: Revert Cloud Instance"
        )  # sub-techniques
        # indicator regex assignments
        t1578html.write("{}-".format(iocs))
        # related techniques
        t1578html.write("{}-</a></td>\n        <td>".format(related))
        t1578html.write("-")
        # mitigations
        t1578html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1578html.write(
            "Routinely monitor user permissions to ensure only the expected users have the capability to modify cloud compute infrastructure components.{}".format(
                insert
            )
        )
        t1578html.write("User Account Management</td>\n        <td>")
        t1578html.write(
            "Limit permissions for creating, deleting, and otherwise altering compute components in accordance with least privilege. Organizations should limit the number of users within the organization with an IAM role that has administrative privileges, strive to reduce all permanent privileged role assignments, and conduct periodic entitlement reviews on IAM users, roles and policies.{}".format(
                footer
            )
        )
    with open(sd + "t1112.html", "w") as t1112html:
        # description
        t1112html.write(
            "{}Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.<br>".format(
                header
            )
        )
        t1112html.write(
            "Access to specific areas of the Registry depends on account permissions, some requiring administrator-level access.<br>"
        )
        t1112html.write(
            "The built-in Windows command-line utility Reg may be used for local or remote Registry modification. Other tools may also be used, such as a remote access tool, which may contain functionality to interact with the Registry through the Windows API.<br>"
        )
        t1112html.write(
            "Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via Reg or other utilities using the Win32 API.<br>"
        )
        t1112html.write(
            "Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence.<br>"
        )
        t1112html.write(
            "The Registry of a remote system may be modified to aid in execution of files as part of lateral movement. It requires the remote Registry service to be running on the target system. Often Valid Accounts are required, along with access to the remote system's SMB/Windows Admin Shares for RPC communication."
        )
        # information
        t1112html.write("{}T1112</td>\n        <td>".format(headings))  # id
        t1112html.write("Windows</td>\n        <td>")  # platforms
        t1112html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1112html.write("-")  # sub-techniques
        # indicator regex assignments
        t1112html.write("{}autoruns</li>\n        <li>".format(iocs))
        t1112html.write("regdelnull</li>\n        <li>")
        t1112html.write("reg.exe</li>")
        # related techniques
        t1112html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1078 target="_blank"">T1078</a></td>\n        <td>'.format(
                related
            )
        )
        t1112html.write("Valid Accounts")
        t1112html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1021 target="_blank"">T1021</a></td>\n        <td>'.format(
                insert
            )
        )
        t1112html.write("Remote Services: SMB/Windows Admin Shares")
        # mitigations
        t1112html.write(
            "{}Restrict Registry Permissions</td>\n        <td>".format(mitigations)
        )
        t1112html.write(
            "Ensure proper permissions are set for Registry hives to prevent users from modifying keys for system components that may lead to privilege escalation.{}".format(
                footer
            )
        )
    with open(sd + "t1601.html", "w") as t1601html:
        # description
        t1601html.write(
            "{}Adversaries may make changes to the operating system of embedded network devices to weaken defenses and provide new capabilities for themselves. On such devices, the operating systems are typically monolithic and most of the device functionality and capabilities are contained within a single file.<br>".format(
                header
            )
        )
        t1601html.write(
            "To change the operating system, the adversary typically only needs to affect this one file, replacing or modifying it. This can either be done live in memory during system runtime for immediate effect, or in storage to implement the change on the next boot of the network device."
        )
        # information
        t1601html.write("{}T1601</td>\n        <td>".format(headings))  # id
        t1601html.write("Containers</td>\n        <td>")  # platforms
        t1601html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1601html.write(
            "T1601.001: Patch System Image<br>T1601.002: Downgrade System Image<br>"
        )  # sub-techniques
        # indicator regex assignments
        t1601html.write("{}-".format(iocs))
        # related techniques
        t1601html.write("{}-</a></td>\n        <td>".format(related))
        t1601html.write("-")
        # mitigations
        t1601html.write("{}Boot Integrity</td>\n        <td>".format(mitigations))
        t1601html.write(
            "Some vendors of embedded network devices provide cryptographic signing to ensure the integrity of operating system images at boot time. Implement where available, following vendor guidelines.{}".format(
                insert
            )
        )
        t1601html.write("Code Signing</td>\n        <td>")
        t1601html.write(
            "Many vendors provide digitally signed operating system images to validate the integrity of the software used on their platform. Make use of this feature where possible in order to prevent and/or detect attempts by adversaries to compromise the system image. {}".format(
                insert
            )
        )
        t1601html.write("Credential Access Protection</td>\n        <td>")
        t1601html.write(
            "Some embedded network devices are capable of storing passwords for local accounts in either plain-text or encrypted formats. Ensure that, where available, local passwords are always encrypted, per vendor recommendations.{}".format(
                insert
            )
        )
        t1601html.write("Multi-factor Authentication</td>\n        <td>")
        t1601html.write(
            "Use multi-factor authentication for user and privileged accounts. Most embedded network devices support TACACS+ and/or RADIUS. Follow vendor prescribed best practices for hardening access control.{}".format(
                insert
            )
        )
        t1601html.write("Password Policies</td>\n        <td>")
        t1601html.write(
            "Refer to NIST guidelines when creating password policies.{}".format(insert)
        )
        t1601html.write("Privileged Account Management</td>\n        <td>")
        t1601html.write(
            "Restrict administrator accounts to as few individuals as possible, following least privilege principles. Prevent credential overlap across systems of administrator and privileged accounts, particularly between network and non-network platforms, such as servers or endpoints.{}".format(
                footer
            )
        )
    with open(sd + "t1599.html", "w") as t1599html:
        # description
        t1599html.write(
            "{}Adversaries may bridge network boundaries by compromising perimeter network devices. Breaching these devices may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks.<br>".format(
                header
            )
        )
        t1599html.write(
            "Devices such as routers and firewalls can be used to create boundaries between trusted and untrusted networks. They achieve this by restricting traffic types to enforce organizational policy in an attempt to reduce the risk inherent in such connections. Restriction of traffic can be achieved by prohibiting IP addresses, layer 4 protocol ports, or through deep packet inspection to identify applications. To participate with the rest of the network, these devices can be directly addressable or transparent, but their mode of operation has no bearing on how the adversary can bypass them when compromised.<br>"
        )
        t1599html.write(
            "When an adversary takes control of such a boundary device, they can bypass its policy enforcement to pass normally prohibited traffic across the trust boundary between the two separated networks without hinderance. By achieving sufficient rights on the device, an adversary can reconfigure the device to allow the traffic they want, allowing them to then further achieve goals such as command and control via Multi-hop Proxy or exfiltration of data via Traffic Duplication. In the cases where a border device separates two separate organizations, the adversary can also facilitate lateral movement into new victim environments."
        )
        # information
        t1599html.write("{}T1599</td>\n        <td>".format(headings))  # id
        t1599html.write("Network</td>\n        <td>")  # platforms
        t1599html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1599html.write(
            "T1599.001: Network Address Translation Traversal"
        )  # sub-techniques
        # indicator regex assignments
        t1599html.write("{}-".format(iocs))
        # related techniques
        t1599html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1090 target="_blank"">T1090</a></td>\n        <td>'.format(
                related
            )
        )
        t1599html.write("Multi-hop Proxy")
        t1599html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1020 target="_blank"">T1020</a></td>\n        <td>'.format(
                insert
            )
        )
        t1599html.write("Traffic Duplication")
        # mitigations
        t1599html.write(
            "{}Credential Access Protection</td>\n        <td>".format(mitigations)
        )
        t1599html.write(
            "Some embedded network devices are capable of storing passwords for local accounts in either plain-text or encrypted formats. Ensure that, where available, local passwords are always encrypted, per vendor recommendations.{}".format(
                insert
            )
        )
        t1599html.write("Filter Network Traffic</td>\n        <td>")
        t1599html.write(
            "Upon identifying a compromised network device being used to bridge a network boundary, block the malicious packets using an unaffected network device in path, such as a firewall or a router that has not been compromised. Continue to monitor for additional activity and to ensure that the blocks are indeed effective.{}".format(
                insert
            )
        )
        t1599html.write("Multi-factor Authentication</td>\n        <td>")
        t1599html.write(
            "Use multi-factor authentication for user and privileged accounts. Most embedded network devices support TACACS+ and/or RADIUS. Follow vendor prescribed best practices for hardening access control.[{}".format(
                insert
            )
        )
        t1599html.write("Password Policies</td>\n        <td>")
        t1599html.write(
            "Refer to NIST guidelines when creating password policies.{}".format(insert)
        )
        t1599html.write("Privileged Account Management</td>\n        <td>")
        t1599html.write(
            "Restrict administrator accounts to as few individuals as possible, following least privilege principles. Prevent credential overlap across systems of administrator and privileged accounts, particularly between network and non-network platforms, such as servers or endpoints.{}".format(
                footer
            )
        )
    with open(sd + "t1027.html", "w") as t1027html:
        # description
        t1027html.write(
            "{}Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.<br>".format(
                header
            )
        )
        t1027html.write(
            "Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open and Deobfuscate/Decode Files or Information for User Execution.<br>"
        )
        t1027html.write(
            "The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. Adversaries may also used compressed or archived scripts, such as JavaScript.<br>"
        )
        t1027html.write(
            "Portions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled.<br>"
        )
        t1027html.write(
            "Adversaries may also obfuscate commands executed from payloads or directly via a Command and Scripting Interpreter. Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and application control mechanisms."
        )
        # information
        t1027html.write("{}T1027</td>\n        <td>".format(headings))  # id
        t1027html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1027html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1027html.write(
            "T1027.001: Binary Padding<br>T1027.002: Software Packing<br>T1027.003: Steganography<br>T1027.004: Complie After Delivery<br>T1027.005: Indicator Removal from Tools"
        )  # sub-techniques
        # indicator regex assignments
        t1027html.write("{}csc.exe</li>\n        <li>".format(iocs))
        t1027html.write("gcc</li>\n        <li>")
        t1027html.write("MinGW</li>\n        <li>")
        t1027html.write("FileRecvWriteRand</li>")
        # related techniques
        t1027html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1140 target="_blank"">T1140</a></td>\n        <td>'.format(
                related
            )
        )
        t1027html.write("Deobfuscate/Decode Files or Information")
        t1027html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1059 target="_blank"">T1059</a></td>\n        <td>'.format(
                insert
            )
        )
        t1027html.write("Command and Scripting Interpreter")
        # mitigations
        t1027html.write(
            "{}Antivirus/Antimalware</td>\n        <td>".format(mitigations)
        )
        t1027html.write(
            "Consider utilizing the Antimalware Scan Interface (AMSI) on Windows 10 to analyze commands after being processed/interpreted.{}".format(
                footer
            )
        )
    with open(sd + "t1207.html", "w") as t1207html:
        # description
        t1207html.write(
            "{}Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data. DCShadow may be used to create a rogue Domain Controller (DC).<br>".format(
                header
            )
        )
        t1207html.write(
            "DCShadow is a method of manipulating Active Directory (AD) data, including objects and schemas, by registering (or reusing an inactive registration) and simulating the behavior of a DC.<br>"
        )
        t1207html.write(
            "Once registered, a rogue DC may be able to inject and replicate changes into AD infrastructure for any domain object, including credentials and keys.<br>"
        )
        t1207html.write(
            "Registering a rogue DC involves creating a new server and nTDSDSA objects in the Configuration partition of the AD schema, which requires Administrator privileges (either Domain or local to the DC) or the KRBTGT hash.<br>"
        )
        t1207html.write(
            "This technique may bypass system logging and security monitors such as security information and event management (SIEM) products (since actions taken on a rogue DC may not be reported to these sensors).<br>"
        )
        t1207html.write(
            "The technique may also be used to alter and delete replication and other associated metadata to obstruct forensic analysis.<br>"
        )
        t1207html.write(
            "Adversaries may also utilize this technique to perform SID-History Injection and/or manipulate AD objects (such as accounts, access control lists, schemas) to establish backdoors for Persistence."
        )
        # information
        t1207html.write("{}T1207</td>\n        <td>".format(headings))  # id
        t1207html.write("Windows</td>\n        <td>")  # platforms
        t1207html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1207html.write("-")
        # indicator regex assignments
        t1207html.write("{}lsadump</li>\n        <li>".format(iocs))
        t1207html.write("DCShadow</li>")
        # related techniques
        t1207html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1134 target="_blank"">T1134</a></td>\n        <td>'.format(
                related
            )
        )
        t1207html.write("SID-History Injection")
        # mitigations
        t1207html.write("{}-</td>\n        <td>".format(mitigations))
        t1207html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1014.html", "w") as t1014html:
        # description
        t1014html.write(
            "{}Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components. Rootkits are programs that hide the existence of malware by intercepting/hooking and modifying operating system API calls that supply system information.<br>".format(
                header
            )
        )
        t1014html.write(
            "Rootkits or rootkit enabling functionality may reside at the user or kernel level in the operating system or lower, to include a hypervisor, Master Boot Record, or System Firmware. Rootkits have been seen for Windows, Linux, and Mac OS X systems."
        )
        # information
        t1014html.write("{}T1014</td>\n        <td>".format(headings))  # id
        t1014html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1014html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1014html.write("-")  # sub-techniques
        # indicator regex assignments
        t1014html.write("{}-".format(iocs))
        # related techniques
        t1014html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1542 target="_blank"">T1542.001</a></td>\n        <td>'.format(
                related
            )
        )
        t1014html.write("Pre-OS Boot: System Firmware")
        # mitigations
        t1014html.write("{}-</td>\n        <td>".format(mitigations))
        t1014html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1218.html", "w") as t1218html:
        # description
        t1218html.write(
            "{}Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries.<br>".format(
                header
            )
        )
        t1218html.write(
            "Binaries signed with trusted digital certificates can execute on Windows systems protected by digital signature validation.<br>"
        )
        t1218html.write(
            "Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files."
        )
        # information
        t1218html.write("{}T1218</td>\n        <td>".format(headings))  # id
        t1218html.write("Windows</td>\n        <td>")  # platforms
        t1218html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1218html.write(
            "T1218.001: Compiled HTML File<br>T1218.002: Control Panel<br>T1218.003: CMSTP<br>T1218.004: InstallUtil<br>T1218.005: Mshta<br>T1218.007: Msiexec<br>T1218.008: Odbcconf<br>T1218.009: Regsvcs/Regasm<br>T1218.010: Regsvr32<br>T1218.011: Rundll32<br>T1218.012: Verclsid"
        )  # sub-techniques
        # indicator regex assignments
        t1218html.write("{}Event IDs: 10, 12, 13</li>\n        <li>".format(iocs))
        t1218html.write(".chm</li>\n        <li>")
        t1218html.write(".hh</li>\n        <li>")
        t1218html.write(".cpl</li>\n        <li>")
        t1218html.write("rundll32.exe</li>\n        <li>")
        t1218html.write("CMSTP.exe</li>\n        <li>")
        t1218html.write("Mshta.exe</li>\n        <li>")
        t1218html.write("Msiexec.exe</li>\n        <li>")
        t1218html.write("odbcconf.exe</li>\n        <li>")
        t1218html.write("verclsid.exe</li>\n        <li>")
        t1218html.write("Regasm</li>\n        <li>")
        t1218html.write("Regsvcs</li>\n        <li>")
        t1218html.write("Regsvr</li>\n        <li>")
        t1218html.write("CMMGR32</li>\n        <li>")
        t1218html.write("CMLUA</li>\n        <li>")
        t1218html.write("InstallUtil</li>\n        <li>")
        t1218html.write("AlwaysInstallElevated</li>\n        <li>")
        t1218html.write("ComRegisterFunction</li>\n        <li>")
        t1218html.write("ComUnregisterFunction</li>\n        <li>")
        t1218html.write("CPlApplet</li>\n        <li>")
        t1218html.write("DllEntryPoint</li>\n        <li>")
        t1218html.write("Control_RunDLL</li>\n        <li>")
        t1218html.write("ControlRunDLLAsUser</li>\n        <li>")
        t1218html.write("panel/cpls</li>")
        # related techniques
        t1218html.write("{}-</a></td>\n        <td>".format(related))
        t1218html.write("-")
        # mitigations
        t1218html.write(
            "{}Disable or Remove Feature or Program</td>\n        <td>".format(
                mitigations
            )
        )
        t1218html.write(
            "Many native binaries may not be necessary within a given environment.{}".format(
                insert
            )
        )
        t1218html.write("Execution Prevention</td>\n        <td>")
        t1218html.write(
            "Consider using application control to prevent execution of binaries that are susceptible to abuse and not required for a given system or network.{}".format(
                insert
            )
        )
        t1218html.write("Exploit Protection</td>\n        <td>")
        t1218html.write(
            "Microsoft's Enhanced Mitigation Experience Toolkit (EMET) Attack Surface Reduction (ASR) feature can be used to block methods of using using trusted binaries to bypass application control.{}".format(
                insert
            )
        )
        t1218html.write("Privileged Account Management</td>\n        <td>")
        t1218html.write(
            "Restrict execution of particularly vulnerable binaries to privileged accounts or groups that need to use it to lessen the opportunities for malicious usage.{}".format(
                footer
            )
        )
    with open(sd + "t1216.html", "w") as t1216html:
        # description
        t1216html.write(
            "{}Adversaries may use scripts signed with trusted certificates to proxy execution of malicious files. Several Microsoft signed scripts that are default on Windows installations can be used to proxy execution of other files.<br>".format(
                header
            )
        )
        t1216html.write(
            "This behavior may be abused by adversaries to execute malicious files that could bypass application control and signature validation on systems."
        )
        # information
        t1216html.write("{}T1216</td>\n        <td>".format(headings))  # id
        t1216html.write("Windows</td>\n        <td>")  # platforms
        t1216html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1216html.write("T1216.001: PubPrn")  # sub-techniques
        # indicator regex assignments
        t1216html.write("{}PubPrn</li>\n        <li>".format(iocs))
        t1216html.write("cscript.exe</li>")
        # related techniques
        t1216html.write("{}-</a></td>\n        <td>".format(related))
        t1216html.write("-")
        # mitigations
        t1216html.write("{}Execution Prevention</td>\n        <td>".format(mitigations))
        t1216html.write(
            "Certain signed scripts that can be used to execute other programs may not be necessary within a given environment. Use application control configured to block execution of these scripts if they are not required for a given system or network to prevent potential misuse by adversaries.{}".format(
                footer
            )
        )
    with open(sd + "t1553.html", "w") as t1553html:
        # description
        t1553html.write(
            "{}Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs. Operating systems and security products may contain mechanisms to identify programs or websites as possessing some level of trust.<br>".format(
                header
            )
        )
        t1553html.write(
            "Examples of such features would include a program being allowed to run because it is signed by a valid code signing certificate, a program prompting the user with a warning because it has an attribute set from being downloaded from the Internet, or getting an indication that you are about to connect to an untrusted site.<br>"
        )
        t1553html.write(
            "Adversaries may attempt to subvert these trust mechanisms. The method adversaries use will depend on the specific mechanism they seek to subvert. Adversaries may conduct File and Directory Permissions Modification or Modify Registry in support of subverting these controls. Adversaries may also create or steal code signing certificates to acquire trust on target systems."
        )
        # information
        t1553html.write("{}T1553</td>\n        <td>".format(headings))  # id
        t1553html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1553html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1553html.write(
            "T1553.001: Gatekeeper Bypass<br>T1553.002: Code Signing<br>T1553.003: SIP and Trust Provider Hijacking<br>T1553.004: Install Root Certificate<br>T1553.005: Mark-of-the-Web Bypass<br>T1553.006: Code Signing Policy Modification"
        )  # sub-techniques
        # indicator regex assignments
        t1553html.write("{}Event IDs: 81, 3033</li>\n        <li>".format(iocs))
        t1553html.write("bcdedit</li>\n        <li>")
        t1553html.write("vssadmin</li>\n        <li>")
        t1553html.write("wbadmin</li>\n        <li>")
        t1553html.write("shadows</li>\n        <li>")
        t1553html.write("shadowcopy</li>\n        <li>")
        t1553html.write("certmgr</li>\n        <li>")
        t1553html.write("certutil</li>\n        <li>")
        t1553html.write("add-trusted-cert</li>\n        <li>")
        t1553html.write("trustRoot</li>\n        <li>")
        t1553html.write("g_CiOptions</li>\n        <li>")
        t1553html.write("requiresigned</li>\n        <li>")
        t1553html.write("testsigning</li>\n        <li>")
        t1553html.write("curl</li>\n        <li>")
        t1553html.write("com.apple.quarantine</li>\n        <li>")
        t1553html.write("xattr</li>\n        <li>")
        t1553html.write("xttr</li>")
        # related techniques
        t1553html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1222 target="_blank"">T1222</a></td>\n        <td>'.format(
                related
            )
        )
        t1553html.write("File and Directory Permissions Modification")
        t1553html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1112 target="_blank"">T1112</a></td>\n        <td>'.format(
                insert
            )
        )
        t1553html.write("Modify Registry")
        # mitigations
        t1553html.write("{}Execution Prevention</td>\n        <td>".format(mitigations))
        t1553html.write(
            "System settings can prevent applications from running that haven't been downloaded through the Apple Store (or other legitimate repositories) which can help mitigate some of these issues. Also enable application control solutions such as AppLocker and/or Device Guard to block the loading of malicious content.{}".format(
                insert
            )
        )
        t1553html.write("Operating System Configuration</td>\n        <td>")
        t1553html.write(
            "Windows Group Policy can be used to manage root certificates and the Flags value of HKLM\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\ProtectedRoots can be set to 1 to prevent non-administrator users from making further root installations into their own HKCU certificate store.{}".format(
                insert
            )
        )
        t1553html.write("Restrict Registry Permissions</td>\n        <td>")
        t1553html.write(
            "Ensure proper permissions are set for Registry hives to prevent users from modifying keys related to SIP and trust provider components. Components may still be able to be hijacked to suitable functions already present on disk if malicious modifications to Registry keys are not prevented.{}".format(
                insert
            )
        )
        t1553html.write("Software Configuration</td>\n        <td>")
        t1553html.write(
            "HTTP Public Key Pinning (HPKP) is one method to mitigate potential man-in-the-middle situations where and adversary uses a mis-issued or fraudulent certificate to intercept encrypted communications by enforcing use of an expected certificate.{}".format(
                footer
            )
        )
    with open(sd + "t1221.html", "w") as t1221html:
        # description
        t1221html.write(
            "{}Adversaries may create or modify references in Office document templates to conceal malicious code or force authentication attempts. Microsoft’s Office Open XML (OOXML) specification defines an XML-based format for Office documents (.docx, xlsx, .pptx) to replace older binary formats (.doc, .xls, .ppt).<br>".format(
                header
            )
        )
        t1221html.write(
            "OOXML files are packed together ZIP archives compromised of various XML files, referred to as parts, containing properties that collectively define how a document is rendered.<br>"
        )
        t1221html.write(
            "Properties within parts may reference shared public resources accessed via online URLs. For example, template properties reference a file, serving as a pre-formatted document blueprint, that is fetched when the document is loaded.<br>"
        )
        t1221html.write(
            "Adversaries may abuse this technology to initially conceal malicious code to be executed via documents. Template references injected into a document may enable malicious payloads to be fetched and executed when the document is loaded.<br>"
        )
        t1221html.write(
            "These documents can be delivered via other techniques such as Phishing and/or Taint Shared Content and may evade static detections since no typical indicators (VBA macro, script, etc.) are present until after the malicious payload is fetched. Examples have been seen in the wild where template injection was used to load malicious code containing an exploit.<br>"
        )
        t1221html.write(
            "This technique may also enable Forced Authentication by injecting a SMB/HTTPS (or other credential prompting) URL and triggering an authentication attempt."
        )
        # information
        t1221html.write("{}T1221</td>\n        <td>".format(headings))  # id
        t1221html.write("Windows</td>\n        <td>")  # platforms
        t1221html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1221html.write("-")  # sub-techniques
        # indicator regex assignments
        t1221html.write("{}.docx</li>\n        <li>".format(iocs))
        t1221html.write(".xlsx</li>\n        <li>")
        t1221html.write(".pptx</li>")
        # related techniques
        t1221html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1566 target="_blank"">T1566</a></td>\n        <td>'.format(
                related
            )
        )
        t1221html.write("Phishing")
        t1221html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1080 target="_blank"">T1080</a></td>\n        <td>'.format(
                insert
            )
        )
        t1221html.write("Taint Shared Content")
        t1221html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1187 target="_blank"">T1187</a></td>\n        <td>'.format(
                insert
            )
        )
        t1221html.write("Forced Authentication")
        # mitigations
        t1221html.write(
            "{}Antivirus/Antimalware</td>\n        <td>".format(mitigations)
        )
        t1221html.write(
            "Network/Host intrusion prevention systems, antivirus, and detonation chambers can be employed to prevent documents from fetching and/or executing malicious payloads.{}".format(
                insert
            )
        )
        t1221html.write("Disable or Remove Feature or Program</td>\n        <td>")
        t1221html.write(
            "Consider disabling Microsoft Office macros/active content to prevent the execution of malicious payloads in documents, though this setting may not mitigate the Forced Authentication use for this technique.{}".format(
                insert
            )
        )
        t1221html.write("Network Intrusion Prevention</td>\n        <td>")
        t1221html.write(
            "Network/Host intrusion prevention systems, antivirus, and detonation chambers can be employed to prevent documents from fetching and/or executing malicious payloads.{}".format(
                insert
            )
        )
        t1221html.write("User Training</td>\n        <td>")
        t1221html.write(
            "Train users to identify social engineering techniques and spearphishing emails.{}".format(
                footer
            )
        )
    with open(sd + "t1127.html", "w") as t1127html:
        # description
        t1127html.write(
            "{}Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads.<br>".format(
                header
            )
        )
        t1127html.write(
            "There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering.<br>"
        )
        t1127html.write(
            "These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application control solutions."
        )
        # information
        t1127html.write("{}T1127</td>\n        <td>".format(headings))  # id
        t1127html.write("Windows</td>\n        <td>")  # platforms
        t1127html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1127html.write("T1127.001: MSBuild")  # sub-techniques
        # indicator regex assignments
        t1127html.write("{}MSBuild".format(iocs))
        # related techniques
        t1127html.write("{}-</a></td>\n        <td>".format(related))
        t1127html.write("-")
        # mitigations
        t1127html.write(
            "{}Disable or Remove Feature or Program</td>\n        <td>".format(
                mitigations
            )
        )
        t1127html.write(
            "Specific developer utilities may not be necessary within a given environment and should be removed if not used.{}".format(
                insert
            )
        )
        t1127html.write("Execution Prevention</td>\n        <td>")
        t1127html.write(
            "Certain developer utilities should be blocked or restricted if not required.{}".format(
                footer
            )
        )
    with open(sd + "t1550.html", "w") as t1550html:
        # description
        t1550html.write(
            "{}Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.<br>".format(
                header
            )
        )
        t1550html.write(
            "Authentication processes generally require a valid identity (e.g., username) along with one or more authentication factors (e.g., password, pin, physical smart card, token generator, etc.).<br>"
        )
        t1550html.write(
            "Alternate authentication material is legitimately generated by systems after a user or application successfully authenticates by providing a valid identity and the required authentication factor(s). Alternate authentication material may also be generated during the identity creation process.<br>"
        )
        t1550html.write(
            "Caching alternate authentication material allows the system to verify an identity has successfully authenticated without asking the user to reenter authentication factor(s).<br>"
        )
        t1550html.write(
            "Because the alternate authentication must be maintained by the system—either in memory or on disk—it may be at risk of being stolen through Credential Access techniques.<br>"
        )
        t1550html.write(
            "By stealing alternate authentication material, adversaries are able to bypass system access controls and authenticate to systems without knowing the plaintext password or any additional authentication factors."
        )
        # information
        t1550html.write("{}T1550</td>\n        <td>".format(headings))  # id
        t1550html.write("Windows, Office 365, SaaS</td>\n        <td>")  # platforms
        t1550html.write(
            "Defense Evasion, Lateral Movement</td>\n        <td>"
        )  # tactics
        t1550html.write(
            "T1550.001: Application Access Token<br>T1550.002: Pass the Hash<br>T1550.003: Pass the Ticket<br>T1550.004: Web Session Cookie"
        )  # sub-techniques
        # indicator regex assignments
        t1550html.write("{}Event IDs: 4768, 4769</li>\n        <li>".format(iocs))
        t1550html.write("DCSync</li>\n        <li>")
        t1550html.write("duo-sid</li>")
        # related techniques
        t1550html.write("{}-</a></td>\n        <td>".format(related))
        t1550html.write("-")
        # mitigations
        t1550html.write(
            "{}Privileged Account Management</td>\n        <td>".format(mitigations)
        )
        t1550html.write(
            "Limit credential overlap across systems to prevent the damage of credential compromise and reduce the adversary's ability to perform Lateral Movement between systems.{}".format(
                insert
            )
        )
        t1550html.write("User Account Management</td>\n        <td>")
        t1550html.write(
            "Enforce the principle of least-privilege. Do not allow a domain user to be in the local administrator group on multiple systems.{}".format(
                footer
            )
        )
    with open(sd + "t1535.html", "w") as t1535html:
        # description
        t1535html.write(
            "{}Adversaries may create cloud instances in unused geographic service regions in order to evade detection. Access is usually obtained through compromising accounts used to manage cloud infrastructure.<br>".format(
                header
            )
        )
        t1535html.write(
            "Cloud service providers often provide infrastructure throughout the world in order to improve performance, provide redundancy, and allow customers to meet compliance requirements.<br>"
        )
        t1535html.write(
            "Oftentimes, a customer will only use a subset of the available regions and may not actively monitor other regions. If an adversary creates resources in an unused region, they may be able to operate undetected.<br>"
        )
        t1535html.write(
            "A variation on this behavior takes advantage of differences in functionality across cloud regions. An adversary could utilize regions which do not support advanced detection services in order to avoid detection of their activity. For example, AWS GuardDuty is not supported in every region.<br>"
        )
        t1535html.write(
            "An example of adversary use of unused AWS regions is to mine cryptocurrency through Resource Hijacking, which can cost organizations substantial amounts of money over time depending on the processing power used."
        )
        # information
        t1535html.write("{}T1535</td>\n        <td>".format(headings))  # id
        t1535html.write("AWS, Azure, GCP</td>\n        <td>")  # platforms
        t1535html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1535html.write("-")  # sub-techniques
        # indicator regex assignments
        t1535html.write("{}-".format(iocs))
        # related techniques
        t1535html.write("{}-</a></td>\n        <td>".format(related))
        t1535html.write("-")
        # mitigations
        t1535html.write(
            "{}Software Configuration</td>\n        <td>".format(mitigations)
        )
        t1535html.write(
            "Cloud service providers may allow customers to deactivate unused regions.{}".format(
                footer
            )
        )
    with open(sd + "t1497.html", "w") as t1497html:
        # description
        t1497html.write(
            "{}Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox.<br>".format(
                header
            )
        )
        t1497html.write(
            "If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads.<br>"
        )
        t1497html.write(
            "Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors.<br>"
        )
        t1497html.write(
            "Adversaries may use several methods to accomplish Virtualization/Sandbox Evasion such as checking for security monitoring tools (e.g., Sysinternals, Wireshark, etc.) or other system artifacts associated with analysis or virtualization.<br>"
        )
        t1497html.write(
            "Adversaries may also check for legitimate user activity to help determine if it is in an analysis environment. Additional methods include use of sleep timers or loops within malware code to avoid operating within a temporary sandbox."
        )
        # information
        t1497html.write("{}T1497</td>\n        <td>".format(headings))  # id
        t1497html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1497html.write("Defense Evasion, Discovery</td>\n        <td>")  # tactics
        t1497html.write(
            "T1497.001: System Checks<br>T1497.002: User Activity Based Checks<br>T1497.003: Time Based Evasion"
        )  # sub-techniques
        # indicator regex assignments
        t1497html.write("{}vpcext</li>\n        <li>".format(iocs))
        t1497html.write("vmtoolsd</li>\n        <li>")
        t1497html.write("MSAcpi_ThermalZoneTemperature</li>\n        <li>")
        t1497html.write("is_debugging</li>\n        <li>")
        t1497html.write("sysctl</li>\n        <li>")
        t1497html.write("ptrace</li>\n        <li>")
        t1497html.write("time</li>\n        <li>")
        t1497html.write("sleep</li>")
        # related techniques
        t1497html.write("{}-</a></td>\n        <td>".format(related))
        t1497html.write("-")
        # mitigations
        t1497html.write("{}-</td>\n        <td>".format(mitigations))
        t1497html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1600.html", "w") as t1600html:
        # description
        t1600html.write(
            "{}Adversaries may compromise a network device’s encryption capability in order to bypass encryption that would otherwise protect data communications.<br>".format(
                header
            )
        )
        t1600html.write(
            "Encryption can be used to protect transmitted network traffic to maintain its confidentiality (protect against unauthorized disclosure) and integrity (protect against unauthorized changes). Encryption ciphers are used to convert a plaintext message to ciphertext and can be computationally intensive to decipher without the associated decryption key. Typically, longer keys increase the cost of cryptanalysis, or decryption without the key.<br>"
        )
        t1600html.write(
            "Adversaries can compromise and manipulate devices that perform encryption of network traffic. For example, through behaviors such as Modify System Image, Reduce Key Space, and Disable Crypto Hardware, an adversary can negatively effect and/or eliminate a device’s ability to securely encrypt network traffic. This poses a greater risk of unauthorized disclosure and may help facilitate data manipulation, Credential Access, or Collection efforts."
        )
        # information
        t1600html.write("{}T1600</td>\n        <td>".format(headings))  # id
        t1600html.write("Network</td>\n        <td>")  # platforms
        t1600html.write("Execution</td>\n        <td>")  # tactics
        t1600html.write(
            "T1600.001: Reduce Key Space<br>T1600.002: Disable Crypto Hardware"
        )  # sub-techniques
        # indicator regex assignments
        t1600html.write("{}-".format(iocs))
        # related techniques
        t1600html.write("{}-</a></td>\n        <td>".format(related))
        t1600html.write("-")
        # mitigations
        t1600html.write("{}-</td>\n        <td>".format(mitigations))
        t1600html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1220.html", "w") as t1220html:
        # description
        t1220html.write(
            "{}Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files. Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files.<br>".format(
                header
            )
        )
        t1220html.write(
            "To support complex operations, the XSL standard includes support for embedded scripting in various languages.<br>"
        )
        t1220html.write(
            "Adversaries may abuse this functionality to execute arbitrary files while potentially bypassing application control. Similar to Trusted Developer Utilities Proxy Execution, the Microsoft common line transformation utility binary (msxsl.exe) can be installed and used to execute malicious JavaScript embedded within local or remote (URL referenced) XSL files.<br>"
        )
        t1220html.write(
            "Since msxsl.exe is not installed by default, an adversary will likely need to package it with dropped files.  Msxsl.exe takes two main arguments, an XML source file and an XSL stylesheet. Since the XSL file is valid XML, the adversary may call the same XSL file twice. When using msxsl.exe adversaries may also give the XML/XSL files an arbitrary file extension."
        )
        # information
        t1220html.write("{}T1220</td>\n        <td>".format(headings))  # id
        t1220html.write("Windows</td>\n        <td>")  # platforms
        t1220html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1220html.write("-")  # sub-techniques
        # indicator regex assignments
        t1220html.write("{}MSXML</li>\n        <li>".format(iocs))
        t1220html.write("wmic</li>\n        <li>")
        t1220html.write("Invoke-Wmi</li>")
        # related techniques
        t1220html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1127 target="_blank"">T1127</a></td>\n        <td>'.format(
                related
            )
        )
        t1220html.write("Trusted Developer Utilities Proxy Execution")
        t1220html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1047 target="_blank"">T1047</a></td>\n        <td>'.format(
                insert
            )
        )
        t1220html.write("Windows Management Instrumentation")
        t1220html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1218 target="_blank"">T1218</a></td>\n        <td>'.format(
                insert
            )
        )
        t1220html.write("Signed Binary Proxy Execution: Regsvr32")
        # mitigations
        t1220html.write("{}Execution Prevention</td>\n        <td>".format(mitigations))
        t1220html.write(
            "If msxsl.exe is unnecessary, then block its execution to prevent abuse by adversaries.{}".format(
                footer
            )
        )
