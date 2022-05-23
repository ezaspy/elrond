#!/usr/bin/env python3 -tt


def create_lateral_movement_html(sd, header, headings, iocs, related, insert, mitigations, footer):
    with open(sd + "t1210.html", "w") as t1210html:
        # description
        t1210html.write(
            "{}Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.<br>".format(
                header
            )
        )
        t1210html.write(
            "Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.<br>"
        )
        t1210html.write(
            "A common goal for post-compromise exploitation of remote services is for lateral movement to enable access to a remote system.<br>"
        )
        t1210html.write(
            "An adversary may need to determine if the remote system is in a vulnerable state, which may be done through Network Service Scanning or other Discovery methods looking for common, vulnerable software that may be deployed in the network, the lack of certain patches that may indicate vulnerabilities, or security software that may be used to detect or contain remote exploitation.<br>"
        )
        t1210html.write(
            "Servers are likely a high value target for lateral movement exploitation, but endpoint systems may also be at risk if they provide an advantage or access to additional resources.<br>"
        )
        t1210html.write(
            "There are several well-known vulnerabilities that exist in common services such as SMB and RDP as well as applications that may be used within internal networks such as MySQL and web server services.<br>"
        )
        t1210html.write(
            "Depending on the permissions level of the vulnerable remote service an adversary may achieve Exploitation for Privilege Escalation as a result of lateral movement exploitation as well."
        )
        # information
        t1210html.write("{}T1210</td>\n        <td>".format(headings))  # id
        t1210html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1210html.write("Lateral Movement</td>\n        <td>")  # tactics
        t1210html.write("-")  # sub-techniques
        # indicator regex assignments
        t1210html.write("{}Ports: 445, 3389".format(iocs))
        # related techniques
        t1210html.write("{}-</a></td>\n        <td>".format(related))
        t1210html.write("-")
        # mitigations
        t1210html.write(
            "{}Application Isolation and Sandboxing</td>\n        <td>".format(
                mitigations
            )
        )
        t1210html.write(
            "Make it difficult for adversaries to advance their operation through exploitation of undiscovered or unpatched vulnerabilities by using sandboxing. Other types of virtualization and application microsegmentation may also mitigate the impact of some types of exploitation. Risks of additional exploits and weaknesses in these systems may still exist.{}".format(
                insert
            )
        )
        t1210html.write("Disable or Remove Feature or Program</td>\n        <td>")
        t1210html.write(
            "Minimize available services to only those that are necessary.{}".format(
                insert
            )
        )
        t1210html.write("Exploit Protection</td>\n        <td>")
        t1210html.write(
            "Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility and may not work for all software or services targeted.{}".format(
                insert
            )
        )
        t1210html.write("Network Segmentation</td>\n        <td>")
        t1210html.write(
            "Segment networks and systems appropriately to reduce access to critical systems and services to controlled methods.{}".format(
                insert
            )
        )
        t1210html.write("Privileged Account Management</td>\n        <td>")
        t1210html.write(
            "Minimize permissions and access for service accounts to limit impact of exploitation.{}".format(
                insert
            )
        )
        t1210html.write("Threat Intelligence Program</td>\n        <td>")
        t1210html.write(
            "Develop a robust cyber threat intelligence capability to determine what types and levels of threat may use software exploits and 0-days against a particular organization.{}".format(
                insert
            )
        )
        t1210html.write("Update Software</td>\n        <td>")
        t1210html.write(
            "Update software regularly by employing patch management for internal enterprise endpoints and servers.{}".format(
                insert
            )
        )
        t1210html.write("Vulnerability Scanning</td>\n        <td>")
        t1210html.write(
            "Regularly scan the internal network for available services to identify new and potentially vulnerable services.{}".format(
                footer
            )
        )
    with open(sd + "t1534.html", "w") as t1534html:
        # description
        t1534html.write(
            "{}Adversaries may use internal spearphishing to gain access to additional information or exploit other users within the same organization after they already have access to accounts or systems within the environment.<br>".format(
                header
            )
        )
        t1534html.write(
            "Internal spearphishing is multi-staged attack where an email account is owned either by controlling the user's device with previously installed malware or by compromising the account credentials of the user.<br>"
        )
        t1534html.write(
            "Adversaries attempt to take advantage of a trusted internal account to increase the likelihood of tricking the target into falling for the phish attempt.<br>"
        )
        t1534html.write(
            "Adversaries may leverage Spearphishing Attachment or Spearphishing Link as part of internal spearphishing to deliver a payload or redirect to an external site to capture credentials through Input Capture on sites that mimic email login interfaces.<br>"
        )
        t1534html.write(
            "There have been notable incidents where internal spearphishing has been used. The Eye Pyramid campaign used phishing emails with malicious attachments for lateral movement between victims, compromising nearly 18,000 email accounts in the process.<br>"
        )
        t1534html.write(
            "The Syrian Electronic Army (SEA) compromised email accounts at the Financial Times (FT) to steal additional account credentials. Once FT learned of the attack and began warning employees of the threat, the SEA sent phishing emails mimicking the Financial Times IT department and were able to compromise even more users."
        )
        # information
        t1534html.write("{}T1534</td>\n        <td>".format(headings))  # id
        t1534html.write(
            "Windows, macOS, Linux, Office 365, SaaS</td>\n        <td>"
        )  # platforms
        t1534html.write("Lateral Movement</td>\n        <td>")  # tactics
        t1534html.write("-")  # sub-techniques
        # indicator regex assignments
        t1534html.write("{}-".format(iocs))
        # related techniques
        t1534html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1566 target="_blank"">T1566</a></td>\n        <td>'.format(
                related
            )
        )
        t1534html.write("Phishing: Spearphishing Attachment")
        t1534html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1566 target="_blank"">T1566</a></td>\n        <td>'.format(
                insert
            )
        )
        t1534html.write("Phishing: Spearphishing Link")
        t1534html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1056 target="_blank"">T1056</a></td>\n        <td>'.format(
                insert
            )
        )
        t1534html.write("Input Capture")
        # mitigations
        t1534html.write("{}-</td>\n        <td>".format(mitigations))
        t1534html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1570.html", "w") as t1570html:
        # description
        t1570html.write(
            "{}Adversaries may transfer tools or other files between systems in a compromised environment. Files may be copied from one system to another to stage adversary tools or other files over the course of an operation.<br>".format(
                header
            )
        )
        t1570html.write(
            "Adversaries may copy files laterally between internal victim systems to support lateral movement using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with SMB/Windows Admin Shares or Remote Desktop Protocol. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp."
        )
        # information
        t1570html.write("{}T1570</td>\n        <td>".format(headings))  # id
        t1570html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1570html.write("Lateral Movement</td>\n        <td>")  # tactics
        t1570html.write("-")  # sub-techniques
        # indicator regex assignments
        t1570html.write("{}ADMIN$</li>\n        <li>".format(iocs))
        t1570html.write("C$</li>\n        <li>")
        t1570html.write("psexec</li>\n        <li>")
        t1570html.write("DISPLAY</li>\n        <li>")
        t1570html.write("HID</li>\n        <li>")
        t1570html.write("PCI</li>\n        <li>")
        t1570html.write("UMB</li>\n        <li>")
        t1570html.write("FDC</li>\n        <li>")
        t1570html.write("SCSI</li>\n        <li>")
        t1570html.write("STORAGE</li>\n        <li>")
        t1570html.write("USB</li>\n        <li>")
        t1570html.write("WpdBusEnumRoot</li>")
        # related techniques
        t1570html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1021 target="_blank"">T1021</a></td>\n        <td>'.format(
                related
            )
        )
        t1570html.write("Remote Services: SMB/Windows Admin Shares")
        t1570html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1021 target="_blank"">T1021</a></td>\n        <td>'.format(
                insert
            )
        )
        t1570html.write("Remote Services: Remote Desktop Protocol")
        # mitigations
        t1570html.write(
            "{}Filter Network Traffic</td>\n        <td>".format(mitigations)
        )
        t1570html.write(
            "Consider using the host firewall to restrict file sharing communications such as SMB.{}".format(
                insert
            )
        )
        t1570html.write("Network Intrusion Prevention</td>\n        <td>")
        t1570html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware or unusual data transfer over known tools and protocols like FTP can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions.{}".format(
                footer
            )
        )
    with open(sd + "t1563.html", "w") as t1563html:
        # description
        t1563html.write(
            "{}Adversaries may take control of preexisting sessions with remote services to move laterally in an environment.<br>".format(
                header
            )
        )
        t1563html.write(
            "Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service.<br>"
        )
        t1563html.write(
            "Adversaries may commandeer these sessions to carry out actions on remote systems. Remote Service Session Hijacking differs from use of Remote Services because it hijacks an existing session rather than creating a new session using Valid Accounts."
        )
        # information
        t1563html.write("{}T1563</td>\n        <td>".format(headings))  # id
        t1563html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1563html.write("Lateral Movement</td>\n        <td>")  # tactics
        t1563html.write(
            "T1563.001: SSH Hijacking<br>T1563.002: RDP Hijacking"
        )  # sub-techniques
        # indicator regex assignments
        t1563html.write("{}tscon".format(iocs))
        # related techniques
        t1563html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1021 target="_blank"">T1021</a></td>\n        <td>'.format(
                related
            )
        )
        t1563html.write("Remote Services")
        t1563html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1078 target="_blank"">T1078</a></td>\n        <td>'.format(
                insert
            )
        )
        t1563html.write("Valid Accounts")
        # mitigations
        t1563html.write(
            "{}Disable or Remove Feature or Program</td>\n        <td>".format(
                mitigations
            )
        )
        t1563html.write(
            "Disable the remote service (ex: SSH, RDP, etc.) if it is unnecessary.{}".format(
                insert
            )
        )
        t1563html.write("Network Segmentation</td>\n        <td>")
        t1563html.write(
            "Enable firewall rules to block unnecessary traffic between network security zones within a network.{}".format(
                insert
            )
        )
        t1563html.write("Privileged Account Management</td>\n        <td>")
        t1563html.write(
            "Do not allow remote access to services as a privileged account unless necessary.{}".format(
                insert
            )
        )
        t1563html.write("User Account Management</td>\n        <td>")
        t1563html.write(
            "Limit remote user permissions if remote access is necessary.{}".format(
                footer
            )
        )
    with open(sd + "t1021.html", "w") as t1021html:
        # description
        t1021html.write(
            "{}Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.<br>".format(
                header
            )
        )
        t1021html.write(
            "In an enterprise environment, servers and workstations can be organized into domains. Domains provide centralized identity management, allowing users to login using one set of credentials across the entire network.<br>"
        )
        t1021html.write(
            "If an adversary is able to obtain a set of valid domain credentials, they could login to many different machines using remote access protocols such as secure shell (SSH) or remote desktop protocol (RDP)."
        )
        # information
        t1021html.write("{}T1021</td>\n        <td>".format(headings))  # id
        t1021html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1021html.write("Lateral Movement</td>\n        <td>")  # tactics
        t1021html.write(
            "T1021.001: Remote Desktop Protocol<br>T1021.002: SMB/Windows Admin Shares<br>T1021.003: Distributed Component Object Model<br>T1021.004: SSH<br>T1021.005: VNC<br>T1021.006: Windows Remote Management"
        )  # sub-techniques
        # indicator regex assignments
        t1021html.write(
            "{}Ports: 22, 23, 445, 3389, 5900</li>\n        <li>".format(iocs)
        )
        t1021html.write("Event IDs: 4697, 7045</li>\n        <li>")
        t1021html.write("winrm</li>\n        <li>")
        t1021html.write("ADMIN$</li>\n        <li>")
        t1021html.write("C$</li>\n        <li>")
        t1021html.write("IPC$</li>")
        # related techniques
        t1021html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1563 target="_blank"">T1563</a></td>\n        <td>'.format(
                related
            )
        )
        t1021html.write("Remote Service Session Hijacking")
        t1021html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1078 target="_blank"">T1078</a></td>\n        <td>'.format(
                insert
            )
        )
        t1021html.write("Valid Accounts")
        # mitigations
        t1021html.write(
            "{}Multi-factor Authentication</td>\n        <td>".format(mitigations)
        )
        t1021html.write(
            "Use multi-factor authentication on remote service logons where possible.{}".format(
                insert
            )
        )
        t1021html.write("User Account Management</td>\n        <td>")
        t1021html.write(
            "Limit the accounts that may use remote services. Limit the permissions for accounts that are at higher risk of compromise; for example, configure SSH so users can only run specific programs.{}".format(
                footer
            )
        )
    with open(sd + "t1080.html", "w") as t1080html:
        # description
        t1080html.write(
            "{}Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories. Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files.<br>".format(
                header
            )
        )
        t1080html.write(
            "Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary's code on a remote system. Adversaries may use tainted shared content to move laterally.<br>"
        )
        t1080html.write(
            "A directory share pivot is a variation on this technique that uses several other techniques to propagate malware when users access a shared network directory. It uses Shortcut Modification of directory .LNK files that use Masquerading to look like the real directories, which are hidden through Hidden Files and Directories.<br>"
        )
        t1080html.write(
            "The malicious .LNK-based directories have an embedded command that executes the hidden malware file in the directory and then opens the real intended directory so that the user's expected action still occurs. When used with frequently used network directories, the technique may result in frequent reinfections and broad access to systems and potentially to new and higher privileged accounts.<br>"
        )
        t1080html.write(
            "Adversaries may also compromise shared network directories through binary infections by appending or prepending its code to the healthy binary on the shared network directory. The malware may modify the original entry point (OEP) of the healthy binary to ensure that it is executed before the legitimate code.<br>"
        )
        t1080html.write(
            "The infection could continue to spread via the newly infected file when it is executed by a remote system. These infections may target both binary and non-binary formats that end with extensions including, but not limited to, .EXE, .DLL, .SCR, .BAT, and/or .VBS."
        )
        # information
        t1080html.write("{}T1221</td>\n        <td>".format(headings))  # id
        t1080html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1080html.write("Lateral Movement</td>\n        <td>")  # tactics
        t1080html.write("-")  # sub-techniques
        # indicator regex assignments
        t1080html.write("{}-".format(iocs))
        # related techniques
        t1080html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1547 target="_blank"">T1547</a></td>\n        <td>'.format(
                related
            )
        )
        t1080html.write("Boot or Logon Autostart Execution: Shortcut Modification")
        t1080html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1036 target="_blank"">T1036</a></td>\n        <td>'.format(
                insert
            )
        )
        t1080html.write("Masquerading")
        t1080html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1564 target="_blank"">T1564</a></td>\n        <td>'.format(
                insert
            )
        )
        t1080html.write("Hide Artifacts: Hidden Files and Directories")
        # mitigations
        t1080html.write("{}Execution Prevention</td>\n        <td>".format(mitigations))
        t1080html.write(
            "Identify potentially malicious software that may be used to taint content or may result from it and audit and/or block the unknown programs by using application control tools, like AppLocker, or Software Restriction Policies [16] where appropriate.{}".format(
                insert
            )
        )
        t1080html.write("Exploit Protection</td>\n        <td>")
        t1080html.write(
            "Use utilities that detect or mitigate common features used in exploitation, such as the Microsoft Enhanced Mitigation Experience Toolkit (EMET).{}".format(
                insert
            )
        )
        t1080html.write("Restrict File and Directory Permissions</td>\n        <td>")
        t1080html.write(
            "Protect shared folders by minimizing users who have write access.{}".format(
                footer
            )
        )
