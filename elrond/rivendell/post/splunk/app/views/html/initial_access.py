#!/usr/bin/env python3 -tt


def create_initial_access_html(sd, header, headings, iocs, related, insert, mitigations, footer):
    with open(sd + "t1189.html", "w") as t1189html:
        # description
        t1189html.write(
            "{}Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user's web browser is typically targeted for exploitation, but adversaries may also use compromised websites for non-exploitation behavior such as acquiring Application Access Token.<br>".format(
                header
            )
        )
        t1189html.write(
            "Often the website used by an adversary is one visited by a specific community, such as government, a particular industry, or region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted attack is referred to a strategic web compromise or watering hole attack. There are several known examples of this occurring.<br>"
        )
        t1189html.write(
            "Unlike Exploit Public-Facing Application, the focus of this technique is to exploit software on a client endpoint upon visiting a website. This will commonly give an adversary access to systems on the internal network instead of external systems that may be in a DMZ.<br>"
        )
        t1189html.write(
            "Adversaries may also use compromised websites to deliver a user to a malicious application designed to Steal Application Access Tokens, like OAuth tokens, to gain access to protected applications and information. These malicious applications have been delivered through popups on legitimate websites."
        )
        # information
        t1189html.write("{}T1189</td>\n        <td>".format(headings))  # id
        t1189html.write("Windows, macOS, Linux, SaaS</td>\n        <td>")  # platforms
        t1189html.write("Initial Access</td>\n        <td>")  # tactics
        t1189html.write("-")  # sub-techniques
        # indicator regex assignments
        t1189html.write("{}Ports: 80, 443".format(iocs))
        # related techniques
        t1189html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1211 target="_blank"">T1211</a></td>\n        <td>'.format(
                related
            )
        )
        t1189html.write(
            "Use Alternate Authentication Material: Application Access Token"
        )
        t1189html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1528 target="_blank"">T1528</a></td>\n        <td>'.format(
                insert
            )
        )
        t1189html.write("Steal Application Access Token")
        # mitigations
        t1189html.write(
            "{}Application Isolation and Sandboxing</td>\n        <td>".format(
                mitigations
            )
        )
        t1189html.write(
            "Browser sandboxes can be used to mitigate some of the impact of exploitation, but sandbox escapes may still exist. Other types of virtualization and application microsegmentation may also mitigate the impact of client-side exploitation. The risks of additional exploits and weaknesses in implementation may still exist for these types of systems.{}".format(
                insert
            )
        )
        t1189html.write("Exploit Protection</td>\n        <td>")
        t1189html.write(
            "Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility.{}".format(
                insert
            )
        )
        t1189html.write("Restrict Web-Based Content</td>\n        <td>")
        t1189html.write(
            "For malicious code served up through ads, adblockers can help prevent that code from executing in the first place.<br>"
        )
        t1189html.write(
            "Script blocking extensions can help prevent the execution of JavaScript that may commonly be used during the exploitation process{}".format(
                insert
            )
        )
        t1189html.write("Update Software</td>\n        <td>")
        t1189html.write(
            "Ensure all browsers and plugins kept updated can help prevent the exploit phase of this technique. Use modern browsers with security features turned on.{}".format(
                footer
            )
        )
    with open(sd + "t1190.html", "w") as t1190html:
        # description
        t1190html.write(
            "{}Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. The weakness in the system can be a bug, a glitch, or a design vulnerability.<br>".format(
                header
            )
        )
        t1190html.write(
            "These applications are often websites, but can include databases (like SQL), standard services (like SMB or SSH), and any other applications with Internet accessible open sockets, such as web servers and related services. Depending on the flaw being exploited this may include Exploitation for Defense Evasion.<br>"
        )
        t1190html.write(
            "If an application is hosted on cloud-based infrastructure, then exploiting it may lead to compromise of the underlying instance. This can allow an adversary a path to access the cloud APIs or to take advantage of weak identity and access management policies.<br>"
        )
        t1190html.write(
            "For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities."
        )
        # information
        t1190html.write("{}T1190</td>\n        <td>".format(headings))  # id
        t1190html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>"
        )  # platforms
        t1190html.write("Initial Access</td>\n        <td>")  # tactics
        t1190html.write("-")  # sub-techniques
        # indicator regex assignments
        t1190html.write("{}-".format(iocs))
        # related techniques
        t1190html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1211 target="_blank"">T1211</a></td>\n        <td>'.format(
                related
            )
        )
        t1190html.write("Exploitation for Defense Evasion")
        # mitigations
        t1190html.write(
            "{}Application Isolation and Sandboxing</td>\n        <td>".format(
                mitigations
            )
        )
        t1190html.write(
            "Application isolation will limit what other processes and system features the exploited target can access.{}".format(
                insert
            )
        )
        t1190html.write("Exploit Protection</td>\n        <td>")
        t1190html.write(
            "Web Application Firewalls may be used to limit exposure of applications to prevent exploit traffic from reaching the application.{}".format(
                insert
            )
        )
        t1190html.write("Network Segmentation</td>\n        <td>")
        t1190html.write(
            "Segment externally facing servers and services from the rest of the network with a DMZ or on separate hosting infrastructure.{}".format(
                insert
            )
        )
        t1190html.write("Privileged Account Management</td>\n        <td>")
        t1190html.write(
            "Use least privilege for service accounts will limit what permissions the exploited process gets on the rest of the system.{}".format(
                insert
            )
        )
        t1190html.write("Update Software</td>\n        <td>")
        t1190html.write(
            "Regularly scan externally facing systems for vulnerabilities and establish procedures to rapidly patch systems when critical vulnerabilities are discovered through scanning and through public disclosure.{}".format(
                insert
            )
        )
        t1190html.write("Vulnerability Scanning</td>\n        <td>")
        t1190html.write(
            "Regularly scan externally facing systems for vulnerabilities and establish procedures to rapidly patch systems when critical vulnerabilities are discovered through scanning and through public disclosure.{}".format(
                footer
            )
        )
    with open(sd + "t1133.html", "w") as t1133html:
        # description
        t1133html.write(
            "{}Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations.<br>".format(
                header
            )
        )
        t1133html.write(
            "There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management can also be used externally.<br>"
        )
        t1133html.write(
            "Access to Valid Accounts to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.<br>"
        )
        t1133html.write(
            "Access to remote services may be used as a redundant or persistent access mechanism during an operation."
        )
        # information
        t1133html.write("{}T1133</td>\n        <td>".format(headings))  # id
        t1133html.write("Windows, Linux</td>\n        <td>")  # platforms
        t1133html.write("Initial Access, Persistence</td>\n        <td>")  # tactics
        t1133html.write("-")  # sub-techniques
        # indicator regex assignments
        t1133html.write("{}Ports: 22, 23, 139, 445".format(iocs))
        # related techniques
        t1133html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1021 target="_blank"">T1021</a></td>\n        <td>'.format(
                related
            )
        )
        t1133html.write("Remote Services: Windows Remote Management")
        t1133html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1078 target="_blank"">T1078</a></td>\n        <td>'.format(
                insert
            )
        )
        t1133html.write("Valid Accounts")
        # mitigations
        t1133html.write(
            "{}Disable or Remove Feature or Program</td>\n        <td>".format(
                mitigations
            )
        )
        t1133html.write(
            "Disable or block remotely available services that may be unnecessary.{}".format(
                insert
            )
        )
        t1133html.write("Limit Access to Resource Over Network</td>\n        <td>")
        t1133html.write(
            "Limit access to remote services through centrally managed concentrators such as VPNs and other managed remote access systems.{}".format(
                insert
            )
        )
        t1133html.write("Multi-factor Authentication</td>\n        <td>")
        t1133html.write(
            "Use strong two-factor or multi-factor authentication for remote service accounts to mitigate an adversary's ability to leverage stolen credentials, but be aware of Two-Factor Authentication Interception techniques for some two-factor authentication implementations.{}".format(
                insert
            )
        )
        t1133html.write("Network Segmentation</td>\n        <td>")
        t1133html.write(
            "Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.{}".format(
                footer
            )
        )
    with open(sd + "t1200.html", "w") as t1200html:
        # description
        t1200html.write(
            "{}Adversaries may introduce computer accessories, computers, or networking hardware into a system or network that can be used as a vector to gain access.<br>".format(
                header
            )
        )
        t1200html.write(
            "While public references of usage by APT groups are scarce, many penetration testers leverage hardware additions for initial access.<br>"
        )
        t1200html.write(
            "Commercial and open source products are leveraged with capabilities such as passive network tapping, man-in-the middle encryption breaking, keystroke injection, kernel memory reading via DMA, adding new wireless access to an existing network, and others."
        )
        # information
        t1200html.write("{}T1200</td>\n        <td>".format(headings))  # id
        t1200html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1200html.write("Initial Access</td>\n        <td>")  # tactics
        t1200html.write("-")  # sub-techniques
        # indicator regex assignments
        t1200html.write("{}DISPLAY</li>\n        <li>".format(iocs))
        t1200html.write("HID</li>\n        <li>")
        t1200html.write("PCI</li>\n        <li>")
        t1200html.write("UMB</li>\n        <li>")
        t1200html.write("FDC</li>\n        <li>")
        t1200html.write("SCSI</li>\n        <li>")
        t1200html.write("STORAGE</li>\n        <li>")
        t1200html.write("USB</li>\n        <li>")
        t1200html.write("WpdBusEnumRoot</li>")
        # related techniques
        t1200html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1091 target="_blank"">T1091</a></td>\n        <td>'.format(
                related
            )
        )
        t1200html.write("Replication Through Removable Media")
        # mitigations
        t1200html.write(
            "{}Limit Access to Resource Over Network</td>\n        <td>".format(
                mitigations
            )
        )
        t1200html.write(
            "Establish network access control policies, such as using device certificates and the 802.1x standard. Restrict use of DHCP to registered devices to prevent unregistered devices from communicating with trusted systems.{}".format(
                insert
            )
        )
        t1200html.write("Limit Hardware Installation</td>\n        <td>")
        t1200html.write(
            "Block unknown devices and accessories by endpoint security configuration and monitoring agent.{}".format(
                footer
            )
        )
    with open(sd + "t1566.html", "w") as t1566html:
        # description
        t1566html.write(
            "{}Adversaries may send phishing messages to elicit sensitive information and/or gain access to victim systems. All forms of phishing are electronically delivered social engineering.<br>".format(
                header
            )
        )
        t1566html.write(
            "Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary.<br>"
        )
        t1566html.write(
            "More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.<br>"
        )
        t1566html.write(
            "Adversaries may send victim’s emails containing malicious attachments or links, typically to execute malicious code on victim systems or to gather credentials for use of Valid Accounts.<br>"
        )
        t1566html.write(
            "Phishing may also be conducted via third-party services, like social media platforms."
        )
        # information
        t1566html.write("{}T1566</td>\n        <td>".format(headings))  # id
        t1566html.write(
            "Windows, macOS, Linux, Office 365, SaaS</td>\n        <td>"
        )  # platforms
        t1566html.write("Initial Access</td>\n        <td>")  # tactics
        t1566html.write(
            "T1566.001: Spearphishing Attachment<br>T1566.002: Spearphishing Link<br>T1566.003: Spearphishing via Service"
        )  # sub-techniques
        # indicator regex assignments
        t1566html.write("{}.msg</li>\n        <li>".format(iocs))
        t1566html.write(".eml</li>")
        # related techniques
        t1566html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1078 target="_blank"">T1078</a></td>\n        <td>'.format(
                related
            )
        )
        t1566html.write("Valid Accounts")
        t1566html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1203 target="_blank"">T1203</a></td>\n        <td>'.format(
                insert
            )
        )
        t1566html.write("Exploitation for Client Execution")
        t1566html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1204 target="_blank"">T1204</a></td>\n        <td>'.format(
                insert
            )
        )
        t1566html.write("User Execution")
        t1566html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1534 target="_blank"">T1534</a></td>\n        <td>'.format(
                insert
            )
        )
        t1566html.write("Internal Spearphishing")
        # mitigations
        t1566html.write(
            "{}Antivirus/Antimalware</td>\n        <td>".format(mitigations)
        )
        t1566html.write(
            "Anti-virus can automatically quarantine suspicious files.{}".format(insert)
        )
        t1566html.write("Network Intrusion Prevention</td>\n        <td>")
        t1566html.write(
            "Network intrusion prevention systems and systems designed to scan and remove malicious email attachments or links can be used to block activity.{}".format(
                insert
            )
        )
        t1566html.write("Restrict Web-Based Content</td>\n        <td>")
        t1566html.write(
            "Determine if certain websites or attachment types (ex: .scr, .exe, .pif, .cpl, etc.) that can be used for phishing are necessary for business operations and consider blocking access if activity cannot be monitored well or if it poses a significant risk.{}".format(
                insert
            )
        )
        t1566html.write("Software Configuration</td>\n        <td>")
        t1566html.write(
            "Use anti-spoofing and email authentication mechanisms to filter messages based on validity checks of the sender domain (using SPF) and integrity of messages (using DKIM). Enabling these mechanisms within an organization (through policies such as DMARC) may enable recipients (intra-org and cross domain) to perform similar message filtering and validation.{}".format(
                insert
            )
        )
        t1566html.write("User Training</td>\n        <td>")
        t1566html.write(
            "Users can be trained to identify social engineering techniques and phishing emails.{}".format(
                footer
            )
        )
    with open(sd + "t1091.html", "w") as t1091html:
        # description
        t1091html.write(
            "{}Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes.<br>".format(
                header
            )
        )
        t1091html.write(
            "In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.<br>"
        )
        t1091html.write(
            "In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system."
        )
        # information
        t1091html.write("{}T1091</td>\n        <td>".format(headings))  # id
        t1091html.write("Windows</td>\n        <td>")  # platforms
        t1091html.write(
            "Initial Access, Lateral Movement</td>\n        <td>"
        )  # tactics
        t1091html.write("-")  # sub-techniques
        # indicator regex assignments
        t1091html.write("{}DISPLAY</li>\n        <li>".format(iocs))
        t1091html.write("HID</li>\n        <li>")
        t1091html.write("PCI</li>\n        <li>")
        t1091html.write("UMB</li>\n        <li>")
        t1091html.write("FDC</li>\n        <li>")
        t1091html.write("SCSI</li>\n        <li>")
        t1091html.write("STORAGE</li>\n        <li>")
        t1091html.write("USB</li>\n        <li>")
        t1091html.write("WpdBusEnumRoot</li>")
        # related techniques
        t1091html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1200 target="_blank"">T1200</a></td>\n        <td>'.format(
                related
            )
        )
        t1091html.write("Hardware Additions")
        # mitigations
        t1091html.write(
            "{}Disable or Remove Feature or Program</td>\n        <td>".format(
                mitigations
            )
        )
        t1091html.write(
            "Disable Autorun if it is unnecessary. Disallow or restrict removable media at an organizational policy level if it is not required for business operations.{}".format(
                insert
            )
        )
        t1091html.write("Limit Hardware Installation</td>\n        <td>")
        t1091html.write(
            "Limit the use of USB devices and removable media within a network.{}".format(
                footer
            )
        )
    with open(sd + "t1195.html", "w") as t1195html:
        # description
        t1195html.write(
            "{}Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.<br>".format(
                header
            )
        )
        t1195html.write(
            "Supply chain compromise can take place at any stage of the supply chain including:<ul>\n          <li>Manipulation of development tools</li>\n          <li>Manipulation of a development environment</li>\n          <li>Manipulation of source code repositories (public or private)</li>\n          <li>Manipulation of source code in open-source dependencies</li>\n          <li>Manipulation of software update/distribution mechanisms</li>\n          <li>Compromised/infected system images (multiple cases of removable media infected at the factory)</li>\n          <li>Replacement of legitimate software with modified versions</li>\n          <li>Sales of modified/counterfeit products to legitimate distributors</li>\n          <li>Shipment interdiction</li>\n        </ul>While supply chain compromise can impact any component of hardware or software, attackers looking to gain execution have often focused on malicious additions to legitimate software in software distribution or update channels.<br>"
        )
        t1195html.write(
            "Targeting may be specific to a desired victim set or malicious software may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.<br>"
        )
        t1195html.write(
            "Popular open source projects that are used as dependencies in many applications may also be targeted as a means to add malicious code to users of the dependency."
        )
        # information
        t1195html.write("{}T1195</td>\n        <td>".format(headings))  # id
        t1195html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1195html.write("Initial Access</td>\n        <td>")  # tactics
        t1195html.write(
            "T1195: Compromise Software Dependencies and Development Tools<br>T1195: Compromise Software Supply Chain<br>T1195: Compromise Hardware Supply Chain"
        )  # sub-techniques
        # indicator regex assignments
        t1195html.write("{}-".format(iocs))
        # related techniques
        t1195html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1199 target="_blank"">T1199</a></td>\n        <td>'.format(
                related
            )
        )
        t1195html.write("Trusted Relationship")
        # mitigations
        t1195html.write("{}Update Software</td>\n        <td>".format(mitigations))
        t1195html.write(
            "A patch management process should be implemented to check unused dependencies, unmaintained and/or previously vulnerable dependencies, unnecessary features, components, files, and documentation.{}".format(
                insert
            )
        )
        t1195html.write("Vulnerability Scanning</td>\n        <td>")
        t1195html.write(
            "Continuous monitoring of vulnerability sources and the use of automatic and manual code review tools should also be implemented as well.{}".format(
                footer
            )
        )
    with open(sd + "t1199.html", "w") as t1199html:
        # description
        t1199html.write(
            "{}Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship exploits an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.<br>".format(
                header
            )
        )
        t1199html.write(
            "Organizations often grant elevated access to second or third-party external providers in order to allow them to manage internal systems as well as cloud-based environments.<br>"
        )
        t1199html.write(
            "Some examples of these relationships include IT services contractors, managed security providers, infrastructure contractors (e.g. HVAC, elevators, physical security). The third-party provider's access may be intended to be limited to the infrastructure being maintained, but may exist on the same network as the rest of the enterprise.<br>"
        )
        t1199html.write(
            "As such, Valid Accounts used by the other party for access to internal network systems may be compromised and used."
        )
        # information
        t1199html.write("{}T1199</td>\n        <td>".format(headings))  # id
        t1199html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP, SaaS</td>\n        <td>"
        )  # platforms
        t1199html.write("Initial Access</td>\n        <td>")  # tactics
        t1199html.write("-")  # sub-techniques
        # indicator regex assignments
        t1199html.write("{}-".format(iocs))
        # related techniques
        t1199html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1078 target="_blank"">T1078</a></td>\n        <td>'.format(
                related
            )
        )
        t1199html.write("Valid Accounts")
        # mitigations
        t1199html.write("{}Network Segmentation</td>\n        <td>".format(mitigations))
        t1199html.write(
            "Network segmentation can be used to isolate infrastructure components that do not require broad network access.{}".format(
                insert
            )
        )
        t1199html.write("User Account Control</td>\n        <td>")
        t1199html.write(
            "Properly manage accounts and permissions used by parties in trusted relationships to minimize potential abuse by the party and if the party is compromised by an adversary.{}".format(
                footer
            )
        )
    with open(sd + "t1078.html", "w") as t1078html:
        # description
        t1078html.write(
            "{}Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.<br>".format(
                header
            )
        )
        t1078html.write(
            "Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop.<br>"
        )
        t1078html.write(
            "Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network.<br>"
        )
        t1078html.write(
            "Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.<br>"
        )
        t1078html.write(
            "The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise."
        )
        # information
        t1078html.write("{}T1078</td>\n        <td>".format(headings))  # id
        t1078html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>"
        )  # platforms
        t1078html.write(
            "Initial Access, Persistence, Privilege Escalation, Defense Evasion</td>\n        <td>"
        )  # tactics
        t1078html.write(
            "T1078: Default Accounts<br>T1078: Domain Accounts<br>T1078: Local Accounts<br>T1078: Cloud Accounts"
        )  # sub-techniques
        # indicator regex assignments
        t1078html.write("{}-".format(iocs))
        # related techniques
        t1078html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1133 target="_blank"">T1133</a></td>\n        <td>'.format(
                related
            )
        )
        t1078html.write("External Remote Services")
        t1078html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1566 target="_blank"">T1566</a></td>\n        <td>'.format(
                insert
            )
        )
        t1078html.write("Phishing")
        t1078html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1199 target="_blank"">T1199</a></td>\n        <td>'.format(
                insert
            )
        )
        t1078html.write("Trusted Relationship")
        t1078html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1556 target="_blank"">T1556</a></td>\n        <td>'.format(
                insert
            )
        )
        t1078html.write("Modify Authentication Process")
        t1078html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1112 target="_blank"">T1112</a></td>\n        <td>'.format(
                insert
            )
        )
        t1078html.write("Modify Registry")
        t1078html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1563 target="_blank"">T1563</a></td>\n        <td>'.format(
                insert
            )
        )
        t1078html.write("Remote Service Session Hijacking")
        t1078html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1021 target="_blank"">T1021</a></td>\n        <td>'.format(
                insert
            )
        )
        t1078html.write("Remote Services")
        t1078html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1485 target="_blank"">T1485</a></td>\n        <td>'.format(
                insert
            )
        )
        t1078html.write("Data Destruction")
        t1078html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1486 target="_blank"">T1486</a></td>\n        <td>'.format(
                insert
            )
        )
        t1078html.write("Data Encrypted for Impact")
        t1078html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1561 target="_blank"">T1561</a></td>\n        <td>'.format(
                insert
            )
        )
        t1078html.write("Disk Wipe")
        # mitigations
        t1078html.write(
            "{}Application Developer Guidance</td>\n        <td>".format(mitigations)
        )
        t1078html.write(
            "Ensure that applications do not store sensitive data or credentials insecurely. (e.g. plaintext credentials in code, published credentials in repositories, or credentials in public cloud storage).{}".format(
                insert
            )
        )
        t1078html.write("Password Policies</td>\n        <td>")
        t1078html.write(
            "Applications and appliances that utilize default username and password should be changed immediately after the installation, and before deployment to a production environment. When possible, applications that use SSH keys should be updated periodically and properly secured.{}".format(
                insert
            )
        )
        t1078html.write("Privileged Account Management</td>\n        <td>")
        t1078html.write(
            "Audit domain and local accounts as well as their permission levels routinely to look for situations that could allow an adversary to gain wide access by obtaining credentials of a privileged account. These audits should also include if default accounts have been enabled, or if new local accounts are created that have not be authorized. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.{}".format(
                footer
            )
        )
