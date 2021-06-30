#!/usr/bin/env python3 -tt
def doHTML(sd):
    header = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n  <head>\n    <p><font size=\"3\"><strong>Description</strong></font></p>\n      <ul>\n        <li>"
    iocs = "</li>\n      </ul>\n    <p><font size=\"3\"><strong>Indicators of Compromise</strong></font></p>\n      <ul>\n        <li>"
    headings = "</li>\n      </ul>\n  </head>\n  <body>\n    <br/>\n    <table id=\"mitre\">\n      <tr>\n        <th width=\"5%\">ID</th>\n        <th width=\"15%\">Operating Systems</th>\n        <th width=\"35%\">Tactics</th>\n        <th width=\"45%\">Sub-Techniques</th>\n      </tr>\n      <tr>\n        <td>&nbsp;"
    related = "</td>\n      </tr>\n    </table>\n    <p><br></p><p><font size=\"3\"><strong>Related Techniques</strong></font></p>\n    <table id=\"id\">\n      <tr>\n        <th width=\"5%\">ID</th>\n        <th width=\"95%\">Title</th>\n      </tr>\n      <tr>\n        <td>"
    insert = "</td>\n      </tr>\n      <tr>\n        <td>"
    mitigations = "</td>\n      </tr>\n    </table>\n    <p><br></p><p><font size=\"3\"><strong>Mitigations</strong></font></p>\n    <table id=\"id\">\n      <tr>\n        <th width=\"15%\">Mitigation</th>\n        <th width=\"85%\">Description</th>\n      </tr>\n      <tr>\n        <td>&nbsp;"
    footer = "</td>\n      </tr>\n    </table>\n    <br/>\n    <table id=\"break\">\n      <tr>\n        <th></th>\n      </tr>\n    </table>\n  </body>\n</html>"
  # Initial Access
    with open(sd+"t1189.html", "w") as t1189html:
        # descriptions
        t1189html.write("{}Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user's web browser is typically targeted for exploitation, but adversaries may also use compromised websites for non-exploitation behavior such as acquiring Application Access Token.</li>\n        <li>".format(header))
        t1189html.write("Often the website used by an adversary is one visited by a specific community, such as government, a particular industry, or region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted attack is referred to a strategic web compromise or watering hole attack. There are several known examples of this occurring.</li>\n        <li>")
        t1189html.write("Unlike Exploit Public-Facing Application, the focus of this technique is to exploit software on a client endpoint upon visiting a website. This will commonly give an adversary access to systems on the internal network instead of external systems that may be in a DMZ.</li>\n        <li>")
        t1189html.write("Adversaries may also use compromised websites to deliver a user to a malicious application designed to Steal Application Access Tokens, like OAuth tokens, to gain access to protected applications and information. These malicious applications have been delivered through popups on legitimate websites.")
        # indicator regex assignments
        t1189html.write("{}Ports: 80, 443".format(iocs))
        # details
        t1189html.write("{}T1189</td>\n        <td>&nbsp;".format(headings)) # id
        t1189html.write("Windows, macOS, Linux, SaaS</td>\n        <td>&nbsp;") # platforms
        t1189html.write("Initial Access</td>\n        <td>&nbsp;") # tactics
        t1189html.write("-") # sub-techniques
        # related techniques
        t1189html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1211 target=\"_blank\"\">&nbsp;T1211</a></td>\n        <td>&nbsp;".format(related))
        t1189html.write("Use Alternate Authentication Material: Application Access Token")
        t1189html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1528 target=\"_blank\"\">&nbsp;T1528</a></td>\n        <td>&nbsp;".format(insert))
        t1189html.write("Steal Application Access Token")
        # mitigations
        t1189html.write("{}Application Isolation and Sandboxing</td>\n        <td>&nbsp;".format(mitigations))
        t1189html.write("Browser sandboxes can be used to mitigate some of the impact of exploitation, but sandbox escapes may still exist.<br>&nbsp;Other types of virtualization and application microsegmentation may also mitigate the impact of client-side exploitation. The risks of additional exploits and weaknesses in implementation may still exist for these types of systems.{}&nbsp;".format(insert))
        t1189html.write("Exploit Protection</td>\n        <td>&nbsp;")
        t1189html.write("Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior.<br>&nbsp;Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility.{}&nbsp;".format(insert))
        t1189html.write("Restrict Web-Based Content</td>\n        <td>&nbsp;")
        t1189html.write("For malicious code served up through ads, adblockers can help prevent that code from executing in the first place.<br>&nbsp;")
        t1189html.write("Script blocking extensions can help prevent the execution of JavaScript that may commonly be used during the exploitation process{}&nbsp;".format(insert))
        t1189html.write("Update Software</td>\n        <td>&nbsp;")
        t1189html.write("Ensure all browsers and plugins kept updated can help prevent the exploit phase of this technique. Use modern browsers with security features turned on.{}".format(footer))
    with open(sd+"t1190.html", "w") as t1190html:
        # descriptions
        t1190html.write("{}Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. The weakness in the system can be a bug, a glitch, or a design vulnerability.</li>\n        <li>".format(header))
        t1190html.write("These applications are often websites, but can include databases (like SQL), standard services (like SMB or SSH), and any other applications with Internet accessible open sockets, such as web servers and related services. Depending on the flaw being exploited this may include Exploitation for Defense Evasion.</li>\n        <li>")
        t1190html.write("If an application is hosted on cloud-based infrastructure, then exploiting it may lead to compromise of the underlying instance. This can allow an adversary a path to access the cloud APIs or to take advantage of weak identity and access management policies.</li>\n        <li>")
        t1190html.write("For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.")
        # indicator regex assignments
        t1190html.write("{}-".format(iocs))
        # details
        t1190html.write("{}T1190</td>\n        <td>&nbsp;".format(headings)) # id
        t1190html.write("Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1190html.write("Initial Access</td>\n        <td>&nbsp;") # tactics
        t1190html.write("-") # sub-techniques
        # related techniques
        t1190html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1211 target=\"_blank\"\">&nbsp;T1211</a></td>\n        <td>&nbsp;".format(related))
        t1190html.write("Exploitation for Defense Evasion")
        # mitigations
        t1190html.write("{}Application Isolation and Sandboxing</td>\n        <td>&nbsp;".format(mitigations))
        t1190html.write("Application isolation will limit what other processes and system features the exploited target can access.{}&nbsp;".format(insert))
        t1190html.write("Exploit Protection</td>\n        <td>&nbsp;")
        t1190html.write("Web Application Firewalls may be used to limit exposure of applications to prevent exploit traffic from reaching the application.{}&nbsp;".format(insert))
        t1190html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1190html.write("Segment externally facing servers and services from the rest of the network with a DMZ or on separate hosting infrastructure.{}&nbsp;".format(insert))
        t1190html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1190html.write("Use least privilege for service accounts will limit what permissions the exploited process gets on the rest of the system.{}&nbsp;".format(insert))
        t1190html.write("Update Software</td>\n        <td>&nbsp;")
        t1190html.write("Regularly scan externally facing systems for vulnerabilities and establish procedures to rapidly patch systems when critical vulnerabilities are discovered through scanning and through public disclosure.{}&nbsp;".format(insert))
        t1190html.write("Vulnerability Scanning</td>\n        <td>&nbsp;")
        t1190html.write("Regularly scan externally facing systems for vulnerabilities and establish procedures to rapidly patch systems when critical vulnerabilities are discovered through scanning and through public disclosure.{}".format(footer))
    with open(sd+"t1133.html", "w") as t1133html:
        # descriptions
        t1133html.write("{}Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations.</li>\n        <li>".format(header))
        t1133html.write("There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management can also be used externally.</li>\n        <li>")
        t1133html.write("Access to Valid Accounts to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.</li>\n        <li>")
        t1133html.write("Access to remote services may be used as a redundant or persistent access mechanism during an operation.")
        # indicator regex assignments
        t1133html.write("{}Ports: 22, 23, 139, 445".format(iocs))
        # details
        t1133html.write("{}T1133</td>\n        <td>&nbsp;".format(headings)) # id
        t1133html.write("Windows, Linux</td>\n        <td>&nbsp;") # platforms
        t1133html.write("Initial Access, Persistence</td>\n        <td>&nbsp;") # tactics
        t1133html.write("-") # sub-techniques
        # related techniques
        t1133html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1021 target=\"_blank\"\">&nbsp;T1021</a></td>\n        <td>&nbsp;".format(related))
        t1133html.write("Remote Services: Windows Remote Management")
        t1133html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1078 target=\"_blank\"\">&nbsp;T1078</a></td>\n        <td>&nbsp;".format(insert))
        t1133html.write("Valid Accounts")
        # mitigations
        t1133html.write("{}Disable or Remove Feature or Program</td>\n        <td>&nbsp;".format(mitigations))
        t1133html.write("Disable or block remotely available services that may be unnecessary.{}&nbsp;".format(insert))
        t1133html.write("Limit Access to Resource Over Network</td>\n        <td>&nbsp;")
        t1133html.write("Limit access to remote services through centrally managed concentrators such as VPNs and other managed remote access systems.{}&nbsp;".format(insert))
        t1133html.write("Multi-factor Authentication</td>\n        <td>&nbsp;")
        t1133html.write("Use strong two-factor or multi-factor authentication for remote service accounts to mitigate an adversary's ability to leverage stolen credentials, but be aware of Two-Factor Authentication Interception techniques for some two-factor authentication implementations.{}&nbsp;".format(insert))
        t1133html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1133html.write("Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.{}".format(footer))
    with open(sd+"t1200.html", "w") as t1200html:
        # descriptions
        t1200html.write("{}Adversaries may introduce computer accessories, computers, or networking hardware into a system or network that can be used as a vector to gain access.</li>\n        <li>".format(header))
        t1200html.write("While public references of usage by APT groups are scarce, many penetration testers leverage hardware additions for initial access.</li>\n        <li>")
        t1200html.write("Commercial and open source products are leveraged with capabilities such as passive network tapping, man-in-the middle encryption breaking, keystroke injection, kernel memory reading via DMA, adding new wireless access to an existing network, and others<li>")
        # indicator regex assignments
        t1200html.write("{}DISPLAY</li>\n        <li>".format(iocs))
        t1200html.write("HID</li>\n        <li>")
        t1200html.write("PCI</li>\n        <li>")
        t1200html.write("IDE</li>\n        <li>")
        t1200html.write("ROOT</li>\n        <li>")
        t1200html.write("UMB</li>\n        <li>")
        t1200html.write("FDC</li>\n        <li>")
        t1200html.write("IDE</li>\n        <li>")
        t1200html.write("SCSI</li>\n        <li>")
        t1200html.write("STORAGE</li>\n        <li>")
        t1200html.write("USBSTOR</li>\n        <li>")
        t1200html.write("USB</li>\n        <li>")
        t1200html.write("WpdBusEnumRoot")
        # details
        t1200html.write("{}T1200</td>\n        <td>&nbsp;".format(headings)) # id
        t1200html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1200html.write("Initial Access</td>\n        <td>&nbsp;") # tactics
        t1200html.write("-") # sub-techniques
        # related techniques
        t1200html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1091 target=\"_blank\"\">&nbsp;T1091</a></td>\n        <td>&nbsp;".format(related))
        t1200html.write("Replication Through Removable Media")
        # mitigations
        t1200html.write("{}Limit Access to Resource Over Network</td>\n        <td>&nbsp;".format(mitigations))
        t1200html.write("Establish network access control policies, such as using device certificates and the 802.1x standard. Restrict use of DHCP to registered devices to prevent unregistered devices from communicating with trusted systems.{}&nbsp;".format(insert))
        t1200html.write("Limit Hardware Installation</td>\n        <td>&nbsp;")
        t1200html.write("Block unknown devices and accessories by endpoint security configuration and monitoring agent.{}".format(footer))
    with open(sd+"t1566.html", "w") as t1566html:
        # descriptions
        t1566html.write("{}Adversaries may send phishing messages to elicit sensitive information and/or gain access to victim systems. All forms of phishing are electronically delivered social engineering.</li>\n        <li>".format(header))
        t1566html.write("Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary.</li>\n        <li>")
        t1566html.write("More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.</li>\n        <li>")
        t1566html.write("Adversaries may send victim’s emails containing malicious attachments or links, typically to execute malicious code on victim systems or to gather credentials for use of Valid Accounts.</li>\n        <li>")
        t1566html.write("Phishing may also be conducted via third-party services, like social media platforms.")
        # indicator regex assignments
        t1566html.write("{}.msg</li>\n        <li>".format(iocs))
        t1566html.write(".eml")
        # details
        t1566html.write("{}T1566</td>\n        <td>&nbsp;".format(headings)) # id
        t1566html.write("Windows, macOS, Linux, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1566html.write("Initial Access</td>\n        <td>&nbsp;") # tactics
        t1566html.write("T1566.001: Spearphishing Attachment<br>&nbsp;T1566.002: Spearphishing Link<br>&nbsp;T1566.003: Spearphishing via Service") # sub-techniques
        # related techniques
        t1566html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1078 target=\"_blank\"\">&nbsp;T1078</a></td>\n        <td>&nbsp;".format(related))
        t1566html.write("Valid Accounts")
        t1566html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1203 target=\"_blank\"\">&nbsp;T1203</a></td>\n        <td>&nbsp;".format(insert))
        t1566html.write("Exploitation for Client Execution")
        t1566html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1204 target=\"_blank\"\">&nbsp;T1204</a></td>\n        <td>&nbsp;".format(insert))
        t1566html.write("User Execution")
        t1566html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1534 target=\"_blank\"\">&nbsp;T1534</a></td>\n        <td>&nbsp;".format(insert))
        t1566html.write("Internal Spearphishing")
        # mitigations
        t1566html.write("{}Antivirus/Antimalware</td>\n        <td>&nbsp;".format(mitigations))
        t1566html.write("Anti-virus can automatically quarantine suspicious files.{}&nbsp;".format(insert))
        t1566html.write("Network Intrusion Prevention</td>\n        <td>&nbsp;")
        t1566html.write("Network intrusion prevention systems and systems designed to scan and remove malicious email attachments or links can be used to block activity.{}&nbsp;".format(insert))
        t1566html.write("Restrict Web-Based Content</td>\n        <td>&nbsp;")
        t1566html.write("Determine if certain websites or attachment types (ex: .scr, .exe, .pif, .cpl, etc.) that can be used for phishing are necessary for business operations and consider blocking access if activity cannot be monitored well or if it poses a significant risk.{}&nbsp;".format(insert))
        t1566html.write("Software Configuration</td>\n        <td>&nbsp;")
        t1566html.write("Use anti-spoofing and email authentication mechanisms to filter messages based on validity checks of the sender domain (using SPF) and integrity of messages (using DKIM). Enabling these mechanisms within an organization (through policies such as DMARC) may enable recipients (intra-org and cross domain) to perform similar message filtering and validation.{}&nbsp;".format(insert))
        t1566html.write("User Training</td>\n        <td>&nbsp;")
        t1566html.write("Users can be trained to identify social engineering techniques and phishing emails.{}".format(footer))
    with open(sd+"t1091.html", "w") as t1091html:
        # descriptions
        t1091html.write("{}Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes.</li>\n        <li>".format(header))
        t1091html.write("In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.</li>\n        <li>")
        t1091html.write("In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system.")
        # indicator regex assignments
        t1091html.write("{}DISPLAY</li>\n        <li>".format(iocs))
        t1091html.write("HID</li>\n        <li>")
        t1091html.write("PCI</li>\n        <li>")
        t1091html.write("IDE</li>\n        <li>")
        t1091html.write("ROOT</li>\n        <li>")
        t1091html.write("UMB</li>\n        <li>")
        t1091html.write("FDC</li>\n        <li>")
        t1091html.write("IDE</li>\n        <li>")
        t1091html.write("SCSI</li>\n        <li>")
        t1091html.write("STORAGE</li>\n        <li>")
        t1091html.write("USBSTOR</li>\n        <li>")
        t1091html.write("USB</li>\n        <li>")
        t1091html.write("WpdBusEnumRoot")
        # details
        t1091html.write("{}T1091</td>\n        <td>&nbsp;".format(headings)) # id
        t1091html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1091html.write("Initial Access, Lateral Movement</td>\n        <td>&nbsp;") # tactics
        t1091html.write("-") # sub-techniques
        # related techniques
        t1091html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1200 target=\"_blank\"\">&nbsp;T1200</a></td>\n        <td>&nbsp;".format(related))
        t1091html.write("Hardware Additions")
        # mitigations
        t1091html.write("{}Disable or Remove Feature or Program</td>\n        <td>&nbsp;".format(mitigations))
        t1091html.write("Disable Autorun if it is unnecessary. Disallow or restrict removable media at an organizational policy level if it is not required for business operations.{}&nbsp;".format(insert))
        t1091html.write("Limit Hardware Installation</td>\n        <td>&nbsp;")
        t1091html.write("Limit the use of USB devices and removable media within a network.{}".format(footer))
    with open(sd+"t1195.html", "w") as t1195html:
        # descriptions
        t1195html.write("{}Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.</li>\n        <li>".format(header))
        t1195html.write("Supply chain compromise can take place at any stage of the supply chain including:</li>\n        <ul>\n          <li>Manipulation of development tools</li>\n          <li>Manipulation of a development environment</li>\n          <li>Manipulation of source code repositories (public or private)</li>\n          <li>Manipulation of source code in open-source dependencies</li>\n          <li>Manipulation of software update/distribution mechanisms</li>\n          <li>Compromised/infected system images (multiple cases of removable media infected at the factory)</li>\n          <li>Replacement of legitimate software with modified versions</li>\n          <li>Sales of modified/counterfeit products to legitimate distributors</li>\n          <li>Shipment interdiction</li>\n        </ul>\n        <li>While supply chain compromise can impact any component of hardware or software, attackers looking to gain execution have often focused on malicious additions to legitimate software in software distribution or update channels.</li>\n        <li>")
        t1195html.write("Targeting may be specific to a desired victim set or malicious software may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.</li>\n        <li>")
        t1195html.write("Popular open source projects that are used as dependencies in many applications may also be targeted as a means to add malicious code to users of the dependency.")
        # indicator regex assignments
        t1195html.write("{}-".format(iocs))
        # details
        t1195html.write("{}T1195</td>\n        <td>&nbsp;".format(headings)) # id
        t1195html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1195html.write("Initial Access</td>\n        <td>&nbsp;") # tactics
        t1195html.write("T1195: Compromise Software Dependencies and Development Tools<br>&nbsp;T1195: Compromise Software Supply Chain<br>&nbsp;T1195: Compromise Hardware Supply Chain") # sub-techniques
        # related techniques
        t1195html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1199 target=\"_blank\"\">&nbsp;T1199</a></td>\n        <td>&nbsp;".format(related))
        t1195html.write("Trusted Relationship")
        # mitigations
        t1195html.write("{}Update Software</td>\n        <td>&nbsp;".format(mitigations))
        t1195html.write("A patch management process should be implemented to check unused dependencies, unmaintained and/or previously vulnerable dependencies, unnecessary features, components, files, and documentation.{}&nbsp;".format(insert))
        t1195html.write("Vulnerability Scanning</td>\n        <td>&nbsp;")
        t1195html.write("Continuous monitoring of vulnerability sources and the use of automatic and manual code review tools should also be implemented as well.{}".format(footer))
    with open(sd+"t1199.html", "w") as t1199html:
        # descriptions
        t1199html.write("{}Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship exploits an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.</li>\n        <li>".format(header))
        t1199html.write("Organizations often grant elevated access to second or third-party external providers in order to allow them to manage internal systems as well as cloud-based environments.</li>\n        <li>")
        t1199html.write("Some examples of these relationships include IT services contractors, managed security providers, infrastructure contractors (e.g. HVAC, elevators, physical security). The third-party provider's access may be intended to be limited to the infrastructure being maintained, but may exist on the same network as the rest of the enterprise.</li>\n        <li>")
        t1199html.write("As such, Valid Accounts used by the other party for access to internal network systems may be compromised and used.")
        # indicator regex assignments
        t1199html.write("{}-".format(iocs))
        # details
        t1199html.write("{}T1199</td>\n        <td>&nbsp;".format(headings)) # id
        t1199html.write("Windows, macOS, Linux, AWS, Azure, GCP, SaaS</td>\n        <td>&nbsp;") # platforms
        t1199html.write("Initial Access</td>\n        <td>&nbsp;") # tactics
        t1199html.write("-") # sub-techniques
        # related techniques
        t1199html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1078 target=\"_blank\"\">&nbsp;T1078</a></td>\n        <td>&nbsp;".format(related))
        t1199html.write("Valid Accounts")
        # mitigations
        t1199html.write("{}Network Segmentation</td>\n        <td>&nbsp;".format(mitigations))
        t1199html.write("Network segmentation can be used to isolate infrastructure components that do not require broad network access.{}&nbsp;".format(insert))
        t1199html.write("User Account Control</td>\n        <td>&nbsp;")
        t1199html.write("Properly manage accounts and permissions used by parties in trusted relationships to minimize potential abuse by the party and if the party is compromised by an adversary.{}".format(footer))
    with open(sd+"t1078.html", "w") as t1078html:
        # descriptions
        t1078html.write("{}Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.</li>\n        <li>".format(header))
        t1078html.write("Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop.</li>\n        <li>")
        t1078html.write("Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network.</li>\n        <li>")
        t1078html.write("Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.</li>\n        <li>")
        t1078html.write("The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.")
        # indicator regex assignments
        t1078html.write("{}-".format(iocs))
        # details
        t1078html.write("{}T1078</td>\n        <td>&nbsp;".format(headings)) # id
        t1078html.write("Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1078html.write("Initial Access, Persistence, Privilege Escalation, Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1078html.write("T1078: Default Accounts<br>&nbsp;T1078: Domain Accounts<br>&nbsp;T1078: Local Accounts<br>&nbsp;T1078: Cloud Accounts") # sub-techniques
        # related techniques
        t1078html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1133 target=\"_blank\"\">&nbsp;T1133</a></td>\n        <td>&nbsp;".format(related))
        t1078html.write("External Remote Services")
        t1078html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1566 target=\"_blank\"\">&nbsp;T1566</a></td>\n        <td>&nbsp;".format(insert))
        t1078html.write("Phishing")
        t1078html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1199 target=\"_blank\"\">&nbsp;T1199</a></td>\n        <td>&nbsp;".format(insert))
        t1078html.write("Trusted Relationship")
        t1078html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1556 target=\"_blank\"\">&nbsp;T1556</a></td>\n        <td>&nbsp;".format(insert))
        t1078html.write("Modify Authentication Process")
        t1078html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1112 target=\"_blank\"\">&nbsp;T1112</a></td>\n        <td>&nbsp;".format(insert))
        t1078html.write("Modify Registry")
        t1078html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1563 target=\"_blank\"\">&nbsp;T1563</a></td>\n        <td>&nbsp;".format(insert))
        t1078html.write("Remote Service Session Hijacking")
        t1078html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1021 target=\"_blank\"\">&nbsp;T1021</a></td>\n        <td>&nbsp;".format(insert))
        t1078html.write("Remote Services")
        t1078html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1485 target=\"_blank\"\">&nbsp;T1485</a></td>\n        <td>&nbsp;".format(insert))
        t1078html.write("Data Destruction")
        t1078html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1486 target=\"_blank\"\">&nbsp;T1486</a></td>\n        <td>&nbsp;".format(insert))
        t1078html.write("Data Encrypted for Impact")
        t1078html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1561 target=\"_blank\"\">&nbsp;T1561</a></td>\n        <td>&nbsp;".format(insert))
        t1078html.write("Disk Wipe")
        # mitigations
        t1078html.write("{}Application Developer Guidance</td>\n        <td>&nbsp;".format(mitigations))
        t1078html.write("Ensure that applications do not store sensitive data or credentials insecurely. (e.g. plaintext credentials in code, published credentials in repositories, or credentials in public cloud storage).{}&nbsp;".format(insert))
        t1078html.write("Password Policies</td>\n        <td>&nbsp;")
        t1078html.write("Applications and appliances that utilize default username and password should be changed immediately after the installation, and before deployment to a production environment. When possible, applications that use SSH keys should be updated periodically and properly secured.{}&nbsp;".format(insert))
        t1078html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1078html.write("Audit domain and local accounts as well as their permission levels routinely to look for situations that could allow an adversary to gain wide access by obtaining credentials of a privileged account. These audits should also include if default accounts have been enabled, or if new local accounts are created that have not be authorized. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.{}".format(footer))
  # Execution
    with open(sd+"t1059.html", "w") as t1059html:
        # descriptions
        t1059html.write("{}Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of Unix Shell while Windows installations include the Windows Command Shell and PowerShell.</li>\n        <li>".format(header))
        t1059html.write("There are also cross-platform interpreters such as Python, as well as those commonly associated with client applications such as JavaScript and Visual Basic.</li>\n        <li>")
        t1059html.write("Adversaries may abuse IPC to execute arbitrary code or commands. IPC mechanisms may differ depending on OS, but typically exists in a form accessible through programming languages/libraries or native interfaces such as Windows Dynamic Data Exchange or Component Object Model.</li>\n        <li>")
        t1059html.write("Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in Initial Access payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells.")
        # indicator regex assignments
        t1059html.write("{}.ps1</li>\n        <li>".format(iocs))
        t1059html.write(".py</li>\n        <li>")
        t1059html.write("PowerShell</li>\n        <li>")
        t1059html.write("cmd</li>\n        <li>")
        t1059html.write("Invoke-Command</li>\n        <li>")
        t1059html.write("Start-Process</li>\n        <li>")
        t1059html.write("vbscript</li>\n        <li>")
        t1059html.write("wscript</li>\n        <li>")
        t1059html.write("system.management.automation")
        # details
        t1059html.write("{}T1059</td>\n        <td>&nbsp;".format(headings)) # id
        t1059html.write("Windows, macOS, Linux, Network</td>\n        <td>&nbsp;") # platforms
        t1059html.write("Execution</td>\n        <td>&nbsp;") # tactics
        t1059html.write("T1059.001: PowerShell<br>&nbsp;T1059.002: AppleScript<br>&nbsp;T1059.003: Windows Command Shell<br>&nbsp;T1059.004: Unix Shell<br>&nbsp;T1059.005: Visual Basic<br>&nbsp;T1059.006: Python<br>&nbsp;T1059.007: JavaScript<br>&nbsp;T1059.008: Network Device CLI") # sub-techniques
        # related techniques - unfinished MANY
        t1059html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1559 target=\"_blank\"\">&nbsp;T1559</a></td>\n        <td>&nbsp;".format(related))
        t1059html.write("Inter-Process Communication")
        t1059html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1106 target=\"_blank\"\">&nbsp;T1106</a></td>\n        <td>&nbsp;".format(insert))
        t1059html.write("Native API")
        t1059html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1197 target=\"_blank\"\">&nbsp;T1197</a></td>\n        <td>&nbsp;".format(insert))
        t1059html.write("BITS Job")
        t1059html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1202 target=\"_blank\"\">&nbsp;T1202</a></td>\n        <td>&nbsp;".format(insert))
        t1059html.write("Indirect Command Execution")
        t1059html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1027 target=\"_blank\"\">&nbsp;T1027</a></td>\n        <td>&nbsp;".format(insert))
        t1059html.write("Obfuscated Files or Information")
        t1059html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1056 target=\"_blank\"\">&nbsp;T1056</a></td>\n        <td>&nbsp;".format(insert))
        t1059html.write("Input Capture")
        t1059html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1613 target=\"_blank\"\">&nbsp;T1613</a></td>\n        <td>&nbsp;".format(insert))
        t1059html.write("Container and Resource Discovery")
        t1059html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1057 target=\"_blank\"\">&nbsp;T1057</a></td>\n        <td>&nbsp;".format(insert))
        t1059html.write("Process Discovery")
        t1059html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1119 target=\"_blank\"\">&nbsp;T1119</a></td>\n        <td>&nbsp;".format(insert))
        t1059html.write("Automated Collection")
        t1059html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1005 target=\"_blank\"\">&nbsp;T1005</a></td>\n        <td>&nbsp;".format(insert))
        t1059html.write("Data from Local System")
        # mitigations
        t1059html.write("{}Antivirus/Antimalware</td>\n        <td>&nbsp;".format(mitigations))
        t1059html.write("Anti-virus can be used to automatically quarantine suspicious files.{}&nbsp;".format(insert))
        t1059html.write("Code Signing</td>\n        <td>&nbsp;")
        t1059html.write("Where possible, only permit execution of signed scripts.{}&nbsp;".format(insert))
        t1059html.write("Disable or Remove Feature or Program</td>\n        <td>&nbsp;")
        t1059html.write("Disable or remove any unnecessary or unused shells or interpreters.{}&nbsp;".format(insert))
        t1059html.write("Execution Prevention</td>\n        <td>&nbsp;")
        t1059html.write("Use application control where appropriate.{}&nbsp;".format(insert))
        t1059html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1059html.write("When PowerShell is necessary, restrict PowerShell execution policy to administrators. Be aware that there are methods of bypassing the PowerShell execution policy, depending on environment configuration.{}&nbsp;".format(insert))
        t1059html.write("Restrict Web-Based Content</td>\n        <td>&nbsp;")
        t1059html.write("Script blocking extensions can help prevent the execution of scripts and HTA files that may commonly be used during the exploitation process. For malicious code served up through ads, adblockers can help prevent that code from executing in the first place.{}".format(footer))
    with open(sd+"t1609.html", "w") as t1609html:
        # descriptions
        t1609html.write("{}Adversaries may abuse a container administration service to execute commands within a container. A container administration service such as the Docker daemon, the Kubernetes API server, or the kubelet may allow remote management of containers within an environment.</li>\n        <li>".format(header))
        t1609html.write("In Docker, adversaries may specify an entrypoint during container deployment that executes a script or command, or they may use a command such as docker exec to execute a command within a running container.</li>\n        <li>")
        t1609html.write("In Kubernetes, if an adversary has sufficient permissions, they may gain remote execution in a container in the cluster via interaction with the Kubernetes API server, the kubelet, or by running a command such as kubectl exec.")
        t1609html.write("docker exec</li>\n        <li>")
        t1609html.write("kubectl exec</li>")
        # details
        t1609html.write("{}T1609</td>\n        <td>&nbsp;".format(headings)) # id
        t1609html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1609html.write("Execution</td>\n        <td>&nbsp;") # tactics
        t1609html.write("-") # sub-techniques
        # related techniques
        t1609html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1610 target=\"_blank\"\">&nbsp;T1610</a></td>\n        <td>&nbsp;".format(related))
        t1609html.write("Deploy Container")
        # mitigations
        t1609html.write("{}Execution Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1609html.write("Use read-only containers and minimal images when possible to prevent the execution of commands.{}&nbsp;".format(insert))
        t1609html.write("Limit Access to Resource Over Network</td>\n        <td>&nbsp;")
        t1609html.write("Limit communications with the container service to local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API and Kubernetes API Server.{}&nbsp;".format(insert))
        t1609html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1609html.write("Ensure containers are not running as root by default.{}".format(footer))
    with open(sd+"t1610.html", "w") as t1610html:
        # descriptions
        t1610html.write("{}Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware. In others, an adversary may deploy a new container configured without network rules, user limitations, etc. to bypass existing defenses within the environment.</li>\n        <li>".format(header))
        t1610html.write("Containers can be deployed by various means, such as via Docker's create and start APIs or via a web application such as the Kubernetes dashboard or Kubeflow. Adversaries may deploy containers based on retrieved or built malicious images or from benign images that download and execute malicious payloads at runtime.")
        t1610html.write("docker create</li>\n        <li>")
        t1610html.write("docker start</li>")
        # details
        t1610html.write("{}T1610</td>\n        <td>&nbsp;".format(headings)) # id
        t1610html.write("Containers</td>\n        <td>&nbsp;") # platforms
        t1610html.write("Execution</td>\n        <td>&nbsp;") # tactics
        t1610html.write("-") # sub-techniques
        # related techniques
        t1610html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1609 target=\"_blank\"\">&nbsp;T1609</a></td>\n        <td>&nbsp;".format(related))
        t1610html.write("Container Administration Command")
        # mitigations
        t1610html.write("{}Limit Access to Resource Over Network</td>\n        <td>&nbsp;".format(mitigations))
        t1610html.write("Limit communications with the container service to local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API, Kubernetes API Server, and container orchestration web applications.{}&nbsp;".format(insert))
        t1610html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1610html.write("Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.{}&nbsp;".format(insert))
        t1610html.write("User Account Management</td>\n        <td>&nbsp;")
        t1610html.write("Enforce the principle of least privilege by limiting container dashboard access to only the necessary users.{}".format(footer))
    with open(sd+"t1203.html", "w") as t1203html:
        # descriptions
        t1203html.write("{}Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior.</li>\n        <li>".format(header))
        t1203html.write("Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution.</li>\n        <li>")
        t1203html.write("Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system.</li>\n        <li>")
        t1203html.write("Users will expect to see files related to the applications they commonly used to do work, so they are a useful target for exploit research and development because of their high utility.</li>\n        <li>")
        t1203html.write("Several types exist:</li>\n        <ul>\n          <li>Browser-based Exploitation</li>\n          <ul>\n            <li>Web browsers are a common target through Drive-by Compromise and Spearphishing Link.</li>\n            <li>Endpoint systems may be compromised through normal web browsing or from certain users being targeted by links in spearphishing emails to adversary controlled sites used to exploit the web browser.</li>\n            <li>These often do not require an action by the user for the exploit to be executed.\n          </ul>\n          <li>Office Applications</li>\n          <ul>\n            <li>Common office and productivity applications such as Microsoft Office are also targeted through Phishing.</li>\n            <li>Malicious files will be transmitted directly as attachments or through links to download them.</li>\n            <li>These require the user to open the document or file for the exploit to run.\n          </ul>\n          <li>Common Third-party Applications</li>\n          <ul>\n            <li>Other applications that are commonly seen or are part of the software deployed in a target network may also be used for exploitation.</li>\n            <li>Applications such as Adobe Reader and Flash, which are common in enterprise environments, have been routinely targeted by adversaries attempting to gain access to systems.</li>\n            <li>Depending on the software and nature of the vulnerability, some may be exploited in the browser or require the user to open a file.</li>\n            <li>For instance, some Flash exploits have been delivered as objects within Microsoft Office documents.")
        # indicator regex assignments
        t1203html.write("{}.doc</li>\n        <li>".format(iocs))
        t1203html.write(".xls</li>\n        <li>")
        t1203html.write(".ppt</li>\n        <li>")
        t1203html.write(".pdf</li>\n        <li>")
        t1203html.write("WinWord</li>\n        <li>")
        t1203html.write("Excel</li>\n        <li>")
        t1203html.write("PowerPnt</li>\n        <li>")
        t1203html.write("Acrobat</li>\n        <li>")
        t1203html.write("Acrord32")
        # details
        t1203html.write("{}T1203</td>\n        <td>&nbsp;".format(headings)) # id
        t1203html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1203html.write("Execution</td>\n        <td>&nbsp;") # tactics
        t1203html.write("-") # sub-techniques
        # related techniques
        t1203html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1189 target=\"_blank\"\">&nbsp;T1189</a></td>\n        <td>&nbsp;".format(related))
        t1203html.write("Drive-by Compromise")
        t1203html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1566 target=\"_blank\"\">&nbsp;T1566</a></td>\n        <td>&nbsp;".format(insert))
        t1203html.write("Phishing")
        t1203html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1204 target=\"_blank\"\">&nbsp;T1204</a></td>\n        <td>&nbsp;".format(insert))
        t1203html.write("User Execution")
        # mitigations
        t1203html.write("{}Application Isolation and Sandboxing</td>\n        <td>&nbsp;".format(mitigations))
        t1203html.write("Browser sandboxes can be used to mitigate some of the impact of exploitation, but sandbox escapes may still exist.<br>&nbsp;Other types of virtualization and application microsegmentation may also mitigate the impact of client-side exploitation. The risks of additional exploits and weaknesses in implementation may still exist for these types of systems.</td>\n      </tr>\n      <tr>\n        <td>&nbsp;".format(insert))
        t1203html.write("Exploit Protection</td>\n        <td>&nbsp;")
        t1203html.write("Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior.<br>&nbsp;Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility.")
    with open(sd+"t1559.html", "w") as t1559html:
        # descriptions
        t1559html.write("{}Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution. IPC is also commonly used to avoid situations such as deadlocks, which occurs when processes are stuck in a cyclic waiting pattern.</li>\n        <li>".format(header))
        t1559html.write("Adversaries may abuse IPC to execute arbitrary code or commands. IPC mechanisms may differ depending on OS, but typically exists in a form accessible through programming languages/libraries or native interfaces such as Windows Dynamic Data Exchange or Component Object Model. Higher level execution mediums, such as those of Command and Scripting Interpreters, may also leverage underlying IPC mechanisms.")
        # indicator regex assignments
        t1559html.write("{}.docm</li>\n        <li>".format(iocs))
        t1559html.write(".xlsm</li>\n        <li>")
        t1559html.write(".pptm</li>\n        <li>")
        t1559html.write("IPC$")
        # details
        t1559html.write("{}T1559</td>\n        <td>&nbsp;".format(headings)) # id
        t1559html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1559html.write("Execution</td>\n        <td>&nbsp;") # tactics
        t1559html.write("T1559.001: Component Object Model<br>&nbsp;T1559.002: Dynamic Data Exchange") # sub-techniques
        # related techniques
        t1559html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1059 target=\"_blank\"\">&nbsp;T1059</a></td>\n        <td>&nbsp;".format(related))
        t1559html.write("Command and Scripting Interpreter")
        t1559html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1106 target=\"_blank\"\">&nbsp;T1106</a></td>\n        <td>&nbsp;".format(insert))
        t1559html.write("Native API")
        t1559html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1197 target=\"_blank\"\">&nbsp;T1197</a></td>\n        <td>&nbsp;".format(insert))
        t1559html.write("BITS Jobs")
        # mitigations
        t1559html.write("{}Antivirus/Antimalware</td>\n        <td>&nbsp;".format(mitigations))
        t1559html.write("Anti-virus can be used to automatically quarantine suspicious files.{}&nbsp;".format(insert))
        t1559html.write("Code Signing</td>\n        <td>&nbsp;")
        t1559html.write("Where possible, only permit execution of signed scripts.{}&nbsp;".format(insert))
        t1559html.write("Disable or Remove Feature or Program</td>\n        <td>&nbsp;")
        t1559html.write("Disable or remove any unnecessary or unused shells or interpreters.{}&nbsp;".format(insert))
        t1559html.write("Execution Prevention</td>\n        <td>&nbsp;")
        t1559html.write("Use application control where appropriate.{}&nbsp;".format(insert))
        t1559html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1559html.write("When PowerShell is necessary, restrict PowerShell execution policy to administrators. Be aware that there are methods of bypassing the PowerShell execution policy, depending on environment configuration.{}&nbsp;".format(insert))
        t1559html.write("Restrict Web-Based Content</td>\n        <td>&nbsp;")
        t1559html.write("Script blocking extensions can help prevent the execution of scripts and HTA files that may commonly be used during the exploitation process. For malicious code served up through ads, adblockers can help prevent that code from executing in the first place.{}".format(footer))
    with open(sd+"t1106.html", "w") as t1106html:
        # descriptions
        t1106html.write("{}Adversaries may directly interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes.</li>\n        <li>".format(header))
        t1106html.write("These native APIs are leveraged by the OS during system boot (when other system components are not yet initialized) as well as carrying out tasks and requests during routine operations.</li>\n        <li>")
        t1106html.write("Functionality provided by native APIs are often also exposed to user-mode applications via interfaces and libraries. For example, functions such as the Windows API CreateProcess() or GNU fork() will allow programs and scripts to start other processes.</li>\n        <li>")
        t1106html.write("This may allow API callers to execute a binary, run a CLI command, load modules, etc. as thousands of similar API functions exist for various system operations.</li>\n        <li>")
        t1106html.write("Higher level software frameworks, such as Microsoft .NET and macOS Cocoa, are also available to interact with native APIs. These frameworks typically provide language wrappers/abstractions to API functionalities and are designed for ease-of-use/portability of code.</li>\n        <li>")
        t1106html.write("Adversaries may abuse these native API functions as a means of executing behaviors. Similar to Command and Scripting Interpreter, the native API and its hierarchy of interfaces, provide mechanisms to interact with and utilize various components of a victimized system.")
        # indicator regex assignments
        t1106html.write("{}PowerShell</li>\n        <li>".format(iocs))
        t1106html.write("cmd.exe</li>\n        <li>")
        t1106html.write("contentsOfDirectoryAtPath")
        t1106html.write("pathExtension")
        t1106html.write("compare")
        t1106html.write("fork")
        t1106html.write("CreateProcess")
        t1106html.write("CreateRemoteThread")
        t1106html.write("LoadLibrary")
        t1106html.write("ShellExecute")
        t1106html.write("IsDebuggerPresent")
        t1106html.write("OutputDebugString")
        t1106html.write("SetLastError")
        t1106html.write("HttpOpenRequestA")
        t1106html.write("CreatePipe")
        t1106html.write("GetUserNameW")
        t1106html.write("CallWindowProc")
        t1106html.write("EnumResourceTypesA")
        t1106html.write("ConnectNamedPipe")
        t1106html.write("WNetAddConnection2")
        t1106html.write("ZwWriteVirtualMemory")
        t1106html.write("ZwProtectVirtualMemory")
        t1106html.write("ZwQueueApcThread")
        t1106html.write("NtResumeThread")
        t1106html.write("TerminateProcess")
        t1106html.write("GetModuleFileName")
        t1106html.write("lstrcat")
        t1106html.write("CreateFile")
        t1106html.write("ReadFile")
        t1106html.write("GetProcessById")
        t1106html.write("WriteFile")
        t1106html.write("CloseHandle")
        t1106html.write("GetCurrentHwProfile")
        t1106html.write("GetProcAddress")
        t1106html.write("FindNextUrlCacheEntryA")
        t1106html.write("FindFirstUrlCacheEntryA")
        t1106html.write("GetWindowsDirectoryW")
        t1106html.write("MoveFileEx")
        t1106html.write("NtQueryInformationProcess")
        t1106html.write("RegEnumKeyW")
        t1106html.write("SetThreadContext")
        t1106html.write("VirtualAlloc")
        t1106html.write("WinExec")
        t1106html.write("WriteProcessMemory")
        # details
        t1106html.write("{}T1106</td>\n        <td>&nbsp;".format(headings)) # id
        t1106html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1106html.write("Execution</td>\n        <td>&nbsp;") # tactics
        t1106html.write("-") # sub-techniques
        # related techniques
        t1106html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1059 target=\"_blank\"\">&nbsp;T1059</a></td>\n        <td>&nbsp;".format(related))
        t1106html.write("Command and Scripting Interpreter")
        t1106html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1559 target=\"_blank\"\">&nbsp;T1559</a></td>\n        <td>&nbsp;".format(insert))
        t1106html.write("Inter-Process Communication")
        t1106html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1129 target=\"_blank\"\">&nbsp;T1129</a></td>\n        <td>&nbsp;".format(insert))
        t1106html.write("Shared Modules")
        # mitigations
        t1106html.write("{}Execution Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1106html.write("Identify and block potentially malicious software executed that may be executed through this technique by using application control tools, like Windows Defender Application Control[90], AppLocker, or Software Restriction Policies where appropriate.{}".format(footer))
    with open(sd+"t1053.html", "w") as t1053html:
        # descriptions
        t1053html.write("{}Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time.</li>\n        <li>".format(header))
        t1053html.write("A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments).</li>\n        <li>")
        t1053html.write("Scheduling a task on a remote system typically requires being a member of an admin or otherwise privileged group on the remote system.</li>\n        <li>")
        t1053html.write("Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges).")
        # indicator regex assignments
        t1053html.write("{}schtask</li>\n        <li>".format(iocs))
        t1053html.write("at</li>\n        <li>")
        t1053html.write(".job")
        # details
        t1053html.write("{}T1133</td>\n        <td>&nbsp;".format(headings)) # id
        t1053html.write("Windows, Linux</td>\n        <td>&nbsp;") # platforms
        t1053html.write("Execution, Persistence, Privilege Escalation</td>\n        <td>&nbsp;") # tactics
        t1053html.write("T1053.001: At (Linux) # sub-techniques<br>&nbsp;T1053.002: At (Windows)<br>&nbsp;T1053.003: Cron<br>&nbsp;T1053.004: Launchd<br>&nbsp;T1053.005: Scheduled Task<br>&nbsp;T1053.006: Systemd Timers<br>&nbsp;T1053.007: Container Orchestration Job")
        # related techniques
        t1053html.write("{}&nbsp;-</td>\n        <td>&nbsp;".format(related))
        t1053html.write("-")
        # mitigations
        t1053html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1053html.write("Toolkits like the PowerSploit framework contain PowerUp modules that can be used to explore systems for permission weaknesses in scheduled tasks that could be used to escalate privileges.{}&nbsp;".format(insert))
        t1053html.write("Operating System Configuration</td>\n        <td>&nbsp;")
        t1053html.write("Configure settings for scheduled tasks to force tasks to run under the context of the authenticated account instead of allowing them to run as SYSTEM. The associated Registry key is located at HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\SubmitControl. The setting can be configured through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > Security Options: Domain Controller: Allow server operators to schedule tasks, set to disabled.{}&nbsp;".format(insert))
        t1053html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1053html.write("Configure the Increase Scheduling Priority option to only allow the Administrators group the rights to schedule a priority process. This can be can be configured through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Increase scheduling priority.{}&nbsp;".format(insert))
        t1053html.write("User Account Management</td>\n        <td>&nbsp;")
        t1053html.write("Limit privileges of user accounts and remediate Privilege Escalation vectors so only authorized administrators can create scheduled tasks on remote systems.{}".format(footer))
    with open(sd+"t1129.html", "w") as t1129html:
        # descriptions
        t1129html.write("{}Adversaries may abuse shared modules to execute malicious payloads. The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths.</li>\n        <li>".format(header))
        t1129html.write("This functionality resides in NTDLL.dll and is part of the Windows Native API which is called from functions like CreateProcess, LoadLibrary, etc. of the Win32 API.")
        # indicator regex assignments
        t1129html.write("{}-".format(iocs))
        # details
        t1129html.write("{}T1129</td>\n        <td>&nbsp;".format(headings)) # id
        t1129html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1129html.write("Execution</td>\n        <td>&nbsp;") # tactics
        t1129html.write("-") # sub-techniques
        # related techniques
        t1129html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1106 target=\"_blank\"\">&nbsp;T1106</a></td>\n        <td>&nbsp;".format(related))
        t1129html.write("Native API")
        # mitigations
        t1129html.write("{}Execution Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1129html.write("Identify and block potentially malicious software executed through this technique by using application control tools capable of preventing unknown DLLs from being loaded.{}".format(footer))
    with open(sd+"t1072.html", "w") as t1072html:
        # descriptions
        t1072html.write("{}Adversaries may gain access to and use third-party software suites installed within an enterprise network, such as administration, monitoring, and deployment systems, to move laterally through the network.</li>\n        <li>".format(header))
        t1072html.write("Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, VNC, HBSS, Altiris, etc.).</li>\n        <li>")
        t1072html.write("Access to a third-party network-wide or enterprise-wide software system may enable an adversary to have remote code execution on all systems that are connected to such a system.</li>\n        <li>")
        t1072html.write("The access may be used to laterally move to other systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.</li>\n        <li>")
        t1072html.write("The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the third-party system, or specific domain credentials may be required.</li>\n        <li>")
        t1072html.write("However, the system may require an administrative account to log in or to perform it's intended purpose.")
        # indicator regex assignments
        t1072html.write("{}-".format(iocs))
        # details
        t1072html.write("{}T1072</td>\n        <td>&nbsp;".format(headings)) # id
        t1072html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1072html.write("Execution, Lateral Movement</td>\n        <td>&nbsp;") # tactics
        t1072html.write("-") # sub-techniques
        # related techniques
        t1072html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1072html.write("-")
        # mitigations
        t1072html.write("{}Active Directory Configuration</td>\n        <td>&nbsp;".format(mitigations))
        t1072html.write("Ensure proper system and access isolation for critical network systems through use of group policy.{}&nbsp;".format(insert))
        t1072html.write("Multi-factor Authentication</td>\n        <td>&nbsp;")
        t1072html.write("Ensure proper system and access isolation for critical network systems through use of multi-factor authentication.{}&nbsp;".format(insert))
        t1072html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1072html.write("Ensure proper system isolation for critical network systems through use of firewalls.{}&nbsp;".format(insert))
        t1072html.write("Password Policies</td>\n        <td>&nbsp;")
        t1072html.write("Verify that account credentials that may be used to access deployment systems are unique and not used throughout the enterprise network.{}&nbsp;".format(insert))
        t1072html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1072html.write("Grant access to application deployment systems only to a limited number of authorized administrators.{}&nbsp;".format(insert))
        t1072html.write("Remote Data Storage</td>\n        <td>&nbsp;")
        t1072html.write("If the application deployment system can be configured to deploy only signed binaries, then ensure that the trusted signing certificates are not co-located with the application deployment system and are instead located on a system that cannot be accessed remotely or to which remote access is tightly controlled.{}&nbsp;".format(insert))
        t1072html.write("Update Software</td>\n        <td>&nbsp;")
        t1072html.write("Patch deployment systems regularly to prevent potential remote access through Exploitation for Privilege Escalation.{}&nbsp;".format(insert))
        t1072html.write("User Account Management</td>\n        <td>&nbsp;")
        t1072html.write("Ensure that any accounts used by third-party providers to access these systems are traceable to the third-party and are not used throughout the network or used by other third-party providers in the same environment. Ensure there are regular reviews of accounts provisioned to these systems to verify continued business need, and ensure there is governance to trace de-provisioning of access that is no longer required. Ensure proper system and access isolation for critical network systems through use of account privilege separation.{}&nbsp;".format(insert))
        t1072html.write("User Training</td>\n        <td>&nbsp;")
        t1072html.write("Have a strict approval policy for use of deployment systems.{}".format(footer))
    with open(sd+"t1569.html", "w") as t1569html:
        # descriptions
        t1569html.write("{}Adversaries may abuse system services or daemons to execute commands or programs. Adversaries can execute malicious content by interacting with or creating services.</li>\n        <li>".format(header))
        t1569html.write("Many services are set to run at boot, which can aid in achieving persistence (Create or Modify System Process), but adversaries can also abuse services for one-time or temporary execution.")
        # indicator regex assignments
        t1569html.write("{}PsExec</li>\n        <li>".format(iocs))
        t1569html.write("services</li>\n        <li>")
        t1569html.write("sc</li>\n        <li>")
        t1569html.write("MSBuild</li>\n        <li>")
        t1569html.write(".service</li>\n        <li>")
        t1569html.write("launchctl")
        # details
        t1569html.write("{}T1569</td>\n        <td>&nbsp;".format(headings)) # id
        t1569html.write("Windows, macOS</td>\n        <td>&nbsp;") # platforms
        t1569html.write("Execution</td>\n        <td>&nbsp;") # tactics
        t1569html.write("T1569.001: Launchctl<br>&nbsp;T1569.002: Service Execution") # sub-techniques
        # related techniques
        t1569html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1543 target=\"_blank\"\">&nbsp;T1543</a></td>\n        <td>&nbsp;".format(related))
        t1569html.write("Create or Modify System Process")
        # mitigations
        t1569html.write("{}Privileged Account Management</td>\n        <td>&nbsp;".format(mitigations))
        t1569html.write("Ensure that permissions disallow services that run at a higher permissions level from being created or interacted with by a user with a lower permission level.{}&nbsp;".format(insert))
        t1569html.write("Restrict File and Directory Permissions</td>\n        <td>&nbsp;")
        t1569html.write("Ensure that high permission level service binaries cannot be replaced or modified by users with a lower permission level.{}&nbsp;".format(insert))
        t1569html.write("User Account Management</td>\n        <td>&nbsp;")
        t1569html.write("Prevent users from installing their own launch agents or launch daemons.{}".format(footer))
    with open(sd+"t1204.html", "w") as t1204html:
        # descriptions
        t1204html.write("{}An adversary may rely upon specific actions by a user in order to gain execution.</li>\n        <li>".format(header))
        t1204html.write("Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link.</li>\n        <li>")
        t1204html.write("These user actions will typically be observed as follow-on behavior from forms of Phishing.</li>\n        <li>")
        t1204html.write("While User Execution frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it.</li>\n        <li>")
        t1204html.write("This activity may also be seen shortly after Internal Spearphishing.")
        # indicator regex assignments
        t1204html.write("{}WinWord</li>\n        <li>".format(iocs))
        t1204html.write("Excel</li>\n        <li>")
        t1204html.write("PowerPnt</li>\n        <li>")
        t1204html.write("Acrobat</li>\n        <li>")
        t1204html.write("Acrord32</li>\n        <li>")
        t1204html.write(".doc</li>\n        <li>")
        t1204html.write(".xls</li>\n        <li>")
        t1204html.write(".ppt</li>\n        <li>")
        t1204html.write(".docx</li>\n        <li>")
        t1204html.write(".xlsx</li>\n        <li>")
        t1204html.write(".pptx</li>\n        <li>")
        t1204html.write(".docm</li>\n        <li>")
        t1204html.write(".xlsm</li>\n        <li>")
        t1204html.write(".pptm</li>\n        <li>")
        t1204html.write(".pdf</li>\n        <li>")
        t1204html.write(".msg</li>\n        <li>")
        t1204html.write(".eml")
        # details
        t1204html.write("{}T1204</td>\n        <td>&nbsp;".format(headings)) # id
        t1204html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1204html.write("Execution</td>\n        <td>&nbsp;") # tactics
        t1204html.write("T1204.001: Malicious Link<br>&nbsp;T1204.002: Malicious File<br>&nbsp;T1204.003: Malicious Image") # sub-techniques
        # related techniques
        t1204html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1566 target=\"_blank\"\">&nbsp;T1566</a></td>\n        <td>&nbsp;".format(related))
        t1204html.write("Phishing")
        t1204html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1203 target=\"_blank\"\">&nbsp;T1203</a></td>\n        <td>&nbsp;".format(insert))
        t1204html.write("Exploitation for Client Execution")
        t1204html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1534 target=\"_blank\"\">&nbsp;T1534</a></td>\n        <td>&nbsp;".format(insert))
        t1204html.write("Internal Spearphishing")
        # mitigations
        t1204html.write("{}Execution Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1204html.write("Application control may be able to prevent the running of executables masquerading as other files.{}&nbsp;".format(insert))
        t1204html.write("Network Intrusion Prevention</td>\n        <td>&nbsp;")
        t1204html.write("If a link is being visited by a user, network intrusion prevention systems and systems designed to scan and remove malicious downloads can be used to block activity.{}&nbsp;".format(insert))
        t1204html.write("Restrict Web-Based Content</td>\n        <td>&nbsp;")
        t1204html.write("If a link is being visited by a user, block unknown or unused files in transit by default that should not be downloaded or by policy from suspicious sites as a best practice to prevent some vectors, such as .scr, .exe, .pif, .cpl, etc. Some download scanning devices can open and analyze compressed and encrypted formats, such as zip and rar that may be used to conceal malicious files.{}&nbsp;".format(insert))
        t1204html.write("User Training</td>\n        <td>&nbsp;")
        t1204html.write("Use user training as a way to bring awareness to common phishing and spearphishing techniques and how to raise suspicion for potentially malicious events.{}".format(footer))
    with open(sd+"t1047.html", "w") as t1047html:
        # descriptions
        t1047html.write("{}Adversaries may abuse Windows Management Instrumentation (WMI) to achieve execution. WMI is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components.</li>\n        <li>".format(header))
        t1047html.write("It relies on the WMI service for local and remote access and the server message block (SMB) and Remote Procedure Call Service (RPCS) for remote access. RPCS operates over port 135.</li>\n        <li>")
        t1047html.write("An adversary can use WMI to interact with local and remote systems and use it as a means to perform many tactic functions, such as gathering information for Discovery and remote Execution of files as part of Lateral Movement.")
        # indicator regex assignments
        t1047html.write("{}Ports: 135</li>\n        <li>".format(iocs))
        t1047html.write("wmic</li>\n        <li>")
        t1047html.write("Invoke-Wmi</li>\n        <li>")
        t1047html.write("msxsl")
        # details
        t1047html.write("{}T1047</td>\n        <td>&nbsp;".format(headings)) # id
        t1047html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1047html.write("Execution</td>\n        <td>&nbsp;") # tactics
        t1047html.write("-") # sub-techniques
        # related techniques
        t1047html.write("{}&nbsp;-</td>\n        <td>&nbsp;".format(related))
        t1047html.write("-")
        # mitigations
        t1047html.write("{}Privileged Account Management</td>\n        <td>&nbsp;".format(mitigations))
        t1047html.write("Prevent credential overlap across systems of administrator and privileged accounts.{}&nbsp;".format(insert))
        t1047html.write("User Account Management</td>\n        <td>&nbsp;")
        t1047html.write("By default, only administrators are allowed to connect remotely using WMI. Restrict other users who are allowed to connect, or disallow all users to connect remotely to WMI.{}".format(footer))
  # Persistence
    with open(sd+"t1098.html", "w") as t1098html:
        # descriptions
        t1098html.write("{}Adversaries may manipulate accounts to maintain access to victim systems. Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups.</li>\n        <li>".format(header))
        t1098html.write("These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials.</li>\n        <li>")
        t1098html.write("In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain.")
        # indicator regex assignments
        t1098html.write("{}authorized_keys</li>\n        <li>".format(iocs))
        t1098html.write("sshd_config</li>\n        <li>")
        t1098html.write("ssh-keygen")
        # details
        t1098html.write("{}T1098</td>\n        <td>&nbsp;".format(headings)) # id
        t1098html.write("Windows, macOS, Linux, AWS, Azure, GCP, Office 365</td>\n        <td>&nbsp;") # platforms
        t1098html.write("Persistence</td>\n        <td>&nbsp;") # tactics
        t1098html.write("T1098.001: Additional Cloud Credentials<br>&nbsp;T1098.002: Exchange Email Delegate Permissions<br>&nbsp;T1098.003: Add Office 365 Global Administrator Role<br>&nbsp;T1098.004: SSH Authorized Keys") # sub-techniques
        # related techniques
        t1098html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t0078 target=\"_blank\"\">&nbsp;T0078</a></td>\n        <td>&nbsp;".format(related))
        t1098html.write("Valid Accounts")
        # mitigations
        t1098html.write("{}Multi-factor Authentication</td>\n        <td>&nbsp;".format(mitigations))
        t1098html.write("Use multi-factor authentication for user and privileged accounts.{}&nbsp;".format(insert))
        t1098html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1098html.write("Configure access controls and firewalls to limit access to critical systems and domain controllers. Most cloud environments support separate virtual private cloud (VPC) instances that enable further segmentation of cloud systems.{}&nbsp;".format(insert))
        t1098html.write("Operating System Configuration</td>\n        <td>&nbsp;")
        t1098html.write("Protect domain controllers by ensuring proper security configuration for critical servers to limit access by potentially unnecessary protocols and services, such as SMB file sharing.{}&nbsp;".format(insert))
        t1098html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1098html.write("Do not allow domain administrator accounts to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.{}".format(footer))
    with open(sd+"t1197.html", "w") as t1197html:
        # descriptions
        t1197html.write("{}Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM).</li>\n        <li>".format(header))
        t1197html.write("BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.</li>\n        <li>")
        t1197html.write("The interface to create and manage BITS jobs is accessible through PowerShell and the BITSAdmin tool.</li>\n        <li>")
        t1197html.write("Adversaries may abuse BITS to download, execute, and even clean up after running malicious code. BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls.</li>\n        <li>")
        t1197html.write("BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots).</li>\n        <li>")
        t1197html.write("BITS upload functionalities can also be used to perform Exfiltration Over Alternative Protocol.")
        # indicator regex assignments
        t1197html.write("{}addfile</li>\n        <li>".format(iocs))
        t1197html.write("bits</li>\n        <li>")
        t1197html.write("setnotifyflags</li>\n        <li>")
        t1197html.write("setnotifycmdline</li>\n        <li>")
        t1197html.write("transfer")
        # details
        t1197html.write("{}T1197</td>\n        <td>&nbsp;".format(headings)) # id
        t1197html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1197html.write("Persistence, Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1197html.write("-") # sub-techniques
        # related techniques
        t1197html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1559 target=\"_blank\"\">&nbsp;T1559</a></td>\n        <td>&nbsp;".format(related))
        t1197html.write("Inter-Process Communication: Component Object Model")
        t1197html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1059 target=\"_blank\"\">&nbsp;T1059</a></td>\n        <td>&nbsp;".format(insert))
        t1197html.write("Command and Scripting Interpreter: PowerShell")
        t1197html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1048 target=\"_blank\"\">&nbsp;T1048</a></td>\n        <td>&nbsp;".format(insert))
        t1197html.write("Exfiltration Over Alternative Protocol")
        # mitigations
        t1197html.write("{}Filter Network Traffic</td>\n        <td>&nbsp;".format(mitigations))
        t1197html.write("Modify network and/or host firewall rules, as well as other network controls, to only allow legitimate BITS traffic.{}&nbsp;".format(insert))
        t1197html.write("Operating System Configuration</td>\n        <td>&nbsp;")
        t1197html.write("Consider reducing the default BITS job lifetime in Group Policy or by editing the JobInactivityTimeout and MaxDownloadTime Registry values in HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\BITS.{}&nbsp;".format(insert))
        t1197html.write("User Account Management</td>\n        <td>&nbsp;")
        t1197html.write("Consider limiting access to the BITS interface to specific users or groups.{}".format(footer))
    with open(sd+"t1547.html", "w") as t1547html:
        # descriptions
        t1547html.write("{}Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon.</li>\n        <li>".format(header))
        t1547html.write("These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.</li>\n        <li>")
        t1547html.write("Since some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges.")
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
        t1547html.write("Authentication Packages")
        t1547html.write("Print Processors")
        t1547html.write("CurrentControlSet/Control/Lsa")
        t1547html.write("CurrentControlSet/Control/Print/Monitors")
        t1547html.write("CurrentControlSet/Control/Session Manager")
        t1547html.write("CurrentControlSet/Services/W32Time/TimeProviders")
        t1547html.write("CurrentVersion/Image File Execution Options")
        t1547html.write("CurrentVersion/WinLogon/Notify")
        t1547html.write("CurrentVersion/WinLogon/UserInit")
        t1547html.write("CurrentVersion/WinLogon/Shell")
        t1547html.write("Manager/SafeDllSearchMode")
        t1547html.write("Security/Policy/Secrets</li>\n        <li>")
        t1547html.write("emond")
        t1547html.write("lc_load_weak_dylib")
        t1547html.write("rpath")
        t1547html.write("loader_path")
        t1547html.write("executable_path")
        t1547html.write("ottol")
        t1547html.write("LD_PRELOAD")
        t1547html.write("DYLD_INSERT_LIBRARIES")
        t1547html.write("export")
        t1547html.write("setenv")
        t1547html.write("putenv")
        t1547html.write("os.environ")
        t1547html.write("ld.so.preload")
        t1547html.write("dlopen")
        t1547html.write("mmap")
        t1547html.write("failure")
        t1547html.write("modprobe")
        t1547html.write("insmod")
        t1547html.write("lsmod")
        t1547html.write("rmmod")
        t1547html.write("modinfo")
        t1547html.write("kextload")
        t1547html.write("kextunload")
        t1547html.write("autostart")
        t1547html.write("xdg")
        t1547html.write("autostart")
        t1547html.write("loginitems")
        t1547html.write("loginwindow")
        t1547html.write("SMLoginItemSetEnabled")
        t1547html.write("uielement")
        t1547html.write("quarantine")
        t1547html.write("startupparameters")
        # details
        t1547html.write("{}T1547</td>\n        <td>&nbsp;".format(headings)) # id
        t1547html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1547html.write("Persistence, Privilege Escalation</td>\n        <td>&nbsp;") # tactics
        t1547html.write("T1547.001: Registry Run Keys/Startup Folder<br>&nbsp;T1547.002: Authentication Package<br>&nbsp;T1547.003: Time Providers<br>&nbsp;T1547.004: Winlogon Helper DLL<br>&nbsp;T1547.005: Security Support Provider<br>&nbsp;T1547.006: Kernel Modules and Extensions<br>&nbsp;T1547.007: Re-opened Applications<br>&nbsp;T1547.008: LSASS Driver<br>&nbsp;T1547.009: Shortcut Modification<br>&nbsp;T1547.010: Port Monitors<br>&nbsp;T1547.011: Plist Modification<br>&nbsp;T1547.012: Print Processors<br>&nbsp;T1547.013: XDG Autostart Entries<br>&nbsp;T1547.014: Active Setup") # sub-techniques
        # related techniques
        t1547html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1037 target=\"_blank\"\">&nbsp;T1037</a></td>\n        <td>&nbsp;".format(related))
        t1547html.write("Boot or Logon Initialization Scripts")
        # mitigations
        t1547html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1547html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1037.html", "w") as t1037html:
        # descriptions
        t1037html.write("{}Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence.</li>\n        <li>".format(header))
        t1037html.write("Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.</li>\n        <li>")
        t1037html.write("Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.</li>\n        <li>")
        t1037html.write("An adversary may also be able to escalate their privileges since some boot or logon initialization scripts run with higher privileges.")
        # indicator regex assignments
        t1037html.write("{}StartupItems</li>\n        <li>".format(iocs))
        t1037html.write("StartupParameters</li>\n        <li>")
        t1037html.write("init.d</li>\n        <li>")
        t1037html.write("rc.local</li>\n        <li>")
        t1037html.write("rc.common</li>\n        <li>")
        t1037html.write("Environment/UserInitMprLogonScript")
        # details
        t1037html.write("{}T1037</td>\n        <td>&nbsp;".format(headings)) # id
        t1037html.write("Windows, macOS</td>\n        <td>&nbsp;") # platforms
        t1037html.write("Persistence, Privilege Escalation</td>\n        <td>&nbsp;") # tactics
        t1037html.write("T1037.001: Logon Script (Windows)<br>&nbsp;T1037.002: Logon Script (Mac)<br>&nbsp;T1037.003: Network Logon Script<br>&nbsp;T1037.004: Rc.common<br>&nbsp;T1037.005: Startup Items") # sub-techniques
        # related techniques
        t1037html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1555 target=\"_blank\"\">&nbsp;T1555</a></td>\n        <td>&nbsp;".format(related))
        t1037html.write("Credentials from Password Stores: Credentials from Web Browsers")
        # mitigations
        t1037html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1037html.write("Ensure extensions that are installed are the intended ones as many malicious extensions will masquerade as legitimate ones.{}&nbsp;".format(insert))
        t1037html.write("Execution Prevention</td>\n        <td>&nbsp;")
        t1037html.write("Set a browser extension allow or deny list as appropriate for your security policy.{}&nbsp;".format(insert))
        t1037html.write("Limit Software Installation</td>\n        <td>&nbsp;")
        t1037html.write("Only install browser extensions from trusted sources that can be verified. Browser extensions for some browsers can be controlled through Group Policy. Change settings to prevent the browser from installing extensions without sufficient permissions.{}&nbsp;".format(insert))
        t1037html.write("Update Software</td>\n        <td>&nbsp;")
        t1037html.write("Ensure operating systems and browsers are using the most current version.{}&nbsp;".format(insert))
        t1037html.write("User Training</td>\n        <td>&nbsp;")
        t1037html.write("Close out all browser sessions when finished using them to prevent any potentially malicious extensions from continuing to run.{}".format(footer))
    with open(sd+"t1176.html", "w") as t1176html:
        # descriptions
        t1176html.write("{}Adversaries may abuse Internet browser extensions to establish persistence access to victim systems. Browser extensions or plugins are small programs that can add functionality and customize aspects of Internet browsers.</li>\n        <li>".format(header))
        t1176html.write("They can be installed directly or through a browser's app store and generally have access and permissions to everything that the browser can access.</li>\n        <li>")
        t1176html.write("Malicious extensions can be installed into a browser through malicious app store downloads masquerading as legitimate extensions, through social engineering, or by an adversary that has already compromised a system.</li>\n        <li>")
        t1176html.write("Security can be limited on browser app stores so it may not be difficult for malicious extensions to defeat automated scanners. Once the extension is installed, it can browse to websites in the background, steal all information that a user enters into a browser (including credentials) and be used as an installer for a RAT for persistence.</li>\n        <li>")
        t1176html.write("There have also been instances of botnets using a persistent backdoor through malicious Chrome extensions. There have also been similar examples of extensions being used for command & control.")
        # indicator regex assignments
        t1176html.write("{}.mobileconfig</li>\n        <li>".format(iocs))
        t1176html.write("profiles")
        # details
        t1176html.write("{}T1176</td>\n        <td>&nbsp;".format(headings)) # id
        t1176html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1176html.write("Persistence</td>\n        <td>&nbsp;") # tactics
        t1176html.write("-") # sub-techniques
        # related techniques
        t1176html.write("{}&nbsp;T1554</td>\n        <td>&nbsp;".format(related))
        t1176html.write("-")
        # mitigations
        t1176html.write("{}Code Signing</td>\n        <td>&nbsp;".format(mitigations))
        t1176html.write("Ensure all application component binaries are signed by the correct application developers.{}".format(footer))
    with open(sd+"t1554.html", "w") as t1554html:
        # descriptions
        t1554html.write("{}Adversaries may modify client software binaries to establish persistent access to systems. Client software enables users to access services provided by a server.</li>\n        <li>".format(header))
        t1554html.write("Common client software types are SSH clients, FTP clients, email clients, and web browsers.</li>\n        <li>")
        t1554html.write("Adversaries may make modifications to client software binaries to carry out malicious tasks when those applications are in use. For example, an adversary may copy source code for the client software, add a backdoor, compile for the target, and replace the legitimate application binary (or support files) with the backdoored one.</li>\n        <li>")
        t1554html.write("Since these applications may be routinely executed by the user, the adversary can leverage this for persistent access to the host.")
        # indicator regex assignments
        t1554html.write("{}-".format(iocs))
        # details
        t1554html.write("{}T1554</td>\n        <td>&nbsp;".format(headings)) # id
        t1554html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1554html.write("Persistence</td>\n        <td>&nbsp;") # tactics
        t1554html.write("-") # sub-techniques
        # related techniques
        t1554html.write("{}-&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1554html.write("-")
        # mitigations
        t1554html.write("{}Multi-factor Authentication</td>\n        <td>&nbsp;".format(mitigations))
        t1554html.write("Use multi-factor authentication for user and privileged accounts.{}&nbsp;".format(insert))
        t1554html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1554html.write("Configure access controls and firewalls to limit access to domain controllers and systems used to create and manage accounts.{}&nbsp;".format(insert))
        t1554html.write("Operating System Configuration</td>\n        <td>&nbsp;")
        t1554html.write("Protect domain controllers by ensuring proper security configuration for critical servers.{}&nbsp;".format(insert))
        t1554html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1554html.write("Do not allow domain administrator accounts to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.{}".format(footer))
    with open(sd+"t1136.html", "w") as t1136html:
        # descriptions
        t1136html.write("{}Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.</li>\n        <li>".format(header))
        t1136html.write("Accounts may be created on the local system or within a domain or cloud tenant. In cloud environments, adversaries may create accounts that only have access to specific services, which can reduce the chance of detection.")
        # indicator regex assignments
        t1136html.write("{}net.exe user /add</li>\n        <li>".format(iocs))
        t1136html.write("net.exe user /domain</li>\n        <li>")
        t1136html.write("net1.exe user /add</li>\n        <li>")
        t1136html.write("net1.exe user /domain")
        # details
        t1136html.write("{}T1136</td>\n        <td>&nbsp;".format(headings)) # id
        t1136html.write("Windows, macOS, Linux, AWS, Azure, GCP, Office 365</td>\n        <td>&nbsp;") # platforms
        t1136html.write("Persistence</td>\n        <td>&nbsp;") # tactics
        t1136html.write("T1136.001: Local Account<br>&nbsp;T1136.002: Domain Account<br>&nbsp;T1136.003: Cloud Account") # sub-techniques
        # related techniques
        t1136html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1136html.write("-")
        # mitigations
        t1136html.write("{}Multi-factor Authentication</td>\n        <td>&nbsp;".format(mitigations))
        t1136html.write("Use multi-factor authentication for user and privileged accounts.{}&nbsp;".format(insert))
        t1136html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1136html.write("Configure access controls and firewalls to limit access to domain controllers and systems used to create and manage accounts.{}&nbsp;".format(insert))
        t1136html.write("Operating System Configuration</td>\n        <td>&nbsp;")
        t1136html.write("Protect domain controllers by ensuring proper security configuration for critical servers.{}&nbsp;".format(insert))
        t1136html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1136html.write("Do not allow domain administrator accounts to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.{}".format(footer))
    with open(sd+"t1543.html", "w") as t1543html:
        # descriptions
        t1543html.write("{}Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions.</li>\n        <li>".format(header))
        t1543html.write("On Windows and Linux, these system processes are referred to as services. On macOS, launchd processes known as Launch Daemon and Launch Agent are run to finish system initialization and load user specific parameters.</li>\n        <li>")
        t1543html.write("Adversaries may install new services, daemons, or agents that can be configured to execute at startup or a repeatable interval in order to establish persistence. Similarly, adversaries may modify existing services, daemons, or agents to achieve the same effect.</li>\n        <li>")
        t1543html.write("Services, daemons, or agents may be created with administrator privileges but executed under root/SYSTEM privileges. Adversaries may leverage this functionality to create or modify system processes in order to escalate privileges.")
        # indicator regex assignments
        t1543html.write("{}services.exe</li>\n        <li>".format(iocs))
        t1543html.write("sc.exe</li>\n        <li>")
        t1543html.write("WinExec</li>\n        <li>")
        t1543html.write(".services</li>\n        <li>")
        t1543html.write("LaunchAgent")
        t1543html.write("LaunchDaemon")
        t1543html.write("systemctl")
        # details
        t1543html.write("{}T1543</td>\n        <td>&nbsp;".format(headings)) # id
        t1543html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1543html.write("Persistence, Privilege Escalation</td>\n        <td>&nbsp;") # tactics
        t1543html.write("T1543.001: Launch Agent<br>&nbsp;T1543.002: Systemd Service<br>&nbsp;T1543.003: Windows Service<br>&nbsp;T1543.004: Launch Daemon") # sub-techniques
        # related techniques
        t1543html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1543html.write("-")
        # mitigations
        t1543html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1543html.write("Use auditing tools capable of detecting privilege and service abuse opportunities on systems within an enterprise and correct them.{}&nbsp;".format(insert))
        t1543html.write("Limit Software Installation</td>\n        <td>&nbsp;")
        t1543html.write("Restrict software installation to trusted repositories only and be cautious of orphaned software packages.{}&nbsp;".format(insert))
        t1543html.write("Restrict File and Directory Permissions</td>\n        <td>&nbsp;")
        t1543html.write("Restrict read/write access to system-level process files to only select privileged users who have a legitimate need to manage system services.{}&nbsp;".format(insert))
        t1543html.write("User Account Management</td>\n        <td>&nbsp;")
        t1543html.write("Limit privileges of user accounts and groups so that only authorized administrators can interact with system-level process changes and service configurations.{}".format(footer))
    with open(sd+"t1546.html", "w") as t1546html:
        # descriptions
        t1546html.write("{}Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries.</li>\n        <li>".format(header))
        t1546html.write("Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via repeatedly executing malicious code. After gaining access to a victim system, adversaries may create/modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked.</li>\n        <li>")
        t1546html.write("Since the execution can be proxied by an account with higher permissions, such as SYSTEM or service accounts, an adversary may be able to abuse these triggered execution mechanisms to escalate their privileges.")
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
        t1546html.write("CurrentControlSet/Control/Session Manager")
        t1546html.write("CurrentVersion/AppCompatFlags/InstalledSDB")
        t1546html.write("CurrentVersion/Explorer/FileExts")
        t1546html.write("CurrentVersion/Image File Execution Options")
        t1546html.write("CurrentVersion/Windows")
        t1546html.write("Software/Microsoft/Netsh</li>\n        <li>")
        t1546html.write("emond</li>\n        <li>")
        t1546html.write("lc_code_signature")
        t1546html.write("lc_load_dylib")
        t1546html.write("profile\\.d")
        t1546html.write("bash_profile")
        t1546html.write("bashrc")
        t1546html.write("bash_login")
        t1546html.write("bash_logout")
        t1546html.write("trap")
        t1546html.write("zshrc")
        t1546html.write("zshenv")
        t1546html.write("zlogout")
        t1546html.write("zlogin")
        # details
        t1546html.write("{}T1546</td>\n        <td>&nbsp;".format(headings)) # id
        t1546html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1546html.write("Persistence, Privilege Escalation</td>\n        <td>&nbsp;") # tactics
        t1546html.write("T1546.001: Change Default File Association<br>&nbsp;T1546.002: Screensaver<br>&nbsp;T1546.003: Windows Management Instrumentation Event Subscription<br>&nbsp;T1546.004: .bash_profile and .bashrc<br>&nbsp;T1546.005: Trap<br>&nbsp;T1546.006: LC_LOAD_DYLIB Addition<br>&nbsp;T1546.007: Netsh Helper DLL<br>&nbsp;T1546.008: Accessibility Features<br>&nbsp;T1546.009: AppCert DLLs<br>&nbsp;T1546.010: AppInit DLLs<br>&nbsp;T1546.011: Application Shimming<br>&nbsp;T1546.012: Image File Execution Options Injection<br>&nbsp;T1546.013: PowerShell Profile<br>&nbsp;T1546.014: emond<br>&nbsp;T1546.015: Component Object Model Hijacking") # sub-techniques
        # related techniques
        t1546html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1222 target=\"_blank\"\">&nbsp;T1222</a></td>\n        <td>&nbsp;".format(related))
        t1546html.write("File and Directory Permissions Modification")
        # mitigations
        t1546html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1546html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1574.html", "w") as t1574html:
        # descriptions
        t1574html.write("{}Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time.</li>\n        <li>".format(header))
        t1574html.write("Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.</li>\n        <li>")
        t1574html.write("There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted.</li>\n        <li>")
        t1574html.write("Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads.")
        # indicator regex assignments
        t1574html.write("{}.local</li>\n        <li>".format(iocs))
        t1574html.write(".manifest</li>\n        <li>")
        t1574html.write("net.exe use</li>\n        <li>")
        t1574html.write("net1.exe use</li>\n        <li>")
        t1574html.write("CurrentControlSet/Services/</li>\n        <li>")
        t1574html.write("LC_CODE_SIGNATURE")
        t1574html.write("LC_LOAD_DYLIB")
        # details
        t1574html.write("{}T1574</td>\n        <td>&nbsp;".format(headings)) # id
        t1574html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1574html.write("Persistence, Privilege Escalation, Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1574html.write("T1574.001: DLL Search Order Hijacking<br>&nbsp;T1574.002: DLL Side-Loading<br>&nbsp;T1574.004: Dylib Hijacking<br>&nbsp;T1574.005: Executable Installer File Permissions Weakness<br>&nbsp;T1574.006: LD_PRELOAD<br>&nbsp;T1574.007: Path Interception by PATH Environment Variable<br>&nbsp;T1574.008: Path Interception by Search Order Hijacking<br>&nbsp;T1574.009: Path Interception by Unquoted Path<br>&nbsp;T1574.010: Services File Permissions Weakness<br>&nbsp;T1574.011: Services Registry Permissions Weakness<br>&nbsp;T1574.012: COR_PROFILER") # sub-techniques
        # related techniques
        t1574html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1548 target=\"_blank\"\">&nbsp;T1548.002</a></td>\n        <td>&nbsp;".format(related))
        t1574html.write("Abuse Elevation Control Mechanism: Bypass User Account Control")
        # mitigations
        t1574html.write("{}Application Developer Guidance</td>\n        <td>&nbsp;".format(mitigations))
        t1574html.write("When possible, include hash values in manifest files to help prevent side-loading of malicious libraries.{}&nbsp;".format(insert))
        t1574html.write("Audit</td>\n        <td>&nbsp;")
        t1574html.write("Use auditing tools capable of detecting hijacking opportunities on systems within an enterprise and correct them. Toolkits like the PowerSploit framework contain PowerUp modules that can be used to explore systems for hijacking weaknesses.<br>&nbsp;Use the program sxstrace.exe that is included with Windows along with manual inspection to check manifest files for side-loading vulnerabilities in software.<br>&nbsp;Find and eliminate path interception weaknesses in program configuration files, scripts, the PATH environment variable, services, and in shortcuts by surrounding PATH variables with quotation marks when functions allow for them. Be aware of the search order Windows uses for executing or loading binaries and use fully qualified paths wherever appropriate.<br>&nbsp;Clean up old Windows Registry keys when software is uninstalled to avoid keys with no associated legitimate binaries. Periodically search for and correct or report path interception weaknesses on systems that may have been introduced using custom or available tools that report software using insecure path configurations.{}&nbsp;".format(insert))
        t1574html.write("Execution Prevention</td>\n        <td>&nbsp;")
        t1574html.write("Adversaries may use new payloads to execute this technique. Identify and block potentially malicious software executed through hijacking by using application control solutions also capable of blocking libraries loaded by legitimate software.{}&nbsp;".format(insert))
        t1574html.write("Restrict File and Directory Permissions</td>\n        <td>&nbsp;")
        t1574html.write("Install software in write-protected locations. Set directory access controls to prevent file writes to the search paths for applications, both in the folders where applications are run from and the standard library folders.{}&nbsp;".format(insert))
        t1574html.write("Restrict Library Loading</td>\n        <td>&nbsp;")
        t1574html.write("Disallow loading of remote DLLs. This is included by default in Windows Server 2012+ and is available by patch for XP+ and Server 2003+.<br>&nbsp;Enable Safe DLL Search Mode to force search for system DLLs in directories with greater restrictions (e.g. %SYSTEMROOT%)to be used before local directory DLLs (e.g. a user's home directory)<br>&nbsp;The Safe DLL Search Mode can be enabled via Group Policy at Computer Configuration > [Policies] > Administrative Templates > MSS (Legacy): MSS: (SafeDllSearchMode) Enable Safe DLL search mode. The associated Windows Registry key for this is located at HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SafeDLLSearchMode{}&nbsp;".format(insert))
        t1574html.write("Restrict Registry Permissions</td>\n        <td>&nbsp;")
        t1574html.write("Ensure proper permissions are set for Registry hives to prevent users from modifying keys for system components that may lead to privilege escalation.{}&nbsp;".format(insert))
        t1574html.write("Update Software</td>\n        <td>&nbsp;")
        t1574html.write("Update software regularly to include patches that fix DLL side-loading vulnerabilities.{}&nbsp;".format(insert))
        t1574html.write("User Account Control</td>\n        <td>&nbsp;")
        t1574html.write("Turn off UAC's privilege elevation for standard users [HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System] to automatically deny elevation requests, add: \"ConsentPromptBehaviorUser\"=dword:00000000. Consider enabling installer detection for all users by adding: \"EnableInstallerDetection\"=dword:00000001. This will prompt for a password for installation and also log the attempt. To disable installer detection, instead add: \"EnableInstallerDetection\"=dword:00000000. This may prevent potential elevation of privileges through exploitation during the process of UAC detecting the installer, but will allow the installation process to continue without being logged.{}&nbsp;".format(insert))
        t1574html.write("User Account Management</td>\n        <td>&nbsp;")
        t1574html.write("Limit privileges of user accounts and groups so that only authorized administrators can interact with service changes and service binary target path locations. Deny execution from user directories such as file download directories and temp directories where able.<>&nbsp;Ensure that proper permissions and directory access control are set to deny users the ability to write files to the top-level directory C: and system directories, such as C:\\Windows\\, to reduce places where malicious files could be placed for execution.{}".format(footer))
    with open(sd+"t1525.html", "w") as t1525html:
        # descriptions
        t1525html.write("{}Adversaries may implant cloud container images with malicious code to establish persistence. Amazon Web Service (AWS) Amazon Machine Images (AMI), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be implanted or backdoored.</li>\n        <li>".format(header))
        t1525html.write("Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image.</li>\n        <li>")
        t1525html.write("A tool has been developed to facilitate planting backdoors in cloud container images. If an attacker has access to a compromised AWS instance, and permissions to list the available container images, they may implant a backdoor such as a Web Shell.</li>\n        <li>")
        t1525html.write("Adversaries may also implant Docker images that may be inadvertently used in cloud deployments, which has been reported in some instances of cryptomining botnets.")
        # indicator regex assignments
        t1525html.write("{}-".format(iocs))
        # details
        t1525html.write("{}T1525</td>\n        <td>&nbsp;".format(headings)) # id
        t1525html.write("AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1525html.write("Persistence</td>\n        <td>&nbsp;") # tactics
        t1525html.write("-") # sub-techniques
        # related techniques
        t1525html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1505 target=\"_blank\"\">&nbsp;T1505</a></td>\n        <td>&nbsp;".format(related))
        t1525html.write("Server Software Component: Web Shell")
        # mitigations
        t1525html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1525html.write("Periodically check the integrity of images and containers used in cloud deployments to ensure they have not been modified to include malicious software.{}&nbsp;".format(insert))
        t1525html.write("Code Signing</td>\n        <td>&nbsp;")
        t1525html.write("Several cloud service providers support content trust models that require container images be signed by trusted sources.{}&nbsp;".format(insert))
        t1525html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1525html.write("Limit permissions associated with creating and modifying platform images or containers based on the principle of least privilege.{}".format(footer))
    with open(sd+"t1556.html", "w") as t1556html:
        # descriptions
        t1556html.write("{}Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts.</li>\n        <li>".format(header))
        t1556html.write("The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows or pluggable authentication modules (PAM) on Unix-based systems, responsible for gathering, storing, and validating credentials.</li>\n        <li>")
        t1556html.write("Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms.</li>\n        <li>")
        t1556html.write("Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop.")
        # indicator regex assignments
        t1556html.write("{}OpenProcess</li>\n        <li>".format(iocs))
        t1556html.write("lsass</li>\n        <li>")
        t1556html.write("CurrentControlSet/Control/Lsa</li>\n        <li>")
        t1556html.write("pam_unix.so")
        t1556html.write("passwd")
        t1556html.write("shadow")
        # details
        t1556html.write("{}T1556</td>\n        <td>&nbsp;".format(headings)) # id
        t1556html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1556html.write("Defense Evasion, Credential Access</td>\n        <td>&nbsp;") # tactics
        t1556html.write("T1556.001: Domain Controller Authentication<br>&nbsp;T1556.002: Password Filter DLL<br>&nbsp;T1556.003: Pluggable Authentication Modules<br>&nbsp;T1556.004: Network Device Authenticiation") # sub-techniques
        # related techniques
        t1556html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1078 target=\"_blank\"\">&nbsp;T1078</a></td>\n        <td>&nbsp;".format(related))
        t1556html.write("Valid Accounts")
        # mitigations
        t1556html.write("{}Multi-factor Authentication</td>\n        <td>&nbsp;".format(mitigations))
        t1556html.write("Integrating multi-factor authentication (MFA) as part of organizational policy can greatly reduce the risk of an adversary gaining control of valid credentials that may be used for additional tactics such as initial access, lateral movement, and collecting information. MFA can also be used to restrict access to cloud resources and APIs.{}&nbsp;".format(insert))
        t1556html.write("Operating System Configuration</td>\n        <td>&nbsp;")
        t1556html.write("Ensure only valid password filters are registered. Filter DLLs must be present in Windows installation directory (C:\\Windows\\System32\\ by default) of a domain controller and/or local computer with a corresponding entry in HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages.{}&nbsp;".format(insert))
        t1556html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1556html.write("Audit domain and local accounts as well as their permission levels routinely to look for situations that could allow an adversary to gain wide access by obtaining credentials of a privileged account. These audits should also include if default accounts have been enabled, or if new local accounts are created that have not be authorized. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.<br>&nbsp;Limit access to the root account and prevent users from modifying protected components through proper privilege separation (ex SELinux, grsecurity, AppArmor, etc.) and limiting Privilege Escalation opportunities.{}&nbsp;".format(insert))
        t1556html.write("Privileged Process Integrity</td>\n        <td>&nbsp;")
        t1556html.write("Enabled features, such as Protected Process Light (PPL), for LSA.{}&nbsp;".format(insert))
        t1556html.write("Restrict File and Directory Permissions</td>\n        <td>&nbsp;")
        t1556html.write("Restrict write access to the /Library/Security/SecurityAgentPlugins directory.{}".format(footer))
    with open(sd+"t1137.html", "w") as t1137html:
        # descriptions
        t1137html.write("{}Adversaries may leverage Microsoft Office-based applications for persistence between startups. Microsoft Office is a fairly common application suite on Windows-based operating systems within an enterprise network.</li>\n        <li>".format(header))
        t1137html.write("There are multiple mechanisms that can be used with Office for persistence when an Office-based application is started; this can include the use of Office Template Macros and add-ins.</li>\n        <li>")
        t1137html.write("A variety of features have been discovered in Outlook that can be abused to obtain persistence, such as Outlook rules, forms, and Home Page. These persistence mechanisms can work within Outlook or be used through Office 365.")
        # indicator regex assignments
        t1137html.write("{}.docm</li>\n        <li>".format(iocs))
        t1137html.write(".xlsm</li>\n        <li>")
        t1137html.write("pptm</li>\n        <li>")
        t1137html.write("Normal.dotm")
        t1137html.write("PERSONAL.xlsb")
        # details
        t1137html.write("{}T1137</td>\n        <td>&nbsp;".format(headings)) # id
        t1137html.write("Windows, Office 365</td>\n        <td>&nbsp;") # platforms
        t1137html.write("Persistence</td>\n        <td>&nbsp;") # tactics
        t1137html.write("T1137.001: Office Template Macros<br>&nbsp;T1137.002: Office Test<br>&nbsp;T1137.003: Outlook Forms<br>&nbsp;T1137.004: Outlook Home Page<br>&nbsp;T1137.005: Outlook Rules<br>&nbsp;T1137.006: Add-ins") # sub-techniques
        # related techniques
        t1137html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1203 target=\"_blank\"\">&nbsp;T1203</a></td>\n        <td>&nbsp;".format(related))
        t1137html.write("Exploitation for Client Execution")
        t1137html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1204 target=\"_blank\"\">&nbsp;T1204</a></td>\n        <td>&nbsp;".format(insert))
        t1137html.write("User Execution")
        # mitigations
        t1137html.write("{}Disable or Remove Feature or Program</td>\n        <td>&nbsp;".format(mitigations))
        t1137html.write("Follow Office macro security best practices suitable for your environment. Disable Office VBA macros from executing.<br>&nbsp;Disable Office add-ins. If they are required, follow best practices for securing them by requiring them to be signed and disabling user notification for allowing add-ins. For some add-ins types (WLL, VBA) additional mitigation is likely required as disabling add-ins in the Office Trust Center does not disable WLL nor does it prevent VBA code from executing.{}&nbsp;".format(insert))
        t1137html.write("Software Configuration</td>\n        <td>&nbsp;")
        t1137html.write("For the Office Test method, create the Registry key used to execute it and set the permissions to \"Read Control\" to prevent easy access to the key without administrator permissions or requiring Privilege Escalation.{}&nbsp;".format(insert))
        t1137html.write("Update Software</td>\n        <td>&nbsp;")
        t1137html.write("For the Outlook methods, blocking macros may be ineffective as the Visual Basic engine used for these features is separate from the macro scripting engine. Microsoft has released patches to try to address each issue. Ensure KB3191938 which blocks Outlook Visual Basic and displays a malicious code warning, KB4011091 which disables custom forms by default, and KB4011162 which removes the legacy Home Page feature, are applied to systems.{}".format(footer))
    with open(sd+"t1542.html", "w") as t1542html:
        # descriptions
        t1542html.write("{}Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system.</li>\n        <li>".format(header))
        t1542html.write("These programs control flow of execution before the operating system takes control.</li>\n        <li>")
        t1542html.write("Adversaries may overwrite data in boot drivers or firmware such as BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) to persist on systems at a layer below the operating system.</li>\n        <li>")
        t1542html.write("This can be particularly difficult to detect as malware at this level will not be detected by host software-based defenses.")
        # indicator regex assignments
        t1542html.write("{}-".format(iocs))
        # details
        t1542html.write("{}T1542</td>\n        <td>&nbsp;".format(headings)) # id
        t1542html.write("Windows, Linux</td>\n        <td>&nbsp;") # platforms
        t1542html.write("Persistence, Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1542html.write("T1542.001: System Firmware<br>&nbsp;T1542.002: Component Firmware<br>&nbsp;T1542.003: Bootkit<br>&nbsp;T1542.004: ROMMONkit<br>&nbsp;T1542.005: TFTP Boot") # sub-techniques
        # related techniques
        t1542html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1200 target=\"_blank\"\">&nbsp;T1200</a></td>\n        <td>&nbsp;".format(related))
        t1542html.write("Hardware Additions")
        # mitigations
        t1542html.write("{}Boot Integrity</td>\n        <td>&nbsp;".format(mitigations))
        t1542html.write("Use Trusted Platform Module technology and a secure or trusted boot process to prevent system integrity from being compromised. Check the integrity of the existing BIOS or EFI to determine if it is vulnerable to modification.{}&nbsp;".format(insert))
        t1542html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1542html.write("Ensure proper permissions are in place to help prevent adversary access to privileged accounts necessary to perform these actions.{}&nbsp;".format(insert))
        t1542html.write("Update Software</td>\n        <td>&nbsp;")
        t1542html.write("Patch the BIOS and EFI as necessary.{}".format(footer))
    with open(sd+"t1505.html", "w") as t1505html:
        # descriptions
        t1505html.write("{}Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems.</li>\n        <li>".format(header))
        t1505html.write("Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application.</li>\n        <li>")
        t1505html.write("Adversaries may install malicious components to extend and abuse server applications.")
        # indicator regex assignments
        t1505html.write("{}-".format(iocs))
        # details
        t1505html.write("{}T1505</td>\n        <td>&nbsp;".format(headings)) # id
        t1505html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1505html.write("Persistence</td>\n        <td>&nbsp;") # tactics
        t1505html.write("T1505.001: SQL Stored Procedures<br>&nbsp;T1505.002: Transport Agent<br>&nbsp;T1505.003: Web Shell") # sub-techniques
        # related techniques
        t1505html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1505html.write("-")
        # mitigations
        t1505html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1505html.write("Regularly check component software on critical services that adversaries may target for persistence to verify the integrity of the systems and identify if unexpected changes have been made.{}&nbsp;".format(insert))
        t1505html.write("Code Signing</td>\n        <td>&nbsp;")
        t1505html.write("Ensure all application component binaries are signed by the correct application developers.{}&nbsp;".format(insert))
        t1505html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1505html.write("Do not allow administrator accounts that have permissions to add component software on these services to be used for day-to-day operations that may expose them to potential adversaries on unprivileged systems.{}".format(footer))
    with open(sd+"t1205.html", "w") as t1205html:
        # descriptions
        t1205html.write("{}Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control.</li>\n        <li>".format(header))
        t1205html.write("Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task.</li>\n        <li>")
        t1205html.write("This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control.</li>\n        <li>")
        t1205html.write("Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. Port Knocking), but can involve unusual flags, specific strings, or other unique characteristics.</li>\n        <li>")
        t1205html.write("After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.</li>\n        <li>")
        t1205html.write("Adversaries may also communicate with an already open port, but the service listening on that port will only respond to commands or trigger other malicious functionality if passed the appropriate magic value(s).</li>\n        <li>")
        t1205html.write("The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r, is to use the libpcap libraries to sniff for the packets in question.</li>\n        <li>")
        t1205html.write("Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs.")
        # indicator regex assignments
        t1205html.write("{}-".format(iocs))
        # details
        t1205html.write("{}T1205</td>\n        <td>&nbsp;".format(headings)) # id
        t1205html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1205html.write("Persistence, Defense Evasion, Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1205html.write("T1205.001: Port Knocking") # sub-techniques
        # related techniques
        t1205html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1556 target=\"_blank\"\">&nbsp;T1556.004</a></td>\n        <td>&nbsp;".format(related))
        t1205html.write("Modify Authentication Process: Network Device Authentication")
        t1205html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1601 target=\"_blank\"\">&nbsp;T1601.001</a></td>\n        <td>&nbsp;".format(insert))
        t1205html.write("Modify System Image: Patch System Image")
        # mitigations
        t1205html.write("{}Disable or Remove Feature or Program</td>\n        <td>&nbsp;".format(mitigations))
        t1205html.write("Disable Wake-on-LAN if it is not needed within an environment.{}&nbsp;".format(insert))
        t1205html.write("Filter Network Traffic</td>\n        <td>&nbsp;")
        t1205html.write("Mitigation of some variants of this technique could be achieved through the use of stateful firewalls, depending upon how it is implemented.{}".format(footer))
  # Privilege Escalation
    with open(sd+"t1548.html", "w") as t1548html:
        # descriptions
        t1548html.write("{}Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine.</li>\n        <li>".format(header))
        t1548html.write("Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.")
        # indicator regex assignments
        t1548html.write("{}eventvwr.exe</li>\n        <li>".format(iocs))
        t1548html.write("sdclt.exe</li>\n        <li>")
        t1548html.write("CurrentVersion/App Paths</li>\n        <li>")
        t1548html.write("Software/Classes/ms-settings/shell/open/command")
        t1548html.write("CurrentVersion/App Paths")
        t1548html.write("Software/Classes/mscfile/shell/open/command")
        t1548html.write("Software/Classes/exefile/shell/runas/command/isolatedcommand</li>\n        <li>")
        t1548html.write("AuthorizationExecuteWithPrivileges")
        t1548html.write("security_authtrampoline")
        t1548html.write("chmod")
        t1548html.write("kill")
        t1548html.write("sudo")
        t1548html.write("timestamp_timeout")
        t1548html.write("tty_tickets")
        # details
        t1548html.write("{}T1574</td>\n        <td>&nbsp;".format(headings)) # id
        t1548html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1548html.write("Privilege Escalation, Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1548html.write("T1574.001: Setuid and Setgid<br>&nbsp;T1574.002: Bypass User Access Control<br>&nbsp;T1574.003: Sudo and Sudo Caching<br>&nbsp;T1574.004: Elevated Execution with Prompt") # sub-techniques
        # related techniques
        t1548html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1548html.write("-")
        # mitigations
        t1548html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1548html.write("Check for common UAC bypass weaknesses on Windows systems to be aware of the risk posture and address issues where appropriate.{}&nbsp;".format(insert))
        t1548html.write("Execution Prevention</td>\n        <td>&nbsp;")
        t1548html.write("System settings can prevent applications from running that haven't been downloaded from legitimate repositories which may help mitigate some of these issues. Not allowing unsigned applications from being run may also mitigate some risk.{}&nbsp;".format(insert))
        t1548html.write("Operating System Configuration</td>\n        <td>&nbsp;")
        t1548html.write("Applications with known vulnerabilities or known shell escapes should not have the setuid or setgid bits set to reduce potential damage if an application is compromised. Additionally, the number of programs with setuid or setgid bits set should be minimized across a system. Ensuring that the sudo tty_tickets setting is enabled will prevent this leakage across tty sessions.{}&nbsp;".format(insert))
        t1548html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1548html.write("Remove users from the local administrator group on systems.<br>&nbsp;By requiring a password, even if an adversary can get terminal access, they must know the password to run anything in the sudoers file. Setting the timestamp_timeout to 0 will require the user to input their password every time sudo is executed.{}&nbsp;".format(insert))
        t1548html.write("Restrict File and Directory Permissions</td>\n        <td>&nbsp;")
        t1548html.write("The sudoers file should be strictly edited such that passwords are always required and that users can't spawn risky processes as users with higher privilege.{}&nbsp;".format(insert))
        t1548html.write("User Account Control</td>\n        <td>&nbsp;")
        t1548html.write("Although UAC bypass techniques exist, it is still prudent to use the highest enforcement level for UAC when possible and mitigate bypass opportunities that exist with techniques such as DLL Search Order Hijacking.{}".format(footer))
    with open(sd+"t1134.html", "w") as t1134html:
        # descriptions
        t1134html.write("{}Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process.</li>\n        <li>".format(header))
        t1134html.write("A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.</li>\n        <li>")
        t1134html.write("An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. These token can then be applied to an existing process (i.e. Token Impersonation/Theft) or used to spawn a new process (i.e. Create Process with Token).</li>\n        <li>")
        t1134html.write("An adversary must already be in a privileged user context (i.e. administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to the SYSTEM level. An adversary can then use a token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system.</li>\n        <li>")
        t1134html.write("Any standard user can use the runas command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account. There are also other mechanisms, such as Active Directory fields, that can be used to modify access tokens.")
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
        t1134html.write("LogonUser")
        # details
        t1134html.write("{}T1134</td>\n        <td>&nbsp;".format(headings)) # id
        t1134html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1134html.write("Privilege Escalation, Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1134html.write("T1134.001: Token Impersonation/Theft<br>&nbsp;T1134.002: Create Process with Token<br>&nbsp;T1134.003: Make and Impersonate Token<br>&nbsp;T1134.004: Parent PID Spoofing<br>&nbsp;T1134.005: SID-History Injection") # sub-techniques
        # related techniques
        t1134html.write("{}-&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1134html.write("-")
        # mitigations
        t1134html.write("{}Privileged Account Management</td>\n        <td>&nbsp;".format(mitigations))
        t1134html.write("Limit permissions so that users and user groups cannot create tokens. This setting should be defined for the local system account only. GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Create a token object. Also define who can create a process level token to only the local and network service through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Replace a process level token.<br>&nbsp;Administrators should log in as a standard user but run their tools with administrator privileges using the built-in access token manipulation command runas.{}&nbsp;".format(insert))
        t1134html.write("User Account Management</td>\n        <td>&nbsp;")
        t1134html.write("An adversary must already have administrator level access on the local system to make full use of this technique; be sure to restrict users and accounts to the least privileges they require.{}".format(footer))
    with open(sd+"t1484.html", "w") as t1484html:
        # descriptions
        t1484html.write("{}Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary access controls for a domain, usually with the intention of escalating privileges on the domain. Group policy allows for centralized management of user and computer settings in Active Directory (AD).</li>\n        <li>".format(header))
        t1484html.write("GPOs are containers for group policy settings made up of files stored within a predicable network path \\<DOMAIN>\\SYSVOL\\<DOMAIN>\\Policies\\.</li>\n        <li>")
        t1484html.write("Like other objects in AD, GPOs have access controls associated with them. By default all user accounts in the domain have permission to read GPOs. It is possible to delegate GPO access control permissions, e.g. write access, to specific users or groups in the domain.</li>\n        <li>")
        t1484html.write("Malicious GPO modifications can be used to implement many other malicious behaviors such as Scheduled Task/Job, Disable or Modify Tools, Ingress Tool Transfer, Create Account, Service Execution, and more.</li>\n        <li>")
        t1484html.write("Since GPOs can control so many user and machine settings in the AD environment, there are a great number of potential attacks that can stem from this GPO abuse.</li>\n        <li>")
        t1484html.write("For example, publicly available scripts such as New-GPOImmediateTask can be leveraged to automate the creation of a malicious Scheduled Task/Job by modifying GPO settings, in this case modifying <GPO_PATH>\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml.</li>\n        <li>")
        t1484html.write("In some cases an adversary might modify specific user rights like SeEnableDelegationPrivilege, set in <GPO_PATH>\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf, to achieve a subtle AD backdoor with complete control of the domain because the user account under the adversary's control would then be able to modify GPOs.")
        # indicator regex assignments
        t1484html.write("{}Event IDs: 307, 510, 4672, 4704, 5136, 5137, 5138, 5139, 5141</li>\n        <li>".format(iocs))
        t1484html.write("GptTmpl.inf</li>\n        <li>")
        t1484html.write("ScheduledTasks.xml</li>\n        <li>")
        t1484html.write("New-GPOImmediateTask")
        # details
        t1484html.write("{}T1484</td>\n        <td>&nbsp;".format(headings)) # id
        t1484html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1484html.write("Privilege Escalation, Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1484html.write("T1484.001: Group Policy Modification<br>&nbsp;T1484.002: Domain Trust Modification") # sub-techniques
        # related techniques
        t1484html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1053 target=\"_blank\"\">&nbsp;T1053</a></td>\n        <td>&nbsp;".format(related))
        t1484html.write("Scheduled Task/Job")
        t1484html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1562 target=\"_blank\"\">&nbsp;T1562.001</a></td>\n        <td>&nbsp;".format(insert))
        t1484html.write("Impair Defenses: Disable or Modify Tools")
        t1484html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1105 target=\"_blank\"\">&nbsp;T1105</a></td>\n        <td>&nbsp;".format(insert))
        t1484html.write("Ingress Tool Transfer")
        t1484html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1136 target=\"_blank\"\">&nbsp;T1136</a></td>\n        <td>&nbsp;".format(insert))
        t1484html.write("Create Account")
        t1484html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1569 target=\"_blank\"\">&nbsp;T1569</a></td>\n        <td>&nbsp;".format(insert))
        t1484html.write("System Services: Service Execution")
        t1484html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1207 target=\"_blank\"\">&nbsp;T1207</a></td>\n        <td>&nbsp;".format(insert))
        t1484html.write("Rogue Domain Controller")
        # mitigations
        t1484html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1484html.write("Identify and correct GPO permissions abuse opportunities (ex: GPO modification privileges) using auditing tools such as BloodHound (version 1.5.1 and later){}&nbsp;".format(insert))
        t1484html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1484html.write("Use least privilege and protect administrative access to the Domain Controller and Active Directory Federation Services (AD FS) server. Do not create service accounts with administrative privileges.{}&nbsp;".format(insert))
        t1484html.write("User Account Management</td>\n        <td>&nbsp;")
        t1484html.write("Consider implementing WMI and security filtering to further tailor which users and computers a GPO will apply to.{}".format(footer))
    with open(sd+"t1611.html", "w") as t1611html:
        # descriptions
        t1611html.write("{}Adversaries may break out of a container to gain access to the underlying host. This can allow an adversary access to other containerized resources from the host level or to the host itself. In principle, containerized resources should provide a clear separation of application functionality and be isolated from the host environment.</li>\n        <li>".format(header))
        t1611html.write("There are multiple ways an adversary may escape to a host environment. Examples include creating a container configured to mount the host’s filesystem using the bind parameter, which allows the adversary to drop payloads and execute control utilities such as cron on the host, and utilizing a privileged container to run commands on the underlying host. Gaining access to the host may provide the adversary with the opportunity to achieve follow-on objectives, such as establishing persistence, moving laterally within the environment, or setting up a command and control channel on the host.")
        # indicator regex assignments
        t1611html.write("{}-".format(iocs))
        # details
        t1611html.write("{}T1611</td>\n        <td>&nbsp;".format(headings)) # id
        t1611html.write("Windows, Linux, Containers</td>\n        <td>&nbsp;") # platforms
        t1611html.write("Privilege Escalation</td>\n        <td>&nbsp;") # tactics
        t1611html.write("-") # sub-techniques
        # related techniques
        t1611html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1612 target=\"_blank\"\">&nbsp;T1612</a></td>\n        <td>&nbsp;".format(related))
        t1611html.write("Build Image on Host")
        # mitigations
        t1611html.write("{}Application Isolation and Sandboxing</td>\n        <td>&nbsp;".format(mitigations))
        t1611html.write("Ensure all COM alerts and Protected View are enabled.{}&nbsp;".format(insert))
        t1611html.write("Behavior Prevention on Endpoint</td>\n        <td>&nbsp;")
        t1611html.write("Consider utilizing seccomp, seccomp-bpf, or a similar solution that restricts certain system calls such as mount.{}&nbsp;".format(insert))
        t1611html.write("Execution Prevention</td>\n        <td>&nbsp;")
        t1611html.write("Use read-only containers and minimal images when possible to prevent the running of commands.{}&nbsp;".format(insert))
        t1611html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1611html.write("Ensure containers are not running as root by default.")
    with open(sd+"t1068.html", "w") as t1068html:
        # descriptions
        t1068html.write("{}Adversaries may exploit software vulnerabilities in an attempt to collect elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.</li>\n        <li>".format(header))
        t1068html.write("Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions.</li>\n        <li>")
        t1068html.write("When initially gaining access to a system, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system.</li>\n        <li>")
        t1068html.write("Vulnerabilities may exist, usually in operating system components and software commonly running at higher permissions, that can be exploited to gain higher levels of access on the system. This could enable someone to move from unprivileged or user level permissions to SYSTEM or root permissions depending on the component that is vulnerable.</li>\n        <li>")
        t1068html.write("This may be a necessary step for an adversary compromising a endpoint system that has been properly configured and limits other privilege escalation methods.")
        # indicator regex assignments
        t1068html.write("{}-".format(iocs))
        # details
        t1068html.write("{}T1068</td>\n        <td>&nbsp;".format(headings)) # id
        t1068html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1068html.write("Privilege Escalation</td>\n        <td>&nbsp;") # tactics
        t1068html.write("-") # sub-techniques
        # related techniques
        t1068html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1105 target=\"_blank\"\">&nbsp;T1105</a></td>\n        <td>&nbsp;".format(related))
        t1068html.write("Ingress Tool Transfer")
        t1068html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1570 target=\"_blank\"\">&nbsp;T1570</a></td>\n        <td>&nbsp;".format(insert))
        t1068html.write("Lateral Tool Transfer")
        # mitigations
        t1068html.write("{}Application Isolation and Sandboxing</td>\n        <td>&nbsp;".format(mitigations))
        t1068html.write("Make it difficult for adversaries to advance their operation through exploitation of undiscovered or unpatched vulnerabilities by using sandboxing. Other types of virtualization and application microsegmentation may also mitigate the impact of some types of exploitation. Risks of additional exploits and weaknesses in these systems may still exist.{}&nbsp;".format(insert))
        t1068html.write("Execution Prevention</td>\n        <td>&nbsp;")
        t1068html.write("Consider blocking the execution of known vulnerable drivers that adversaries may exploit to execute code in kernel mode. Validate driver block rules in audit mode to ensure stability prior to production deployment.{}&nbsp;".format(insert))
        t1068html.write("Exploit Protection</td>\n        <td>&nbsp;")
        t1068html.write("Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility and may not work for software components targeted for privilege escalation.{}&nbsp;".format(insert))
        t1068html.write("Threat Intelligence Program</td>\n        <td>&nbsp;")
        t1068html.write("Develop a robust cyber threat intelligence capability to determine what types and levels of threat may use software exploits and 0-days against a particular organization.{}&nbsp;".format(insert))
        t1068html.write("Update Software</td>\n        <td>&nbsp;")
        t1068html.write("Update software regularly by employing patch management for internal enterprise endpoints and servers.{}".format(footer))
    with open(sd+"t1055.html", "w") as t1055html:
        # descriptions
        t1055html.write("{}Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process.</li>\n        <li>".format(header))
        t1055html.write("Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.</li>\n        <li>")
        t1055html.write("There are many different ways to inject code into a process, many of which abuse legitimate functionalities. These implementations exist for every major OS but are typically platform specific.</li>\n        <li>")
        t1055html.write("More sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel.")
        # indicator regex assignments
        t1055html.write("{}Evant IDs: 17, 18</li>\n        <li>".format(iocs))
        t1055html.write("CreateFileTransacted")
        t1055html.write("CreateTransaction")
        t1055html.write("NtCreateThreadEx")
        t1055html.write("NtUnmapViewOfSection")
        t1055html.write("RollbackTransaction")
        t1055html.write("VirtualProtectEx")
        t1055html.write("CreateRemoteThread")
        t1055html.write("GetWindowLong")
        t1055html.write("SetWindowLong")
        t1055html.write("LoadLibrary")
        t1055html.write("NtUnmapViewOfSection")
        t1055html.write("NtQueueApcThread")
        t1055html.write("QueueUserApc")
        t1055html.write("ResumeThread")
        t1055html.write("SetThreadContext")
        t1055html.write("SuspendThread")
        t1055html.write("VirtualAlloc")
        t1055html.write("ZwUnmapViewOfSection</li>\n        <li>")
        t1055html.write("malloc</li>\n        <li>")
        t1055html.write("ptrace_setregs")
        t1055html.write("ptrace_poketext")
        t1055html.write("ptrace_pokedata")
        # details
        t1055html.write("{}T1055</td>\n        <td>&nbsp;".format(headings)) # id
        t1055html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1055html.write("Privilege Escalation, Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1055html.write("T1574.001: Dynamic-link Library Injection<br>&nbsp;T1574.002: Portable Execution Injection<br>&nbsp;T1574.003: Thread Execution Hijacking<br>&nbsp;T1574.004: Asynchronous Procedure Call<br>&nbsp;T1574.005: Thread Local Storage<br>&nbsp;T1574.008: Ptrace System Calls<br>&nbsp;T1574.009: Proc Memory<br>&nbsp;T1574.011: Extra Windows Memory Injection<br>&nbsp;T1574.012: Process Hollowing<br>&nbsp;T1574.013: Process Doppelganging<br>&nbsp;T1574.014: VDSO Hijacking") # sub-techniques
        # related techniques
        t1055html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1055html.write("-")
        # mitigations
        t1055html.write("{}Behavior Prevention on Endpoint</td>\n        <td>&nbsp;".format(mitigations))
        t1055html.write("Some endpoint security solutions can be configured to block some types of process injection based on common sequences of behavior that occur during the injection process.{}&nbsp;".format(insert))
        t1055html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1055html.write("Utilize Yama (ex: /proc/sys/kernel/yama/ptrace_scope) to mitigate ptrace based process injection by restricting the use of ptrace to privileged users only. Other mitigation controls involve the deployment of security kernel modules that provide advanced access control and process restrictions such as SELinux, grsecurity, and AppArmor.{}".format(footer))
  # Defense Evasion
    with open(sd+"t1612.html", "w") as t1612html:
        # descriptions
        t1612html.write("{}Adversaries may build a container image directly on a host to bypass defenses that monitor for the retrieval of malicious images from a public registry. A remote build request may be sent to the Docker API that includes a Dockerfile that pulls a vanilla base image, such as alpine, from a public or local registry and then builds a custom image upon it.</li>\n        <li>".format(header))
        t1612html.write("An adversary may take advantage of that build API to build a custom image on the host that includes malware downloaded from their C2 server, and then they then may utilize Deploy Container using that custom image. If the base image is pulled from a public registry, defenses will likely not detect the image as malicious since it’s a vanilla image. If the base image already resides in a local registry, the pull may be considered even less suspicious since the image is already in the environment.")
        # indicator regex assignments
        t1612html.write("{}Ports: 2375, 2376</li>\n        <li>".format(iocs))
        t1612html.write("docker build</li>")
        # details
        t1612html.write("{}T1610</td>\n        <td>&nbsp;".format(headings)) # id
        t1612html.write("Containers</td>\n        <td>&nbsp;") # platforms
        t1612html.write("Execution</td>\n        <td>&nbsp;") # tactics
        t1612html.write("-") # sub-techniques
        # related techniques
        t1612html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1610 target=\"_blank\"\">&nbsp;T1610</a></td>\n        <td>&nbsp;".format(related))
        t1612html.write("Deploy Container")
        t1612html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1609 target=\"_blank\"\">&nbsp;T1609</a></td>\n        <td>&nbsp;".format(insert))
        t1612html.write("Container Administration Command")
        # mitigations
        t1612html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1612html.write("Audit images deployed within the environment to ensure they do not contain any malicious components.{}&nbsp;".format(insert))
        t1612html.write("Limit Access to Resource Over Network</td>\n        <td>&nbsp;")
        t1612html.write("Limit communications with the container service to local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API on port 2375. Instead, communicate with the Docker API over TLS on port 2376.{}&nbsp;".format(insert))
        t1612html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1612html.write("Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.{}&nbsp;".format(insert))
        t1612html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1612html.write("Ensure containers are not running as root by default.{}".format(footer))
    with open(sd+"t1140.html", "w") as t1140html:
        # descriptions
        t1140html.write("{}Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it.</li>\n        <li>".format(header))
        t1140html.write("Methods for doing that include built-in functionality of malware or by using utilities present on the system.</li>\n        <li>")
        t1140html.write("One such example is use of certutil to decode a remote access tool portable executable file that has been hidden inside a certificate file. Another example is using the Windows copy /b command to reassemble binary fragments into a malicious payload.</li>\n        <li>")
        t1140html.write("Sometimes a user's action may be required to open it for deobfuscation or decryption as part of User Execution. The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary.")
        # indicator regex assignments
        t1140html.write("{}certutil</li>\n        <li>".format(iocs))
        t1140html.write("-decode</li>\n        <li>")
        t1140html.write("openssl")
        # details
        t1140html.write("{}T1140</td>\n        <td>&nbsp;".format(headings)) # id
        t1140html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1140html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1140html.write("-") # sub-techniques
        # related techniques
        t1140html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1027 target=\"_blank\"\">&nbsp;T1027</a></td>\n        <td>&nbsp;".format(related))
        t1140html.write("Obfuscated Files or Information")
        t1140html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1204 target=\"_blank\"\">&nbsp;T1204</a></td>\n        <td>&nbsp;".format(insert))
        t1140html.write("User Execution")
        # mitigations
        t1140html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1140html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1006.html", "w") as t1006html:
        # descriptions
        t1006html.write("{}Adversaries may directly access a volume to bypass file access controls and file system monitoring.</li>\n        <li>".format(header))
        t1006html.write("Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures.</li>\n        <li>")
        t1006html.write("This technique bypasses Windows file access controls as well as file system monitoring tools.</li>\n        <li>")
        t1006html.write("Utilities, such as NinjaCopy, exist to perform these actions in PowerShell.")
        # indicator regex assignments
        t1006html.write("{}-".format(iocs))
        # details
        t1006html.write("{}T1006</td>\n        <td>&nbsp;".format(headings)) # id
        t1006html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1006html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1006html.write("-") # sub-techniques
        # related techniques
        t1006html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1059 target=\"_blank\"\">&nbsp;T1059.001</a></td>\n        <td>&nbsp;".format(related))
        t1006html.write("Command and Scripting Interpreter: PowerShell")
        # mitigations
        t1006html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1006html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1480.html", "w") as t1480html:
        # descriptions
        t1480html.write("{}Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target.</li>\n        <li>".format(header))
        t1480html.write("Guardrails ensure that a payload only executes against an intended target and reduces collateral damage from an adversary’s campaign.</li>\n        <li>")
        t1480html.write("Values an adversary can provide about a target system or environment to use as guardrails may include specific network share names, attached physical devices, files, joined Active Directory (AD) domains, and local/external IP addresses.</li>\n        <li>")
        t1480html.write("Guardrails can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. This use of guardrails is distinct from typical Virtualization/Sandbox Evasion.</li>\n        <li>")
        t1480html.write("While use of Virtualization/Sandbox Evasion may involve checking for known sandbox values and continuing with execution only if there is no match, the use of guardrails will involve checking for an expected target-specific value and only continuing with execution if there is such a match.")
        # indicator regex assignments
        t1480html.write("{}-".format(iocs))
        # details
        t1480html.write("{}T1480</td>\n        <td>&nbsp;".format(headings)) # id
        t1480html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1480html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1480html.write("T1480.001: Environmental Keying") # sub-techniques
        # related techniques
        t1480html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1487 target=\"_blank\"\">&nbsp;T1487</a></td>\n        <td>&nbsp;".format(related))
        t1480html.write("Virtualization/Sandbox Evasion")
        # mitigations
        t1480html.write("{}Do Not Mitigate</td>\n        <td>&nbsp;".format(mitigations))
        t1480html.write("Execution Guardrails likely should not be mitigated with preventative controls because it may protect unintended targets from being compromised. If targeted, efforts should be focused on preventing adversary tools from running earlier in the chain of activity and on identifying subsequent malicious behavior if compromised.{}".format(footer))
    with open(sd+"t1211.html", "w") as t1211html:
        # descriptions
        t1211html.write("{}Adversaries may exploit software vulnerabilities in an attempt to collect credentials.</li>\n        <li>".format(header))
        t1211html.write("Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.</li>\n        <li>")
        t1211html.write("Credentialing and authentication mechanisms may be targeted for exploitation by adversaries as a means to gain access to useful credentials or circumvent the process to gain access to systems.</li>\n        <li>")
        t1211html.write("One example of this is MS14-068, which targets Kerberos and can be used to forge Kerberos tickets using domain user permissions.</li>\n        <li>")
        t1211html.write("Exploitation for credential access may also result in Privilege Escalation depending on the process targeted or credentials obtained.")
        # indicator regex assignments
        t1211html.write("{}-".format(iocs))
        # details
        t1211html.write("{}T1212</td>\n        <td>&nbsp;".format(headings)) # id
        t1211html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1211html.write("Credential Access</td>\n        <td>&nbsp;") # tactics
        t1211html.write("-") # sub-techniques
        # related techniques
        t1211html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1518 target=\"_blank\"\">&nbsp;T1518</a></td>\n        <td>&nbsp;".format(related))
        t1211html.write("Security Software Discovery")
        # mitigations
        t1211html.write("{}Application Isolation and Sandboxing</td>\n        <td>&nbsp;".format(mitigations))
        t1211html.write("Make it difficult for adversaries to advance their operation through exploitation of undiscovered or unpatched vulnerabilities by using sandboxing. Other types of virtualization and application microsegmentation may also mitigate the impact of some types of exploitation. Risks of additional exploits and weaknesses in these systems may still exist.{}&nbsp;".format(insert))
        t1211html.write("Exploit Protection</td>\n        <td>&nbsp;")
        t1211html.write("Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility and may not work for software targeted for defense evasion.{}&nbsp;".format(insert))
        t1211html.write("Threat Intelligence Program</td>\n        <td>&nbsp;")
        t1211html.write("Develop a robust cyber threat intelligence capability to determine what types and levels of threat may use software exploits and 0-days against a particular organization.{}&nbsp;".format(insert))
        t1211html.write("Update Software</td>\n        <td>&nbsp;")
        t1211html.write("Update software regularly by employing patch management for internal enterprise endpoints and servers.{}".format(footer))
    with open(sd+"t1222.html", "w") as t1222html:
        # descriptions
        t1222html.write("{}Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions.</li>\n        <li>".format(header))
        t1222html.write("File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).</li>\n        <li>")
        t1222html.write("Modifications may include changing specific access rights, which may require taking ownership of a file or directory and/or elevated permissions depending on the file or directory’s existing permissions. This may enable malicious activity such as modifying, replacing, or deleting specific files or directories.</li>\n        <li>")
        t1222html.write("Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via Accessibility Features, Boot or Logon Initialization Scripts, .bash_profile and .bashrc, or tainting/hijacking other instrumental binary/configuration files via Hijack Execution Flow.")
        # indicator regex assignments
        t1222html.write("{}Event IDs: 4670</li>\n        <li>".format(iocs))
        t1222html.write("icacls</li>\n        <li>")
        t1222html.write("cacls</li>\n        <li>")
        t1222html.write("takeown</li>\n        <li>")
        t1222html.write("attrib</li>\n        <li>")
        t1222html.write("chmod</li>\n        <li>")
        t1222html.write("chown</li>\n        <li>")
        t1222html.write("chgrp")
        # details
        t1222html.write("{}T1222</td>\n        <td>&nbsp;".format(headings)) # id
        t1222html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1222html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1222html.write("T1222.001: Windows File and Directory Permissions Modification<br>&nbsp;T1222.002: Linux and Mac File and Directory Permissions Modification") # sub-techniques
        # related
        t1222html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1546 target=\"_blank\"\">&nbsp;T1546.008</a></td>\n        <td>&nbsp;".format(insert))
        t1222html.write("Event Triggered Execution: Accessibility Features")
        t1222html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1037 target=\"_blank\"\">&nbsp;T1037</a></td>\n        <td>&nbsp;".format(insert))
        t1222html.write("Boot or Logon Initialization Scripts")
        t1222html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1546 target=\"_blank\"\">&nbsp;T1546.004</a></td>\n        <td>&nbsp;".format(insert))
        t1222html.write("Event Triggered Execution: Unix Shell Configuration Modification")
        t1222html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1574 target=\"_blank\"\">&nbsp;T1574</a></td>\n        <td>&nbsp;".format(insert))
        t1222html.write("Hijack Execution Flow")
        # mitigations
        t1222html.write("{}Privileged Account Management</td>\n        <td>&nbsp;".format(mitigations))
        t1222html.write("Ensure critical system files as well as those known to be abused by adversaries have restrictive permissions and are owned by an appropriately privileged account, especially if access is not required by users nor will inhibit system functionality.{}&nbsp;".format(insert))
        t1222html.write("Restrict File and Directory Permissions</td>\n        <td>&nbsp;")
        t1222html.write("Applying more restrictive permissions to files and directories could prevent adversaries from modifying the access control lists.{}".format(footer))
    with open(sd+"t1564.html", "w") as t1564html:
        # descriptions
        t1564html.write("{}Adversaries may attempt to hide artifacts associated with their behaviors to evade detection. Operating systems may have features to hide various artifacts, such as important system files and administrative task execution, to avoid disrupting user work environments and prevent users from changing files or features on the system.</li>\n        <li>".format(header))
        t1564html.write("Adversaries may abuse these features to hide artifacts such as files, directories, user accounts, or other system activity to evade detection.</li>\n        <li>")
        t1564html.write("Adversaries may also attempt to hide artifacts associated with malicious behavior by creating computing regions that are isolated from common security instrumentation, such as through the use of virtualization technology.")
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
        t1564html.write("LoginWindow")
        t1564html.write("Hide500Users")
        t1564html.write("UniqueID")
        t1564html.write("UIElement")
        # details
        t1564html.write("{}T1564</td>\n        <td>&nbsp;".format(headings)) # id
        t1564html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1564html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1564html.write("T1564.001: Hidden Files and Directories<br>&nbsp;T1564.002: Hidden Users<br>&nbsp;T1564.003: Hidden Window<br>&nbsp;T1564.004: NTFS File Attributes<br>&nbsp;T1564.005: Hidden File System<br>&nbsp;T1564.006: Run Virtual Instance<br>&nbsp;T1564.007: VBA Stomping") # sub-techniques
        # related techniques
        t1564html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1564html.write("-")
        # mitigations
        t1564html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1564html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1562.html", "w") as t1562html:
        # descriptions
        t1562html.write("{}Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior.</li>\n        <li>".format(header))
        t1562html.write("This may also span both native defenses as well as supplemental capabilities installed by users and administrators.</li>\n        <li>")
        t1562html.write("Adversaries could also target event aggregation and analysis mechanisms, or otherwise disrupt these procedures by altering other system components.")
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
        t1562html.write("HISTCONTROL")
        t1562html.write("HISTFILE")
        t1562html.write("kill")
        # details
        t1562html.write("{}T1562</td>\n        <td>&nbsp;".format(headings)) # id
        t1562html.write("Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1562html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1562html.write("T1562.001: Disable or Modify Tools<br>&nbsp;T1562.002: Disable Windows Event Logging<br>&nbsp;T1562.003: HISTCONTROL<br>&nbsp;T1562.004: Disable or Modify System Firewall<br>&nbsp;T1562.006: Indicator Blocking<br>&nbsp;T1562.007: Disable or Modify Cloud Firewall<br>&nbsp;T1562.008: Disable Cloud Logs") # sub-techniques
        # related techniques
        t1562html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1562html.write("-")
        # mitigations
        t1562html.write("{}Restrict File and Directory Permissions</td>\n        <td>&nbsp;".format(mitigations))
        t1562html.write("Ensure proper process and file permissions are in place to prevent adversaries from disabling or interfering with security/logging services.{}&nbsp;".format(insert))
        t1562html.write("Restrict Registry Permissions</td>\n        <td>&nbsp;")
        t1562html.write("Ensure proper Registry permissions are in place to prevent adversaries from disabling or interfering with security/logging services.{}&nbsp;".format(insert))
        t1562html.write("User Account Management</td>\n        <td>&nbsp;")
        t1562html.write("Ensure proper user permissions are in place to prevent adversaries from disabling or interfering with security/logging services.{}".format(footer))
    with open(sd+"t1070.html", "w") as t1070html:
        # descriptions
        t1070html.write("{}Adversaries may delete or alter generated artifacts on a host system, including logs or captured files such as quarantined malware.</li>\n        <li>".format(header))
        t1070html.write("Locations and format of logs are platform or product-specific, however standard operating system logs are captured as Windows events or Linux/macOS files such as Bash History and /var/log/*.</li>\n        <li>")
        t1070html.write("These actions may interfere with event collection, reporting, or other notifications used to detect intrusion activity. This that may compromise the integrity of security solutions by causing notable events to go unreported.</li>\n        <li>")
        t1070html.write("This activity may also impede forensic analysis and incident response, due to lack of sufficient data to determine what occurred.")
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
        t1070html.write("/var/log")
        # details
        t1070html.write("{}T1070</td>\n        <td>&nbsp;".format(headings)) # id
        t1070html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1070html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1070html.write("T1070.001: Clear Windows Event Logs<br>&nbsp;T1070.002: Clear Linux or Mac System Logs<br>&nbsp;T1070.003: Clear Command History<br>&nbsp;T1070.004: File Deletion<br>&nbsp;T1070.005: Network Share Connection Removal<br>&nbsp;T1070.006: Timestomp") # sub-techniques
        # related techniques
        t1070html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1552 target=\"_blank\"\">&nbsp;T1552</a></td>\n        <td>&nbsp;".format(related))
        t1070html.write("Unsecured Credentials: Bash History")
        # mitigations
        t1070html.write("{}Encrypt Sensitive Information</td>\n        <td>&nbsp;".format(mitigations))
        t1070html.write("Obfuscate/encrypt event files locally and in transit to avoid giving feedback to an adversary.{}&nbsp;".format(insert))
        t1070html.write("Remote Data Storage</td>\n        <td>&nbsp;")
        t1070html.write("Automatically forward events to a log server or data repository to prevent conditions in which the adversary can locate and manipulate data on the local system. When possible, minimize time delay on event reporting to avoid prolonged storage on the local system.{}&nbsp;".format(insert))
        t1070html.write("Restrict File and Directory Permissions</td>\n        <td>&nbsp;")
        t1070html.write("Protect generated event files that are stored locally with proper permissions and authentication and limit opportunities for adversaries to increase privileges by preventing Privilege Escalation opportunities.{}".format(footer))
    with open(sd+"t1202.html", "w") as t1202html:
        # descriptions
        t1202html.write("{}Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters. Various Windows utilities may be used to execute commands, possibly without invoking cmd.</li>\n        <li>".format(header))
        t1202html.write("For example, Forfiles, the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a Command and Scripting Interpreter, Run window, or via scripts.</li>\n        <li>")
        t1202html.write("Adversaries may abuse these features for Defense Evasion, specifically to perform arbitrary execution while subverting detections and/or mitigation controls (such as Group Policy) that limit/prevent the usage of cmd or file extensions more commonly associated with malicious payloads.")
        # indicator regex assignments
        t1202html.write("{}-".format(iocs))
        # details
        t1202html.write("{}T1202</td>\n        <td>&nbsp;".format(headings)) # id
        t1202html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1202html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1202html.write("-") # sub-techniques
        # related techniques
        t1202html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1059 target=\"_blank\"\">&nbsp;T1059</a></td>\n        <td>&nbsp;".format(related))
        t1202html.write("Command and Scripting Interpreter")
        # mitigations
        t1202html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1202html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1036.html", "w") as t1036html:
        # descriptions
        t1036html.write("{}Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools.</li>\n        <li>".format(header))
        t1036html.write("Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation.</li>\n        <li>")
        t1036html.write("This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.</li>\n        <li>")
        t1036html.write("Renaming abusable system utilities to evade security monitoring is also a form of Masquerading.")
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
        t1036html.write("iexplorar")
        # details
        t1036html.write("{}T1036</td>\n        <td>&nbsp;".format(headings)) # id
        t1036html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1036html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1036html.write("T1036.001: Invalid Code Signature<br>&nbsp;T1036.002: Right-to-Left Override<br>&nbsp;T1036.003: Rename System Utilities<br>&nbsp;T1036.004: Masquerade Task or Service<br>&nbsp;T1036.005: Match Legitimate Name or Location<br>&nbsp;T1036.006: Space after Filename") # sub-techniques
        # related techniques
        t1036html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1036html.write("-")
        # mitigations
        t1036html.write("{}Code Signing</td>\n        <td>&nbsp;".format(mitigations))
        t1036html.write("Require signed binaries.{}&nbsp;".format(insert))
        t1036html.write("Execution Prevention</td>\n        <td>&nbsp;")
        t1036html.write("Use tools that restrict program execution via application control by attributes other than file name for common operating system utilities that are needed.{}&nbsp;".format(insert))
        t1036html.write("Restrict File and Directory Permissions</td>\n        <td>&nbsp;")
        t1036html.write("Use file system access controls to protect folders such as C:\\Windows\\System32.{}".format(footer))
    with open(sd+"t1578.html", "w") as t1578html:
        # descriptions
        t1578html.write("{}An adversary may attempt to modify a cloud account's compute service infrastructure to evade defenses.</li>\n        <li>".format(header))
        t1578html.write("A modification to the compute service infrastructure can include the creation, deletion, or modification of one or more components such as compute instances, virtual machines, and snapshots.</li>\n        <li>")
        t1578html.write("Permissions gained from the modification of infrastructure components may bypass restrictions that prevent access to existing infrastructure.</li>\n        <li>")
        t1578html.write("Modifying infrastructure components may also allow an adversary to evade detection and remove evidence of their presence.")
        # indicator regex assignments
        t1578html.write("{}-".format(iocs))
        # details
        t1578html.write("{}T1578</td>\n        <td>&nbsp;".format(headings)) # id
        t1578html.write("AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1578html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1578html.write("T1578.001: Create Snapshot<br>&nbsp;T1578.002: Create Cloud Instance<br>&nbsp;T1578: Delete Cloud Instance<br>&nbsp;T1578.003: Revert Cloud Instance") # sub-techniques
        # related techniques
        t1578html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1578html.write("-")
        # mitigations
        t1578html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1578html.write("Routinely monitor user permissions to ensure only the expected users have the capability to modify cloud compute infrastructure components.{}&nbsp;".format(insert))
        t1578html.write("User Account Management</td>\n        <td>&nbsp;")
        t1578html.write("Limit permissions for creating, deleting, and otherwise altering compute components in accordance with least privilege. Organizations should limit the number of users within the organization with an IAM role that has administrative privileges, strive to reduce all permanent privileged role assignments, and conduct periodic entitlement reviews on IAM users, roles and policies.{}".format(footer))
    with open(sd+"t1112.html", "w") as t1112html:
        # descriptions
        t1112html.write("{}Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.</li>\n        <li>".format(header))
        t1112html.write("Access to specific areas of the Registry depends on account permissions, some requiring administrator-level access.</li>\n        <li>")
        t1112html.write("The built-in Windows command-line utility Reg may be used for local or remote Registry modification. Other tools may also be used, such as a remote access tool, which may contain functionality to interact with the Registry through the Windows API.</li>\n        <li>")
        t1112html.write("Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via Reg or other utilities using the Win32 API.</li>\n        <li>")
        t1112html.write("Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence.</li>\n        <li>")
        t1112html.write("The Registry of a remote system may be modified to aid in execution of files as part of lateral movement. It requires the remote Registry service to be running on the target system. Often Valid Accounts are required, along with access to the remote system's SMB/Windows Admin Shares for RPC communication.")
        # indicator regex assignments
        t1112html.write("{}autoruns</li>\n        <li>".format(iocs))
        t1112html.write("regdelnull</li>\n        <li>")
        t1112html.write("reg.exe")
        # details
        t1112html.write("{}T1112</td>\n        <td>&nbsp;".format(headings)) # id
        t1112html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1112html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1112html.write("-") # sub-techniques
        # related techniques
        t1112html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1078 target=\"_blank\"\">&nbsp;T1078</a></td>\n        <td>&nbsp;".format(related))
        t1112html.write("Valid Accounts")
        t1112html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1021 target=\"_blank\"\">&nbsp;T1021</a></td>\n        <td>&nbsp;".format(insert))
        t1112html.write("Remote Services: SMB/Windows Admin Shares")
        # mitigations
        t1112html.write("{}Restrict Registry Permissions</td>\n        <td>&nbsp;".format(mitigations))
        t1112html.write("Ensure proper permissions are set for Registry hives to prevent users from modifying keys for system components that may lead to privilege escalation.{}".format(footer))
    with open(sd+"t1601.html", "w") as t1601html:
        # descriptions
        t1601html.write("{}Adversaries may make changes to the operating system of embedded network devices to weaken defenses and provide new capabilities for themselves. On such devices, the operating systems are typically monolithic and most of the device functionality and capabilities are contained within a single file.</li>\n        <li>".format(header))
        t1601html.write("To change the operating system, the adversary typically only needs to affect this one file, replacing or modifying it. This can either be done live in memory during system runtime for immediate effect, or in storage to implement the change on the next boot of the network device.")
        t1601html.write("{}-".format(iocs))
        # details
        t1601html.write("{}T1601</td>\n        <td>&nbsp;".format(headings)) # id
        t1601html.write("Containers</td>\n        <td>&nbsp;") # platforms
        t1601html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1601html.write("T1601.001: Patch System Image&nbsp;T1601.002: Downgrade System Image<br>") # sub-techniques
        # related techniques
        t1601html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1601html.write("-")
        # mitigations
        t1601html.write("{}Boot Integrity</td>\n        <td>&nbsp;".format(mitigations))
        t1601html.write("Some vendors of embedded network devices provide cryptographic signing to ensure the integrity of operating system images at boot time. Implement where available, following vendor guidelines.{}&nbsp;".format(insert))
        t1601html.write("Code Signing</td>\n        <td>&nbsp;")
        t1601html.write("Many vendors provide digitally signed operating system images to validate the integrity of the software used on their platform. Make use of this feature where possible in order to prevent and/or detect attempts by adversaries to compromise the system image. {}&nbsp;".format(insert))
        t1601html.write("Credential Access Protection</td>\n        <td>&nbsp;")
        t1601html.write("Some embedded network devices are capable of storing passwords for local accounts in either plain-text or encrypted formats. Ensure that, where available, local passwords are always encrypted, per vendor recommendations.{}&nbsp;".format(insert))
        t1601html.write("Multi-factor Authentication</td>\n        <td>&nbsp;")
        t1601html.write("Use multi-factor authentication for user and privileged accounts. Most embedded network devices support TACACS+ and/or RADIUS. Follow vendor prescribed best practices for hardening access control.{}&nbsp;".format(insert))
        t1601html.write("Password Policies</td>\n        <td>&nbsp;")
        t1601html.write("Refer to NIST guidelines when creating password policies.{}&nbsp;".format(insert))
        t1601html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1601html.write("Restrict administrator accounts to as few individuals as possible, following least privilege principles. Prevent credential overlap across systems of administrator and privileged accounts, particularly between network and non-network platforms, such as servers or endpoints.{}".format(footer))
    with open(sd+"t1599.html", "w") as t1599html:
        # descriptions
        t1599html.write("{}Adversaries may bridge network boundaries by compromising perimeter network devices. Breaching these devices may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks.</li>\n        <li>".format(header))
        t1599html.write("Devices such as routers and firewalls can be used to create boundaries between trusted and untrusted networks. They achieve this by restricting traffic types to enforce organizational policy in an attempt to reduce the risk inherent in such connections. Restriction of traffic can be achieved by prohibiting IP addresses, layer 4 protocol ports, or through deep packet inspection to identify applications. To participate with the rest of the network, these devices can be directly addressable or transparent, but their mode of operation has no bearing on how the adversary can bypass them when compromised.</li>\n        <li>")
        t1599html.write("When an adversary takes control of such a boundary device, they can bypass its policy enforcement to pass normally prohibited traffic across the trust boundary between the two separated networks without hinderance. By achieving sufficient rights on the device, an adversary can reconfigure the device to allow the traffic they want, allowing them to then further achieve goals such as command and control via Multi-hop Proxy or exfiltration of data via Traffic Duplication. In the cases where a border device separates two separate organizations, the adversary can also facilitate lateral movement into new victim environments.")
        # indicator regex assignments
        t1599html.write("{}-".format(iocs))
        # details
        t1599html.write("{}T1599</td>\n        <td>&nbsp;".format(headings)) # id
        t1599html.write("Network</td>\n        <td>&nbsp;") # platforms
        t1599html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1599html.write("T1599.001: Network Address Translation Traversal") # sub-techniques
        # related techniques
        t1599html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1090 target=\"_blank\"\">&nbsp;T1090</a></td>\n        <td>&nbsp;".format(related))
        t1599html.write("Multi-hop Proxy")
        # related techniques
        t1599html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1020 target=\"_blank\"\">&nbsp;T1020</a></td>\n        <td>&nbsp;".format(insert))
        t1599html.write("Traffic Duplication")
        # mitigations
        t1599html.write("{}Credential Access Protection</td>\n        <td>&nbsp;".format(mitigations))
        t1599html.write("Some embedded network devices are capable of storing passwords for local accounts in either plain-text or encrypted formats. Ensure that, where available, local passwords are always encrypted, per vendor recommendations.{}&nbsp;".format(insert))
        t1599html.write("Filter Network Traffic</td>\n        <td>&nbsp;")
        t1599html.write("Upon identifying a compromised network device being used to bridge a network boundary, block the malicious packets using an unaffected network device in path, such as a firewall or a router that has not been compromised. Continue to monitor for additional activity and to ensure that the blocks are indeed effective.{}&nbsp;".format(insert))
        t1599html.write("Multi-factor Authentication</td>\n        <td>&nbsp;")
        t1599html.write("Use multi-factor authentication for user and privileged accounts. Most embedded network devices support TACACS+ and/or RADIUS. Follow vendor prescribed best practices for hardening access control.[{}&nbsp;".format(insert))
        t1599html.write("Password Policies</td>\n        <td>&nbsp;")
        t1599html.write("Refer to NIST guidelines when creating password policies.{}&nbsp;".format(insert))
        t1599html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1599html.write("Restrict administrator accounts to as few individuals as possible, following least privilege principles. Prevent credential overlap across systems of administrator and privileged accounts, particularly between network and non-network platforms, such as servers or endpoints.{}".format(footer))
    with open(sd+"t1027.html", "w") as t1027html:
        # descriptions
        t1027html.write("{}Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.</li>\n        <li>".format(header))
        t1027html.write("Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open and Deobfuscate/Decode Files or Information for User Execution.</li>\n        <li>")
        t1027html.write("The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. Adversaries may also used compressed or archived scripts, such as JavaScript.</li>\n        <li>")
        t1027html.write("Portions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled.</li>\n        <li>")
        t1027html.write("Adversaries may also obfuscate commands executed from payloads or directly via a Command and Scripting Interpreter. Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and application control mechanisms.")
        # indicator regex assignments
        t1027html.write("{}csc.exe</li>\n        <li>".format(iocs))
        t1027html.write("gcc</li>\n        <li>")
        t1027html.write("MinGW</li>\n        <li>")
        t1027html.write("FileRecvWriteRand")
        # details
        t1027html.write("{}T1027</td>\n        <td>&nbsp;".format(headings)) # id
        t1027html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1027html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1027html.write("T1027.001: Binary Padding<br>&nbsp;T1027.002: Software Packing<br>&nbsp;T1027.003: Steganography<br>&nbsp;T1027.004: Complie After Delivery<br>&nbsp;T1027.005: Indicator Removal from Tools") # sub-techniques
        # related techniques
        t1027html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1140 target=\"_blank\"\">&nbsp;T1140</a></td>\n        <td>&nbsp;".format(related))
        t1027html.write("Deobfuscate/Decode Files or Information")
        t1027html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1059 target=\"_blank\"\">&nbsp;T1059</a></td>\n        <td>&nbsp;".format(insert))
        t1027html.write("Command and Scripting Interpreter")
        # mitigations
        t1027html.write("{}Antivirus/Antimalware</td>\n        <td>&nbsp;".format(mitigations))
        t1027html.write("Consider utilizing the Antimalware Scan Interface (AMSI) on Windows 10 to analyze commands after being processed/interpreted.{}".format(footer))
    with open(sd+"t1207.html", "w") as t1207html:
        # descriptions
        t1207html.write("{}Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data. DCShadow may be used to create a rogue Domain Controller (DC).</li>\n        <li>".format(header))
        t1207html.write("DCShadow is a method of manipulating Active Directory (AD) data, including objects and schemas, by registering (or reusing an inactive registration) and simulating the behavior of a DC.</li>\n        <li>")
        t1207html.write("Once registered, a rogue DC may be able to inject and replicate changes into AD infrastructure for any domain object, including credentials and keys.</li>\n        <li>")
        t1207html.write("Registering a rogue DC involves creating a new server and nTDSDSA objects in the Configuration partition of the AD schema, which requires Administrator privileges (either Domain or local to the DC) or the KRBTGT hash.</li>\n        <li>")
        t1207html.write("This technique may bypass system logging and security monitors such as security information and event management (SIEM) products (since actions taken on a rogue DC may not be reported to these sensors).</li>\n        <li>")
        t1207html.write("The technique may also be used to alter and delete replication and other associated metadata to obstruct forensic analysis.</li>\n        <li>")
        t1207html.write("Adversaries may also utilize this technique to perform SID-History Injection and/or manipulate AD objects (such as accounts, access control lists, schemas) to establish backdoors for Persistence.")
        # indicator regex assignments
        t1207html.write("{}lsadump</li>\n        <li>".format(iocs))
        t1207html.write("DCShadow")
        # details
        t1207html.write("{}T1207</td>\n        <td>&nbsp;".format(headings)) # id
        t1207html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1207html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1207html.write("-")
        # related techniques
        t1207html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1134 target=\"_blank\"\">&nbsp;T1134</a></td>\n        <td>&nbsp;".format(related))
        t1207html.write("SID-History Injection")
        # mitigations
        t1207html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1207html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1014.html", "w") as t1014html:
        # descriptions
        t1014html.write("{}Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components. Rootkits are programs that hide the existence of malware by intercepting/hooking and modifying operating system API calls that supply system information.</li>\n        <li>".format(header))
        t1014html.write("Rootkits or rootkit enabling functionality may reside at the user or kernel level in the operating system or lower, to include a hypervisor, Master Boot Record, or System Firmware. Rootkits have been seen for Windows, Linux, and Mac OS X systems.")
        # indicator regex assignments
        t1014html.write("{}-".format(iocs))
        # details
        t1014html.write("{}T1014</td>\n        <td>&nbsp;".format(headings)) # id
        t1014html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1014html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1014html.write("-") # sub-techniques
        # related techniques
        t1014html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1542 target=\"_blank\"\">&nbsp;T1542.001</a></td>\n        <td>&nbsp;".format(related))
        t1014html.write("Pre-OS Boot: System Firmware")
        # mitigations
        t1014html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1014html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1218.html", "w") as t1218html:
        # descriptions
        t1218html.write("{}Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries.</li>\n        <li>".format(header))
        t1218html.write("Binaries signed with trusted digital certificates can execute on Windows systems protected by digital signature validation.</li>\n        <li>")
        t1218html.write("Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files.")
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
        t1218html.write("panel/cpls")
        # details
        t1218html.write("{}T1218</td>\n        <td>&nbsp;".format(headings)) # id
        t1218html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1218html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1218html.write("T1218.001: Compiled HTML File<br>&nbsp;T1218.002: Control Panel<br>&nbsp;T1218.003: CMSTP<br>&nbsp;T1218.004: InstallUtil<br>&nbsp;T1218.005: Mshta<br>&nbsp;T1218.007: Msiexec<br>&nbsp;T1218.008: Odbcconf<br>&nbsp;T1218.009: Regsvcs/Regasm<br>&nbsp;T1218.010: Regsvr32<br>&nbsp;T1218.011: Rundll32<br>&nbsp;T1218.012: Verclsid") # sub-techniques
        # related techniques
        t1218html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1218html.write("-")
        # mitigations
        t1218html.write("{}Disable or Remove Feature or Program</td>\n        <td>&nbsp;".format(mitigations))
        t1218html.write("Many native binaries may not be necessary within a given environment.{}&nbsp;".format(insert))
        t1218html.write("Execution Prevention</td>\n        <td>&nbsp;")
        t1218html.write("Consider using application control to prevent execution of binaries that are susceptible to abuse and not required for a given system or network.{}&nbsp;".format(insert))
        t1218html.write("Exploit Protection</td>\n        <td>&nbsp;")
        t1218html.write("Microsoft's Enhanced Mitigation Experience Toolkit (EMET) Attack Surface Reduction (ASR) feature can be used to block methods of using using trusted binaries to bypass application control.{}&nbsp;".format(insert))
        t1218html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1218html.write("Restrict execution of particularly vulnerable binaries to privileged accounts or groups that need to use it to lessen the opportunities for malicious usage.{}".format(footer))
    with open(sd+"t1216.html", "w") as t1216html:
        # descriptions
        t1216html.write("{}Adversaries may use scripts signed with trusted certificates to proxy execution of malicious files. Several Microsoft signed scripts that are default on Windows installations can be used to proxy execution of other files.</li>\n        <li>".format(header))
        t1216html.write("This behavior may be abused by adversaries to execute malicious files that could bypass application control and signature validation on systems.")
        # indicator regex assignments
        t1216html.write("{}PubPrn</li>\n        <li>".format(iocs))
        t1216html.write("cscript.exe")
        # details
        t1216html.write("{}T1216</td>\n        <td>&nbsp;".format(headings)) # id
        t1216html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1216html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1216html.write("T1216.001: PubPrn") # sub-techniques
        # related techniques
        t1216html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1216html.write("-")
        # mitigations
        t1216html.write("{}Execution Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1216html.write("Certain signed scripts that can be used to execute other programs may not be necessary within a given environment. Use application control configured to block execution of these scripts if they are not required for a given system or network to prevent potential misuse by adversaries.{}".format(footer))
    with open(sd+"t1553.html", "w") as t1553html:
        # descriptions
        t1553html.write("{}Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs. Operating systems and security products may contain mechanisms to identify programs or websites as possessing some level of trust.</li>\n        <li>".format(header))
        t1553html.write("Examples of such features would include a program being allowed to run because it is signed by a valid code signing certificate, a program prompting the user with a warning because it has an attribute set from being downloaded from the Internet, or getting an indication that you are about to connect to an untrusted site.</li>\n        <li>")
        t1553html.write("Adversaries may attempt to subvert these trust mechanisms. The method adversaries use will depend on the specific mechanism they seek to subvert. Adversaries may conduct File and Directory Permissions Modification or Modify Registry in support of subverting these controls. Adversaries may also create or steal code signing certificates to acquire trust on target systems.")
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
        t1553html.write("com.apple.quarantine")
        t1553html.write("xattr")
        t1553html.write("xttr")
        # details
        t1553html.write("{}T1553</td>\n        <td>&nbsp;".format(headings)) # id
        t1553html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1553html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1553html.write("T1553.001: Gatekeeper Bypass<br>&nbsp;T1553.002: Code Signing<br>&nbsp;T1553.003: SIP and Trust Provider Hijacking<br>&nbsp;T1553.004: Install Root Certificate<br>&nbsp;T1553.005: Mark-of-the-Web Bypass<br>&nbsp;T1553.006: Code Signing Policy Modification") # sub-techniques
        # related techniques
        t1553html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1222 target=\"_blank\"\">&nbsp;T1222</a></td>\n        <td>&nbsp;".format(related))
        t1553html.write("File and Directory Permissions Modification")
        t1553html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1112 target=\"_blank\"\">&nbsp;T1112</a></td>\n        <td>&nbsp;".format(insert))
        t1553html.write("Modify Registry")
        # mitigations
        t1553html.write("{}Execution Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1553html.write("System settings can prevent applications from running that haven't been downloaded through the Apple Store (or other legitimate repositories) which can help mitigate some of these issues. Also enable application control solutions such as AppLocker and/or Device Guard to block the loading of malicious content.{}&nbsp;".format(insert))
        t1553html.write("Operating System Configuration</td>\n        <td>&nbsp;")
        t1553html.write("Windows Group Policy can be used to manage root certificates and the Flags value of HKLM\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\ProtectedRoots can be set to 1 to prevent non-administrator users from making further root installations into their own HKCU certificate store.{}&nbsp;".format(insert))
        t1553html.write("Restrict Registry Permissions</td>\n        <td>&nbsp;")
        t1553html.write("Ensure proper permissions are set for Registry hives to prevent users from modifying keys related to SIP and trust provider components. Components may still be able to be hijacked to suitable functions already present on disk if malicious modifications to Registry keys are not prevented.{}&nbsp;".format(insert))
        t1553html.write("Software Configuration</td>\n        <td>&nbsp;")
        t1553html.write("HTTP Public Key Pinning (HPKP) is one method to mitigate potential man-in-the-middle situations where and adversary uses a mis-issued or fraudulent certificate to intercept encrypted communications by enforcing use of an expected certificate.{}".format(footer))
    with open(sd+"t1221.html", "w") as t1221html:
        # descriptions
        t1221html.write("{}Adversaries may create or modify references in Office document templates to conceal malicious code or force authentication attempts. Microsoft’s Office Open XML (OOXML) specification defines an XML-based format for Office documents (.docx, xlsx, .pptx) to replace older binary formats (.doc, .xls, .ppt).</li>\n        <li>".format(header))
        t1221html.write("OOXML files are packed together ZIP archives compromised of various XML files, referred to as parts, containing properties that collectively define how a document is rendered.</li>\n        <li>")
        t1221html.write("Properties within parts may reference shared public resources accessed via online URLs. For example, template properties reference a file, serving as a pre-formatted document blueprint, that is fetched when the document is loaded.</li>\n        <li>")
        t1221html.write("Adversaries may abuse this technology to initially conceal malicious code to be executed via documents. Template references injected into a document may enable malicious payloads to be fetched and executed when the document is loaded.</li>\n        <li>")
        t1221html.write("These documents can be delivered via other techniques such as Phishing and/or Taint Shared Content and may evade static detections since no typical indicators (VBA macro, script, etc.) are present until after the malicious payload is fetched. Examples have been seen in the wild where template injection was used to load malicious code containing an exploit.</li>\n        <li>")
        t1221html.write("This technique may also enable Forced Authentication by injecting a SMB/HTTPS (or other credential prompting) URL and triggering an authentication attempt.")
        # indicator regex assignments
        t1221html.write("{}.docx</li>\n        <li>".format(iocs))
        t1221html.write(".xlsx</li>\n        <li>")
        t1221html.write(".pptx")
        # details
        t1221html.write("{}T1221</td>\n        <td>&nbsp;".format(headings)) # id
        t1221html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1221html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1221html.write("-") # sub-techniques
        # related techniques
        t1221html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1566 target=\"_blank\"\">&nbsp;T1566</a></td>\n        <td>&nbsp;".format(related))
        t1221html.write("Phishing")
        t1221html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1080 target=\"_blank\"\">&nbsp;T1080</a></td>\n        <td>&nbsp;".format(insert))
        t1221html.write("Taint Shared Content")
        t1221html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1187 target=\"_blank\"\">&nbsp;T1187</a></td>\n        <td>&nbsp;".format(insert))
        t1221html.write("Forced Authentication")
        # mitigations
        t1221html.write("{}Antivirus/Antimalware</td>\n        <td>&nbsp;".format(mitigations))
        t1221html.write("Network/Host intrusion prevention systems, antivirus, and detonation chambers can be employed to prevent documents from fetching and/or executing malicious payloads.{}&nbsp;".format(insert))
        t1221html.write("Disable or Remove Feature or Program</td>\n        <td>&nbsp;")
        t1221html.write("Consider disabling Microsoft Office macros/active content to prevent the execution of malicious payloads in documents, though this setting may not mitigate the Forced Authentication use for this technique.{}&nbsp;".format(insert))
        t1221html.write("Network Intrusion Prevention</td>\n        <td>&nbsp;")
        t1221html.write("Network/Host intrusion prevention systems, antivirus, and detonation chambers can be employed to prevent documents from fetching and/or executing malicious payloads.{}&nbsp;".format(insert))
        t1221html.write("User Training</td>\n        <td>&nbsp;")
        t1221html.write("Train users to identify social engineering techniques and spearphishing emails.{}".format(footer))
    with open(sd+"t1127.html", "w") as t1127html:
        # descriptions
        t1127html.write("{}Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads.</li>\n        <li>".format(header))
        t1127html.write("There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering.</li>\n        <li>")
        t1127html.write("These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application control solutions.")
        # indicator regex assignments
        t1127html.write("{}MSBuild".format(iocs))
        # details
        t1127html.write("{}T1127</td>\n        <td>&nbsp;".format(headings)) # id
        t1127html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1127html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1127html.write("T1127.001: MSBuild") # sub-techniques
        # related techniques
        t1127html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1127html.write("-")
        # mitigations
        t1127html.write("{}Disable or Remove Feature or Program</td>\n        <td>&nbsp;".format(mitigations))
        t1127html.write("Specific developer utilities may not be necessary within a given environment and should be removed if not used.{}&nbsp;".format(insert))
        t1127html.write("Execution Prevention</td>\n        <td>&nbsp;")
        t1127html.write("Certain developer utilities should be blocked or restricted if not required.{}".format(footer))
    with open(sd+"t1550.html", "w") as t1550html:
        # descriptions
        t1550html.write("{}Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.</li>\n        <li>".format(header))
        t1550html.write("Authentication processes generally require a valid identity (e.g., username) along with one or more authentication factors (e.g., password, pin, physical smart card, token generator, etc.).</li>\n        <li>")
        t1550html.write("Alternate authentication material is legitimately generated by systems after a user or application successfully authenticates by providing a valid identity and the required authentication factor(s). Alternate authentication material may also be generated during the identity creation process.</li>\n        <li>")
        t1550html.write("Caching alternate authentication material allows the system to verify an identity has successfully authenticated without asking the user to reenter authentication factor(s).</li>\n        <li>")
        t1550html.write("Because the alternate authentication must be maintained by the system—either in memory or on disk—it may be at risk of being stolen through Credential Access techniques.</li>\n        <li>")
        t1550html.write("By stealing alternate authentication material, adversaries are able to bypass system access controls and authenticate to systems without knowing the plaintext password or any additional authentication factors.")
        # indicator regex assignments
        t1550html.write("{}Event IDs: 4768, 4769</li>\n        <li>".format(iocs))
        t1550html.write("DCSync</li>\n        <li>")
        t1550html.write("duo-sid")
        # details
        t1550html.write("{}T1550</td>\n        <td>&nbsp;".format(headings)) # id
        t1550html.write("Windows, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1550html.write("Defense Evasion, Lateral Movement</td>\n        <td>&nbsp;") # tactics
        t1550html.write("T1550.001: Application Access Token<br>&nbsp;T1550.002: Pass the Hash<br>&nbsp;T1550.003: Pass the Ticket<br>&nbsp;T1550.004: Web Session Cookie") # sub-techniques
        # related techniques
        t1550html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1550html.write("-")
        # mitigations
        t1550html.write("{}Privileged Account Management</td>\n        <td>&nbsp;".format(mitigations))
        t1550html.write("Limit credential overlap across systems to prevent the damage of credential compromise and reduce the adversary's ability to perform Lateral Movement between systems.{}&nbsp;".format(insert))
        t1550html.write("User Account Management</td>\n        <td>&nbsp;")
        t1550html.write("Enforce the principle of least-privilege. Do not allow a domain user to be in the local administrator group on multiple systems.{}".format(footer))
    with open(sd+"t1535.html", "w") as t1535html:
        # descriptions
        t1535html.write("{}Adversaries may create cloud instances in unused geographic service regions in order to evade detection. Access is usually obtained through compromising accounts used to manage cloud infrastructure.</li>\n        <li>".format(header))
        t1535html.write("Cloud service providers often provide infrastructure throughout the world in order to improve performance, provide redundancy, and allow customers to meet compliance requirements.</li>\n        <li>")
        t1535html.write("Oftentimes, a customer will only use a subset of the available regions and may not actively monitor other regions. If an adversary creates resources in an unused region, they may be able to operate undetected.</li>\n        <li>")
        t1535html.write("A variation on this behavior takes advantage of differences in functionality across cloud regions. An adversary could utilize regions which do not support advanced detection services in order to avoid detection of their activity. For example, AWS GuardDuty is not supported in every region.</li>\n        <li>")
        t1535html.write("An example of adversary use of unused AWS regions is to mine cryptocurrency through Resource Hijacking, which can cost organizations substantial amounts of money over time depending on the processing power used.")
        # indicator regex assignments
        t1535html.write("{}-".format(iocs))
        # details
        t1535html.write("{}T1535</td>\n        <td>&nbsp;".format(headings)) # id
        t1535html.write("AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1535html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1535html.write("-") # sub-techniques
        # related techniques
        t1535html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1535html.write("-")
        # mitigations
        t1535html.write("{}Software Configuration</td>\n        <td>&nbsp;".format(mitigations))
        t1535html.write("Cloud service providers may allow customers to deactivate unused regions.{}".format(footer))
    with open(sd+"t1497.html", "w") as t1497html:
        # descriptions
        t1497html.write("{}Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox.</li>\n        <li>".format(header))
        t1497html.write("If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads.</li>\n        <li>")
        t1497html.write("Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors.</li>\n        <li>")
        t1497html.write("Adversaries may use several methods to accomplish Virtualization/Sandbox Evasion such as checking for security monitoring tools (e.g., Sysinternals, Wireshark, etc.) or other system artifacts associated with analysis or virtualization.</li>\n        <li>")
        t1497html.write("Adversaries may also check for legitimate user activity to help determine if it is in an analysis environment. Additional methods include use of sleep timers or loops within malware code to avoid operating within a temporary sandbox<li>")
        # indicator regex assignments
        t1497html.write("{}vpcext</li>\n        <li>".format(iocs))
        t1497html.write("vmtoolsd</li>\n        <li>")
        t1497html.write("MSAcpi_ThermalZoneTemperature</li>\n        <li>")
        t1497html.write("is_debugging")
        t1497html.write("sysctl")
        t1497html.write("ptrace")
        t1497html.write("time")
        t1497html.write("sleep")
        # details
        t1497html.write("{}T1497</td>\n        <td>&nbsp;".format(headings)) # id
        t1497html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1497html.write("Defense Evasion, Discovery</td>\n        <td>&nbsp;") # tactics
        t1497html.write("T1497.001: System Checks<br>&nbsp;T1497.002: User Activity Based Checks<br>&nbsp;T1497.003: Time Based Evasion") # sub-techniques
        # related techniques
        t1497html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1497html.write("-")
        # mitigations
        t1497html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1497html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1600.html", "w") as t1600html:
        # descriptions
        t1600html.write("{}Adversaries may compromise a network device’s encryption capability in order to bypass encryption that would otherwise protect data communications.</li>\n        <li>".format(header))
        t1600html.write("Encryption can be used to protect transmitted network traffic to maintain its confidentiality (protect against unauthorized disclosure) and integrity (protect against unauthorized changes). Encryption ciphers are used to convert a plaintext message to ciphertext and can be computationally intensive to decipher without the associated decryption key. Typically, longer keys increase the cost of cryptanalysis, or decryption without the key.</li>\n        <li>")
        t1600html.write("Adversaries can compromise and manipulate devices that perform encryption of network traffic. For example, through behaviors such as Modify System Image, Reduce Key Space, and Disable Crypto Hardware, an adversary can negatively effect and/or eliminate a device’s ability to securely encrypt network traffic. This poses a greater risk of unauthorized disclosure and may help facilitate data manipulation, Credential Access, or Collection efforts.")
        # indicator regex assignments
        t1600html.write("{}-".format(iocs))
        # details
        t1600html.write("{}T1600</td>\n        <td>&nbsp;".format(headings)) # id
        t1600html.write("Network</td>\n        <td>&nbsp;") # platforms
        t1600html.write("Execution</td>\n        <td>&nbsp;") # tactics
        t1600html.write("T1600.001: Reduce Key Space<br>&nbsp;T1600.002: Disable Crypto Hardware") # sub-techniques
        # related techniques
        t1600html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1600html.write("-")
        # mitigations
        t1600html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1600html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1220.html", "w") as t1220html:
        # descriptions
        t1220html.write("{}Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files. Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files.</li>\n        <li>".format(header))
        t1220html.write("To support complex operations, the XSL standard includes support for embedded scripting in various languages.</li>\n        <li>")
        t1220html.write("Adversaries may abuse this functionality to execute arbitrary files while potentially bypassing application control. Similar to Trusted Developer Utilities Proxy Execution, the Microsoft common line transformation utility binary (msxsl.exe) can be installed and used to execute malicious JavaScript embedded within local or remote (URL referenced) XSL files.</li>\n        <li>")
        t1220html.write("Since msxsl.exe is not installed by default, an adversary will likely need to package it with dropped files.  Msxsl.exe takes two main arguments, an XML source file and an XSL stylesheet. Since the XSL file is valid XML, the adversary may call the same XSL file twice. When using msxsl.exe adversaries may also give the XML/XSL files an arbitrary file extension.")
        # indicator regex assignments
        t1220html.write("{}MSXML</li>\n        <li>".format(iocs))
        t1220html.write("wmic</li>\n        <li>")
        t1220html.write("Invoke-Wmi")
        # details
        t1220html.write("{}T1220</td>\n        <td>&nbsp;".format(headings)) # id
        t1220html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1220html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1220html.write("-") # sub-techniques
        # related techniques
        t1220html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1127 target=\"_blank\"\">&nbsp;T1127</a></td>\n        <td>&nbsp;".format(related))
        t1220html.write("Trusted Developer Utilities Proxy Execution")
        t1220html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1047 target=\"_blank\"\">&nbsp;T1047</a></td>\n        <td>&nbsp;".format(insert))
        t1220html.write("Windows Management Instrumentation")
        t1220html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1218 target=\"_blank\"\">&nbsp;T1218</a></td>\n        <td>&nbsp;".format(insert))
        t1220html.write("Signed Binary Proxy Execution: Regsvr32")
        # mitigations
        t1220html.write("{}Execution Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1220html.write("If msxsl.exe is unnecessary, then block its execution to prevent abuse by adversaries.{}".format(footer))
  # Credential Access
    with open(sd+"t1110.html", "w") as t1110html:
        t1110html.write("Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism.</li>\n        <liv>Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes.")
        # indicator regex assignments
        t1110html.write("{}Ports: 139, 22, 23, 389, 88, 1433, 1521, 3306, 445, 80, 443, </li>\n        <li>".format(iocs))
        t1110html.write("Event IDs: 4625, 4648, 4771")
        # details
        t1110html.write("{}T1110</td>\n        <td>&nbsp;".format(headings)) # id
        t1110html.write("Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1110html.write("Credential Access</td>\n        <td>&nbsp;") # tactics
        t1110html.write("T1110.001: Password Guessing<br>&nbsp;T1110.002: Password Cracking<br>&nbsp;T1110.003: Password Spraying<br>&nbsp;T1110.004: Credentials Stuffing") # sub-techniques
        # related techniques
        t1110html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1110html.write("-")
        # mitigations
        t1110html.write("{}Account Use Policies</td>\n        <td>&nbsp;".format(mitigations))
        t1110html.write("Set account lockout policies after a certain number of failed login attempts to prevent passwords from being guessed. Too strict a policy may create a denial of service condition and render environments un-usable, with all accounts used in the brute force being locked-out.{}&nbsp;".format(insert))
        t1110html.write("Multi-factor Authentication</td>\n        <td>&nbsp;")
        t1110html.write("Use multi-factor authentication. Where possible, also enable multi-factor authentication on externally facing services.{}&nbsp;".format(insert))
        t1110html.write("Password Policies</td>\n        <td>&nbsp;")
        t1110html.write("Refer to NIST guidelines when creating password policies.{}&nbsp;".format(insert))
        t1110html.write("User Account Management</td>\n        <td>&nbsp;")
        t1110html.write("Proactively reset accounts that are known to be part of breached credentials either immediately, or after detecting bruteforce attempts.{}".format(footer))
    with open(sd+"t1555.html", "w") as t1555html:
        # descriptions
        t1555html.write("{}Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials.</li>\n        <li>".format(header))
        t1555html.write("There are also specific applications that store passwords to make it easier for users manage and maintain. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.")
        # indicator regex assignments
        t1555html.write("{}policy.vpol</li>\n        <li>".format(iocs))
        t1555html.write("password</li>\n        <li>")
        t1555html.write("secure</li>\n        <li>")
        t1555html.write("credentials</li>\n        <li>")
        t1555html.write("security</li>\n        <li>")
        t1555html.write("vaultcmd</li>\n        <li>")
        t1555html.write("vcrd</li>\n        <li>")
        t1555html.write("listcreds</li>\n        <li>")
        t1555html.write("credenumeratea</li>\n        <li>")
        t1555html.write("keychain</li>\n        <li>")
        t1555html.write("password</li>\n        <li>")
        t1555html.write("pwd</li>\n        <li>")
        t1555html.write("login</li>\n        <li>")
        t1555html.write("store</li>\n        <li>")
        t1555html.write("secure</li>\n        <li>")
        t1555html.write("credentials")
        # details
        t1555html.write("{}T1555</td>\n        <td>&nbsp;".format(headings)) # id
        t1555html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1555html.write("Credential Access</td>\n        <td>&nbsp;") # tactics
        t1555html.write("T1555.001: Keychain<br>&nbsp;T1555.002: Securityd Memory<br>&nbsp;T1555.003: Credentials from Web Browsers<br>&nbsp;T1555.004: Windows Credential Manager<br>&nbsp;T1555.005: Password Managers") # sub-techniques
        # related techniques
        t1555html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1555html.write("-")
        # mitigations
        t1555html.write("{}Password Policies</td>\n        <td>&nbsp;".format(mitigations))
        t1555html.write("The password for the user's login keychain can be changed from the user's login password. This increases the complexity for an adversary because they need to know an additional password.<br>&nbsp;Organizations may consider weighing the risk of storing credentials in password stores and web browsers. If system, software, or web browser credential disclosure is a significant concern, technical controls, policy, and user training may be used to prevent storage of credentials in improper locations.{}".format(footer))
    with open(sd+"t1212.html", "w") as t1212html:
        # descriptions
        t1212html.write("{}Adversaries may exploit software vulnerabilities in an attempt to collect credentials.</li>\n        <li>".format(header))
        t1212html.write("Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.</li>\n        <li>")
        t1212html.write("Credentialing and authentication mechanisms may be targeted for exploitation by adversaries as a means to gain access to useful credentials or circumvent the process to gain access to systems.</li>\n        <li>")
        t1212html.write("One example of this is MS14-068, which targets Kerberos and can be used to forge Kerberos tickets using domain user permissions.</li>\n        <li>")
        t1212html.write("Exploitation for credential access may also result in Privilege Escalation depending on the process targeted or credentials obtained.")
        # indicator regex assignments
        t1212html.write("{}-".format(iocs))
        # details
        t1212html.write("{}T1212</td>\n        <td>&nbsp;".format(headings)) # id
        t1212html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1212html.write("Credential Access</td>\n        <td>&nbsp;") # tactics
        t1212html.write("-") # sub-techniques
        # related techniques
        t1212html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1046 target=\"_blank\"\">&nbsp;T1046</a></td>\n        <td>&nbsp;".format(related))
        t1212html.write("Network Service Scanning")
        t1212html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1068 target=\"_blank\"\">&nbsp;T1068</a></td>\n        <td>&nbsp;".format(insert))
        t1212html.write("Exploitation for Privilege Escalation")
        # mitigations
        t1212html.write("{}Application Isolation and Sandboxing</td>\n        <td>&nbsp;".format(mitigations))
        t1212html.write("Make it difficult for adversaries to advance their operation through exploitation of undiscovered or unpatched vulnerabilities by using sandboxing. Other types of virtualization and application microsegmentation may also mitigate the impact of some types of exploitation. Risks of additional exploits and weaknesses in these systems may still exist.{}&nbsp;".format(insert))
        t1212html.write("Exploit Protection</td>\n        <td>&nbsp;")
        t1212html.write("Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility and may not work for software targeted for defense evasion.{}&nbsp;".format(insert))
        t1212html.write("Threat Intelligence Program</td>\n        <td>&nbsp;")
        #t1212html.write("Develop a robust cyber threat intelligence capability to determine what types and levels of threat may use software exploits and 0-days against a particular organization.{}&nbsp;".format(insert))
        t1212html.write("Update Software</td>\n        <td>&nbsp;")
        t1212html.write("Update software regularly by employing patch management for internal enterprise endpoints and servers.{}".format(footer))
    with open(sd+"t1187.html", "w") as t1187html:
        # descriptions
        t1187html.write("{}Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept.</li>\n        <li>".format(header))
        t1187html.write("The Server Message Block (SMB) protocol is commonly used in Windows networks for authentication and communication between systems for access to resources and file sharing.</li>\n        <li>")
        t1187html.write("When a Windows system attempts to connect to an SMB resource it will automatically attempt to authenticate and send credential information for the current user to the remote system.</li>\n        <li>")
        t1187html.write("This behavior is typical in enterprise environments so that users do not need to enter credentials to access network resources.</li>\n        <li>")
        t1187html.write("Web Distributed Authoring and Versioning (WebDAV) is also typically used by Windows systems as a backup protocol when SMB is blocked or fails. WebDAV is an extension of HTTP and will typically operate over TCP ports 80 and 443.</li>\n        <li>")
        t1187html.write("Adversaries may take advantage of this behavior to gain access to user account hashes through forced SMB/WebDAV authentication.</li>\n        <li>")
        t1187html.write("An adversary can send an attachment to a user through spearphishing that contains a resource link to an external server controlled by the adversary (i.e. Template Injection), or place a specially crafted file on navigation path for privileged accounts (e.g. .SCF file placed on desktop) or on a publicly accessible share to be accessed by victim(s).</li>\n        <li>")
        t1187html.write("When the user's system accesses the untrusted resource it will attempt authentication and send information, including the user's hashed credentials, over SMB to the adversary controlled server.  With access to the credential hash, an adversary can perform off-line Brute Force cracking to gain access to plaintext credentials.")
        # indicator regex assignments
        t1187html.write("{}Ports: 137".format(iocs))
        # details
        t1187html.write("{}T1187</td>\n        <td>&nbsp;".format(headings)) # id
        t1187html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1187html.write("Credential Access</td>\n        <td>&nbsp;") # tactics
        t1187html.write("-") # sub-techniques
        # related techniques
        t1187html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1221 target=\"_blank\"\">&nbsp;T1221</a></td>\n        <td>&nbsp;".format(related))
        t1187html.write("Template Injection")
        t1187html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1110 target=\"_blank\"\">&nbsp;T1110</a></td>\n        <td>&nbsp;".format(insert))
        t1187html.write("Brute Force")
        # mitigations
        t1187html.write("{}Filter Network Traffic</td>\n        <td>&nbsp;".format(mitigations))
        t1187html.write("Block SMB traffic from exiting an enterprise network with egress filtering or by blocking TCP ports 139, 445 and UDP port 137. Filter or block WebDAV protocol traffic from exiting the network. If access to external resources over SMB and WebDAV is necessary, then traffic should be tightly limited with allowlisting.{}&nbsp;".format(insert))
        t1187html.write("Password Policies</td>\n        <td>&nbsp;")
        t1187html.write("Use strong passwords to increase the difficulty of credential hashes from being cracked if they are obtained.{}".format(footer))
    with open(sd+"t1606.html", "w") as t1606html:
        # descriptions
        t1606html.write("{}Adversaries may forge credential materials that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies, tokens, or other materials to authenticate and authorize user access.</li>\n        <li>".format(header))
        t1606html.write("Adversaries may generate these credential materials in order to gain access to web resources. This differs from Steal Web Session Cookie, Steal Application Access Token, and other similar behaviors in that the credentials are new and forged by the adversary, rather than stolen or intercepted from legitimate users. The generation of web credentials often requires secret values, such as passwords, Private Keys, or other cryptographic seed values.</li>\n        <li>")
        t1606html.write("Once forged, adversaries may use these web credentials to access resources (ex: Use Alternate Authentication Material), which may bypass multi-factor and other authentication protection mechanisms.")
        # indicator regex assignments
        t1606html.write("{}NotOnOrAfter</li>\n        <li>".format(iocs))
        t1606html.write("AccessTokenLifetime</li>\n        <li>")
        t1606html.write("LifetimeTokenPolicy")
        # details
        t1606html.write("{}T1606</td>\n        <td>&nbsp;".format(headings)) # id
        t1606html.write("Windows, macOS, Linux, Azure, Google Workspace, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1606html.write("Credential Access</td>\n        <td>&nbsp;") # tactics
        t1606html.write("T1606.001: Web Cookies<br>&nbsp;T1606.002: SAML Tokens") # sub-techniques
        # related techniques
        t1606html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1539 target=\"_blank\"\">&nbsp;T1539</a></td>\n        <td>&nbsp;".format(related))
        t1606html.write("Steal Web Session Cookie")
        t1606html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1528 target=\"_blank\"\">&nbsp;T1528</a></td>\n        <td>&nbsp;".format(insert))
        t1606html.write("Steal Application Access Token")
        t1606html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1552/004 target=\"_blank\"\">&nbsp;T1552.004</a></td>\n        <td>&nbsp;".format(related))
        t1606html.write("Private Keys")
        t1606html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1550 target=\"_blank\"\">&nbsp;T1550</a></td>\n        <td>&nbsp;".format(insert))
        t1606html.write("Use Alternate Authentication Material")
        # mitigations
        t1606html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1606html.write("Administrators should perform an audit of all access lists and the permissions they have been granted to access web applications and services. This should be done extensively on all resources in order to establish a baseline, followed up on with periodic audits of new or updated resources. Suspicious accounts/credentials should be investigated and removed. Enable advanced auditing on ADFS. Check the success and failure audit options in the ADFS Management snap-in.<br>&nbsp;Enable Audit Application Generated events on the AD FS farm via Group Policy Object.{}&nbsp;".format(insert))
        t1606html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1606html.write("Restrict permissions and access to the AD FS server to only originate from privileged access workstations.{}&nbsp;".format(insert))
        t1606html.write("Software Configuration</td>\n        <td>&nbsp;")
        t1606html.write("Configure browsers/applications to regularly delete persistent web credentials (such as cookies).{}&nbsp;".format(insert))
        t1606html.write("User Account Management</td>\n        <td>&nbsp;")
        t1606html.write("Ensure that user accounts with administrative rights follow best practices, including use of privileged access workstations, Just in Time/Just Enough Administration (JIT/JEA), and strong authentication. Reduce the number of users that are members of highly privileged Directory Roles.{}".format(footer))
    with open(sd+"t1056.html", "w") as t1056html:
        # descriptions
        t1056html.write("{}Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes.</li>\n        <li>".format(header))
        t1056html.write("Input capture mechanisms may be transparent to the user (e.g. Credential API Hooking) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. Web Portal Capture).")
        # indicator regex assignments
        t1056html.write("{}DISPLAY</li>\n        <li>".format(iocs))
        t1056html.write("HID</li>\n        <li>")
        t1056html.write("PCI</li>\n        <li>")
        t1056html.write("IDE</li>\n        <li>")
        t1056html.write("ROOT</li>\n        <li>")
        t1056html.write("UMB</li>\n        <li>")
        t1056html.write("FDC</li>\n        <li>")
        t1056html.write("IDE</li>\n        <li>")
        t1056html.write("SCSI</li>\n        <li>")
        t1056html.write("STORAGE</li>\n        <li>")
        t1056html.write("USBSTOR</li>\n        <li>")
        t1056html.write("USB</li>\n        <li>")
        t1056html.write("WpdBusEnumRoot")
        # details
        t1056html.write("{}T1056</td>\n        <td>&nbsp;".format(headings)) # id
        t1056html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1056html.write("Credential Access</td>\n        <td>&nbsp;") # tactics
        t1056html.write("T1056.001: Keylogging<br>&nbsp;T1056.002: GUI Input Capture<br>&nbsp;T1056.003: Web Portal Capture<br>&nbsp;T1056.004: Credential API Hooking") # sub-techniques
        # related techniques
        t1056html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1059 target=\"_blank\"\">&nbsp;T1059</a></td>\n        <td>&nbsp;".format(related))
        t1056html.write("Command and Scripting Interpreter")
        # mitigations
        t1056html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1056html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1557.html", "w") as t1557html:
        # descriptions
        t1557html.write("{}Adversaries may attempt to position themselves between two or more networked devices using a man-in-the-middle (MiTM) technique to support follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation.</li>\n        <li>".format(header))
        t1557html.write("By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.</li>\n        <li>")
        t1557html.write("Adversaries may leverage the MiTM position to attempt to modify traffic, such as in Transmitted Data Manipulation. Adversaries can also stop traffic from flowing to the appropriate destination, causing denial of service.")
        # indicator regex assignments
        t1557html.write("{}Ports: 137, 5355</li>\n        <li>".format(iocs))
        t1557html.write("Event IDs: 4657, 7045</li>\n        <li>")
        t1557html.write("EnableMulticast</li>\n        <li>")
        t1557html.write("NT/DNSClient")
        # details
        t1557html.write("{}T1557</td>\n        <td>&nbsp;".format(headings)) # id
        t1557html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1557html.write("Credential Access, Collection</td>\n        <td>&nbsp;") # tactics
        t1557html.write("T1557.001: LLMNR/NBT-NS Poisoning and SMB Relay<br>&nbsp;T1557.002: ARP Cache Poisoning") # sub-techniques
        # related techniques
        t1557html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1040 target=\"_blank\"\">&nbsp;T1040</a></td>\n        <td>&nbsp;".format(related))
        t1557html.write("Network Sniffing")
        t1557html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1565 target=\"_blank\"\">&nbsp;T1565</a></td>\n        <td>&nbsp;".format(insert))
        t1557html.write("Data Manipulation: Transmitted Data Manipulation")
        # mitigations
        t1557html.write("{}Disable or Remove Feature or Program</td>\n        <td>&nbsp;".format(mitigations))
        t1557html.write("Disable legacy network protocols that may be used for MiTM if applicable and they are not needed within an environment.{}&nbsp;".format(insert))
        t1557html.write("Encrypt Sensitive Information</td>\n        <td>&nbsp;")
        t1557html.write("Ensure that all wired and/or wireless traffic is encrypted appropriately. Use best practices for authentication protocols, such as Kerberos, and ensure web traffic that may contain credentials is protected by SSL/TLS.{}&nbsp;".format(insert))
        t1557html.write("Filter Network Traffic</td>\n        <td>&nbsp;")
        t1557html.write("Use network appliances and host-based security software to block network traffic that is not necessary within the environment, such as legacy protocols that may be leveraged for MiTM.{}&nbsp;".format(insert))
        t1557html.write("Limit Access to Resource Over Network</td>\n        <td>&nbsp;")
        t1557html.write("Limit access to network infrastructure and resources that can be used to reshape traffic or otherwise produce MiTM conditions.{}&nbsp;".format(insert))
        t1557html.write("Network Intrusion Prevention</td>\n        <td>&nbsp;")
        t1557html.write("Network intrusion detection and prevention systems that can identify traffic patterns indicative of MiTM activity can be used to mitigate activity at the network level.{}&nbsp;".format(insert))
        t1557html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1557html.write("Network segmentation can be used to isolate infrastructure components that do not require broad network access. This may mitigate, or at least alleviate, the scope of MiTM activity.{}&nbsp;".format(insert))
        t1557html.write("User Training</td>\n        <td>&nbsp;")
        t1557html.write("Train users to be suspicious about certificate errors. Adversaries may use their own certificates in an attempt to MiTM HTTPS traffic. Certificate errors may arise when the application’s certificate does not match the one expected by the host.{}".format(footer))
    with open(sd+"t1040.html", "w") as t1040html:
        # descriptions
        t1040html.write("{}Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection.</li>\n        <li>".format(header))
        t1040html.write("An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.</li>\n        <li>")
        t1040html.write("Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as LLMNR/NBT-NS Poisoning and SMB Relay, can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.</li>\n        <li>")
        t1040html.write("Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent Lateral Movement and/or Defense Evasion activities.")
        # indicator regex assignments
        t1040html.write("{}-".format(iocs))
        # details
        t1040html.write("{}T1040</td>\n        <td>&nbsp;".format(headings)) # id
        t1040html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1040html.write("Credential Access, Discovery</td>\n        <td>&nbsp;") # tactics
        t1040html.write("-") # sub-techniques
        # related techniques
        t1040html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1557 target=\"_blank\"\">&nbsp;T1557</a></td>\n        <td>&nbsp;".format(related))
        t1040html.write("Man-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay")
        # mitigations
        t1040html.write("{}Encrypt Sensitive Information</td>\n        <td>&nbsp;".format(mitigations))
        t1040html.write("Ensure that all wired and/or wireless traffic is encrypted appropriately. Use best practices for authentication protocols, such as Kerberos, and ensure web traffic that may contain credentials is protected by SSL/TLS.{}&nbsp;".format(insert))
        t1040html.write("Multi-factor Authentication</td>\n        <td>&nbsp;")
        t1040html.write("Use multi-factor authentication wherever possible.{}".format(footer))
    with open(sd+"t1003.html", "w") as t1003html:
        # descriptions
        t1003html.write("{}Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software.</li>\n        <li>".format(header))
        t1003html.write("Credentials can then be used to perform Lateral Movement and access restricted information.</li>\n        <li>")
        t1003html.write("Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.")
        # indicator regex assignments
        t1003html.write("{}procdump</li>\n        <li>".format(iocs))
        t1003html.write("sekurlsa</li>\n        <li>")
        t1003html.write("cmsadcs</li>\n        <li>")
        t1003html.write("NTDS</li>\n        <li>")
        t1003html.write("gsecdump</li>\n        <li>")
        t1003html.write("mimikatz</li>\n        <li>")
        t1003html.write("pwdumpx</li>\n        <li>")
        t1003html.write("secretsdump</li>\n        <li>")
        t1003html.write("procdump</li>\n        <li>")
        t1003html.write("sekurlsa</li>\n        <li>")
        t1003html.write("lsass</li>\n        <li>")
        t1003html.write("psexec</li>\n        <li>")
        t1003html.write("net user</li>\n        <li>")
        t1003html.write("net1 user</li>\n        <li>")
        t1003html.write("reg save</li>\n        <li>")
        t1003html.write("hklm/sam</li>\n        <li>")
        t1003html.write("hklm/system</li>\n        <li>")
        t1003html.write("currentcontrolset/control/lsa</li>\n        <li>")
        t1003html.write("/security/policy/secrets</li>\n        <li>")
        t1003html.write("manager/safedllsearchmode</li>\n        <li>")
        t1003html.write("passwd</li>\n        <li>")
        t1003html.write("shadow")
        # details
        t1003html.write("{}T1003</td>\n        <td>&nbsp;".format(headings)) # id
        t1003html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1003html.write("Credential Access</td>\n        <td>&nbsp;") # tactics
        t1003html.write("T1003.001: LSASS Memory<br>&nbsp;T1003.002: Security Account Manager<br>&nbsp;T1003.003: NTDS<br>&nbsp;T1003.004: LSA Secrets<br>&nbsp;T1003.005: Cached Domain Credentials<br>&nbsp;T1003.006: DCSync<br>&nbsp;T1003.007: Proc Filesystem<br>&nbsp;T1003.008: /etc/passwd and /etc/shadow") # sub-techniques
        # related techniques
        t1003html.write("{}-&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1003html.write("-")
        # mitigations
        t1003html.write("{}Active Directory Configuration</td>\n        <td>&nbsp;".format(mitigations))
        t1003html.write("Manage the access control list for \"Replicating Directory Changes\" and other permissions associated with domain controller replication. Consider adding users to the \"Protected Users\" Active Directory security group. This can help limit the caching of users' plaintext credentials.{}&nbsp;".format(insert))
        t1003html.write("Credential Access Protection</td>\n        <td>&nbsp;")
        t1003html.write("With Windows 10, Microsoft implemented new protections called Credential Guard to protect the LSA secrets that can be used to obtain credentials through forms of credential dumping. It is not configured by default and has hardware and firmware system requirements. It also does not protect against all forms of credential dumping.{}&nbsp;".format(insert))
        t1003html.write("Encrypt Sensitive Information</td>\n        <td>&nbsp;")
        t1003html.write("Ensure Domain Controller backups are properly secured.{}&nbsp;".format(insert))
        t1003html.write("Operating System Configuration</td>\n        <td>&nbsp;")
        t1003html.write("Consider disabling or restricting NTLM. Consider disabling WDigest authentication.{}&nbsp;".format(insert))
        t1003html.write("Password Policies</td>\n        <td>&nbsp;")
        t1003html.write("Ensure that local administrator accounts have complex, unique passwords across all systems on the network.{}&nbsp;".format(insert))
        t1003html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1003html.write("Windows: Do not put user or admin domain accounts in the local administrator groups across systems unless they are tightly controlled, as this is often equivalent to having a local administrator account with the same password on all systems. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.<br>&nbsp;Linux: Scraping the passwords from memory requires root privileges. Follow best practices in restricting access to privileged accounts to avoid hostile programs from accessing such sensitive regions of memory.{}&nbsp;".format(insert))
        t1003html.write("Privileged Process Integrity</td>\n        <td>&nbsp;")
        t1003html.write("On Windows 8.1 and Windows Server 2012 R2, enable Protected Process Light for LSA.{}&nbsp;".format(insert))
        t1003html.write("User Training</td>\n        <td>&nbsp;")
        t1003html.write("Limit credential overlap across accounts and systems by training users and administrators not to use the same password for multiple accounts.{}".format(footer))
    with open(sd+"t1528.html", "w") as t1528html:
        # descriptions
        t1528html.write("{}Adversaries can steal user application access tokens as a means of acquiring credentials to access remote systems and resources. This can occur through social engineering and typically requires user action to grant access.</li>\n        <li>".format(header))
        t1528html.write("Application access tokens are used to make authorized API requests on behalf of a user and are commonly used as a way to access resources in cloud-based applications and software-as-a-service (SaaS). OAuth is one commonly implemented framework that issues tokens to users for access to systems.</li>\n        <li>")
        t1528html.write("An application desiring access to cloud-based services or protected APIs can gain entry using OAuth 2.0 through a variety of authorization protocols. An example commonly-used sequence is Microsoft's Authorization Code Grant flow. An OAuth access token enables a third-party application to interact with resources containing user data in the ways requested by the application without obtaining user credentials.</li>\n        <li>")
        t1528html.write("Adversaries can leverage OAuth authorization by constructing a malicious application designed to be granted access to resources with the target user's OAuth token. The adversary will need to complete registration of their application with the authorization server, for example Microsoft Identity Platform using Azure Portal, the Visual Studio IDE, the command-line interface, PowerShell, or REST API calls.</li>\n        <li>")
        t1528html.write("Then, they can send a link through Spearphishing Link to the target user to entice them to grant access to the application. Once the OAuth access token is granted, the application can gain potentially long-term access to features of the user account through Application Access Token.</li>\n        <li>")
        t1528html.write("Adversaries have been seen targeting Gmail, Microsoft Outlook, and Yahoo Mail users.")
        # indicator regex assignments
        t1528html.write("{}-".format(iocs))
        # details
        t1528html.write("{}T1528</td>\n        <td>&nbsp;".format(headings)) # id
        t1528html.write("Azure, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1528html.write("Credential Access</td>\n        <td>&nbsp;") # tactics
        t1528html.write("-") # sub-techniques
        # related techniques
        t1528html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1566 target=\"_blank\"\">&nbsp;T1566</a></td>\n        <td>&nbsp;".format(related))
        t1528html.write("Phishing: Spearphishing Link")
        t1528html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1550 target=\"_blank\"\">&nbsp;T1550</a></td>\n        <td>&nbsp;".format(insert))
        t1528html.write("Use Alternate Authentication Material: Application Access Token")
        # mitigations
        t1528html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1528html.write("Administrators should perform an audit of all OAuth applications and the permissions they have been granted to access organizational data. This should be done extensively on all applications in order to establish a baseline, followed up on with periodic audits of new or updated applications. Suspicious applications should be investigated and removed.{}&nbsp;".format(insert))
        t1528html.write("Restrict Web-Based Content</td>\n        <td>&nbsp;")
        t1528html.write("Administrators can block end-user consent to OAuth applications, disabling users from authorizing third-party apps through OAuth 2.0 and forcing administrative consent for all requests. They can also block end-user registration of applications by their users, to reduce risk. A Cloud Access Security Broker can also be used to ban applications.<br>&nbsp;Azure offers a couple of enterprise policy settings in the Azure Management Portal that may help: \"Users -> User settings -> App registrations: Users can register applications\" can be set to \"no\" to prevent users from registering new applications. \"Enterprise applications -> User settings -> Enterprise applications: Users can consent to apps accessing company data on their behalf\" can be set to \"no\" to prevent users from consenting to allow third-party multi-tenant applications.{}&nbsp;".format(insert))
        t1528html.write("User Account Management</td>\n        <td>&nbsp;")
        t1528html.write("A Cloud Access Security Broker (CASB) can be used to set usage policies and manage user permissions on cloud applications to prevent access to application access tokens.{}&nbsp;".format(insert))
        t1528html.write("User Training</td>\n        <td>&nbsp;")
        t1528html.write("Users need to be trained to not authorize third-party applications they don’t recognize. The user should pay particular attention to the redirect URL: if the URL is a misspelled or convoluted sequence of words related to an expected service or SaaS application, the website is likely trying to spoof a legitimate service. Users should also be cautious about the permissions they are granting to apps. For example, offline access and access to read emails should excite higher suspicions because adversaries can utilize SaaS APIs to discover credentials and other sensitive communications.{}".format(footer))
    with open(sd+"t1558.html", "w") as t1558html:
        # descriptions
        t1558html.write("{}Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket.</li>\n        <li>".format(header))
        t1558html.write("Kerberos is an authentication protocol widely used in modern Windows domain environments. In Kerberos environments, referred to as \"realms\", there are three basic participants: client, service, and Key Distribution Center (KDC).</li>\n        <li>Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated.</li>\n        <li>The KDC is responsible for both authentication and ticket granting. Attackers may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access.")
        # indicator regex assignments
        t1558html.write("{}Event IDs: 4624, 4634, 4768, 4769, 4672".format(iocs))
        # details
        t1558html.write("{}T1558</td>\n        <td>&nbsp;".format(headings)) # id
        t1558html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1558html.write("Credential Access</td>\n        <td>&nbsp;") # tactics
        t1558html.write("T1558.001: Golden Ticket<br>&nbsp;T1558.002: Silver Ticket<br>&nbsp;T1558.003: Kerberoasting<br>&nbsp;T1558.004: AS-REP Roasting") # sub-techniques
        # related techniques
        t1558html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1550 target=\"_blank\"\">&nbsp;T1550</a></td>\n        <td>&nbsp;".format(related))
        t1558html.write("Use Alternate Authentication Material: Pass the Ticket")
        # mitigations
        t1558html.write("{}Active Directory Configuration</td>\n        <td>&nbsp;".format(mitigations))
        t1558html.write("For containing the impact of a previously generated golden ticket, reset the built-in KRBTGT account password twice, which will invalidate any existing golden tickets that have been created with the KRBTGT hash and other Kerberos tickets derived from it. For each domain, change the KRBTGT account password once, force replication, and then change the password a second time. Consider rotating the KRBTGT account password every 180 days.{}&nbsp;".format(insert))
        t1558html.write("Encrypt Sensitive Information</td>\n        <td>&nbsp;")
        t1558html.write("Enable AES Kerberos encryption (or another stronger encryption algorithm), rather than RC4, where possible.{}&nbsp;".format(insert))
        t1558html.write("Password Policies</td>\n        <td>&nbsp;")
        t1558html.write("Ensure strong password length (ideally 25+ characters) and complexity for service accounts and that these passwords periodically expire. Also consider using Group Managed Service Accounts or another third party product such as password vaulting.{}&nbsp;".format(insert))
        t1558html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1558html.write("Limit domain admin account permissions to domain controllers and limited servers. Delegate other admin functions to separate accounts.<br>nbsp;Limit service accounts to minimal required privileges, including membership in privileged groups such as Domain Administrators.{}".format(footer))
    with open(sd+"t1539.html", "w") as t1539html:
        # descriptions
        t1539html.write("{}An adversary may steal web application or service session cookies and use them to gain access web applications or Internet services as an authenticated user without needing credentials. Web applications and services often use session cookies as an authentication token after a user has authenticated to a website.</li>\n        <li>".format(header))
        t1539html.write("Cookies are often valid for an extended period of time, even if the web application is not actively used. Cookies can be found on disk, in the process memory of the browser, and in network traffic to remote systems.</li>\n        <li>")
        t1539html.write("Additionally, other applications on the targets machine might store sensitive authentication cookies in memory (e.g. apps which authenticate to cloud services). Session cookies can be used to bypasses some multi-factor authentication protocols.</li>\n        <li>")
        t1539html.write("There are several examples of malware targeting cookies from web browsers on the local system. There are also open source frameworks such as Evilginx 2 and Muraena that can gather session cookies through a man-in-the-middle proxy that can be set up by an adversary and used in phishing campaigns.</li>\n        <li>")
        t1539html.write("After an adversary acquires a valid cookie, they can then perform a Web Session Cookie technique to login to the corresponding web application.")
        # indicator regex assignments
        t1539html.write("{}-".format(iocs))
        # details
        t1539html.write("{}T1539</td>\n        <td>&nbsp;".format(headings)) # id
        t1539html.write("Windows, macOS, Linux, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1539html.write("Credential Access</td>\n        <td>&nbsp;") # tactics
        t1539html.write("-") # sub-techniques
        # related techniques
        t1539html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1550 target=\"_blank\"\">&nbsp;T1550.004</a></td>\n        <td>&nbsp;".format(related))
        t1539html.write("Use Alternate Authentication Material: Web Session Cookie")
        # mitigations
        t1539html.write("{}Multi-factor Authentication</td>\n        <td>&nbsp;".format(mitigations))
        t1539html.write("A physical second factor key that uses the target login domain as part of the negotiation protocol will prevent session cookie theft through proxy methods.{}&nbsp;".format(insert))
        t1539html.write("Software Configuration</td>\n        <td>&nbsp;")
        t1539html.write("Configure browsers or tasks to regularly delete persistent cookies.{}&nbsp;".format(insert))
        t1539html.write("User Training</td>\n        <td>&nbsp;")
        t1539html.write("Train users to identify aspects of phishing attempts where they're asked to enter credentials into a site that has the incorrect domain for the application they are logging into.{}".format(footer))
    with open(sd+"t1111.html", "w") as t1111html:
        # descriptions
        t1111html.write("{}Adversaries may target two-factor authentication mechanisms, such as smart cards, to gain access to credentials that can be used to access systems, services, and network resources.</li>\n        <li>".format(header))
        t1111html.write("Use of two or multi-factor authentication (2FA or MFA) is recommended and provides a higher level of security than user names and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms.</li>\n        <li>")
        t1111html.write("If a smart card is used for two-factor authentication, then a keylogger will need to be used to obtain the password associated with a smart card during normal use.</li>\n        <li>")
        t1111html.write("With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token.</li>\n        <li>")
        t1111html.write("Adversaries may also employ a keylogger to similarly target other hardware tokens, such as RSA SecurID.</li>\n        <li>")
        t1111html.write("Capturing token input (including a user's personal identification code) may provide temporary access (i.e. replay the one-time passcode until the next value rollover) as well as possibly enabling adversaries to reliably predict future authentication values (given access to both the algorithm and any seed values used to generate appended temporary codes).</li>\n        <li>")
        t1111html.write("Other methods of 2FA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS).</li>\n        <li>")
        t1111html.write("If the device and/or service is not secured, then it may be vulnerable to interception. Although primarily focused on by cyber criminals, these authentication mechanisms have been targeted by advanced actors.")
        # indicator regex assignments
        t1111html.write("{}-".format(iocs))
        # details
        t1111html.write("{}T1111</td>\n        <td>&nbsp;".format(headings)) # id
        t1111html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1111html.write("Credential Access</td>\n        <td>&nbsp;") # tactics
        t1111html.write("-") # sub-techniques
        # related techniques
        t1111html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1056 target=\"_blank\"\">&nbsp;T1056</a></td>\n        <td>&nbsp;".format(related))
        t1111html.write("Input Capture")
        # mitigations
        t1111html.write("{}User Training</td>\n        <td>&nbsp;".format(mitigations))
        t1111html.write("Remove smart cards when not in use.{}".format(footer))
    with open(sd+"t1552.html", "w") as t1552html:
        t1552html.write("Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. Bash History), operating system or application-specific repositories (e.g. Credentials in Registry), or other specialized files/artifacts (e.g. Private Keys).")
        # indicator regex assignments
        t1552html.write("{}.asc</li>\n        <li>".format(iocs))
        t1552html.write(".cer</li>\n        <li>")
        t1552html.write(".gpg</li>\n        <li>")
        t1552html.write(".key</li>\n        <li>")
        t1552html.write(".p12</li>\n        <li>")
        t1552html.write(".p7b</li>\n        <li>")
        t1552html.write(".pem</li>\n        <li>")
        t1552html.write(".pfx</li>\n        <li>")
        t1552html.write(".pgp</li>\n        <li>")
        t1552html.write(".ppk</li>\n        <li>")
        t1552html.write("Get-UnattendedInstallFile</li>\n        <li>")
        t1552html.write("Get-WebConfig</li>\n        <li>")
        t1552html.write("Get-ApplicationHost</li>\n        <li>")
        t1552html.write("Get-SiteListPassword</li>\n        <li>")
        t1552html.write("Get-CachedGPPPassword</li>\n        <li>")
        t1552html.write("Get-RegistryAutoLogon</li>\n        <li>")
        t1552html.write("password</li>\n        <li>")
        t1552html.write("pwd</li>\n        <li>")
        t1552html.write("login</li>\n        <li>")
        t1552html.write("store</li>\n        <li>")
        t1552html.write("secure</li>\n        <li>")
        t1552html.write("credentials</li>\n        <li>")
        t1552html.write("security</li>\n        <li>")
        t1552html.write("bash_history")
        t1552html.write("history")
        t1552html.write("HISTFILE")
        # details
        t1552html.write("{}T1552</td>\n        <td>&nbsp;".format(headings)) # id
        t1552html.write("Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1552html.write("Credential Access</td>\n        <td>&nbsp;") # tactics
        t1552html.write("T1552.001: Credentials In Files<br>&nbsp;T1552.002: Credentials In Registry<br>&nbsp;T1552.003: Bash History<br>&nbsp;T1552.004: Private Keys<br>&nbsp;T1552.005: Cloud Instance Metadata API<br>&nbsp;T1552.006: Group Policy Preferences<br>&nbsp;T1552.007: Container API") # sub-techniques
        # related techniques
        t1552html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1552html.write("-")
        # mitigations
        t1552html.write("{}Active Directory Configuration</td>\n        <td>&nbsp;".format(mitigations))
        t1552html.write("Remove vulnerable Group Policy Preferences.{}&nbsp;".format(insert))
        t1552html.write("Audit</td>\n        <td>&nbsp;")
        t1552html.write("Preemptively search for files containing passwords or other credentials and take actions to reduce the exposure risk when found.{}&nbsp;".format(insert))
        t1552html.write("Encrypt Sensitive Information</td>\n        <td>&nbsp;")
        t1552html.write("When possible, store keys on separate cryptographic hardware instead of on the local system.{}&nbsp;".format(insert))
        t1552html.write("Filter Network Traffic</td>\n        <td>&nbsp;")
        t1552html.write("Limit access to the Instance Metadata API using a host-based firewall such as iptables. A properly configured Web Application Firewall (WAF) may help prevent external adversaries from exploiting Server-side Request Forgery (SSRF) attacks that allow access to the Cloud Instance Metadata API.{}&nbsp;".format(insert))
        t1552html.write("Operating System Configuration</td>\n        <td>&nbsp;")
        t1552html.write("There are multiple methods of preventing a user's command history from being flushed to their .bash_history file, including use of the following commands:set +o history and set -o history to start logging again; unset HISTFILE being added to a user's .bash_rc file; andln -s /dev/null ~/.bash_history to write commands to /dev/nullinstead.{}&nbsp;".format(insert))
        t1552html.write("Password Policies</td>\n        <td>&nbsp;")
        t1552html.write("Use strong passphrases for private keys to make cracking difficult. Do not store credentials within the Registry. Establish an organizational policy that prohibits password storage in files.{}&nbsp;".format(insert))
        t1552html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1552html.write("If it is necessary that software must store credentials in the Registry, then ensure the associated accounts have limited permissions so they cannot be abused if obtained by an adversary.{}&nbsp;".format(insert))
        t1552html.write("Restrict File and Directory Permissions</td>\n        <td>&nbsp;")
        t1552html.write("Restrict file shares to specific directories with access only to necessary users.{}&nbsp;".format(insert))
        t1552html.write("Update Software</td>\n        <td>&nbsp;")
        t1552html.write("Apply patch KB2962486 which prevents credentials from being stored in GPPs.{}&nbsp;".format(insert))
        t1552html.write("User Training</td>\n        <td>&nbsp;")
        t1552html.write("Ensure that developers and system administrators are aware of the risk associated with having plaintext passwords in software configuration files that may be left on endpoint systems or servers.{}".format(footer))
  # Discovery
    with open(sd+"t1087.html", "w") as t1087html:
        t1087html.write("Adversaries may attempt to get a listing of accounts on a system or within an environment. This information can help adversaries determine which accounts exist to aid in follow-on behavior.")
        # indicator regex assignments
        t1087html.write("{}Get-GlobalAddressList</li>\n        <li>".format(iocs))
        t1087html.write("CurrentVersion\Policies\CredUI\EnumerateAdministrators</li>\n        <li>")
        t1087html.write("dscacheutil")
        t1087html.write("ldapsearch")
        t1087html.write("passwd")
        t1087html.write("shadow")
        # details
        t1087html.write("{}T1087</td>\n        <td>&nbsp;".format(headings)) # id
        t1087html.write("Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1087html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1087html.write("T1087.001: Local Account<br>&nbsp;T1087.002: Domain Account<br>&nbsp;T1087.003: Email Account<br>&nbsp;T1087.004: Cloud Account") # sub-techniques
        # related techniques
        t1087html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1087html.write("-")
        # mitigations
        t1087html.write("{}Operating System Configuration</td>\n        <td>&nbsp;".format(mitigations))
        t1087html.write("Prevent administrator accounts from being enumerated when an application is elevating through UAC since it can lead to the disclosure of account names. The Registry key is located HKLM\\ SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI\\EnumerateAdministrators. It can be disabled through GPO: Computer Configuration > [Policies] > Administrative Templates > Windows Components > Credential User Interface: E numerate administrator accounts on elevation.{}".format(footer))
    with open(sd+"t1010.html", "w") as t1010html:
        t1010html.write("Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used or give context to information collected by a keylogger.")
        # indicator regex assignments
        t1010html.write("{}-".format(iocs))
        # details
        t1010html.write("{}T1010</td>\n        <td>&nbsp;".format(headings)) # id
        t1010html.write("Windows, macOS</td>\n        <td>&nbsp;") # platforms
        t1010html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1010html.write("-") # sub-techniques
        # related techniques
        t1010html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1010html.write("-")
        # mitigations
        t1010html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1010html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1217.html", "w") as t1217html:
        # descriptions
        t1217html.write("{}Adversaries may enumerate browser bookmarks to learn more about compromised hosts. Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure.</li>\n        <li>".format(header))
        t1217html.write("Browser bookmarks may also highlight additional targets after an adversary has access to valid credentials, especially Credentials In Files associated with logins cached by a browser.</li>\n        <li>")
        t1217html.write("Specific storage locations vary based on platform and/or application, but browser bookmarks are typically stored in local files/databases.")
        # indicator regex assignments
        t1217html.write("{}-".format(iocs))
        # details
        t1217html.write("{}T1217</td>\n        <td>&nbsp;".format(headings)) # id
        t1217html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1217html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1217html.write("-") # sub-techniques
        # related techniques
        t1217html.write("<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1552 target=\"_blank\"\">&nbsp;T1552</a></td>\n        <td>&nbsp;")
        t1217html.write("Unsecured Credentials: Credentials In Files")
        # mitigations
        t1217html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1217html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1580.html", "w") as t1580html:
        # descriptions
        t1580html.write("{}An adversary may attempt to discover resources that are available within an infrastructure-as-a-service (IaaS) environment. This includes compute service resources such as instances, virtual machines, and snapshots as well as resources of other services including the storage and database services.</li>\n        <li>".format(header))
        t1580html.write("Cloud providers offer methods such as APIs and commands issued through CLIs to serve information about infrastructure. For example, AWS provides a DescribeInstances API within the Amazon EC2 API that can return information about one or more instances within an account, as well as the ListBuckets API that returns a list of all buckets owned by the authenticated sender of the request. Similarly, GCP's Cloud SDK CLI provides the gcloud compute instances list command to list all Google Compute Engine instances in a project, and Azure's CLI command az vm list lists details of virtual machines.</li>\n        <li>")
        t1580html.write("An adversary may enumerate resources using a compromised user's access keys to determine which are available to that user. The discovery of these available resources may help adversaries determine their next steps in the Cloud environment, such as establishing Persistence. Unlike in Cloud Service Discovery, this technique focuses on the discovery of components of the provided services rather than the services themselves.")
        # indicator regex assignments
        t1580html.write("{}-".format(iocs))
        # details
        t1580html.write("{}T1580</td>\n        <td>&nbsp;".format(headings)) # id
        t1580html.write("IaaS</td>\n        <td>&nbsp;") # platforms
        t1580html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1580html.write("-") # sub-techniques
        # related techniques
        t1580html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1526 target=\"_blank\"\">&nbsp;T1526</a></td>\n        <td>&nbsp;".format(related))
        t1580html.write("Cloud Service Discovery")
        # mitigations
        t1580html.write("{}User Account Management</td>\n        <td>&nbsp;")
        t1580html.write("Limit permissions to discover cloud infrastructure in accordance with least privilege. Organizations should limit the number of users within the organization with an IAM role that has administrative privileges, strive to reduce all permanent privileged role assignments, and conduct periodic entitlement reviews on IAM users, roles and policies.{}".format(footer))
    with open(sd+"t1538.html", "w") as t1538html:
        # descriptions
        t1538html.write("{}An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features.</li>\n        <li>".format(header))
        t1538html.write("For example, the GCP Command Center can be used to view all assets, findings of potential security risks, and to run additional queries, such as finding public IP addresses and open ports.</li>\n        <li>")
        t1538html.write("Depending on the configuration of the environment, an adversary may be able to enumerate more information via the graphical dashboard than an API. This allows the adversary to gain information without making any API requests.")
        # indicator regex assignments
        t1538html.write("{}-".format(iocs))
        # details
        t1538html.write("{}T1538</td>\n        <td>&nbsp;".format(headings)) # id
        t1538html.write("AWS, Azure, GCP, Office 365</td>\n        <td>&nbsp;") # platforms
        t1538html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1538html.write("-") # sub-techniques
        # related techniques
        t1538html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t0000 target=\"_blank\"\">&nbsp;T0000</a></td>\n        <td>&nbsp;".format(related))
        t1538html.write("Scheduled Task/Job")
        # mitigations
        t1538html.write("{}User Account Management</td>\n        <td>&nbsp;".format(mitigations))
        t1538html.write("Enforce the principle of least-privilege by limiting dashboard visibility to only the resources required. This may limit the discovery value of the dashboard in the event of a compromised account.{}".format(footer))
    with open(sd+"t1526.html", "w") as t1526html:
        # descriptions
        t1526html.write("{}An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS).</li>\n        <li>".format(header))
        t1526html.write("Many services exist throughout the various cloud providers and can include Continuous Integration and Continuous Delivery (CI/CD), Lambda Functions, Azure AD, etc.</li>\n        <li>")
        t1526html.write("Adversaries may attempt to discover information about the services enabled throughout the environment. Azure tools and APIs, such as the Azure AD Graph API and Azure Resource Manager API, can enumerate resources and services, including applications, management groups, resources and policy definitions, and their relationships that are accessible by an identity.</li>\n        <li>")
        t1526html.write("Stormspotter is an open source tool for enumerating and constructing a graph for Azure resources and services, and Pacu is an open source AWS exploitation framework that supports several methods for discovering cloud services.")
        # indicator regex assignments
        t1526html.write("{}-".format(iocs))
        # details
        t1526html.write("{}T1526</td>\n        <td>&nbsp;".format(headings)) # id
        t1526html.write("AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1526html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1526html.write("-") # sub-techniques
        # related techniques
        t1526html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1580 target=\"_blank\"\">&nbsp;T1580</a></td>\n        <td>&nbsp;".format(related))
        t1526html.write("Cloud Infrastructure Discovery")
        # mitigations
        t1526html.write("{}User Account Management</td>\n        <td>&nbsp;")
        t1526html.write("Limit permissions to discover cloud infrastructure in accordance with least privilege. Organizations should limit the number of users within the organization with an IAM role that has administrative privileges, strive to reduce all permanent privileged role assignments, and conduct periodic entitlement reviews on IAM users, roles and policies.{}".format(footer))
    with open(sd+"t1613.html", "w") as t1613html:
        # descriptions
        t1613html.write("{}Adversaries may attempt to discover containers and other resources that are available within a containers environment. Other resources may include images, deployments, pods, nodes, and other information such as the status of a cluster.</li>\n        <li>".format(header))
        t1613html.write("These resources can be viewed within web applications such as the Kubernetes dashboard or can be queried via the Docker and Kubernetes APIs. In Docker, logs may leak information about the environment, such as the environment’s configuration, which services are available, and what cloud provider the victim may be utilizing. The discovery of these resources may inform an adversary’s next steps in the environment, such as how to perform lateral movement and which methods to utilize for execution.")
        # indicator regex assignments
        t1613html.write("{}-".format(iocs))
        # details
        t1613html.write("{}T1613</td>\n        <td>&nbsp;".format(headings)) # id
        t1613html.write("Containers</td>\n        <td>&nbsp;") # platforms
        t1613html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1613html.write("-") # sub-techniques
        # related techniques
        t1613html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1059 target=\"_blank\"\">&nbsp;T1059</a></td>\n        <td>&nbsp;".format(related))
        t1613html.write("Command and Scripting Interpreter")
        # mitigations
        t1613html.write("{}Limit Access to Resource Over Network</td>\n        <td>&nbsp;".format(mitigations))
        t1613html.write("Limit communications with the container service to local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API and Kubernetes API Server.{}&nbsp;".format(insert))
        t1613html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1613html.write("Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.{}&nbsp;".format(insert))
        t1613html.write("User Account Management</td>\n        <td>&nbsp;")
        t1613html.write("Enforce the principle of least privilege by limiting dashboard visibility to only the required users.{}".format(footer))
    with open(sd+"t1482.html", "w") as t1482html:
        # descriptions
        t1482html.write("{}Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain.</li>\n        <li>".format(header))
        t1482html.write("Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct SID-History Injection, Pass the Ticket, and Kerberoasting.</li>\n        <li>")
        t1482html.write("Domain trusts can be enumerated using the DSEnumerateDomainTrusts() Win32 API call, .NET methods, and LDAP. The Windows utility Nltest is known to be used by adversaries to enumerate domain trusts.")
        # indicator regex assignments
        t1482html.write("{}DSEnumerateDomainTrusts</li>\n        <li>".format(iocs))
        t1482html.write("GetAllTrustRelationships</li>\n        <li>")
        t1482html.write("Get-AcceptedDomain</li>\n        <li>")
        t1482html.write("Get-NetDomainTrust</li>\n        <li>")
        t1482html.write("Get-NetForestTrust</li>\n        <li>")
        t1482html.write("nltest</li>\n        <li>")
        t1482html.write("dsquery")
        # details
        t1482html.write("{}T1482</td>\n        <td>&nbsp;".format(headings)) # id
        t1482html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1482html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1482html.write("-") # sub-techniques
        # related techniques
        t1482html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1134 target=\"_blank\"\">&nbsp;T1134</a></td>\n        <td>&nbsp;".format(related))
        t1482html.write("Access Token Manipulation: SID-History Injection")
        t1482html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1550 target=\"_blank\"\">&nbsp;T1550</a></td>\n        <td>&nbsp;".format(insert))
        t1482html.write("Use Alternate Authentication Material: Pass the Ticket")
        t1482html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1558 target=\"_blank\"\">&nbsp;T1558</a></td>\n        <td>&nbsp;".format(insert))
        t1482html.write("Steal or Forge Kerberos Tickets: Kerberoasting")
        # mitigations
        t1482html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1482html.write("Map the trusts within existing domains/forests and keep trust relationships to a minimum.{}&nbsp;".format(insert))
        t1482html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1482html.write("Employ network segmentation for sensitive domains.{}".format(footer))
    with open(sd+"t1083.html", "w") as t1083html:
        # descriptions
        t1083html.write("{}Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.</li>\n        <li>".format(header))
        t1083html.write("Adversaries may use the information from File and Directory Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.</li>\n        <li>")
        t1083html.write("Many command shell utilities can be used to obtain this information. Examples include dir, tree, ls, find, and locate. Custom tools may also be used to gather file and directory information and interact with the Native API.")
        # indicator regex assignments
        t1083html.write("{}dir</li>\n        <li>".format(iocs))
        t1083html.write("tree</li>\n        <li>")
        t1083html.write("ls</li>\n        <li>")
        t1083html.write("find</li>\n        <li>")
        t1083html.write("locate")
        # details
        t1083html.write("{}T1083</td>\n        <td>&nbsp;".format(headings)) # id
        t1083html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1083html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1083html.write("-") # sub-techniques
        # related techniques
        t1083html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1106 target=\"_blank\"\">&nbsp;T1106</a></td>\n        <td>&nbsp;".format(related))
        t1083html.write("Native API")
        # mitigations
        t1083html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1083html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1046.html", "w") as t1046html:
        # descriptions
        t1046html.write("{}Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods to acquire this information include port scans and vulnerability scans using tools that are brought onto a system.</li>\n        <li>".format(header))
        t1046html.write("Within cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well.")
        # indicator regex assignments
        t1046html.write("{}-".format(iocs))
        # details
        t1046html.write("{}T1046</td>\n        <td>&nbsp;".format(headings)) # id
        t1046html.write("Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1046html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1046html.write("-") # sub-techniques
        # related techniques
        t1046html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1046html.write("-")
        # mitigations
        t1046html.write("{}Disable or Remove Feature or Program</td>\n        <td>&nbsp;".format(mitigations))
        t1046html.write("Ensure that unnecessary ports and services are closed to prevent risk of discovery and potential exploitation.{}&nbsp;".format(insert))
        t1046html.write("Network Intrusion Prevention</td>\n        <td>&nbsp;")
        t1046html.write("Use network intrusion detection/prevention systems to detect and prevent remote service scans.{}&nbsp;".format(insert))
        t1046html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1046html.write("Ensure proper network segmentation is followed to protect critical servers and devices.{}".format(footer))
    with open(sd+"t1135.html", "w") as t1135html:
        # descriptions
        t1135html.write("{}Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement. Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network.</li>\n        <li>".format(header))
        t1135html.write("File sharing over a Windows network occurs over the SMB protocol. Net can be used to query a remote system for available shared drives using the net view \\remotesystem command. It can also be used to query shared drives on the local system using net share.</li>\n        <li>")
        t1135html.write("Cloud virtual networks may contain remote network shares or file storage services accessible to an adversary after they have obtained access to a system. For example, AWS, GCP, and Azure support creation of Network File System (NFS) shares and Server Message Block (SMB) shares that may be mapped on endpoint or cloud-based systems.")
        # indicator regex assignments
        t1135html.write("{}net.exe share</li>\n        <li>".format(iocs))
        t1135html.write("net1.exe share</li>\n        <li>")
        t1135html.write("net.exe view</li>\n        <li>")
        t1135html.write("net1.exe view</li>\n        <li>")
        t1135html.write("netsh")
        # details
        t1135html.write("{}T1135</td>\n        <td>&nbsp;".format(headings)) # id
        t1135html.write("Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1135html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1135html.write("-") # sub-techniques
        # related techniques
        t1135html.write("{}-&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1135html.write("-")
        # mitigations
        t1135html.write("{}Operating System Configuration</td>\n        <td>&nbsp;".format(mitigations))
        t1135html.write("Enable Windows Group Policy \"Do Not Allow Anonymous Enumeration of SAM Accounts and Shares\" security setting to limit users who can enumerate network shares.{}".format(footer))
    with open(sd+"t1201.html", "w") as t1201html:
        # descriptions
        t1201html.write("{}Adversaries may attempt to access detailed information about the password policy used within an enterprise network. Password policies for networks are a way to enforce complex passwords that are difficult to guess or crack through Brute Force.</li>\n        <li>".format(header))
        t1201html.write("This would help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts).</li>\n        <li>")
        t1201html.write("Password policies can be set and discovered on Windows, Linux, and macOS systems via various command shell utilities such as net accounts (/domain), chage -l , cat /etc/pam.d/common-password, and pwpolicy getaccountpolicies.")
        # indicator regex assignments
        t1201html.write("{}net.exe accounts</li>\n        <li>".format(iocs))
        t1201html.write("net1.exe accounts</li>\n        <li>")
        t1201html.write("Get-AdDefaultDomainPasswordPolicy</li>\n        <li>")
        t1201html.write("chage</li>\n        <li>")
        t1201html.write("common-password")
        t1201html.write("pwpolicy")
        t1201html.write("getaccountpolicies")
        # details
        t1201html.write("{}T1221</td>\n        <td>&nbsp;".format(headings)) # id
        t1201html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1201html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1201html.write("-") # sub-techniques
        # related techniques
        t1201html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1110 target=\"_blank\"\">&nbsp;T1110</a></td>\n        <td>&nbsp;".format(related))
        t1201html.write("Brute Force")
        # mitigations
        t1201html.write("{}Password Policies</td>\n        <td>&nbsp;".format(mitigations))
        t1201html.write("Ensure only valid password filters are registered. Filter DLLs must be present in Windows installation directory (C:\\Windows\\System32\\ by default) of a domain controller and/or local computer with a corresponding entry in HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages.{}".format(footer))
    with open(sd+"t1120.html", "w") as t1120html:
        # descriptions
        t1120html.write("{}Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage.</li>\n        <li>".format(header))
        t1120html.write("The information may be used to enhance their awareness of the system and network environment or may be used for further actions.")
        # indicator regex assignments
        t1120html.write("{}fsutil</li>\n        <li>".format(iocs))
        t1120html.write("fsinfo")
        # details
        t1120html.write("{}T1120</td>\n        <td>&nbsp;".format(headings)) # id
        t1120html.write("Windows, macOS</td>\n        <td>&nbsp;") # platforms
        t1120html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1120html.write("-") # sub-techniques
        # related techniques
        t1120html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1120html.write("-")
        # mitigations
        t1120html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1120html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1069.html", "w") as t1069html:
        t1069html.write("Adversaries may attempt to find group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions.")
        # indicator regex assignments
        t1069html.write("{}dscacheutil</li>\n        <li>".format(iocs))
        t1069html.write("ldapsearch</li>\n        <li>")
        t1069html.write("dscl</li>\n        <li>")
        t1069html.write("group")
        # details
        t1069html.write("{}T1069</td>\n        <td>&nbsp;".format(headings)) # id
        t1069html.write("Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1069html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1069html.write("T1069.001: Local Groups<br>&nbsp;T1069.002: Domain Groups<br>&nbsp;T1069.003: Cloud Groups") # sub-techniques
        # related techniques
        t1069html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1069html.write("-")
        # mitigations
        t1069html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1069html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1057.html", "w") as t1057html:
        # descriptions
        t1057html.write("{}Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Adversaries may use the information from Process Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.</li>\n        <li>".format(header))
        t1057html.write("In Windows environments, adversaries could obtain details on running processes using the Tasklist utility via cmd or Get-Process via PowerShell. Information about processes can also be extracted from the output of Native API calls such as CreateToolhelp32Snapshot. In Mac and Linux, this is accomplished with the ps command. Adversaries may also opt to enumerate processes via /proc.")
        # indicator regex assignments
        t1057html.write("{}Get-Process</li>\n        <li>".format(iocs))
        t1057html.write("CreateToolhelp32Snapshot</li>\n        <li>")
        t1057html.write("ps")
        # details
        t1057html.write("{}T1057</td>\n        <td>&nbsp;".format(headings)) # id
        t1057html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1057html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1057html.write("-") # sub-techniques
        # related techniques
        t1057html.write("<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1059 target=\"_blank\"\">&nbsp;T1059</a></td>\n        <td>&nbsp;")
        t1057html.write("Command and Scripting Interpreter: PowerShell")
        t1057html.write("<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1057 target=\"_blank\"\">&nbsp;T1057</a></td>\n        <td>&nbsp;")
        t1057html.write("Native API")
        # mitigations
        t1057html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1057html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1012.html", "w") as t1012html:
        # descriptions
        t1012html.write("{}Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.</li>\n        <li>".format(header))
        t1012html.write("The Registry contains a significant amount of information about the operating system, configuration, software, and security. Information can easily be queried using the Reg utility, though other means to access the Registry exist. Some of the information may help adversaries to further their operation within a network.</li>\n        <li>")
        t1012html.write("Adversaries may use the information from Query Registry during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.")
        # indicator regex assignments
        t1012html.write("{}reg query".format(iocs))
        # details
        t1012html.write("{}T1012</td>\n        <td>&nbsp;".format(headings)) # id
        t1012html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1012html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1012html.write("-") # sub-techniques
        # related techniques
        t1012html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1012html.write("-")
        # mitigations
        t1012html.write("{}Execution Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1012html.write("Use read-only containers and minimal images when possible to prevent the execution of commands.{}&nbsp;".format(insert))
        t1012html.write("Limit Access to Resource Over Network</td>\n        <td>&nbsp;")
        t1012html.write("Limit communications with the container service to local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API and Kubernetes API Server.{}&nbsp;".format(insert))
        t1012html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1012html.write("Ensure containers are not running as root by default.{}".format(footer))
    with open(sd+"t1018.html", "w") as t1018html:
        # descriptions
        t1018html.write("{}Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used such as Ping or net view using Net.</li>\n        <li>".format(header))
        t1018html.write("Adversaries may also use local host files (ex: C:\\Windows\\System32\\Drivers\\etc\\hosts or /etc/hosts) in order to discover the hostname to IP address mappings of remote systems.</li>\n        <li>")
        t1018html.write("Specific to macOS</li>\n        <li>")
        t1018html.write("the bonjour protocol exists to discover additional Mac-based systems within the same broadcast domain.</li>\n        <li>")
        t1018html.write("Within IaaS (Infrastructure as a Service) environments, remote systems include instances and virtual machines in various states, including the running or stopped state. Cloud providers have created methods to serve information about remote systems, such as APIs and CLIs.</li>\n        <li>")
        t1018html.write("For example, AWS provides a DescribeInstances API within the Amazon EC2 API and a describe-instances command within the AWS CLI that can return information about all instances within an account. Similarly, GCP's Cloud SDK CLI provides the gcloud compute instances list command to list all Google Compute Engine instances in a project, and Azure's CLI az vm list lists details of virtual machines.")
        # indicator regex assignments
        t1018html.write("{}net.exe view</li>\n        <li>".format(iocs))
        t1018html.write("net1.exe view</li>\n        <li>")
        t1018html.write("ping</li>\n        <li>")
        t1018html.write("tracert</li>\n        <li>")
        t1018html.write("traceroute</li>\n        <li>")
        t1018html.write("etc/host</li>\n        <li>")
        t1018html.write("etc/hosts</li>\n        <li>")
        t1018html.write("bonjour")
        # details
        t1018html.write("{}T1018</td>\n        <td>&nbsp;".format(headings)) # id
        t1018html.write("Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1018html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1018html.write("-") # sub-techniques
        # related techniques
        t1018html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1018html.write("-")
        # mitigations
        t1018html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1018html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1518.html", "w") as t1518html:
        # descriptions
        t1518html.write("{}Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment.</li>\n        <li>".format(header))
        t1518html.write("Adversaries may use the information from Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.</li>\n        <li>")
        t1518html.write("Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable to Exploitation for Privilege Escalation.")
        # indicator regex assignments
        t1518html.write("{}netsh</li>\n        <li>".format(iocs))
        t1518html.write("tasklist")
        # details
        t1518html.write("{}T1518</td>\n        <td>&nbsp;".format(headings)) # id
        t1518html.write("Windows, macOS, Linux, AWS, Azure, GCP, Office 365, Saas</td>\n        <td>&nbsp;") # platforms
        t1518html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1518html.write("T1518.001: Security Software Discovery") # sub-techniques
        # related techniques
        t1518html.write("<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1068 target=\"_blank\"\">&nbsp;T1068</a></td>\n        <td>&nbsp;")
        t1518html.write("Exploitation for Privilege Escalation")
        # mitigations
        t1518html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1518html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1082.html", "w") as t1082html:
        # descriptions
        t1082html.write("{}An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.</li>\n        <li>".format(header))
        t1082html.write("Adversaries may use the information from System Information Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.</li>\n        <li>")
        t1082html.write("Tools such as Systeminfo can be used to gather detailed system information. A breakdown of system data can also be gathered through the macOS systemsetup command, but it requires administrative privileges.</li>\n        <li>")
        t1082html.write("Infrastructure as a Service (IaaS) cloud providers such as AWS, GCP, and Azure allow access to instance and virtual machine information via APIs. Successful authenticated API calls can return data such as the operating system platform and status of a particular instance or the model view of a virtual machine.")
        # indicator regex assignments
        t1082html.write("{}systemsetup".format(iocs))
        # details
        t1082html.write("{}T1082</td>\n        <td>&nbsp;".format(headings)) # id
        t1082html.write("Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1082html.write("Defense Evasion</td>\n        <td>&nbsp;") # tactics
        t1082html.write("-") # sub-techniques
        # related techniques
        t1082html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1082html.write("-")
        # mitigations
        t1082html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1082html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1614.html", "w") as t1614html:
        # descriptions
        t1614html.write("{}Adversaries may gather information in an attempt to calculate the geographical location of a victim host. Adversaries may use the information from System Location Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.</li>\n        <li>".format(header))
        t1614html.write("Adversaries may attempt to infer the location of a system using various system checks, such as time zone, keyboard layout, and/or language settings. Windows API functions such as GetLocaleInfoW can also be used to determine the locale of the host. In cloud environments, an instance's availability zone may also be discovered by accessing the instance metadata service from the instance.</li>\n        <li>")
        t1614html.write("Adversaries may also attempt to infer the location of a victim host using IP addressing, such as via online geolocation IP-lookup services.")
        # indicator regex assignments
        t1614html.write("{}GetLocaleInfoW".format(iocs))
        # details
        t1614html.write("{}T1614</td>\n        <td>&nbsp;".format(headings)) # id
        t1614html.write("Windows, macOS, Linux, IaaS</td>\n        <td>&nbsp;") # platforms
        t1614html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1614html.write("-") # sub-techniques
        # related techniques
        t1614html.write("<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1053 target=\"_blank\"\">&nbsp;T1124</a></td>\n        <td>&nbsp;")
        t1614html.write("System Time Discovery")
        # mitigations
        t1614html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1614html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1016.html", "w") as t1016html:
        # descriptions
        t1016html.write("{}Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include Arp, ipconfig/ifconfig, nbtstat, and route.</li>\n        <li>".format(header))
        t1016html.write("Adversaries may use the information from System Network Configuration Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.")
        # indicator regex assignments
        t1016html.write("{}ipconfig</li>\n        <li>".format(iocs))
        t1016html.write("ifconfig</li>\n        <li>")
        t1016html.write("ping</li>\n        <li>")
        t1016html.write("traceroute</li>\n        <li>")
        t1016html.write("etc/host</li>\n        <li>")
        t1016html.write("etc/hosts</li>\n        <li>")
        t1016html.write("bonjour")
        # details
        t1016html.write("{}T1016</td>\n        <td>&nbsp;".format(headings)) # id
        t1016html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1016html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1016html.write("T1016:001: Internet Connection Discovery") # sub-techniques
        # related techniques
        t1016html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1016html.write("-")
        # mitigations
        t1016html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1016html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1049.html", "w") as t1049html:
        # descriptions
        t1049html.write("{}Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.</li>\n        <li>".format(header))
        t1049html.write("An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected</li>\n        <li>")
        t1049html.write("The actions performed are likely the same types of discovery techniques depending on the operating system, but the resulting information may include details about the networked cloud environment relevant to the adversary's goals. Cloud providers may have different ways in which their virtual networks operate.</li>\n        <li>")
        t1049html.write("Utilities and commands that acquire this information include netstat, \"net use,\" and \"net session\" with Net. In Mac and Linux, netstat and lsof can be used to list current connections. who -a and w can be used to show which users are currently logged in, similar to \"net session\".")
        # indicator regex assignments
        t1049html.write("{}net use</li>\n        <li>".format(iocs))
        t1049html.write("net1 use</li>\n        <li>")
        t1049html.write("net session</li>\n        <li>")
        t1049html.write("net1 session</li>\n        <li>")
        t1049html.write("netsh</li>\n        <li>")
        t1049html.write("lsof</li>\n        <li>")
        t1049html.write("who")
        # details
        t1049html.write("{}T1049</td>\n        <td>&nbsp;".format(headings)) # id
        t1049html.write("Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1049html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1049html.write("-") # sub-techniques
        # related techniques
        t1049html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1049html.write("-")
        # mitigations
        t1049html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1049html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1033.html", "w") as t1033html:
        # descriptions
        t1033html.write("{}Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using OS Credential Dumping.</li>\n        <li>".format(header))
        t1033html.write("The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs.</li>\n        <li>")
        t1033html.write("Adversaries may use the information from System Owner/User Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.</li>\n        <li>")
        t1033html.write("Utilities and commands that acquire this information include whoami. In Mac and Linux, the currently logged in user can be identified with w and who.")
        # indicator regex assignments
        t1033html.write("{}net config</li>\n        <li>".format(iocs))
        t1033html.write("net1 config</li>\n        <li>")
        t1033html.write("query user</li>\n        <li>")
        t1033html.write("hostname</li>\n        <li>")
        t1033html.write("ipconfig</li>\n        <li>")
        t1033html.write("quser</li>\n        <li>")
        t1033html.write("systeminfo</li>\n        <li>")
        t1033html.write("whoami</li>\n        <li>")
        t1033html.write("NetUser-GetInfo</li>\n        <li>")
        t1033html.write("ifconfig")
        # details
        t1033html.write("{}T1033</td>\n        <td>&nbsp;".format(headings)) # id
        t1033html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1033html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1033html.write("-") # sub-techniques
        # related techniques
        t1033html.write("<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1003 target=\"_blank\"\">&nbsp;T1003</a></td>\n        <td>&nbsp;")
        t1033html.write("OS Credential Dumping")
        # mitigations
        t1033html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1033html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1007.html", "w") as t1007html:
        t1007html.write("Adversaries may try to get information about registered services. Commands that may obtain information about services using operating system utilities are \"sc,\" \"tasklist /svc\" using Tasklist, and \"net start\" using Net, but adversaries may also use other tools as well.</li>\n        <li>Adversaries may use the information from System Service Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.")
        # indicator regex assignments
        t1007html.write("{}services.exe</li>\n        <li>".format(iocs))
        t1007html.write("sc.exe</li>\n        <li>")
        t1007html.write("tasklist</li>\n        <li>")
        t1007html.write("net start</li>\n        <li>")
        t1007html.write("net1 start</li>\n        <li>")
        t1007html.write("net stop</li>\n        <li>")
        t1007html.write("net1 stop")
        # details
        t1007html.write("{}T1007</td>\n        <td>&nbsp;".format(headings)) # id
        t1007html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1007html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1007html.write("-") # sub-techniques
        # related techniques
        t1007html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1007html.write("-")
        # mitigations
        t1007html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1007html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1124.html", "w") as t1124html:
        # descriptions
        t1124html.write("{}An adversary may gather the system time and/or time zone from a local or remote system. The system time is set and stored by the Windows Time Service within a domain to maintain time synchronization between systems and services in an enterprise network.</li>\n        <li>".format(header))
        t1124html.write("System time information may be gathered in a number of ways, such as with Net on Windows by performing net time \\hostname to gather the system time on a remote system. The victim's time zone may also be inferred from the current system time or gathered by using w32tm /tz.</li>\n        <li>")
        t1124html.write("The information could be useful for performing other techniques, such as executing a file with a Scheduled Task/Job, or to discover locality information based on time zone to assist in victim targeting.")
        # indicator regex assignments
        t1124html.write("{}net time</li>\n        <li>".format(iocs))
        t1124html.write("net1 time")
        # details
        t1124html.write("{}T1124</td>\n        <td>&nbsp;".format(headings)) # id
        t1124html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1124html.write("Discovery</td>\n        <td>&nbsp;") # tactics
        t1124html.write("-") # sub-techniques
        # related techniques
        t1124html.write("<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1053 target=\"_blank\"\">&nbsp;T1053</a></td>\n        <td>&nbsp;")
        t1124html.write("Scheduled Task/Job")
        t1124html.write("<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1053 target=\"_blank\"\">&nbsp;T1614</a></td>\n        <td>&nbsp;")
        t1124html.write("System Location Discovery")
        # mitigations
        t1124html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1124html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
  # Lateral Movement
    with open(sd+"t1210.html", "w") as t1210html:
        # descriptions
        t1210html.write("{}Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.</li>\n        <li>".format(header))
        t1210html.write("Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.</li>\n        <li>")
        t1210html.write("A common goal for post-compromise exploitation of remote services is for lateral movement to enable access to a remote system.</li>\n        <li>")
        t1210html.write("An adversary may need to determine if the remote system is in a vulnerable state, which may be done through Network Service Scanning or other Discovery methods looking for common, vulnerable software that may be deployed in the network, the lack of certain patches that may indicate vulnerabilities, or security software that may be used to detect or contain remote exploitation.</li>\n        <li>")
        t1210html.write("Servers are likely a high value target for lateral movement exploitation, but endpoint systems may also be at risk if they provide an advantage or access to additional resources.</li>\n        <li>")
        t1210html.write("There are several well-known vulnerabilities that exist in common services such as SMB and RDP as well as applications that may be used within internal networks such as MySQL and web server services.</li>\n        <li>")
        t1210html.write("Depending on the permissions level of the vulnerable remote service an adversary may achieve Exploitation for Privilege Escalation as a result of lateral movement exploitation as well.")
        # indicator regex assignments
        t1210html.write("{}Ports: 445, 3389".format(iocs))
        # details
        t1210html.write("{}T1210</td>\n        <td>&nbsp;".format(headings)) # id
        t1210html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1210html.write("Lateral Movement</td>\n        <td>&nbsp;") # tactics
        t1210html.write("-") # sub-techniques
        # related techniques
        t1210html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1210html.write("-")
        # mitigations
        t1210html.write("{}Application Isolation and Sandboxing</td>\n        <td>&nbsp;".format(mitigations))
        t1210html.write("Make it difficult for adversaries to advance their operation through exploitation of undiscovered or unpatched vulnerabilities by using sandboxing. Other types of virtualization and application microsegmentation may also mitigate the impact of some types of exploitation. Risks of additional exploits and weaknesses in these systems may still exist.{}&nbsp;".format(insert))
        t1210html.write("Disable or Remove Feature or Program</td>\n        <td>&nbsp;")
        t1210html.write("Minimize available services to only those that are necessary.{}&nbsp;".format(insert))
        t1210html.write("Exploit Protection</td>\n        <td>&nbsp;")
        t1210html.write("Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility and may not work for all software or services targeted.{}&nbsp;".format(insert))
        t1210html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1210html.write("Segment networks and systems appropriately to reduce access to critical systems and services to controlled methods.{}&nbsp;".format(insert))
        t1210html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1210html.write("Minimize permissions and access for service accounts to limit impact of exploitation.{}&nbsp;".format(insert))
        t1210html.write("Threat Intelligence Program</td>\n        <td>&nbsp;")
        t1210html.write("Develop a robust cyber threat intelligence capability to determine what types and levels of threat may use software exploits and 0-days against a particular organization.{}&nbsp;".format(insert))
        t1210html.write("Update Software</td>\n        <td>&nbsp;")
        t1210html.write("Update software regularly by employing patch management for internal enterprise endpoints and servers.{}&nbsp;".format(insert))
        t1210html.write("Vulnerability Scanning</td>\n        <td>&nbsp;")
        t1210html.write("Regularly scan the internal network for available services to identify new and potentially vulnerable services.{}".format(footer))
    with open(sd+"t1534.html", "w") as t1534html:
        # descriptions
        t1534html.write("{}Adversaries may use internal spearphishing to gain access to additional information or exploit other users within the same organization after they already have access to accounts or systems within the environment.</li>\n        <li>".format(header))
        t1534html.write("Internal spearphishing is multi-staged attack where an email account is owned either by controlling the user's device with previously installed malware or by compromising the account credentials of the user.</li>\n        <li>")
        t1534html.write("Adversaries attempt to take advantage of a trusted internal account to increase the likelihood of tricking the target into falling for the phish attempt.</li>\n        <li>")
        t1534html.write("Adversaries may leverage Spearphishing Attachment or Spearphishing Link as part of internal spearphishing to deliver a payload or redirect to an external site to capture credentials through Input Capture on sites that mimic email login interfaces.</li>\n        <li>")
        t1534html.write("There have been notable incidents where internal spearphishing has been used. The Eye Pyramid campaign used phishing emails with malicious attachments for lateral movement between victims, compromising nearly 18,000 email accounts in the process.</li>\n        <li>")
        t1534html.write("The Syrian Electronic Army (SEA) compromised email accounts at the Financial Times (FT) to steal additional account credentials. Once FT learned of the attack and began warning employees of the threat, the SEA sent phishing emails mimicking the Financial Times IT department and were able to compromise even more users.")
        # indicator regex assignments
        t1534html.write("{}-".format(iocs))
        # details
        t1534html.write("{}T1534</td>\n        <td>&nbsp;".format(headings)) # id
        t1534html.write("Windows, macOS, Linux, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1534html.write("Lateral Movement</td>\n        <td>&nbsp;") # tactics
        t1534html.write("-") # sub-techniques
        # related techniques
        t1534html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1566 target=\"_blank\"\">&nbsp;T1566</a></td>\n        <td>&nbsp;".format(related))
        t1534html.write("Phishing: Spearphishing Attachment")
        t1534html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1566 target=\"_blank\"\">&nbsp;T1566</a></td>\n        <td>&nbsp;".format(insert))
        t1534html.write("Phishing: Spearphishing Link")
        t1534html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1056 target=\"_blank\"\">&nbsp;T1056</a></td>\n        <td>&nbsp;".format(insert))
        t1534html.write("Input Capture")
        # mitigations
        t1534html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1534html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1570.html", "w") as t1570html:
        # descriptions
        t1570html.write("{}Adversaries may transfer tools or other files between systems in a compromised environment. Files may be copied from one system to another to stage adversary tools or other files over the course of an operation.</li>\n        <li>".format(header))
        t1570html.write("Adversaries may copy files laterally between internal victim systems to support lateral movement using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with SMB/Windows Admin Shares or Remote Desktop Protocol. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.")
        # indicator regex assignments
        t1570html.write("{}ADMIN$</li>\n        <li>".format(iocs))
        t1570html.write("C$</li>\n        <li>")
        t1570html.write("psexec</li>\n        <li>")
        t1570html.write("DISPLAY</li>\n        <li>")
        t1570html.write("HID</li>\n        <li>")
        t1570html.write("PCI</li>\n        <li>")
        t1570html.write("IDE</li>\n        <li>")
        t1570html.write("ROOT</li>\n        <li>")
        t1570html.write("UMB</li>\n        <li>")
        t1570html.write("FDC</li>\n        <li>")
        t1570html.write("IDE</li>\n        <li>")
        t1570html.write("SCSI</li>\n        <li>")
        t1570html.write("STORAGE</li>\n        <li>")
        t1570html.write("USBSTOR</li>\n        <li>")
        t1570html.write("USB</li>\n        <li>")
        t1570html.write("WpdBusEnumRoot")
        # details
        t1570html.write("{}T1570</td>\n        <td>&nbsp;".format(headings)) # id
        t1570html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1570html.write("Lateral Movement</td>\n        <td>&nbsp;") # tactics
        t1570html.write("-") # sub-techniques
        # related techniques
        t1570html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1021 target=\"_blank\"\">&nbsp;T1021</a></td>\n        <td>&nbsp;".format(related))
        t1570html.write("Remote Services: SMB/Windows Admin Shares")
        t1570html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1021 target=\"_blank\"\">&nbsp;T1021</a></td>\n        <td>&nbsp;".format(insert))
        t1570html.write("Remote Services: Remote Desktop Protocol")
        # mitigations
        t1570html.write("{}Filter Network Traffic</td>\n        <td>&nbsp;".format(mitigations))
        t1570html.write("Consider using the host firewall to restrict file sharing communications such as SMB.{}&nbsp;".format(insert))
        t1570html.write("Network Intrusion Prevention</td>\n        <td>&nbsp;")
        t1570html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware or unusual data transfer over known tools and protocols like FTP can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions.{}".format(footer))
    with open(sd+"t1563.html", "w") as t1563html:
        # descriptions
        t1563html.write("{}Adversaries may take control of preexisting sessions with remote services to move laterally in an environment.</li>\n        <li>".format(header))
        t1563html.write("Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service.</li>\n        <li>")
        t1563html.write("Adversaries may commandeer these sessions to carry out actions on remote systems. Remote Service Session Hijacking differs from use of Remote Services because it hijacks an existing session rather than creating a new session using Valid Accounts.")
        # indicator regex assignments
        t1563html.write("{}tscon".format(iocs))
        # details
        t1563html.write("{}T1563</td>\n        <td>&nbsp;".format(headings)) # id
        t1563html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1563html.write("Lateral Movement</td>\n        <td>&nbsp;") # tactics
        t1563html.write("T1563.001: SSH Hijacking<br>&nbsp;T1563.002: RDP Hijacking") # sub-techniques
        # related techniques
        t1563html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1021 target=\"_blank\"\">&nbsp;T1021</a></td>\n        <td>&nbsp;".format(related))
        t1563html.write("Remote Services")
        t1563html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1078 target=\"_blank\"\">&nbsp;T1078</a></td>\n        <td>&nbsp;".format(insert))
        t1563html.write("Valid Accounts")
        # mitigations
        t1563html.write("{}Disable or Remove Feature or Program</td>\n        <td>&nbsp;".format(mitigations))
        t1563html.write("Disable the remote service (ex: SSH, RDP, etc.) if it is unnecessary.{}&nbsp;".format(insert))
        t1563html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1563html.write("Enable firewall rules to block unnecessary traffic between network security zones within a network.{}&nbsp;".format(insert))
        t1563html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1563html.write("Do not allow remote access to services as a privileged account unless necessary.{}&nbsp;".format(insert))
        t1563html.write("User Account Management</td>\n        <td>&nbsp;")
        t1563html.write("Limit remote user permissions if remote access is necessary.{}".format(footer))
    with open(sd+"t1021.html", "w") as t1021html:
        # descriptions
        t1021html.write("{}Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.</li>\n        <li>".format(header))
        t1021html.write("In an enterprise environment, servers and workstations can be organized into domains. Domains provide centralized identity management, allowing users to login using one set of credentials across the entire network.</li>\n        <li>")
        t1021html.write("If an adversary is able to obtain a set of valid domain credentials, they could login to many different machines using remote access protocols such as secure shell (SSH) or remote desktop protocol (RDP).")
        # indicator regex assignments
        t1021html.write("{}Ports: 22, 23, 445, 3389, 5900</li>\n        <li>".format(iocs))
        t1021html.write("Event IDs: 4697, 7045</li>\n        <li>")
        t1021html.write("winrm</li>\n        <li>")
        t1021html.write("ADMIN$</li>\n        <li>")
        t1021html.write("C$</li>\n        <li>")
        t1021html.write("IPC$")
        # details
        t1021html.write("{}T1021</td>\n        <td>&nbsp;".format(headings)) # id
        t1021html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1021html.write("Lateral Movement</td>\n        <td>&nbsp;") # tactics
        t1021html.write("T1021.001: Remote Desktop Protocol<br>&nbsp;T1021.002: SMB/Windows Admin Shares<br>&nbsp;T1021.003: Distributed Component Object Model<br>&nbsp;T1021.004: SSH<br>&nbsp;T1021.005: VNC<br>&nbsp;T1021.006: Windows Remote Management") # sub-techniques
        # related techniques
        t1021html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1563 target=\"_blank\"\">&nbsp;T1563</a></td>\n        <td>&nbsp;".format(related))
        t1021html.write("Remote Service Session Hijacking")
        t1021html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1078 target=\"_blank\"\">&nbsp;T1078</a></td>\n        <td>&nbsp;".format(insert))
        t1021html.write("Valid Accounts")
        # mitigations
        t1021html.write("{}Multi-factor Authentication</td>\n        <td>&nbsp;".format(mitigations))
        t1021html.write("Use multi-factor authentication on remote service logons where possible.{}&nbsp;".format(insert))
        t1021html.write("User Account Management</td>\n        <td>&nbsp;")
        t1021html.write("Limit the accounts that may use remote services. Limit the permissions for accounts that are at higher risk of compromise; for example, configure SSH so users can only run specific programs.{}".format(footer))
    with open(sd+"t1080.html", "w") as t1080html:
        # descriptions
        t1080html.write("{}Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories. Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files.</li>\n        <li>".format(header))
        t1080html.write("Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary's code on a remote system. Adversaries may use tainted shared content to move laterally.</li>\n        <li>")
        t1080html.write("A directory share pivot is a variation on this technique that uses several other techniques to propagate malware when users access a shared network directory. It uses Shortcut Modification of directory .LNK files that use Masquerading to look like the real directories, which are hidden through Hidden Files and Directories.</li>\n        <li>")
        t1080html.write("The malicious .LNK-based directories have an embedded command that executes the hidden malware file in the directory and then opens the real intended directory so that the user's expected action still occurs. When used with frequently used network directories, the technique may result in frequent reinfections and broad access to systems and potentially to new and higher privileged accounts.</li>\n        <li>")
        t1080html.write("Adversaries may also compromise shared network directories through binary infections by appending or prepending its code to the healthy binary on the shared network directory. The malware may modify the original entry point (OEP) of the healthy binary to ensure that it is executed before the legitimate code.</li>\n        <li>")
        t1080html.write("The infection could continue to spread via the newly infected file when it is executed by a remote system. These infections may target both binary and non-binary formats that end with extensions including, but not limited to, .EXE, .DLL, .SCR, .BAT, and/or .VBS.")
        # indicator regex assignments
        t1080html.write("{}-".format(iocs))
        # details
        t1080html.write("{}T1221</td>\n        <td>&nbsp;".format(headings)) # id
        t1080html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1080html.write("Lateral Movement</td>\n        <td>&nbsp;") # tactics
        t1080html.write("-") # sub-techniques
        # related techniques
        t1080html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1547 target=\"_blank\"\">&nbsp;T1547</a></td>\n        <td>&nbsp;".format(related))
        t1080html.write("Boot or Logon Autostart Execution: Shortcut Modification")
        t1080html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1036 target=\"_blank\"\">&nbsp;T1036</a></td>\n        <td>&nbsp;".format(insert))
        t1080html.write("Masquerading")
        t1080html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1564 target=\"_blank\"\">&nbsp;T1564</a></td>\n        <td>&nbsp;".format(insert))
        t1080html.write("Hide Artifacts: Hidden Files and Directories")
        # mitigations
        t1080html.write("{}Execution Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1080html.write("Identify potentially malicious software that may be used to taint content or may result from it and audit and/or block the unknown programs by using application control tools, like AppLocker, or Software Restriction Policies [16] where appropriate.{}&nbsp;".format(insert))
        t1080html.write("Exploit Protection</td>\n        <td>&nbsp;")
        t1080html.write("Use utilities that detect or mitigate common features used in exploitation, such as the Microsoft Enhanced Mitigation Experience Toolkit (EMET).{}&nbsp;".format(insert))
        t1080html.write("Restrict File and Directory Permissions</td>\n        <td>&nbsp;")
        t1080html.write("Protect shared folders by minimizing users who have write access.{}".format(footer))
  # Collection
    with open(sd+"t1560.html", "w") as t1560html:
        # descriptions
        t1560html.write("{}An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network.</li>\n        <li>".format(header))
        t1560html.write("Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender.</li>\n        <li>")
        t1560html.write("Both compression and encryption are done prior to exfiltration, and can be performed using a utility, 3rd party library, or custom method.")
        # indicator regex assignments
        t1560html.write("{}.7z</li>\n        <li>".format(iocs))
        t1560html.write(".arj</li>\n        <li>")
        t1560html.write(".tar</li>\n        <li>")
        t1560html.write(".tgz</li>\n        <li>")
        t1560html.write(".zip</li>\n        <li>")
        t1560html.write("libzip</li>\n        <li>")
        t1560html.write("zlib</li>\n        <li>")
        t1560html.write("rarfile</li>\n        <li>")
        t1560html.write("bzip2")
        # details
        t1560html.write("{}T1560</td>\n        <td>&nbsp;".format(headings)) # id
        t1560html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1560html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1560html.write("T1560.001: Archive via Utility<br>&nbsp;T1560.002: Archive via Library<br>&nbsp;T1560.003: Archive via Custom Method") # sub-techniques
        # related techniques
        t1560html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1560html.write("-")
        # mitigations
        t1560html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1560html.write("System scans can be performed to identify unauthorized archival utilities.{}".format(footer))
    with open(sd+"t1123.html", "w") as t1123html:
        # descriptions
        t1123html.write("{}Adversaries may abuse shared modules to execute malicious payloads. The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths.</li>\n        <li>".format(header))
        t1123html.write("This functionality resides in NTDLL.dll and is part of the Windows Native API which is called from functions like CreateProcess, LoadLibrary, etc. of the Win32 API.")
        # indicator regex assignments
        t1123html.write("{}.mp3</li>\n        <li>".format(iocs))
        t1123html.write(".wav</li>\n        <li>")
        t1123html.write(".aac</li>\n        <li>")
        t1123html.write(".m4a</li>\n        <li>")
        t1123html.write("microphone")
        # details
        t1123html.write("{}T1129</td>\n        <td>&nbsp;".format(headings)) # id
        t1123html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1123html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1123html.write("-") # sub-techniques
        # related techniques
        t1123html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1106 target=\"_blank\"\">&nbsp;T1106</a></td>\n        <td>&nbsp;".format(related))
        t1123html.write("Native API")
        # mitigations
        t1123html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1123html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1119.html", "w") as t1119html:
        # descriptions
        t1119html.write("{}Once established within a system or network, an adversary may use automated techniques for collecting internal data.</li>\n        <li>".format(header))
        t1119html.write("Methods for performing this technique could include use of a Command and Scripting Interpreter to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. This functionality could also be built into remote access tools.</li>\n        <li>")
        t1119html.write("This technique may incorporate use of other techniques such as File and Directory Discovery and Lateral Tool Transfer to identify and move files.")
        # indicator regex assignments
        t1119html.write("{}-".format(iocs))
        # details
        t1119html.write("{}T1119</td>\n        <td>&nbsp;".format(headings)) # id
        t1119html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1119html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1119html.write("-") # sub-techniques
        # related techniques
        t1119html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1059 target=\"_blank\"\">&nbsp;T1059</a></td>\n        <td>&nbsp;".format(related))
        t1119html.write("Command and Scripting Interpreter")
        t1119html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1083 target=\"_blank\"\">&nbsp;T1083</a></td>\n        <td>&nbsp;".format(insert))
        t1119html.write("File and Directory Discovery")
        t1119html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1570 target=\"_blank\"\">&nbsp;T1570</a></td>\n        <td>&nbsp;".format(insert))
        t1119html.write("Lateral Tool Transfer")
        # mitigations
        t1119html.write("{}Encrypt Sensitive Information</td>\n        <td>&nbsp;".format(mitigations))
        t1119html.write("Encryption and off-system storage of sensitive information may be one way to mitigate collection of files, but may not stop an adversary from acquiring the information if an intrusion persists over a long period of time and the adversary is able to discover and access the data through other means. Strong passwords should be used on certain encrypted documents that use them to prevent offline cracking through Brute Force techniques.{}&nbsp;".format(insert))
        t1119html.write("Remote Data Storage</td>\n        <td>&nbsp;")
        t1119html.write("Encryption and off-system storage of sensitive information may be one way to mitigate collection of files, but may not stop an adversary from acquiring the information if an intrusion persists over a long period of time and the adversary is able to discover and access the data through other means.{}".format(footer))
    with open(sd+"t1115.html", "w") as t1115html:
        # descriptions
        t1115html.write("{}Adversaries may collect data stored in the clipboard from users copying information within or between applications.</li>\n        <li>".format(header))
        t1115html.write("In Windows, Applications can access clipboard data by using the Windows API. OSX provides a native command, pbpaste, to grab clipboard contents.")
        # indicator regex assignments
        t1115html.write("{}clipboard</li>\n        <li>".format(iocs))
        t1115html.write("pbpaste")
        # details
        t1115html.write("{}T1115</td>\n        <td>&nbsp;".format(headings)) # id
        t1115html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1115html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1115html.write("-") # sub-techniques
        # related techniques
        t1115html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1106 target=\"_blank\"\">&nbsp;T1106</a></td>\n        <td>&nbsp;".format(related))
        t1115html.write("Native API")
        # mitigations
        t1115html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1115html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1530.html", "w") as t1530html:
        # descriptions
        t1530html.write("{}Adversaries may access data objects from improperly secured cloud storage.</li>\n        <li>".format(header))
        t1530html.write("Many cloud service providers offer solutions for online data storage such as Amazon S3, Azure Storage, and Google Cloud Storage. These solutions differ from other storage solutions (such as SQL or Elasticsearch) in that there is no overarching application.</li>\n        <li>")
        t1530html.write("Data from these solutions can be retrieved directly using the cloud provider's APIs. Solution providers typically offer security guides to help end users configure systems.</li>\n        <li>")
        t1530html.write("Misconfiguration by end users is a common problem. There have been numerous incidents where cloud storage has been improperly secured (typically by unintentionally allowing public access by unauthenticated users or overly-broad access by all users), allowing open access to credit cards, personally identifiable information, medical records, and other sensitive information.</li>\n        <li>")
        t1530html.write("Adversaries may also obtain leaked credentials in source repositories, logs, or other means as a way to gain access to cloud storage objects that have access permission controls.")
        # indicator regex assignments
        t1530html.write("{}-".format(iocs))
        # details
        t1530html.write("{}T1530</td>\n        <td>&nbsp;".format(headings)) # id
        t1530html.write("AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1530html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1530html.write("-") # sub-techniques
        # related techniques
        t1530html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1530html.write("-")
        # mitigations
        t1530html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1530html.write("Frequently check permissions on cloud storage to ensure proper permissions are set to deny open or unprivileged access to resources.{}&nbsp;".format(insert))
        t1530html.write("Encrypt Sensitive Information</td>\n        <td>&nbsp;")
        t1530html.write("Encrypt data stored at rest in cloud storage. Managed encryption keys can be rotated by most providers. At a minimum, ensure an incident response plan to storage breach includes rotating the keys and test for impact on client applications.{}&nbsp;".format(insert))
        t1530html.write("Filter Network Traffic</td>\n        <td>&nbsp;")
        t1530html.write("Cloud service providers support IP-based restrictions when accessing cloud resources. Consider using IP allowlisting along with user account management to ensure that data access is restricted not only to valid users but only from expected IP ranges to mitigate the use of stolen credentials to access data.{}&nbsp;".format(insert))
        t1530html.write("Multi-factor Authentication</td>\n        <td>&nbsp;")
        t1530html.write("Consider using multi-factor authentication to restrict access to resources and cloud storage APIs.{}&nbsp;".format(insert))
        t1530html.write("Restrict File and Directory Permissions</td>\n        <td>&nbsp;")
        t1530html.write("Use access control lists on storage systems and objects.{}&nbsp;".format(insert))
        t1530html.write("User Account Management</td>\n        <td>&nbsp;")
        t1530html.write("Configure user permissions groups and roles for access to cloud storage. Implement strict Identity and Access Management (IAM) controls to prevent access to storage solutions except for the applications, users, and services that require access. Ensure that temporary access tokens are issued rather than permanent credentials, especially when access is being granted to entities outside of the internal security boundary.{}".format(footer))
    with open(sd+"t1602.html", "w") as t1602html:
        # descriptions
        t1602html.write("{}Adversaries may collect data related to managed devices from configuration repositories. Configuration repositories are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may also facilitate remote access and administration of devices.</li>\n        <li>".format(header))
        t1602html.write("Adversaries may target these repositories in order to collect large quantities of sensitive system administration data. Data from configuration repositories may be exposed by various protocols and software and can store a wide variety of data, much of which may align with adversary Discovery objectives.")
        # indicator regex assignments
        t1602html.write("{}-".format(iocs))
        # details
        t1602html.write("{}T1602</td>\n        <td>&nbsp;".format(headings)) # id
        t1602html.write("Network</td>\n        <td>&nbsp;") # platforms
        t1602html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1602html.write("T1602.001: SNMP (MIB Dump)<br>&nbsp;T1602.002: Network Device Configuration Dump") # sub-techniques
        # related techniques
        t1602html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1602html.write("-")
        # mitigations
        t1602html.write("{}Encrypt Sensitive Information</td>\n        <td>&nbsp;".format(mitigations))
        t1602html.write("Configure SNMPv3 to use the highest level of security (authPriv) available.{}&nbsp;".format(insert))
        t1602html.write("Filter Network Traffic</td>\n        <td>&nbsp;")
        t1602html.write("Apply extended ACLs to block unauthorized protocols outside the trusted network.{}&nbsp;".format(insert))
        t1602html.write("Network Intrusion Prevention</td>\n        <td>&nbsp;")
        t1602html.write("Configure intrusion prevention devices to detect SNMP queries and commands from unauthorized sources.{}&nbsp;".format(insert))
        t1602html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1602html.write("Segregate SNMP traffic on a separate management network.{}&nbsp;".format(insert))
        t1602html.write("Software Configuration</td>\n        <td>&nbsp;")
        t1602html.write("Allowlist MIB objects and implement SNMP views.{}&nbsp;".format(insert))
        t1602html.write("UpdateSoftware</td>\n        <td>&nbsp;")
        t1602html.write("Keep system images and software updated and migrate to SNMPv3.{}".format(footer))
    with open(sd+"t1213.html", "w") as t1213html:
        # descriptions
        t1213html.write("{}Adversaries may leverage information repositories to mine valuable information. Information repositories are tools that allow for storage of information, typically to facilitate collaboration or information sharing between users, and can store a wide variety of data that may aid adversaries in further objectives, or direct access to the target information.</li>\n        <li>".format(header))
        t1213html.write("Adversaries may also collect information from shared storage repositories hosted on cloud infrastructure or in software-as-a-service (SaaS) applications, as storage is one of the more fundamental requirements for cloud services and systems.</li>\n        <li>")
        t1213html.write("The following is a brief list of example information that may hold potential value to an adversary and may also be found on an information repository:</li>\n        <ul>\n          <li>Policies, procedures, and standards</li>\n          <li>Physical / logical network diagrams</li>\n          <li>System architecture diagrams</li>\n          <li>Technical system documentation</li>\n          <li>Testing / development credentials</li>\n          <li>Work / project schedules</li>\n          <li>Source code snippets</li>\n          <li>Links to network shares and other internal resources</li>\n        </ul>\n        <li>Information stored in a repository may vary based on the specific instance or environment. Specific common information repositories include Sharepoint, Confluence, and enterprise databases such as SQL Server.")
        # indicator regex assignments
        t1213html.write("{}-".format(iocs))
        # details
        t1213html.write("{}T1213</td>\n        <td>&nbsp;".format(headings)) # id
        t1213html.write("Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1213html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1213html.write("T1213.001: Confluence<br>&nbsp;T1213.002: Sharepoint") # sub-techniques
        # related techniques
        t1213html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1213html.write("-")
        # mitigations
        t1213html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1213html.write("Consider periodic review of accounts and privileges for critical and sensitive repositories.{}&nbsp;".format(insert))
        t1213html.write("User Account Management</td>\n        <td>&nbsp;")
        t1213html.write("Enforce the principle of least-privilege. Consider implementing access control mechanisms that include both authentication and authorization.{}&nbsp;".format(insert))
        t1213html.write("User Training</td>\n        <td>&nbsp;")
        t1213html.write("Develop and publish policies that define acceptable information to be stored in repositories.{}".format(footer))
    with open(sd+"t1005.html", "w") as t1005html:
        # descriptions
        t1005html.write("{}Adversaries may search local system sources, such as file systems or local databases, to find files of interest and sensitive data prior to Exfiltration.</li>\n        <li>".format(header))
        t1005html.write("Adversaries may do this using a Command and Scripting Interpreter, such as cmd, which has functionality to interact with the file system to gather information. Some adversaries may also use Automated Collection on the local system.")
        # indicator regex assignments
        t1005html.write("{}-".format(iocs))
        # details
        t1005html.write("{}T1005</td>\n        <td>&nbsp;".format(headings)) # id
        t1005html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1005html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1005html.write("-") # sub-techniques
        # related techniques
        t1005html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1059 target=\"_blank\"\">&nbsp;T1059</a></td>\n        <td>&nbsp;".format(related))
        t1005html.write("Command and Scripting Interpreter")
        t1005html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1119 target=\"_blank\"\">&nbsp;T1119</a></td>\n        <td>&nbsp;".format(insert))
        t1005html.write("Automated Collection")
        # mitigations
        t1005html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1005html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1039.html", "w") as t1039html:
        # descriptions
        t1039html.write("{}Adversaries may search network shares on computers they have compromised to find files of interest.</li>\n        <li>".format(header))
        t1039html.write("Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration.</li>\n        <li>")
        t1039html.write("Interactive command shells may be in use, and common functionality within cmd may be used to gather information.")
        # indicator regex assignments
        t1039html.write("{}-".format(iocs))
        # details
        t1039html.write("{}T1039</td>\n        <td>&nbsp;".format(headings)) # id
        t1039html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1039html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1039html.write("-") # sub-techniques
        # related techniques
        t1039html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1039html.write("-")
        # mitigations
        t1039html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1039html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1025.html", "w") as t1025html:
        # descriptions
        t1025html.write("{}Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration.</li>\n        <li>".format(header))
        t1025html.write("Interactive command shells may be in use, and common functionality within cmd may be used to gather information.</li>\n        <li>")
        t1025html.write("Some adversaries may also use Automated Collection on removable media.")
        # indicator regex assignments
        t1025html.write("{}DISPLAY</li>\n        <li>".format(iocs))
        t1025html.write("HID</li>\n        <li>")
        t1025html.write("PCI</li>\n        <li>")
        t1025html.write("IDE</li>\n        <li>")
        t1025html.write("ROOT</li>\n        <li>")
        t1025html.write("UMB</li>\n        <li>")
        t1025html.write("FDC</li>\n        <li>")
        t1025html.write("IDE</li>\n        <li>")
        t1025html.write("SCSI</li>\n        <li>")
        t1025html.write("STORAGE</li>\n        <li>")
        t1025html.write("USBSTOR</li>\n        <li>")
        t1025html.write("USB</li>\n        <li>")
        t1025html.write("WpdBusEnumRoot")
        # details
        t1025html.write("{}T1025</td>\n        <td>&nbsp;".format(headings)) # id
        t1025html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1025html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1025html.write("-") # sub-techniques
        # related techniques
        t1025html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1119 target=\"_blank\"\">&nbsp;T1119</a></td>\n        <td>&nbsp;".format(related))
        t1025html.write("Automated Collection")
        # mitigations
        t1025html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1025html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1074.html", "w") as t1074html:
        # descriptions
        t1074html.write("{}Adversaries may stage collected data in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location.</li>\n        <li>".format(header))
        t1074html.write("In cloud environments, adversaries may stage data within a particular instance or virtual machine before exfiltration. An adversary may Create Cloud Instance and stage data in that instance.</li>\n        <li>")
        t1074html.write("Adversaries may choose to stage data from a victim network in a centralized location prior to Exfiltration to minimize the number of connections made to their C2 server and better evade detection.")
        # indicator regex assignments
        t1074html.write("{}-".format(iocs))
        # details
        t1074html.write("{}T1074</td>\n        <td>&nbsp;".format(headings)) # id
        t1074html.write("Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1074html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1074html.write("T1074.001: Local Data Staging<br>&nbsp;T1074.002: Remote Data Staging")
        # related techniques
        t1074html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1560 target=\"_blank\"\">&nbsp;T1560</a></td>\n        <td>&nbsp;".format(related))
        t1074html.write("Archive Collected Data")
        t1074html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1578 target=\"_blank\"\">&nbsp;T1578</a></td>\n        <td>&nbsp;".format(insert))
        t1074html.write("Modify Cloud Compute Infrastructure: Create Cloud Instance")
        # mitigations
        t1074html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1074html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1114.html", "w") as t1114html:
        t1114html.write("Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries. Adversaries can collect or forward email from mail servers or clients.")
        # indicator regex assignments
        t1114html.write("{}.ost</li>\n        <li>".format(iocs))
        t1114html.write(".pst</li>\n        <li>")
        t1114html.write(".msg</li>\n        <li>")
        t1114html.write(".eml</li>\n        <li>")
        t1114html.write("*MailboxExportEequest")
        t1114html.write("X-MS-Exchange-Organization-AutoForwarded")
        t1114html.write("X-MailFwdBy")
        t1114html.write("X-Forwarded-To")
        t1114html.write("ForwardingSMTPAddress")
        # details
        t1114html.write("{}T1114</td>\n        <td>&nbsp;".format(headings)) # id
        t1114html.write("Windows, Office 365</td>\n        <td>&nbsp;") # platforms
        t1114html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1114html.write("T1114.001: Local Email Collection<br>&nbsp;T1114.002: Remote Email Collection<br>&nbsp;T1114.003: Email Forwarding Rule") # sub-techniques
        # related techniques
        t1114html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1114html.write("-")
        # mitigations
        t1114html.write("{}Audit</td>\n        <td>&nbsp;".format(mitigations))
        t1114html.write("Enterprise email solutions have monitoring mechanisms that may include the ability to audit auto-forwarding rules on a regular basis.<br>&nbsp;In an Exchange environment, Administrators can use Get-InboxRule to discover and remove potentially malicious auto-forwarding rules.{}&nbsp;".format(insert))
        t1114html.write("Encrypt Sensitive Information</td>\n        <td>&nbsp;")
        t1114html.write("Use of encryption provides an added layer of security to sensitive information sent over email. Encryption using public key cryptography requires the adversary to obtain the private certificate along with an encryption key to decrypt messages.{}&nbsp;".format(insert))
        t1114html.write("Multi-factor Authentication</td>\n        <td>&nbsp;")
        t1114html.write("Use of multi-factor authentication for public-facing webmail servers is a recommended best practice to minimize the usefulness of usernames and passwords to adversaries.{}".format(footer))
    with open(sd+"t1185.html", "w") as t1185html:
        # descriptions
        t1185html.write("{}Adversaries can take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify behavior, and intercept information as part of various man in the browser techniques.</li>\n        <li>".format(header))
        t1185html.write("A specific example is when an adversary injects software into a browser that allows an them to inherit cookies, HTTP sessions, and SSL client certificates of a user and use the browser as a way to pivot into an authenticated intranet.</li>\n        <li>")
        t1185html.write("Browser pivoting requires the SeDebugPrivilege and a high-integrity process to execute. Browser traffic is pivoted from the adversary's browser through the user's browser by setting up an HTTP proxy which will redirect any HTTP and HTTPS traffic.</li>\n        <li>")
        t1185html.write("This does not alter the user's traffic in any way. The proxy connection is severed as soon as the browser is closed. Whichever browser process the proxy is injected into, the adversary assumes the security context of that process. Browsers typically create a new process for each tab that is opened and permissions and certificates are separated accordingly.</li>\n        <li>")
        t1185html.write("With these permissions, an adversary could browse to any resource on an intranet that is accessible through the browser and which the browser has sufficient permissions, such as Sharepoint or webmail. Browser pivoting also eliminates the security provided by 2-factor authentication.")
        # indicator regex assignments
        t1185html.write("{}-".format(iocs))
        # details
        t1185html.write("{}T1185</td>\n        <td>&nbsp;".format(headings)) # id
        t1185html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1185html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1185html.write("-") # sub-techniques
        # related techniques
        t1185html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1185html.write("-")
        # mitigations
        t1185html.write("{}User Account Management</td>\n        <td>&nbsp;".format(mitigations))
        t1185html.write("Since browser pivoting requires a high integrity process to launch from, restricting user permissions and addressing Privilege Escalation and Bypass User Account Control opportunities can limit the exposure to this technique.{}&nbsp;".format(insert))
        t1185html.write("User Training</td>\n        <td>&nbsp;")
        t1185html.write("Close all browser sessions regularly and when they are no longer needed.{}".format(footer))
    with open(sd+"t1113.html", "w") as t1113html:
        # descriptions
        t1113html.write("{}Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations.</li>\n        <li>".format(header))
        t1113html.write("Taking a screenshot is also typically possible through native utilities or API calls, such as CopyFromScreen, xwd, or screencapture.")
        # indicator regex assignments
        t1113html.write("{}CopyFromScreen</li>\n        <li>".format(iocs))
        t1113html.write("xwd</li>\n        <li>")
        t1113html.write("screencapture")
        # details
        t1113html.write("{}T1113</td>\n        <td>&nbsp;".format(headings)) # id
        t1113html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1113html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1113html.write("-") # sub-techniques
        # related techniques
        t1113html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1113html.write("-")
        # mitigations
        t1113html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1113html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1125.html", "w") as t1125html:
        # descriptions
        t1125html.write("{}An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files.</li>\n        <li>".format(header))
        t1125html.write("Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture video or images. Video or image files may be written to disk and exfiltrated later. This technique differs from Screen Capture due to use of specific devices or applications for video recording rather than capturing the victim's screen.</li>\n        <li>")
        t1125html.write("In macOS, there are a few different malware samples that record the user's webcam such as FruitFly and Proton.")
        # indicator regex assignments
        t1125html.write("{}.mp4</li>\n        <li>".format(iocs))
        t1125html.write("mkv</li>\n        <li>")
        t1125html.write("avi</li>\n        <li>")
        t1125html.write("mov</li>\n        <li>")
        t1125html.write("wmv</li>\n        <li>")
        t1125html.write("mpg</li>\n        <li>")
        t1125html.write("mpeg</li>\n        <li>")
        t1125html.write("m4v</li>\n        <li>")
        t1125html.write("flv</li>\n        <li>")
        t1125html.write("")
        # details
        t1125html.write("{}T1125</td>\n        <td>&nbsp;".format(headings)) # id
        t1125html.write("Windows, macOS</td>\n        <td>&nbsp;") # platforms
        t1125html.write("Collection</td>\n        <td>&nbsp;") # tactics
        t1125html.write("-") # sub-techniques
        # related techniques
        t1125html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1125html.write("-")
        # mitigations
        t1125html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1125html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
  # Command and Control
    with open(sd+"t1071.html", "w") as t1071html:
        # descriptions
        t1071html.write("{}Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.</li>\n        <li>".format(header))
        t1071html.write("Adversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, or DNS. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are SMB, SSH, or RDP.")
        # indicator regex assignments
        t1071html.write("{}Ports: 20, 21, 25, 53, 69, 80, 110, 143, 443, 465, 993, 995, 989, 990".format(iocs))
        # details
        t1071html.write("{}T1071</td>\n        <td>&nbsp;".format(headings)) # id
        t1071html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1071html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1071html.write("T1071.001: Web Protocols<br>&nbsp;T1071.002: File Transfer Protocols<br>&nbsp;T1071.003: Mail Protocols<br>&nbsp;T1071.004: DNS") # sub-techniques
        # related techniques
        t1071html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1071html.write("-")
        # mitigations
        t1071html.write("{}Network Intrusion Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1071html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.{}".format(footer))
    with open(sd+"t1092.html", "w") as t1092html:
        # descriptions
        t1092html.write("{}Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system.</li>\n        <li>".format(header))
        t1092html.write("Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by Replication Through Removable Media.</li>\n        <li>")
        t1092html.write("Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access.")
        # indicator regex assignments
        t1092html.write("{}-".format(iocs))
        # details
        t1092html.write("{}T1092</td>\n        <td>&nbsp;".format(headings)) # id
        t1092html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1092html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1092html.write("-") # sub-techniques
        # related techniques
        t1092html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1091 target=\"_blank\"\">&nbsp;T1091</a></td>\n        <td>&nbsp;".format(related))
        t1092html.write("Replication Through Removable Media")
        # mitigations
        t1092html.write("{}Disable or Remove Feature or Program</td>\n        <td>&nbsp;".format(mitigations))
        t1092html.write("Disable Autoruns if it is unnecessary.{}&nbsp;".format(insert))
        t1092html.write("Operating System Configuration</td>\n        <td>&nbsp;")
        t1092html.write("Disallow or restrict removable media at an organizational policy level if they are not required for business operations.{}".format(footer))
    with open(sd+"t1132.html", "w") as t1132html:
        # descriptions
        t1132html.write("{}Adversaries may encode data to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system.</li>\n        <li>".format(header))
        t1132html.write("Use of data encoding may adhere to existing protocol specifications and includes use of ASCII, Unicode, Base64, MIME, or other binary-to-text and character encoding systems. Some data encoding systems may also result in data compression, such as gzip.")
        # indicator regex assignments
        t1132html.write("{}ASCII</li>\n        <li>".format(iocs))
        t1132html.write("unicode</li>\n        <li>")
        t1132html.write("HEX</li>\n        <li>")
        t1132html.write("base64</li>\n        <li>")
        t1132html.write("MIME")
        # details
        t1132html.write("{}T1132</td>\n        <td>&nbsp;".format(headings)) # id
        t1132html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1132html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1132html.write("T1132.001: Standard Encoding<br>&nbsp;T1132.002: Non-Standard Encoding") # sub-techniques
        # related techniques
        t1132html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1132html.write("-")
        # mitigations
        t1132html.write("{}Network Intrusion Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1132html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.{}".format(footer))
    with open(sd+"t1001.html", "w") as t1001html:
        # descriptions
        t1001html.write("{}Adversaries may obfuscate command and control traffic to make it more difficult to detect.</li>\n        <li>".format(header))
        t1001html.write("Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen.</li>\n        <li>")
        t1001html.write("This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols.")
        # indicator regex assignments
        t1001html.write("{}Invoke-PSImage".format(iocs))
        # details
        t1001html.write("{}T1001</td>\n        <td>&nbsp;".format(headings)) # id
        t1001html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1001html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1001html.write("T1001.001: Junk Data<br>&nbsp;T1001.002: Steganography<br>&nbsp;T1001.003: Protocol Impersonation") # sub-techniques
        # related techniques
        t1001html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1001html.write("-")
        # mitigations
        t1001html.write("{}Network Intrusion Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1001html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate some obfuscation activity at the network level.{}".format(footer))
    with open(sd+"t1568.html", "w") as t1568html:
        # descriptions
        t1568html.write("{}Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations.</li>\n        <li>".format(header))
        t1568html.write("This may be achieved by using malware that shares a common algorithm with the infrastructure the adversary uses to receive the malware's communications.</li>\n        <li>")
        t1568html.write("These calculations can be used to dynamically adjust parameters such as the domain name, IP address, or port number the malware uses for command and control.</li>\n        <li>")
        t1568html.write("Adversaries may use dynamic resolution for the purpose of Fallback Channels.</li>\n        <li>")
        t1568html.write("When contact is lost with the primary command and control server malware may employ dynamic resolution as a means to reestablishing command and control.")
        # indicator regex assignments
        t1568html.write("{}-".format(iocs))
        # details
        t1568html.write("{}T1568</td>\n        <td>&nbsp;".format(headings)) # id
        t1568html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1568html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1568html.write("T1568.001: Fast Flux DNS<br>&nbsp;T1568.002: Domain Generation Algorithms<br>&nbsp;T1568.003: DNS Calculation") # sub-techniques
        # related techniques
        t1568html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1008 target=\"_blank\"\">&nbsp;T1008</a></td>\n        <td>&nbsp;".format(related))
        t1568html.write("Fallback Channels")
        # mitigations
        t1568html.write("{}Network Intrusion Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1568html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Malware researchers can reverse engineer malware variants that use dynamic resolution and determine future C2 infrastructure that the malware will attempt to contact, but this is a time and resource intensive effort.{}&nbsp;".format(insert))
        t1568html.write("Restrict Web-Based Content</td>\n        <td>&nbsp;")
        t1568html.write("In some cases a local DNS sinkhole may be used to help prevent behaviors associated with dynamic resolution.{}".format(footer))
    with open(sd+"t1573.html", "w") as t1573html:
        # descriptions
        t1573html.write("{}Adversaries may employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.</li>\n        <li>".format(header))
        t1573html.write("Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files.")
        # indicator regex assignments
        t1573html.write("{}encrypt".format(iocs))
        # details
        t1573html.write("{}T1573</td>\n        <td>&nbsp;".format(headings)) # id
        t1573html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1573html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1573html.write("T1573.001: Symmetric Cryptography<br>&nbsp;T1573.002: Asymmetric Cryptography") # sub-techniques
        # related techniques
        t1573html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1573html.write("-")
        # mitigations
        t1573html.write("{}Network Intrusion Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1573html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.{}&nbsp;".format(insert))
        t1573html.write("SSL/TLS Inspection</td>\n        <td>&nbsp;")
        t1573html.write("SSL/TLS inspection can be used to see the contents of encrypted sessions to look for network-based indicators of malware communication protocols.{}".format(footer))
    with open(sd+"t1008.html", "w") as t1008html:
        t1008html.write("Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.")
        # indicator regex assignments
        t1008html.write("{}-".format(iocs))
        # details
        t1008html.write("{}T1008</td>\n        <td>&nbsp;".format(headings)) # id
        t1008html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1008html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1008html.write("-") # sub-techniques
        # related techniques
        t1008html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1568 target=\"_blank\"\">&nbsp;T1568</a></td>\n        <td>&nbsp;".format(related))
        t1008html.write("Dynamic Resolution")
        t1008html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1104 target=\"_blank\"\">&nbsp;T1104</a></td>\n        <td>&nbsp;".format(insert))
        t1008html.write("Multi-Stage Channels")
        # mitigations
        t1008html.write("{}Network Intrusion Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1008html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific protocol used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.{}".format(footer))
    with open(sd+"t1105.html", "w") as t1105html:
        # descriptions
        t1105html.write("{}Adversaries may transfer tools or other files from an external system into a compromised environment.</li>\n        <li>".format(header))
        t1105html.write("Files may be copied from an external adversary controlled system through the command and control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP.</li>\n        <li>")
        t1105html.write("Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.")
        # indicator regex assignments
        t1105html.write("{}scp</li>\n        <li>".format(iocs))
        t1105html.write("rsync</li>\n        <li>")
        t1105html.write("sftp")
        # details
        t1105html.write("{}T1572</td>\n        <td>&nbsp;".format(headings)) # id
        t1105html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1105html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1105html.write("-") # sub-techniques
        # related techniques
        t1105html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1105html.write("-")
        # mitigations
        t1105html.write("{}Network Intrusion Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1105html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware or unusual data transfer over known tools and protocols like FTP can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.{}".format(footer))
    with open(sd+"t1104.html", "w") as t1104html:
        # descriptions
        t1104html.write("{}Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult.</li>\n        <li>".format(header))
        t1104html.write("Remote access tools will call back to the first-stage command and control server for instructions. The first stage may have automated capabilities to collect basic host information, update tools, and upload additional files.</li>\n        <li>")
        t1104html.write("A second remote access tool (RAT) could be uploaded at that point to redirect the host to the second-stage command and control server. The second stage will likely be more fully featured and allow the adversary to interact with the system through a reverse shell and additional RAT features.</li>\n        <li>")
        t1104html.write("The different stages will likely be hosted separately with no overlapping infrastructure. The loader may also have backup first-stage callbacks or Fallback Channels in case the original first-stage communication path is discovered and blocked.")
        # indicator regex assignments
        t1104html.write("{}-".format(iocs))
        # details
        t1104html.write("{}T1104</td>\n        <td>&nbsp;".format(headings)) # id
        t1104html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1104html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1104html.write("-") # sub-techniques
        # related techniques
        t1104html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1008 target=\"_blank\"\">&nbsp;T1008</a></td>\n        <td>&nbsp;".format(related))
        t1104html.write("Fallback Channels")
        # mitigations
        t1104html.write("{}Network Intrusion Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1104html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.{}".format(footer))
    with open(sd+"t1095.html", "w") as t1095html:
        # descriptions
        t1095html.write("{}Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive.</li>\n        <li>".format(header))
        t1095html.write("Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL).</li>\n        <li>")
        t1095html.write("ICMP communication between hosts is one example. Because ICMP is part of the Internet Protocol Suite, it is required to be implemented by all IP-compatible hosts; however, it is not as commonly monitored as other Internet Protocols such as TCP or UDP and may be used by adversaries to hide communications.")
        # indicator regex assignments
        t1095html.write("{}-".format(iocs))
        # details
        t1095html.write("{}T1095</td>\n        <td>&nbsp;".format(headings)) # id
        t1095html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1095html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1095html.write("-") # sub-techniques
        # related techniques
        t1095html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1095html.write("-")
        # mitigations
        t1095html.write("{}Filter Network Traffic</td>\n        <td>&nbsp;".format(mitigations))
        t1095html.write("Filter network traffic to prevent use of protocols across the network boundary that are unnecessary.{}&nbsp;".format(insert))
        t1095html.write("Network Intrusion Prevention</td>\n        <td>&nbsp;")
        t1095html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.{}&nbsp;".format(insert))
        t1095html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1095html.write("Properly configure firewalls and proxies to limit outgoing traffic to only necessary ports and through proper network gateway systems. Also ensure hosts are only provisioned to communicate over authorized interfaces.{}".format(footer))
    with open(sd+"t1571.html", "w") as t1571html:
        # descriptions
        t1571html.write("{}Adversaries may communicate using a protocol and port paring that are typically not associated. For example, HTTPS over port 8088 or port 587 as opposed to the traditional port 443.</li>\n        <li>".format(header))
        t1571html.write("Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.")
        # indicator regex assignments
        t1571html.write("{}-".format(iocs))
        # details
        t1571html.write("{}T1571</td>\n        <td>&nbsp;".format(headings)) # id
        t1571html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1571html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1571html.write("-") # sub-techniques
        # related techniques
        t1571html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1571html.write("-")
        # mitigations
        t1571html.write("{}Network Intrusion Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1571html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.{}&nbsp;".format(insert))
        t1571html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1571html.write("Properly configure firewalls and proxies to limit outgoing traffic to only necessary ports for that particular network segment.{}".format(footer))
    with open(sd+"t1572.html", "w") as t1572html:
        # descriptions
        t1572html.write("{}Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems.</li>\n        <li>".format(header))
        t1572html.write("Tunneling involves explicitly encapsulating a protocol within another. This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to a VPN).</li>\n        <li>")
        t1572html.write("Tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as SMB, RDP, or other traffic that would be filtered by network appliances or not routed over the Internet.</li>\n        <li>")
        t1572html.write("There are various means to encapsulate a protocol within another protocol. For example, adversaries may perform SSH tunneling (also known as SSH port forwarding), which involves forwarding arbitrary data over an encrypted SSH tunnel.</li>\n        <li>")
        t1572html.write("Protocol Tunneling may also be abused by adversaries during Dynamic Resolution. Known as DNS over HTTPS (DoH), queries to resolve C2 infrastructure may be encapsulated within encrypted HTTPS packets.</li>\n        <li>")
        t1572html.write("Adversaries may also leverage Protocol Tunneling in conjunction with Proxy and/or Protocol Impersonation to further conceal C2 communications and infrastructure.")
        # indicator regex assignments
        t1572html.write("{}-".format(iocs))
        # details
        t1572html.write("{}T1572</td>\n        <td>&nbsp;".format(headings)) # id
        t1572html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1572html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1572html.write("-") # sub-techniques
        # related techniques
        t1572html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1568 target=\"_blank\"\">&nbsp;T1568</a></td>\n        <td>&nbsp;".format(related))
        t1572html.write("Dynamic Resolution")
        t1572html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1090 target=\"_blank\"\">&nbsp;T1090</a></td>\n        <td>&nbsp;".format(insert))
        t1572html.write("Proxy")
        t1572html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1001 target=\"_blank\"\">&nbsp;T1001</a></td>\n        <td>&nbsp;".format(insert))
        t1572html.write("Data Obfuscation: Protocol Impersonation")
        # mitigations
        t1572html.write("{}Filter Network Traffic</td>\n        <td>&nbsp;".format(mitigations))
        t1572html.write("Consider filtering network traffic to untrusted or known bad domains and resources.{}&nbsp;".format(insert))
        t1572html.write("Network Intrusion Prevention</td>\n        <td>&nbsp;")
        t1572html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.{}".format(footer))
    with open(sd+"t1090.html", "w") as t1090html:
        # descriptions
        t1090html.write("{}Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap.</li>\n        <li>".format(header))
        t1090html.write("Adversaries use these types of proxies to manage command and control communications, reduce the number of simultaneous outbound network connections, provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion. Adversaries may chain together multiple proxies to further disguise the source of malicious traffic.</li>\n        <li>")
        t1090html.write("Adversaries can also take advantage of routing schemes in Content Delivery Networks (CDNs) to proxy command and control traffic.")
        # indicator regex assignments
        t1090html.write("{}netsh</li>\n        <li>".format(iocs))
        t1090html.write("portopening")
        # details
        t1090html.write("{}T1090</td>\n        <td>&nbsp;".format(headings)) # id
        t1090html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1090html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1090html.write("T1090.001: Internal Proxy<br>&nbsp;T1090.002: External Proxy<br>&nbsp;T1090.003: Multi-hop Proxy<br>&nbsp;T1090.004: Domain Fronting") # sub-techniques
        # related techniques
        t1090html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1572 target=\"_blank\"\">&nbsp;T1572</a></td>\n        <td>&nbsp;".format(related))
        t1090html.write("Protocol Tunneling")
        # mitigations
        t1090html.write("{}Filter Network Traffic</td>\n        <td>&nbsp;".format(mitigations))
        t1090html.write("Traffic to known anonymity networks and C2 infrastructure can be blocked through the use of network allow and block lists. It should be noted that this kind of blocking may be circumvented by other techniques like Domain Fronting.{}&nbsp;".format(insert))
        t1090html.write("Network Intrusion Prevention</td>\n        <td>&nbsp;")
        t1090html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific C2 protocol used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.{}&nbsp;".format(insert))
        t1090html.write("SSL/TLS Inspection</td>\n        <td>&nbsp;")
        t1090html.write("If it is possible to inspect HTTPS traffic, the captures can be analyzed for connections that appear to be domain fronting.{}".format(footer))
    with open(sd+"t1219.html", "w") as t1219html:
        # descriptions
        t1219html.write("{}An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks. These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.</li>\n        <li>".format(header))
        t1219html.write("Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries.</li>\n        <li>")
        t1219html.write("Remote access tools may be established and used post-compromise as alternate communications channel for redundant access or as a way to establish an interactive remote desktop session with the target system. They may also be used as a component of malware to establish a reverse connection or back-connect to a service or adversary controlled system.</li>\n        <li>")
        t1219html.write("Admin tools such as TeamViewer have been used by several groups targeting institutions in countries of interest to the Russian state and criminal campaigns.")
        # indicator regex assignments
        t1219html.write("{}Ports: 5800, 5895, 5900, 5938, 5984, 5986, 8200</li>\n        <li>".format(iocs))
        t1219html.write("")
        # details
        t1219html.write("{}T1219</td>\n        <td>&nbsp;".format(headings)) # id
        t1219html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1219html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1219html.write("-") # sub-techniques
        # related techniques
        t1219html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1219html.write("-")
        # mitigations
        t1219html.write("{}Execution Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1219html.write("Use application control to mitigate installation and use of unapproved software that can be used for remote access.{}&nbsp;".format(insert))
        t1219html.write("Filter Network Traffic</td>\n        <td>&nbsp;")
        t1219html.write("Properly configure firewalls, application firewalls, and proxies to limit outgoing traffic to sites and services used by remote access tools.{}&nbsp;".format(insert))
        t1219html.write("Network Intrusion Prevention</td>\n        <td>&nbsp;")
        t1219html.write("Network intrusion detection and prevention systems that use network signatures may be able to prevent traffic to remote access services.{}".format(footer))
    with open(sd+"t1102.html", "w") as t1102html:
        # descriptions
        t1102html.write("{}Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise.</li>\n        <li>".format(header))
        t1102html.write("Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.</li>\n        <li>")
        t1102html.write("Use of Web services may also protect back-end C2 infrastructure from discovery through malware binary analysis while also enabling operational resiliency (since this infrastructure may be dynamically changed).")
        # indicator regex assignments
        t1102html.write("{}-".format(iocs))
        # details
        t1102html.write("{}T1102</td>\n        <td>&nbsp;".format(headings)) # id
        t1102html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1102html.write("Command &amp; Control</td>\n        <td>&nbsp;") # tactics
        t1102html.write("T1102.001: Dead Drop Resolver<br>&nbsp;T1102.002: Bidirectional Communication<br>&nbsp;T1102.003: One-Way Communication") # sub-techniques
        # related techniques
        t1102html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1102html.write("-")
        # mitigations
        t1102html.write("{}Network Intrusion Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1102html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.{}&nbsp;".format(insert))
        t1102html.write("Restrict Web-Based Content</td>\n        <td>&nbsp;")
        t1102html.write("Web proxies can be used to enforce external network communication policy that prevents use of unauthorized external services.{}".format(footer))
  # Exfiltration
    with open(sd+"t1020.html", "w") as t1020html:
        # descriptions
        t1020html.write("{}Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection.</li>\n        <li>".format(header))
        t1020html.write("When automated exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as Exfiltration Over C2 Channel and Exfiltration Over Alternative Protocol.")
        # indicator regex assignments
        t1020html.write("{}-".format(iocs))
        # details
        t1020html.write("{}T1030</td>\n        <td>&nbsp;".format(headings)) # id
        t1020html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1020html.write("Exfiltration</td>\n        <td>&nbsp;") # tactics
        t1020html.write("T1020.001: Traffic Duplication")
        # related techniques
        t1020html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1041 target=\"_blank\"\">&nbsp;T1041</a></td>\n        <td>&nbsp;".format(related))
        t1020html.write("Exfiltration Over C2 Channel")
        t1020html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1048 target=\"_blank\"\">&nbsp;T1048</a></td>\n        <td>&nbsp;".format(insert))
        t1020html.write("Exfiltration Over Alternative Protocol")
        # mitigations
        t1020html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1020html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1030.html", "w") as t1030html:
        t1030html.write("An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.")
        # indicator regex assignments
        t1030html.write("{}-".format(iocs))
        # details
        t1030html.write("{}T1030</td>\n        <td>&nbsp;".format(headings)) # id
        t1030html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1030html.write("Exfiltration</td>\n        <td>&nbsp;") # tactics
        t1030html.write("-") # sub-techniques
        # related techniques
        t1030html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1030html.write("-")
        # mitigations
        t1030html.write("{}Network Intrusion Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1030html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level.{}".format(footer))
    with open(sd+"t1048.html", "w") as t1048html:
        # descriptions
        t1048html.write("{}Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.</li>\n        <li>".format(header))
        t1048html.write("Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Different protocol channels could also include Web services such as cloud storage. Adversaries may also opt to encrypt and/or obfuscate these alternate channels.</li>\n        <li>")
        t1048html.write("Exfiltration Over Alternative Protocol can be done using various common operating system utilities such as Net/SMB or FTP.")
        # indicator regex assignments
        t1048html.write("{}Ports: 20, 21, 22, 23, 25, 53, 69, 80, 110, 135, 143, 443, 465, 989, 990, 993, 995, 3389, 5355, 5800, 5895, 5900, 5938, 5984, 5986, 8200".format(iocs))
        # details
        t1048html.write("{}T1048</td>\n        <td>&nbsp;".format(headings)) # id
        t1048html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1048html.write("Exfiltration</td>\n        <td>&nbsp;") # tactics
        t1048html.write("T1048.001: Exfiltration Over Symmetric Encrypted Non-C2 Protocol<br>&nbsp;T1048.002: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol<br>&nbsp;T1048.003: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol") # sub-techniques
        # related techniques
        t1048html.write("{}&nbsp;<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1029 target=\"_blank\"\">&nbsp;T1029</td>\n        <td>&nbsp;".format(related))
        t1048html.write("Scheduled Transfer")
        # mitigations
        t1048html.write("{}Filter Network Traffic</td>\n        <td>&nbsp;".format(mitigations))
        t1048html.write("Enforce proxies and use dedicated servers for services such as DNS and only allow those systems to communicate over respective ports/protocols, instead of all systems within a network.{}&nbsp;".format(insert))
        t1048html.write("Network Intrusion Prevention</td>\n        <td>&nbsp;")
        t1048html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level.{}&nbsp;".format(insert))
        t1048html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1048html.write("Follow best practices for network firewall configurations to allow only necessary ports and traffic to enter and exit the network.{}".format(footer))
    with open(sd+"t1041.html", "w") as t1041html:
        t1041html.write("Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.")
        # indicator regex assignments
        t1041html.write("{}Ports: 20, 21, 25, 445, 53, 80, 443, 445".format(iocs))
        # details
        t1041html.write("{}T1041</td>\n        <td>&nbsp;".format(headings)) # id
        t1041html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1041html.write("Exfiltration</td>\n        <td>&nbsp;") # tactics
        t1041html.write("-") # sub-techniques
        # related techniques
        t1041html.write("{}&nbsp;<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1029 target=\"_blank\"\">&nbsp;T1029</td>\n        <td>&nbsp;".format(related))
        t1041html.write("Scheduled Transfer")
        # mitigations
        t1041html.write("{}Network Intrusion Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1041html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool command and control signatures over time or construct protocols in such a way to avoid detection by common defensive tools.{}".format(footer))
    with open(sd+"t1011.html", "w") as t1011html:
        # descriptions
        t1011html.write("{}Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel.</li>\n        <li>".format(header))
        t1011html.write("Adversaries may choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network.")
        # indicator regex assignments
        t1011html.write("{}bluetooth".format(iocs))
        # details
        t1011html.write("{}T1011</td>\n        <td>&nbsp;".format(headings)) # id
        t1011html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1011html.write("Exfiltration</td>\n        <td>&nbsp;") # tactics
        t1011html.write("T1011.001: Exfiltration Over Bluetooth") # sub-techniques
        # related techniques
        t1011html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1011html.write("-")
        # mitigations
        t1011html.write("{}Operating System Configuration</td>\n        <td>&nbsp;".format(mitigations))
        t1011html.write("Prevent the creation of new network adapters where possible.{}".format(footer))
    with open(sd+"t1052.html", "w") as t1052html:
        # descriptions
        t1052html.write("{}Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user.</li>\n        <li>".format(header))
        t1052html.write("Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.")
        # indicator regex assignments
        t1052html.write("{}DISPLAY</li>\n        <li>".format(iocs))
        t1052html.write("HID</li>\n        <li>")
        t1052html.write("PCI</li>\n        <li>")
        t1052html.write("IDE</li>\n        <li>")
        t1052html.write("ROOT</li>\n        <li>")
        t1052html.write("UMB</li>\n        <li>")
        t1052html.write("FDC</li>\n        <li>")
        t1052html.write("IDE</li>\n        <li>")
        t1052html.write("SCSI</li>\n        <li>")
        t1052html.write("STORAGE</li>\n        <li>")
        t1052html.write("USBSTOR</li>\n        <li>")
        t1052html.write("USB</li>\n        <li>")
        t1052html.write("WpdBusEnumRoot")
        # details
        t1052html.write("{}T1052</td>\n        <td>&nbsp;".format(headings)) # id
        t1052html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1052html.write("Exfiltration</td>\n        <td>&nbsp;") # tactics
        t1052html.write("T1052.001: Exfiltration over USB") # sub-techniques
        # related techniques
        t1052html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1052html.write("-")
        # mitigations
        t1052html.write("{}Disable or Remove Feature or Program</td>\n        <td>&nbsp;".format(mitigations))
        t1052html.write("Disable Autorun if it is unnecessary. Disallow or restrict removable media at an organizational policy level if they are not required for business operations.{}&nbsp;".format(insert))
        t1052html.write("Limit Hardware Installation</td>\n        <td>&nbsp;")
        t1052html.write("Limit the use of USB devices and removable media within a network.{}".format(footer))
    with open(sd+"t1567.html", "w") as t1567html:
        # descriptions
        t1567html.write("{}Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel.</li>\n        <li>".format(header))
        t1567html.write("Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise.</li>\n        <li>")
        t1567html.write("Firewall rules may also already exist to permit traffic to these services.</li>\n        <li>")
        t1567html.write("Web service providers also commonly use SSL/TLS encryption, giving adversaries an added level of protection.")
        # indicator regex assignments
        t1567html.write("{}github</li>\n        <li>".format(iocs))
        t1567html.write("gitlab</li>\n        <li>")
        t1567html.write("bitbucket</li>\n        <li>")
        t1567html.write("dropbox</li>\n        <li>")
        t1567html.write("onedrive</li>\n        <li>")
        t1567html.write("4shared")
        # details
        t1567html.write("{}T1567</td>\n        <td>&nbsp;".format(headings)) # id
        t1567html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1567html.write("Execution</td>\n        <td>&nbsp;") # tactics
        t1567html.write("T1567.001: Exfiltration to Code Repository<br>&nbsp;T1567.002: Exfiltration to Cloud Storage") # sub-techniques
        # related techniques
        t1567html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1567html.write("-")
        # mitigations
        t1567html.write("{}Restrict Web-Based Content</td>\n        <td>&nbsp;".format(mitigations))
        t1567html.write("Web proxies can be used to enforce an external network communication policy that prevents use of unauthorized external services.{}".format(footer))
    with open(sd+"t1029.html", "w") as t1029html:
        t1029html.write("Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.")
        # indicator regex assignments
        t1029html.write("{}-".format(iocs))
        # details
        t1029html.write("{}T1029</td>\n        <td>&nbsp;".format(headings)) # id
        t1029html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1029html.write("Exfiltration</td>\n        <td>&nbsp;") # tactics
        t1029html.write("-")
        # related techniques
        t1029html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1041 target=\"_blank\"\">&nbsp;T1041</a></td>\n        <td>&nbsp;".format(related))
        t1029html.write("Exfiltration Over C2 Channel")
        t1029html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1048 target=\"_blank\"\">&nbsp;T1048</a></td>\n        <td>&nbsp;".format(insert))
        t1029html.write("Exfiltration Over Alternative Protocol")
        # mitigations
        t1029html.write("{}Network Intrusion Prevention</td>\n        <td>&nbsp;".format(mitigations))
        t1029html.write("Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool command and control signatures over time or construct protocols in such a way to avoid detection by common defensive tools.{}".format(footer))
    with open(sd+"t1537.html", "w") as t1537html:
        # descriptions
        t1537html.write("{}Adversaries may exfiltrate data by transferring the data, including backups of cloud environments, to another cloud account they control on the same service to avoid typical file transfers/downloads and network-based exfiltration detection.</li>\n        <li>".format(header))
        t1537html.write("A defender who is monitoring for large transfers to outside the cloud environment through normal file transfers or over command and control channels may not be watching for data transfers to another account within the same cloud provider.</li>\n        <li>")
        t1537html.write("Such transfers may utilize existing cloud provider APIs and the internal address space of the cloud provider to blend into normal traffic or avoid data transfers over external network interfaces.</li>\n        <li>")
        t1537html.write("Incidents have been observed where adversaries have created backups of cloud instances and transferred them to separate accounts.")
        # indicator regex assignments
        t1537html.write("{}onedrive</li>\n        <li>".format(iocs))
        t1537html.write("1drv</li>\n        <li>")
        t1537html.write("azure</li>\n        <li>")
        t1537html.write("icloud</li>\n        <li>")
        t1537html.write("cloudrive</li>\n        <li>")
        t1537html.write("dropbox</li>\n        <li>")
        t1537html.write("drive\\.google</li>\n        <li>")
        t1537html.write("fileshare</li>\n        <li>")
        t1537html.write("mediafire</li>\n        <li>")
        t1537html.write("zippyshare</li>\n        <li>")
        t1537html.write("megaupload")
        # details
        t1537html.write("{}T1537</td>\n        <td>&nbsp;".format(headings)) # id
        t1537html.write("AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1537html.write("Exfiltration</td>\n        <td>&nbsp;") # tactics
        t1537html.write("-") # sub-techniques
        # related techniques
        t1537html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1537html.write("-")
        # mitigations
        t1537html.write("{}Filter Network Traffic</td>\n        <td>&nbsp;".format(mitigations))
        t1537html.write("Implement network-based filtering restrictions to prohibit data transfers to untrusted VPCs.{}&nbsp;".format(insert))
        t1537html.write("Password Policies</td>\n        <td>&nbsp;")
        t1537html.write("Consider rotating access keys within a certain number of days to reduce the effectiveness of stolen credentials.{}&nbsp;".format(insert))
        t1537html.write("User Account Management</td>\n        <td>&nbsp;")
        t1537html.write("Limit user account and IAM policies to the least privileges required. Consider using temporary credentials for accounts that are only valid for a certain period of time to reduce the effectiveness of compromised accounts.{}".format(footer))
  # Impact
    with open(sd+"t1531.html", "w") as t1531html:
        # descriptions
        t1531html.write("{}Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts.</li>\n        <li>".format(header))
        t1531html.write("Adversaries may also subsequently log off and/or reboot boxes to set malicious changes into place.")
        # indicator regex assignments
        t1531html.write("{}Events IDs: 4723, 4724, 4726, 4740".format(iocs))
        # details
        t1531html.write("{}T1531</td>\n        <td>&nbsp;".format(headings)) # id
        t1531html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1531html.write("Impact</td>\n        <td>&nbsp;") # tactics
        t1531html.write("-") # sub-techniques
        # related techniques
        t1531html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1531html.write("-")
        # mitigations
        t1531html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1531html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1485.html", "w") as t1485html:
        # descriptions
        t1485html.write("{}Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives.</li>\n        <li>".format(header))
        t1485html.write("Common operating system file deletion commands such as del and rm often only remove pointers to files without wiping the contents of the files themselves, making the files recoverable by proper forensic methodology. This behavior is distinct from Disk Content Wipe and Disk Structure Wipe because individual files are destroyed rather than sections of a storage disk or the disk's logical structure.</li>\n        <li>")
        t1485html.write("Adversaries may attempt to overwrite files and directories with randomly generated data to make it irrecoverable. In some cases politically oriented image files have been used to overwrite data.</li>\n        <li>")
        t1485html.write("To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware designed for destroying data may have worm-like features to propagate across a network by leveraging additional techniques like Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares.")
        # indicator regex assignments
        t1485html.write("{}del</li>\n        <li>".format(iocs))
        t1485html.write("rm</li>\n        <li>")
        t1485html.write("/delete</li>\n        <li>")
        t1485html.write("sdelete")
        # details
        t1485html.write("{}T1485</td>\n        <td>&nbsp;".format(headings)) # id
        t1485html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1485html.write("Impact</td>\n        <td>&nbsp;") # tactics
        t1485html.write("-") # sub-techniques
        # related techniques
        t1485html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1561 target=\"_blank\"\">&nbsp;T1561</a></td>\n        <td>&nbsp;".format(related))
        t1485html.write("Disk Wipe: Disk Content Wipe")
        t1485html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1561 target=\"_blank\"\">&nbsp;T1561</a></td>\n        <td>&nbsp;".format(insert))
        t1485html.write("Disk Wipe: Disk Structure Wipe")
        t1485html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1078 target=\"_blank\"\">&nbsp;T1078</a></td>\n        <td>&nbsp;".format(insert))
        t1485html.write("Valid Accounts")
        t1485html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1003 target=\"_blank\"\">&nbsp;T1003</a></td>\n        <td>&nbsp;".format(insert))
        t1485html.write("OS Credential Dumping")
        t1485html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1021 target=\"_blank\"\">&nbsp;T1021</a></td>\n        <td>&nbsp;".format(insert))
        t1485html.write("Remote Services: SMB/Windows Admin Shares")
        # mitigations
        t1485html.write("{}Data Backup</td>\n        <td>&nbsp;".format(mitigations))
        t1485html.write("Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery.{}".format(footer))
    with open(sd+"t1486.html", "w") as t1486html:
        # descriptions
        t1486html.write("{}Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key.</li>\n        <li>".format(header))
        t1486html.write("This may be done in order to extract monetary compensation from a victim in exchange for decryption or a decryption key (ransomware) or to render data permanently inaccessible in cases where the key is not saved or transmitted.</li>\n        <li>")
        t1486html.write("In the case of ransomware, it is typical that common user files like Office documents, PDFs, images, videos, audio, text, and source code files will be encrypted. In some cases, adversaries may encrypt critical system files, disk partitions, and the MBR.</li>\n        <li>")
        t1486html.write("To maximize impact on the target organization, malware designed for encrypting data may have worm-like features to propagate across a network by leveraging other attack techniques like Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares.")
        # indicator regex assignments
        t1486html.write("{}-".format(iocs))
        # details
        t1486html.write("{}T1486</td>\n        <td>&nbsp;".format(headings)) # id
        t1486html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1486html.write("Impact</td>\n        <td>&nbsp;") # tactics
        t1486html.write("-") # sub-techniques
        # related techniques
        t1486html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1078 target=\"_blank\"\">&nbsp;T1078</a></td>\n        <td>&nbsp;".format(related))
        t1486html.write("Valid Accounts")
        t1486html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1003 target=\"_blank\"\">&nbsp;T1003</a></td>\n        <td>&nbsp;".format(insert))
        t1486html.write("OS Credential Dumping")
        t1486html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1021 target=\"_blank\"\">&nbsp;T1021</a></td>\n        <td>&nbsp;".format(insert))
        t1486html.write("Remote Services: SMB/Windows Admin Shares")
        # mitigations
        t1486html.write("{}Data Backup</td>\n        <td>&nbsp;".format(mitigations))
        t1486html.write("Consider implementing IT disaster recovery plans that contain procedures for regularly taking and testing data backups that can be used to restore organizational data.[48] Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery. Consider enabling versioning in cloud environments to maintain backup copies of storage objects.{}".format(footer))
    with open(sd+"t1565.html", "w") as t1565html:
        # descriptions
        t1565html.write("{}Adversaries may insert, delete, or manipulate data in order to manipulate external outcomes or hide activity. By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.</li>\n        <li>".format(header))
        t1565html.write("The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary.</li>\n        <li>")
        t1565html.write("For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.")
        # indicator regex assignments
        t1565html.write("{}-".format(iocs))
        # details
        t1565html.write("{}T1565</td>\n        <td>&nbsp;".format(headings)) # id
        t1565html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1565html.write("Impact</td>\n        <td>&nbsp;") # tactics
        t1565html.write("T1565.001: Stored Data Manipulation<br>&nbsp;T1565.002: Transmitted Data Manipulation<br>&nbsp;T1565.003: Runtime Data Manipulation") # sub-techniques
        # related techniques
        t1565html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1565html.write("-")
        # mitigations
        t1565html.write("{}Encrypt Sensitive Information</td>\n        <td>&nbsp;".format(mitigations))
        t1565html.write("Consider encrypting important information to reduce an adversary’s ability to perform tailored data modifications.{}&nbsp;".format(insert))
        t1565html.write("Network Segmentation</td>\n        <td>&nbsp;")
        t1565html.write("Identify critical business and system processes that may be targeted by adversaries and work to isolate and secure those systems against unauthorized access and tampering.{}&nbsp;".format(insert))
        t1565html.write("Remote Data Storage</td>\n        <td>&nbsp;")
        t1565html.write("Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and manipulate backups.{}&nbsp;".format(insert))
        t1565html.write("Restrict File and Directory Permissions</td>\n        <td>&nbsp;")
        t1565html.write("Ensure least privilege principles are applied to important information resources to reduce exposure to data manipulation risk.{}".format(footer))
    with open(sd+"t1491.html", "w") as t1491html:
        # descriptions
        t1491html.write("{}Adversaries may modify visual content available internally or externally to an enterprise network. Reasons for Defacement include delivering messaging, intimidation, or claiming (possibly false) credit for an intrusion.</li>\n        <li>".format(header))
        t1491html.write("Disturbing or offensive images may be used as a part of Defacement in order to cause user discomfort, or to pressure compliance with accompanying messages.")
        # indicator regex assignments
        t1491html.write("{}-".format(iocs))
        # details
        t1491html.write("{}T1491</td>\n        <td>&nbsp;".format(headings)) # id
        t1491html.write("Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1491html.write("Impact</td>\n        <td>&nbsp;") # tactics
        t1491html.write("T1491.001: Internal Defacement<br>&nbsp;T1491.002: External Defacement") # sub-techniques
        # related techniques
        t1491html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1491html.write("-")
        # mitigations
        t1491html.write("{}Data Backup</td>\n        <td>&nbsp;".format(mitigations))
        t1491html.write("Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery.{}".format(footer))
    with open(sd+"t1561.html", "w") as t1561html:
        # descriptions
        t1561html.write("{}Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources.</li>\n        <li>".format(header))
        t1561html.write("With direct write access to a disk, adversaries may attempt to overwrite portions of disk data. Adversaries may opt to wipe arbitrary portions of disk data and/or wipe disk structures like the master boot record (MBR). A complete wipe of all disk sectors may be attempted.</li>\n        <li>")
        t1561html.write("To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware used for wiping disks may have worm-like features to propagate across a network by leveraging additional techniques like Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares.")
        # indicator regex assignments
        t1561html.write("{}-".format(iocs))
        # details
        t1561html.write("{}T1561</td>\n        <td>&nbsp;".format(headings)) # id
        t1561html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1561html.write("Impact</td>\n        <td>&nbsp;") # tactics
        t1561html.write("T1561.001 Disk Content Wipe<br>&nbsp;T1561.002: Disk Structure Wipe") # sub-techniques
        # related techniques
        t1561html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1078 target=\"_blank\"\">&nbsp;T1078</a></td>\n        <td>&nbsp;".format(related))
        t1561html.write("Valid Accounts")
        t1561html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1003 target=\"_blank\"\">&nbsp;T1003</a></td>\n        <td>&nbsp;".format(insert))
        t1561html.write("OS Credential Dumping")
        t1561html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1021 target=\"_blank\"\">&nbsp;T1021</a></td>\n        <td>&nbsp;".format(insert))
        t1561html.write("Remote Services: SMB/Windows Admin Shares")
        t1561html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1485 target=\"_blank\"\">&nbsp;T1485</a></td>\n        <td>&nbsp;".format(insert))
        t1561html.write("Data Destruction")
        # mitigations
        t1561html.write("{}Data Backup</td>\n        <td>&nbsp;".format(mitigations))
        t1561html.write("Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data.[2] Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery.{}".format(footer))
    with open(sd+"t1499.html", "w") as t1499html:
        # descriptions
        t1499html.write("{}Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Endpoint DoS can be performed by exhausting the system resources those services are hosted on or exploiting the system to cause a persistent crash condition.</li>\n        <li>".format(header))
        t1499html.write("Example services include websites, email services, DNS, and web-based applications. Adversaries have been observed conducting DoS attacks for political purposes and to support other malicious activities, including distraction, hacktivism, and extortion.</li>\n        <li>")
        t1499html.write("An Endpoint DoS denies the availability of a service without saturating the network used to provide access to the service. Adversaries can target various layers of the application stack that is hosted on the system used to provide the service.</li>\n        <li>")
        t1499html.write("These layers include the Operating Systems (OS), server applications such as web servers, DNS servers, databases, and the (typically web-based) applications that sit on top of them.</li>\n        <li>")
        t1499html.write("Attacking each layer requires different techniques that take advantage of bottlenecks that are unique to the respective components.</li>\n        <li>")
        t1499html.write("A DoS attack may be generated by a single system or multiple systems spread across the internet, which is commonly referred to as a distributed DoS (DDoS). To perform DoS attacks against endpoint resources, several aspects apply to multiple methods, including IP address spoofing and botnets.\n        <li>Adversaries may use the original IP address of an attacking system, or spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection.</li>\n        <li>")
        t1499html.write("This can increase the difficulty defenders have in defending against the attack by reducing or eliminating the effectiveness of filtering by the source address on network defense devices.</li>\n        <li>")
        t1499html.write("Botnets are commonly used to conduct DDoS attacks against networks and services. Large botnets can generate a significant amount of traffic from systems spread across the global internet.</li>\n        <li>")
        t1499html.write("Adversaries may have the resources to build out and control their own botnet infrastructure or may rent time on an existing botnet to conduct an attack.</li>\n        <li>")
        t1499html.write("In some of the worst cases for DDoS, so many systems are used to generate requests that each one only needs to send out a small amount of traffic to produce enough volume to exhaust the target's resources.</li>\n        <li>")
        t1499html.write("In such circumstances, distinguishing DDoS traffic from legitimate clients becomes exceedingly difficult. Botnets have been used in some of the most high-profile DDoS attacks, such as the 2012 series of incidents that targeted major US banks.</li>\n        <li>")
        t1499html.write("In cases where traffic manipulation is used, there may be points in the the global network (such as high traffic gateway routers) where packets can be altered and cause legitimate clients to execute code that directs network packets toward a target in high volume.</li>\n        <li>")
        t1499html.write("This type of capability was previously used for the purposes of web censorship where client HTTP traffic was modified to include a reference to JavaScript that generated the DDoS code to overwhelm target web servers.\n        <li>For attacks attempting to saturate the providing network, see Network Denial of Service.")
        # indicator regex assignments
        t1499html.write("{}-".format(iocs))
        # details
        t1499html.write("{}T1499</td>\n        <td>&nbsp;".format(headings)) # id
        t1499html.write("Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1499html.write("Impact</td>\n        <td>&nbsp;") # tactics
        t1499html.write("T1499.001: OS Exhaustion Flood<br>&nbsp; T1499.002: Service Exhaustion Flood<br>&nbsp; T1499.003: Application Exhaustion Flood<br>&nbsp; T1499.004: Application or System Exploitation") # sub-techniques
        # related techniques
        t1499html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1498 target=\"_blank\"\">&nbsp;T1498</a></td>\n        <td>&nbsp;".format(related))
        t1499html.write("Network Denial of Service")
        # mitigations
        t1499html.write("{}Filter Network Traffic</td>\n        <td>&nbsp;".format(mitigations))
        t1499html.write("Leverage services provided by Content Delivery Networks (CDN) or providers specializing in DoS mitigations to filter traffic upstream from services. Filter boundary traffic by blocking source addresses sourcing the attack, blocking ports that are being targeted, or blocking protocols being used for transport. To defend against SYN floods, enable SYN Cookies.{}".format(footer))
    with open(sd+"t1495.html", "w") as t1495html:
        # descriptions
        t1495html.write("{}Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot.</li>\n        <li>".format(header))
        t1495html.write("Firmware is software that is loaded and executed from non-volatile memory on hardware devices in order to initialize and manage device functionality.</li>\n        <li>")
        t1495html.write("These devices could include the motherboard, hard drive, or video cards.")
        # indicator regex assignments
        t1495html.write("{}-".format(iocs))
        # details
        t1495html.write("{}T1495</td>\n        <td>&nbsp;".format(headings)) # id
        t1495html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1495html.write("Impact</td>\n        <td>&nbsp;") # tactics
        t1495html.write("-") # sub-techniques
        # related techniques
        t1495html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t0000 target=\"_blank\"\">&nbsp;T0000</a></td>\n        <td>&nbsp;".format(related))
        t1495html.write("-")
        # mitigations
        t1495html.write("{}Boot Integrity</td>\n        <td>&nbsp;".format(mitigations))
        t1495html.write("Check the integrity of the existing BIOS and device firmware to determine if it is vulnerable to modification.{}&nbsp;".format(insert))
        t1495html.write("Privileged Account Management</td>\n        <td>&nbsp;")
        t1495html.write("Prevent adversary access to privileged accounts or access necessary to replace system firmware.{}&nbsp;".format(insert))
        t1495html.write("Update Software</td>\n        <td>&nbsp;")
        t1495html.write("Patch the BIOS and other firmware as necessary to prevent successful use of known vulnerabilities.{}".format(footer))
    with open(sd+"t1490.html", "w") as t1490html:
        # descriptions
        t1490html.write("{}Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.</li>\n        <li>".format(header))
        t1490html.write("Operating systems may contain features that can help fix corrupted systems, such as a backup catalog, volume shadow copies, and automatic repair features.</li>\n        <li>")
        t1490html.write("Adversaries may disable or delete system recovery features to augment the effects of Data Destruction and Data Encrypted for Impact.")
        # indicator regex assignments
        t1490html.write("{}vssadmin</li>\n        <li>".format(iocs))
        t1490html.write("wbadmin</li>\n        <li>")
        t1490html.write("shadows</li>\n        <li>")
        t1490html.write("shadowcopy")
        # details
        t1490html.write("{}T1490</td>\n        <td>&nbsp;".format(headings)) # id
        t1490html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1490html.write("Impact</td>\n        <td>&nbsp;") # tactics
        t1490html.write("-") # sub-techniques
        # related techniques
        t1490html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1485 target=\"_blank\"\">&nbsp;T1485</a></td>\n        <td>&nbsp;".format(related))
        t1490html.write("Data Destruction")
        t1490html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1486 target=\"_blank\"\">&nbsp;T1486</a></td>\n        <td>&nbsp;".format(insert))
        t1490html.write("Data Encrypted for Impact")
        t1490html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1047 target=\"_blank\"\">&nbsp;T1047</a></td>\n        <td>&nbsp;".format(insert))
        t1490html.write("Windows Management Instrumentation")
        # mitigations
        t1490html.write("{}Data Backup</td>\n        <td>&nbsp;".format(mitigations))
        t1490html.write("Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery.{}&nbsp;".format(insert))
        t1490html.write("Operating System Configuration</td>\n        <td>&nbsp;")
        t1490html.write("Consider technical controls to prevent the disabling of services or deletion of files involved in system recovery.{}".format(footer))
    with open(sd+"t1498.html", "w") as t1498html:
        t1498html.write("Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users.<li>Network DoS can be performed by exhausting the network bandwidth services rely on. Example resources include specific websites, email services, DNS, and web-based applications.<li>Adversaries have been observed conducting network DoS attacks for political purposes and to support other malicious activities, including distraction, hacktivism, and extortion.</li>\n        <li>")
        t1498html.write("A Network DoS will occur when the bandwidth capacity of the network connection to a system is exhausted due to the volume of malicious traffic directed at the resource or the network connections and network devices the resource relies on.<li>For example, an adversary may send 10Gbps of traffic to a server that is hosted by a network with a 1Gbps connection to the internet.<li>This traffic can be generated by a single system or multiple systems spread across the internet, which is commonly referred to as a distributed DoS (DDoS).</li>\n        <li>")
        t1498html.write("To perform Network DoS attacks several aspects apply to multiple methods, including IP address spoofing, and botnets.</li>\n        <li>")
        t1498html.write("Adversaries may use the original IP address of an attacking system, or spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection.<li>This can increase the difficulty defenders have in defending against the attack by reducing or eliminating the effectiveness of filtering by the source address on network defense devices.</li>\n        <li>")
        t1498html.write("For DoS attacks targeting the hosting system directly, see Endpoint Denial of Service.")
        # indicator regex assignments
        t1498html.write("{}-".format(iocs))
        # details
        t1498html.write("{}T1499</td>\n        <td>&nbsp;".format(headings)) # id
        t1498html.write("Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>&nbsp;") # platforms
        t1498html.write("Impact</td>\n        <td>&nbsp;") # tactics
        t1498html.write("T1498.001: Direct Network Flood<br>&nbsp; T1498.002: Reflection Amplification") # sub-techniques
        # related techniques
        t1498html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1499 target=\"_blank\"\">&nbsp;T1499</a></td>\n        <td>&nbsp;".format(related))
        t1498html.write("Endpoint Denial of Service")
        # mitigations
        t1498html.write("{}Filter Network Traffic</td>\n        <td>&nbsp;".format(mitigations))
        t1498html.write("When flood volumes exceed the capacity of the network connection being targeted, it is typically necessary to intercept the incoming traffic upstream to filter out the attack traffic from the legitimate traffic. Such defenses can be provided by the hosting Internet Service Provider (ISP) or by a 3rd party such as a Content Delivery Network (CDN) or providers specializing in DoS mitigations.<br>&nbsp;Depending on flood volume, on-premises filtering may be possible by blocking source addresses sourcing the attack, blocking ports that are being targeted, or blocking protocols being used for transport.<br>&nbsp;As immediate response may require rapid engagement of 3rd parties, analyze the risk associated to critical resources being affected by Network DoS attacks and create a disaster recovery plan/business continuity plan to respond to incidents.{}".format(footer))
    with open(sd+"t1496.html", "w") as t1496html:
        # descriptions
        t1496html.write("{}Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems which may impact system and/or hosted service availability.</li>\n        <li>".format(header))
        t1496html.write("One common purpose for Resource Hijacking is to validate transactions of cryptocurrency networks and earn virtual currency. Adversaries may consume enough system resources to negatively impact and/or cause affected machines to become unresponsive.</li>\n        <li>")
        t1496html.write("Servers and cloud-based systems are common targets because of the high potential for available resources, but user endpoint systems may also be compromised and used for Resource Hijacking and cryptocurrency mining.")
        # indicator regex assignments
        t1496html.write("{}-".format(iocs))
        # details
        t1496html.write("{}T1496</td>\n        <td>&nbsp;".format(headings)) # id
        t1496html.write("Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>&nbsp;") # platforms
        t1496html.write("Impact</td>\n        <td>&nbsp;") # tactics
        t1496html.write("-") # sub-techniques
        # related techniques
        t1496html.write("{}&nbsp;-</a></td>\n        <td>&nbsp;".format(related))
        t1496html.write("-")
        # mitigations
        t1496html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1496html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
    with open(sd+"t1489.html", "w") as t1489html:
        # descriptions
        t1489html.write("{}Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment.</li>\n        <li>".format(header))
        t1489html.write("Adversaries may accomplish this by disabling individual services of high importance to an organization, such as MSExchangeIS, which will make Exchange content inaccessible. In some cases, adversaries may stop or disable many or all services to render systems unusable.</li>\n        <li>")
        t1489html.write("Services may not allow for modification of their data stores while running. Adversaries may stop services in order to conduct Data Destruction or Data Encrypted for Impact on the data stores of services like Exchange and SQL Server.")
        # indicator regex assignments
        t1489html.write("{}services.exe</li>\n        <li>".format(iocs))
        t1489html.write("sc.exe</li>\n        <li>")
        t1489html.write("kill</li>\n        <li>")
        t1489html.write("MSExchangeIs</li>\n        <li>")
        t1489html.write("ChangeServiceConfigW</li>\n        <li>")
        t1489html.write("net stop</li>\n        <li>")
        t1489html.write("net1 stop")
        # details
        t1489html.write("{}T1489</td>\n        <td>&nbsp;".format(headings)) # id
        t1489html.write("Windows</td>\n        <td>&nbsp;") # platforms
        t1489html.write("Impact</td>\n        <td>&nbsp;") # tactics
        t1489html.write("-") # sub-techniques
        # related techniques
        t1489html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1485 target=\"_blank\"\">&nbsp;T1485</a></td>\n        <td>&nbsp;".format(related))
        t1489html.write("Data Destruction")
        t1489html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1486 target=\"_blank\"\">&nbsp;T1486</a></td>\n        <td>&nbsp;".format(insert))
        t1489html.write("Data Encrypted for Impact")
        # mitigations
        t1489html.write("{}Network Segmentation</td>\n        <td>&nbsp;".format(mitigations))
        t1489html.write("Operate intrusion detection, analysis, and response systems on a separate network from the production environment to lessen the chances that an adversary can see and interfere with critical response functions.{}&nbsp;".format(insert))
        t1489html.write("Restrict File and Directory Permissions</td>\n        <td>&nbsp;")
        t1489html.write("Ensure proper process and file permissions are in place to inhibit adversaries from disabling or interfering with critical services.{}&nbsp;".format(insert))
        t1489html.write("Restrict Registry Permissions</td>\n        <td>&nbsp;")
        t1489html.write("Ensure proper registry permissions are in place to inhibit adversaries from disabling or interfering with critical services.{}&nbsp;".format(insert))
        t1489html.write("User Account Management</td>\n        <td>&nbsp;")
        t1489html.write("Limit privileges of user accounts and groups so that only authorized administrators can interact with service changes and service configurations.{}".format(footer))
    with open(sd+"t1529.html", "w") as t1529html:
        # descriptions
        t1529html.write("{}Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine.</li>\n        <li>".format(header))
        t1529html.write("In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer. Shutting down or rebooting systems may disrupt access to computer resources for legitimate users.</li>\n        <li>")
        t1529html.write("Adversaries may attempt to shutdown/reboot a system after impacting it in other ways, such as Disk Structure Wipe or Inhibit System Recovery, to hasten the intended effects on system availability.")
        # indicator regex assignments
        t1529html.write("{}Event IDs: 1074, 6006</li>\n        <li>".format(iocs))
        t1529html.write("shutdown</li>\n        <li>")
        t1529html.write("halt")
        # details
        t1529html.write("{}T1529</td>\n        <td>&nbsp;".format(headings)) # id
        t1529html.write("Windows, macOS, Linux</td>\n        <td>&nbsp;") # platforms
        t1529html.write("Impact</td>\n        <td>&nbsp;") # tactics
        t1529html.write("-")
        # related techniques
        t1529html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1561 target=\"_blank\"\">&nbsp;T1561</a></td>\n        <td>&nbsp;".format(related))
        t1529html.write("Disk Structure Wipe")
        t1529html.write("{}<a href=\"http://127.0.0.1:8000/en-US/app/elrond/t1490 target=\"_blank\"\">&nbsp;T1490</a></td>\n        <td>&nbsp;".format(insert))
        t1529html.write("Inhibit System Recovery")
        # mitigations
        t1529html.write("{}-</td>\n        <td>&nbsp;".format(mitigations))
        t1529html.write("This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(footer))
