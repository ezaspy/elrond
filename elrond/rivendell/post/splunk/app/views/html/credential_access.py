#!/usr/bin/env python3 -tt


def create_credential_access_html(
    sd, header, headings, iocs, related, insert, mitigations, footer
):
    with open(sd + "t1110.html", "w") as t1110html:
        # description
        t1110html.write(
            "{}Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism.</li>\n        <liv>Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes.".format(
                header
            )
        )
        # information
        t1110html.write("{}T1110</td>\n        <td>".format(headings))  # id
        t1110html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>"
        )  # platforms
        t1110html.write("Credential Access</td>\n        <td>")  # tactics
        t1110html.write(
            "T1110.001: Password Guessing<br>T1110.002: Password Cracking<br>T1110.003: Password Spraying<br>T1110.004: Credentials Stuffing"
        )  # sub-techniques
        # indicator regex assignments
        t1110html.write(
            "{}Ports: 139, 22, 23, 389, 88, 1433, 1521, 3306, 445, 80, 443, </li>\n        <li>".format(
                iocs
            )
        )
        t1110html.write("Event IDs: 4625, 4648, 4771</li>")
        # related techniques
        t1110html.write("{}-</a></td>\n        <td>".format(related))
        t1110html.write("-")
        # mitigations
        t1110html.write("{}Account Use Policies</td>\n        <td>".format(mitigations))
        t1110html.write(
            "Set account lockout policies after a certain number of failed login attempts to prevent passwords from being guessed. Too strict a policy may create a denial of service condition and render environments un-usable, with all accounts used in the brute force being locked-out.{}".format(
                insert
            )
        )
        t1110html.write("Multi-factor Authentication</td>\n        <td>")
        t1110html.write(
            "Use multi-factor authentication. Where possible, also enable multi-factor authentication on externally facing services.{}".format(
                insert
            )
        )
        t1110html.write("Password Policies</td>\n        <td>")
        t1110html.write(
            "Refer to NIST guidelines when creating password policies.{}".format(insert)
        )
        t1110html.write("User Account Management</td>\n        <td>")
        t1110html.write(
            "Proactively reset accounts that are known to be part of breached credentials either immediately, or after detecting bruteforce attempts.{}".format(
                footer
            )
        )
    with open(sd + "t1555.html", "w") as t1555html:
        # description
        t1555html.write(
            "{}Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials.<br>".format(
                header
            )
        )
        t1555html.write(
            "There are also specific applications that store passwords to make it easier for users manage and maintain. Once credentials are obtained, they can be used to perform lateral movement and access restricted information."
        )
        # information
        t1555html.write("{}T1555</td>\n        <td>".format(headings))  # id
        t1555html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1555html.write("Credential Access</td>\n        <td>")  # tactics
        t1555html.write(
            "T1555.001: Keychain<br>T1555.002: Securityd Memory<br>T1555.003: Credentials from Web Browsers<br>T1555.004: Windows Credential Manager<br>T1555.005: Password Managers"
        )  # sub-techniques
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
        t1555html.write("credentials</li>")
        # related techniques
        t1555html.write("{}-</a></td>\n        <td>".format(related))
        t1555html.write("-")
        # mitigations
        t1555html.write("{}Password Policies</td>\n        <td>".format(mitigations))
        t1555html.write(
            "The password for the user's login keychain can be changed from the user's login password. This increases the complexity for an adversary because they need to know an additional password. Organizations may consider weighing the risk of storing credentials in password stores and web browsers. If system, software, or web browser credential disclosure is a significant concern, technical controls, policy, and user training may be used to prevent storage of credentials in improper locations.{}".format(
                footer
            )
        )
    with open(sd + "t1212.html", "w") as t1212html:
        # description
        t1212html.write(
            "{}Adversaries may exploit software vulnerabilities in an attempt to collect credentials.<br>".format(
                header
            )
        )
        t1212html.write(
            "Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.<br>"
        )
        t1212html.write(
            "Credentialing and authentication mechanisms may be targeted for exploitation by adversaries as a means to gain access to useful credentials or circumvent the process to gain access to systems.<br>"
        )
        t1212html.write(
            "One example of this is MS14-068, which targets Kerberos and can be used to forge Kerberos tickets using domain user permissions.<br>"
        )
        t1212html.write(
            "Exploitation for credential access may also result in Privilege Escalation depending on the process targeted or credentials obtained."
        )
        # information
        t1212html.write("{}T1212</td>\n        <td>".format(headings))  # id
        t1212html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1212html.write("Credential Access</td>\n        <td>")  # tactics
        t1212html.write("-")  # sub-techniques
        # indicator regex assignments
        t1212html.write("{}-".format(iocs))
        # related techniques
        t1212html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1046 target="_blank"">T1046</a></td>\n        <td>'.format(
                related
            )
        )
        t1212html.write("Network Service Scanning")
        t1212html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1068 target="_blank"">T1068</a></td>\n        <td>'.format(
                insert
            )
        )
        t1212html.write("Exploitation for Privilege Escalation")
        # mitigations
        t1212html.write(
            "{}Application Isolation and Sandboxing</td>\n        <td>".format(
                mitigations
            )
        )
        t1212html.write(
            "Make it difficult for adversaries to advance their operation through exploitation of undiscovered or unpatched vulnerabilities by using sandboxing. Other types of virtualization and application microsegmentation may also mitigate the impact of some types of exploitation. Risks of additional exploits and weaknesses in these systems may still exist.{}".format(
                insert
            )
        )
        t1212html.write("Exploit Protection</td>\n        <td>")
        t1212html.write(
            "Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility and may not work for software targeted for defense evasion.{}".format(
                insert
            )
        )
        t1212html.write("Threat Intelligence Program</td>\n        <td>")
        # t1212html.write("Develop a robust cyber threat intelligence capability to determine what types and levels of threat may use software exploits and 0-days against a particular organization.{}".format(insert))
        t1212html.write("Update Software</td>\n        <td>")
        t1212html.write(
            "Update software regularly by employing patch management for internal enterprise endpoints and servers.{}".format(
                footer
            )
        )
    with open(sd + "t1187.html", "w") as t1187html:
        # description
        t1187html.write(
            "{}Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept.<br>".format(
                header
            )
        )
        t1187html.write(
            "The Server Message Block (SMB) protocol is commonly used in Windows networks for authentication and communication between systems for access to resources and file sharing.<br>"
        )
        t1187html.write(
            "When a Windows system attempts to connect to an SMB resource it will automatically attempt to authenticate and send credential information for the current user to the remote system.<br>"
        )
        t1187html.write(
            "This behavior is typical in enterprise environments so that users do not need to enter credentials to access network resources.<br>"
        )
        t1187html.write(
            "Web Distributed Authoring and Versioning (WebDAV) is also typically used by Windows systems as a backup protocol when SMB is blocked or fails. WebDAV is an extension of HTTP and will typically operate over TCP ports 80 and 443.<br>"
        )
        t1187html.write(
            "Adversaries may take advantage of this behavior to gain access to user account hashes through forced SMB/WebDAV authentication.<br>"
        )
        t1187html.write(
            "An adversary can send an attachment to a user through spearphishing that contains a resource link to an external server controlled by the adversary (i.e. Template Injection), or place a specially crafted file on navigation path for privileged accounts (e.g. .SCF file placed on desktop) or on a publicly accessible share to be accessed by victim(s).<br>"
        )
        t1187html.write(
            "When the user's system accesses the untrusted resource it will attempt authentication and send information, including the user's hashed credentials, over SMB to the adversary controlled server.  With access to the credential hash, an adversary can perform off-line Brute Force cracking to gain access to plaintext credentials."
        )
        # information
        t1187html.write("{}T1187</td>\n        <td>".format(headings))  # id
        t1187html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1187html.write("Credential Access</td>\n        <td>")  # tactics
        t1187html.write("-")  # sub-techniques
        # indicator regex assignments
        t1187html.write("{}Ports: 137".format(iocs))
        # related techniques
        t1187html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1221 target="_blank"">T1221</a></td>\n        <td>'.format(
                related
            )
        )
        t1187html.write("Template Injection")
        t1187html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1110 target="_blank"">T1110</a></td>\n        <td>'.format(
                insert
            )
        )
        t1187html.write("Brute Force")
        # mitigations
        t1187html.write(
            "{}Filter Network Traffic</td>\n        <td>".format(mitigations)
        )
        t1187html.write(
            "Block SMB traffic from exiting an enterprise network with egress filtering or by blocking TCP ports 139, 445 and UDP port 137. Filter or block WebDAV protocol traffic from exiting the network. If access to external resources over SMB and WebDAV is necessary, then traffic should be tightly limited with allowlisting.{}".format(
                insert
            )
        )
        t1187html.write("Password Policies</td>\n        <td>")
        t1187html.write(
            "Use strong passwords to increase the difficulty of credential hashes from being cracked if they are obtained.{}".format(
                footer
            )
        )
    with open(sd + "t1606.html", "w") as t1606html:
        # description
        t1606html.write(
            "{}Adversaries may forge credential materials that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies, tokens, or other materials to authenticate and authorize user access.<br>".format(
                header
            )
        )
        t1606html.write(
            "Adversaries may generate these credential materials in order to gain access to web resources. This differs from Steal Web Session Cookie, Steal Application Access Token, and other similar behaviors in that the credentials are new and forged by the adversary, rather than stolen or intercepted from legitimate users. The generation of web credentials often requires secret values, such as passwords, Private Keys, or other cryptographic seed values.<br>"
        )
        t1606html.write(
            "Once forged, adversaries may use these web credentials to access resources (ex: Use Alternate Authentication Material), which may bypass multi-factor and other authentication protection mechanisms."
        )
        # information
        t1606html.write("{}T1606</td>\n        <td>".format(headings))  # id
        t1606html.write(
            "Windows, macOS, Linux, Azure, Google Workspace, Office 365, SaaS</td>\n        <td>"
        )  # platforms
        t1606html.write("Credential Access</td>\n        <td>")  # tactics
        t1606html.write(
            "T1606.001: Web Cookies<br>T1606.002: SAML Tokens"
        )  # sub-techniques
        # indicator regex assignments
        t1606html.write("{}NotOnOrAfter</li>\n        <li>".format(iocs))
        t1606html.write("AccessTokenLifetime</li>\n        <li>")
        t1606html.write("LifetimeTokenPolicy</li>")
        # related techniques
        t1606html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1539 target="_blank"">T1539</a></td>\n        <td>'.format(
                related
            )
        )
        t1606html.write("Steal Web Session Cookie")
        t1606html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1528 target="_blank"">T1528</a></td>\n        <td>'.format(
                insert
            )
        )
        t1606html.write("Steal Application Access Token")
        t1606html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1552/004 target="_blank"">T1552.004</a></td>\n        <td>'.format(
                related
            )
        )
        t1606html.write("Private Keys")
        t1606html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1550 target="_blank"">T1550</a></td>\n        <td>'.format(
                insert
            )
        )
        t1606html.write("Use Alternate Authentication Material")
        # mitigations
        t1606html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1606html.write(
            "Administrators should perform an audit of all access lists and the permissions they have been granted to access web applications and services. This should be done extensively on all resources in order to establish a baseline, followed up on with periodic audits of new or updated resources. Suspicious accounts/credentials should be investigated and removed. Enable advanced auditing on ADFS. Check the success and failure audit options in the ADFS Management snap-in. Enable Audit Application Generated events on the AD FS farm via Group Policy Object.{}".format(
                insert
            )
        )
        t1606html.write("Privileged Account Management</td>\n        <td>")
        t1606html.write(
            "Restrict permissions and access to the AD FS server to only originate from privileged access workstations.{}".format(
                insert
            )
        )
        t1606html.write("Software Configuration</td>\n        <td>")
        t1606html.write(
            "Configure browsers/applications to regularly delete persistent web credentials (such as cookies).{}".format(
                insert
            )
        )
        t1606html.write("User Account Management</td>\n        <td>")
        t1606html.write(
            "Ensure that user accounts with administrative rights follow best practices, including use of privileged access workstations, Just in Time/Just Enough Administration (JIT/JEA), and strong authentication. Reduce the number of users that are members of highly privileged Directory Roles.{}".format(
                footer
            )
        )
    with open(sd + "t1056.html", "w") as t1056html:
        # description
        t1056html.write(
            "{}Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes.<br>".format(
                header
            )
        )
        t1056html.write(
            "Input capture mechanisms may be transparent to the user (e.g. Credential API Hooking) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. Web Portal Capture)."
        )
        # information
        t1056html.write("{}T1056</td>\n        <td>".format(headings))  # id
        t1056html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1056html.write("Credential Access</td>\n        <td>")  # tactics
        t1056html.write(
            "T1056.001: Keylogging<br>T1056.002: GUI Input Capture<br>T1056.003: Web Portal Capture<br>T1056.004: Credential API Hooking"
        )  # sub-techniques
        # indicator regex assignments
        t1056html.write("{}DISPLAY</li>\n        <li>".format(iocs))
        t1056html.write("HID</li>\n        <li>")
        t1056html.write("PCI</li>\n        <li>")
        t1056html.write("UMB</li>\n        <li>")
        t1056html.write("FDC</li>\n        <li>")
        t1056html.write("SCSI</li>\n        <li>")
        t1056html.write("STORAGE</li>\n        <li>")
        t1056html.write("USB</li>\n        <li>")
        t1056html.write("WpdBusEnumRoot</li>")
        # related techniques
        t1056html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1059 target="_blank"">T1059</a></td>\n        <td>'.format(
                related
            )
        )
        t1056html.write("Command and Scripting Interpreter")
        # mitigations
        t1056html.write("{}-</td>\n        <td>".format(mitigations))
        t1056html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1557.html", "w") as t1557html:
        # description
        t1557html.write(
            "{}Adversaries may attempt to position themselves between two or more networked devices using a advesary-in-the-middle (AiTM) technique to support follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation.<br>".format(
                header
            )
        )
        t1557html.write(
            "By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.<br>"
        )
        t1557html.write(
            "Adversaries may leverage the AiTM position to attempt to modify traffic, such as in Transmitted Data Manipulation. Adversaries can also stop traffic from flowing to the appropriate destination, causing denial of service."
        )
        # information
        t1557html.write("{}T1557</td>\n        <td>".format(headings))  # id
        t1557html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1557html.write("Credential Access, Collection</td>\n        <td>")  # tactics
        t1557html.write(
            "T1557.001: LLMNR/NBT-NS Poisoning and SMB Relay<br>T1557.002: ARP Cache Poisoning<br>T1557.003: DHCP Spoofing"
        )  # sub-techniques
        # indicator regex assignments
        t1557html.write("{}Ports: 137, 5355</li>\n        <li>".format(iocs))
        t1557html.write(
            "Event IDs: 1020, 1063, 1341, 1342, 4657, 7045</li>\n        <li>"
        )
        t1557html.write("EnableMulticast</li>\n        <li>")
        t1557html.write("NT/DNSClient</li>\n        <li>")
        t1557html.write("DISCOVER</li>\n        <li>")
        t1557html.write("OFFER</li>\n        <li>")
        t1557html.write("REQUEST</li>")
        # related techniques
        t1557html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1040 target="_blank"">T1040</a></td>\n        <td>'.format(
                related
            )
        )
        t1557html.write("Network Sniffing")
        t1557html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1565 target="_blank"">T1565</a></td>\n        <td>'.format(
                insert
            )
        )
        t1557html.write("Data Manipulation: Transmitted Data Manipulation")
        # mitigations
        t1557html.write(
            "{}Disable or Remove Feature or Program</td>\n        <td>".format(
                mitigations
            )
        )
        t1557html.write(
            "Disable legacy network protocols that may be used for MiTM if applicable and they are not needed within an environment.{}".format(
                insert
            )
        )
        t1557html.write("Encrypt Sensitive Information</td>\n        <td>")
        t1557html.write(
            "Ensure that all wired and/or wireless traffic is encrypted appropriately. Use best practices for authentication protocols, such as Kerberos, and ensure web traffic that may contain credentials is protected by SSL/TLS.{}".format(
                insert
            )
        )
        t1557html.write("Filter Network Traffic</td>\n        <td>")
        t1557html.write(
            "Use network appliances and host-based security software to block network traffic that is not necessary within the environment, such as legacy protocols that may be leveraged for MiTM.{}".format(
                insert
            )
        )
        t1557html.write("Limit Access to Resource Over Network</td>\n        <td>")
        t1557html.write(
            "Limit access to network infrastructure and resources that can be used to reshape traffic or otherwise produce MiTM conditions.{}".format(
                insert
            )
        )
        t1557html.write("Network Intrusion Prevention</td>\n        <td>")
        t1557html.write(
            "Network intrusion detection and prevention systems that can identify traffic patterns indicative of MiTM activity can be used to mitigate activity at the network level.{}".format(
                insert
            )
        )
        t1557html.write("Network Segmentation</td>\n        <td>")
        t1557html.write(
            "Network segmentation can be used to isolate infrastructure components that do not require broad network access. This may mitigate, or at least alleviate, the scope of MiTM activity.{}".format(
                insert
            )
        )
        t1557html.write("User Training</td>\n        <td>")
        t1557html.write(
            "Train users to be suspicious about certificate errors. Adversaries may use their own certificates in an attempt to MiTM HTTPS traffic. Certificate errors may arise when the application’s certificate does not match the one expected by the host.{}".format(
                footer
            )
        )
    with open(sd + "t1040.html", "w") as t1040html:
        # description
        t1040html.write(
            "{}Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection.<br>".format(
                header
            )
        )
        t1040html.write(
            "An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.<br>"
        )
        t1040html.write(
            "Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as LLMNR/NBT-NS Poisoning and SMB Relay, can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.<br>"
        )
        t1040html.write(
            "Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent Lateral Movement and/or Defense Evasion activities."
        )
        # information
        t1040html.write("{}T1040</td>\n        <td>".format(headings))  # id
        t1040html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1040html.write("Credential Access, Discovery</td>\n        <td>")  # tactics
        t1040html.write("-")  # sub-techniques
        # indicator regex assignments
        t1040html.write("{}-".format(iocs))
        # related techniques
        t1040html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1557 target="_blank"">T1557</a></td>\n        <td>'.format(
                related
            )
        )
        t1040html.write("Advesary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay")
        # mitigations
        t1040html.write(
            "{}Encrypt Sensitive Information</td>\n        <td>".format(mitigations)
        )
        t1040html.write(
            "Ensure that all wired and/or wireless traffic is encrypted appropriately. Use best practices for authentication protocols, such as Kerberos, and ensure web traffic that may contain credentials is protected by SSL/TLS.{}".format(
                insert
            )
        )
        t1040html.write("Multi-factor Authentication</td>\n        <td>")
        t1040html.write(
            "Use multi-factor authentication wherever possible.{}".format(footer)
        )
    with open(sd + "t1003.html", "w") as t1003html:
        # description
        t1003html.write(
            "{}Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software.<br>".format(
                header
            )
        )
        t1003html.write(
            "Credentials can then be used to perform Lateral Movement and access restricted information.<br>"
        )
        t1003html.write(
            "Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well."
        )
        # information
        t1003html.write("{}T1003</td>\n        <td>".format(headings))  # id
        t1003html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1003html.write("Credential Access</td>\n        <td>")  # tactics
        t1003html.write(
            "T1003.001: LSASS Memory<br>T1003.002: Security Account Manager<br>T1003.003: NTDS<br>T1003.004: LSA Secrets<br>T1003.005: Cached Domain Credentials<br>T1003.006: DCSync<br>T1003.007: Proc Filesystem<br>T1003.008: /etc/passwd and /etc/shadow"
        )  # sub-techniques
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
        t1003html.write("shadow</li>")
        # related techniques
        t1003html.write("{}--</a></td>\n        <td>".format(related))
        t1003html.write("-")
        # mitigations
        t1003html.write(
            "{}Active Directory Configuration</td>\n        <td>".format(mitigations)
        )
        t1003html.write(
            'Manage the access control list for "Replicating Directory Changes" and other permissions associated with domain controller replication. Consider adding users to the "Protected Users" Active Directory security group. This can help limit the caching of users\' plaintext credentials.{}'.format(
                insert
            )
        )
        t1003html.write("Credential Access Protection</td>\n        <td>")
        t1003html.write(
            "With Windows 10, Microsoft implemented new protections called Credential Guard to protect the LSA secrets that can be used to obtain credentials through forms of credential dumping. It is not configured by default and has hardware and firmware system requirements. It also does not protect against all forms of credential dumping.{}".format(
                insert
            )
        )
        t1003html.write("Encrypt Sensitive Information</td>\n        <td>")
        t1003html.write(
            "Ensure Domain Controller backups are properly secured.{}".format(insert)
        )
        t1003html.write("Operating System Configuration</td>\n        <td>")
        t1003html.write(
            "Consider disabling or restricting NTLM. Consider disabling WDigest authentication.{}".format(
                insert
            )
        )
        t1003html.write("Password Policies</td>\n        <td>")
        t1003html.write(
            "Ensure that local administrator accounts have complex, unique passwords across all systems on the network.{}".format(
                insert
            )
        )
        t1003html.write("Privileged Account Management</td>\n        <td>")
        t1003html.write(
            "Windows: Do not put user or admin domain accounts in the local administrator groups across systems unless they are tightly controlled, as this is often equivalent to having a local administrator account with the same password on all systems. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers. Linux: Scraping the passwords from memory requires root privileges. Follow best practices in restricting access to privileged accounts to avoid hostile programs from accessing such sensitive regions of memory.{}".format(
                insert
            )
        )
        t1003html.write("Privileged Process Integrity</td>\n        <td>")
        t1003html.write(
            "On Windows 8.1 and Windows Server 2012 R2, enable Protected Process Light for LSA.{}".format(
                insert
            )
        )
        t1003html.write("User Training</td>\n        <td>")
        t1003html.write(
            "Limit credential overlap across accounts and systems by training users and administrators not to use the same password for multiple accounts.{}".format(
                footer
            )
        )
    with open(sd + "t1528.html", "w") as t1528html:
        # description
        t1528html.write(
            "{}Adversaries can steal user application access tokens as a means of acquiring credentials to access remote systems and resources. This can occur through social engineering and typically requires user action to grant access.<br>".format(
                header
            )
        )
        t1528html.write(
            "Application access tokens are used to make authorized API requests on behalf of a user and are commonly used as a way to access resources in cloud-based applications and software-as-a-service (SaaS). OAuth is one commonly implemented framework that issues tokens to users for access to systems.<br>"
        )
        t1528html.write(
            "An application desiring access to cloud-based services or protected APIs can gain entry using OAuth 2.0 through a variety of authorization protocols. An example commonly-used sequence is Microsoft's Authorization Code Grant flow. An OAuth access token enables a third-party application to interact with resources containing user data in the ways requested by the application without obtaining user credentials.<br>"
        )
        t1528html.write(
            "Adversaries can leverage OAuth authorization by constructing a malicious application designed to be granted access to resources with the target user's OAuth token. The adversary will need to complete registration of their application with the authorization server, for example Microsoft Identity Platform using Azure Portal, the Visual Studio IDE, the command-line interface, PowerShell, or REST API calls.<br>"
        )
        t1528html.write(
            "Then, they can send a link through Spearphishing Link to the target user to entice them to grant access to the application. Once the OAuth access token is granted, the application can gain potentially long-term access to features of the user account through Application Access Token.<br>"
        )
        t1528html.write(
            "Adversaries have been seen targeting Gmail, Microsoft Outlook, and Yahoo Mail users."
        )
        # information
        t1528html.write("{}T1528</td>\n        <td>".format(headings))  # id
        t1528html.write("Azure, Office 365, SaaS</td>\n        <td>")  # platforms
        t1528html.write("Credential Access</td>\n        <td>")  # tactics
        t1528html.write("-")  # sub-techniques
        # indicator regex assignments
        t1528html.write("{}-".format(iocs))
        # related techniques
        t1528html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1566 target="_blank"">T1566</a></td>\n        <td>'.format(
                related
            )
        )
        t1528html.write("Phishing: Spearphishing Link")
        t1528html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1550 target="_blank"">T1550</a></td>\n        <td>'.format(
                insert
            )
        )
        t1528html.write(
            "Use Alternate Authentication Material: Application Access Token"
        )
        # mitigations
        t1528html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1528html.write(
            "Administrators should perform an audit of all OAuth applications and the permissions they have been granted to access organizational data. This should be done extensively on all applications in order to establish a baseline, followed up on with periodic audits of new or updated applications. Suspicious applications should be investigated and removed.{}".format(
                insert
            )
        )
        t1528html.write("Restrict Web-Based Content</td>\n        <td>")
        t1528html.write(
            'Administrators can block end-user consent to OAuth applications, disabling users from authorizing third-party apps through OAuth 2.0 and forcing administrative consent for all requests. They can also block end-user registration of applications by their users, to reduce risk. A Cloud Access Security Broker can also be used to ban applications. Azure offers a couple of enterprise policy settings in the Azure Management Portal that may help: "Users -> User settings -> App registrations: Users can register applications" can be set to "no" to prevent users from registering new applications. "Enterprise applications -> User settings -> Enterprise applications: Users can consent to apps accessing company data on their behalf" can be set to "no" to prevent users from consenting to allow third-party multi-tenant applications.{}'.format(
                insert
            )
        )
        t1528html.write("User Account Management</td>\n        <td>")
        t1528html.write(
            "A Cloud Access Security Broker (CASB) can be used to set usage policies and manage user permissions on cloud applications to prevent access to application access tokens.{}".format(
                insert
            )
        )
        t1528html.write("User Training</td>\n        <td>")
        t1528html.write(
            "Users need to be trained to not authorize third-party applications they don’t recognize. The user should pay particular attention to the redirect URL: if the URL is a misspelled or convoluted sequence of words related to an expected service or SaaS application, the website is likely trying to spoof a legitimate service. Users should also be cautious about the permissions they are granting to apps. For example, offline access and access to read emails should excite higher suspicions because adversaries can utilize SaaS APIs to discover credentials and other sensitive communications.{}".format(
                footer
            )
        )
    with open(sd + "t1558.html", "w") as t1558html:
        # description
        t1558html.write(
            "{}Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket.<br>".format(
                header
            )
        )
        t1558html.write(
            'Kerberos is an authentication protocol widely used in modern Windows domain environments. In Kerberos environments, referred to as "realms", there are three basic participants: client, service, and Key Distribution Center (KDC).<br>'
        )
        t1558html.write(
            "Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated.<br>"
        )
        t1558html.write(
            "The KDC is responsible for both authentication and ticket granting. Attackers may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access."
        )
        # information
        t1558html.write("{}T1558</td>\n        <td>".format(headings))  # id
        t1558html.write("Windows</td>\n        <td>")  # platforms
        t1558html.write("Credential Access</td>\n        <td>")  # tactics
        t1558html.write(
            "T1558.001: Golden Ticket<br>T1558.002: Silver Ticket<br>T1558.003: Kerberoasting<br>T1558.004: AS-REP Roasting"
        )  # sub-techniques
        # indicator regex assignments
        t1558html.write("{}Event IDs: 4624, 4634, 4768, 4769, 4672".format(iocs))
        # related techniques
        t1558html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1550 target="_blank"">T1550</a></td>\n        <td>'.format(
                related
            )
        )
        t1558html.write("Use Alternate Authentication Material: Pass the Ticket")
        # mitigations
        t1558html.write(
            "{}Active Directory Configuration</td>\n        <td>".format(mitigations)
        )
        t1558html.write(
            "For containing the impact of a previously generated golden ticket, reset the built-in KRBTGT account password twice, which will invalidate any existing golden tickets that have been created with the KRBTGT hash and other Kerberos tickets derived from it. For each domain, change the KRBTGT account password once, force replication, and then change the password a second time. Consider rotating the KRBTGT account password every 180 days.{}".format(
                insert
            )
        )
        t1558html.write("Encrypt Sensitive Information</td>\n        <td>")
        t1558html.write(
            "Enable AES Kerberos encryption (or another stronger encryption algorithm), rather than RC4, where possible.{}".format(
                insert
            )
        )
        t1558html.write("Password Policies</td>\n        <td>")
        t1558html.write(
            "Ensure strong password length (ideally 25+ characters) and complexity for service accounts and that these passwords periodically expire. Also consider using Group Managed Service Accounts or another third party product such as password vaulting.{}".format(
                insert
            )
        )
        t1558html.write("Privileged Account Management</td>\n        <td>")
        t1558html.write(
            "Limit domain admin account permissions to domain controllers and limited servers. Delegate other admin functions to separate accounts. nbsp;Limit service accounts to minimal required privileges, including membership in privileged groups such as Domain Administrators.{}".format(
                footer
            )
        )
    with open(sd + "t1539.html", "w") as t1539html:
        # description
        t1539html.write(
            "{}An adversary may steal web application or service session cookies and use them to gain access web applications or Internet services as an authenticated user without needing credentials. Web applications and services often use session cookies as an authentication token after a user has authenticated to a website.<br>".format(
                header
            )
        )
        t1539html.write(
            "Cookies are often valid for an extended period of time, even if the web application is not actively used. Cookies can be found on disk, in the process memory of the browser, and in network traffic to remote systems.<br>"
        )
        t1539html.write(
            "Additionally, other applications on the targets machine might store sensitive authentication cookies in memory (e.g. apps which authenticate to cloud services). Session cookies can be used to bypasses some multi-factor authentication protocols.<br>"
        )
        t1539html.write(
            "There are several examples of malware targeting cookies from web browsers on the local system. There are also open source frameworks such as Evilginx 2 and Muraena that can gather session cookies through a advesary-in-the-middle proxy that can be set up by an adversary and used in phishing campaigns.<br>"
        )
        t1539html.write(
            "After an adversary acquires a valid cookie, they can then perform a Web Session Cookie technique to login to the corresponding web application."
        )
        # information
        t1539html.write("{}T1539</td>\n        <td>".format(headings))  # id
        t1539html.write(
            "Windows, macOS, Linux, Office 365, SaaS</td>\n        <td>"
        )  # platforms
        t1539html.write("Credential Access</td>\n        <td>")  # tactics
        t1539html.write("-")  # sub-techniques
        # indicator regex assignments
        t1539html.write("{}-".format(iocs))
        # related techniques
        t1539html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1550 target="_blank"">T1550.004</a></td>\n        <td>'.format(
                related
            )
        )
        t1539html.write("Use Alternate Authentication Material: Web Session Cookie")
        # mitigations
        t1539html.write(
            "{}Multi-factor Authentication</td>\n        <td>".format(mitigations)
        )
        t1539html.write(
            "A physical second factor key that uses the target login domain as part of the negotiation protocol will prevent session cookie theft through proxy methods.{}".format(
                insert
            )
        )
        t1539html.write("Software Configuration</td>\n        <td>")
        t1539html.write(
            "Configure browsers or tasks to regularly delete persistent cookies.{}".format(
                insert
            )
        )
        t1539html.write("User Training</td>\n        <td>")
        t1539html.write(
            "Train users to identify aspects of phishing attempts where they're asked to enter credentials into a site that has the incorrect domain for the application they are logging into.{}".format(
                footer
            )
        )
    with open(sd + "t1111.html", "w") as t1111html:
        # description
        t1111html.write(
            "{}Adversaries may target two-factor authentication mechanisms, such as smart cards, to gain access to credentials that can be used to access systems, services, and network resources.<br>".format(
                header
            )
        )
        t1111html.write(
            "Use of two or multi-factor authentication (2FA or MFA) is recommended and provides a higher level of security than user names and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms.<br>"
        )
        t1111html.write(
            "If a smart card is used for two-factor authentication, then a keylogger will need to be used to obtain the password associated with a smart card during normal use.<br>"
        )
        t1111html.write(
            "With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token.<br>"
        )
        t1111html.write(
            "Adversaries may also employ a keylogger to similarly target other hardware tokens, such as RSA SecurID.<br>"
        )
        t1111html.write(
            "Capturing token input (including a user's personal identification code) may provide temporary access (i.e. replay the one-time passcode until the next value rollover) as well as possibly enabling adversaries to reliably predict future authentication values (given access to both the algorithm and any seed values used to generate appended temporary codes).<br>"
        )
        t1111html.write(
            "Other methods of 2FA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS).<br>"
        )
        t1111html.write(
            "If the device and/or service is not secured, then it may be vulnerable to interception. Although primarily focused on by cyber criminals, these authentication mechanisms have been targeted by advanced actors."
        )
        # information
        t1111html.write("{}T1111</td>\n        <td>".format(headings))  # id
        t1111html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1111html.write("Credential Access</td>\n        <td>")  # tactics
        t1111html.write("-")  # sub-techniques
        # indicator regex assignments
        t1111html.write("{}-".format(iocs))
        # related techniques
        t1111html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1056 target="_blank"">T1056</a></td>\n        <td>'.format(
                related
            )
        )
        t1111html.write("Input Capture")
        # mitigations
        t1111html.write("{}User Training</td>\n        <td>".format(mitigations))
        t1111html.write("Remove smart cards when not in use.{}".format(footer))
    with open(sd + "t1621.html", "w") as t1621html:
        # description
        t1621html.write(
            "{}Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users.<br>".format(
                header
            )
        )
        t1621html.write(
            "Adversaries in possession credentials to Valid Accounts may be unable to complete the login process if they lack access to the 2FA or MFA mechanisms required as an additional credential and security control. To circumvent this, adversaries may abuse the automatic generation of push notifications to MFA services such as Duo Push, Microsoft Authenticator, Okta, or similar services to have the user grant access to their account.<br>"
        )
        t1621html.write(
            'In some cases, adversaries may continuously repeat login attempts in order to bombard users with MFA push notifications, SMS messages, and phone calls, potentially resulting in the user finally accepting the authentication request in response to "MFA fatigue."'
        )
        # information
        t1621html.write("{}T1621</td>\n        <td>".format(headings))  # id
        t1621html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1621html.write("Credential Access</td>\n        <td>")  # tactics
        t1621html.write("-")  # sub-techniques
        # indicator regex assignments
        t1621html.write("{}-".format(iocs))
        # related techniques
        t1621html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1078 target="_blank"">T1078</a></td>\n        <td>'.format(
                related
            )
        )
        t1621html.write("Valid Accounts")
        # mitigations
        t1621html.write("{}Account Use Policies</td>\n        <td>".format(mitigations))
        t1621html.write(
            "Enable account restrictions to prevent login attempts, and the subsequent 2FA/MFA service requests, from being initiated from suspicious locations or when the source of the login attempts do not match the location of the 2FA/MFA smart device.{}".format(
                insert
            )
        )
        t1621html.write("Multi-factor Authentication</td>\n        <td>")
        t1621html.write(
            "Implement more secure 2FA/MFA mechanisms in replacement of simple push or one-click 2FA/MFA options. For example, having users enter a one-time code provided by the login screen into the 2FA/MFA application or utilizing other out-of-band 2FA/MFA mechanisms (such as rotating code-based hardware tokens providing rotating codes that need an accompanying user pin) may be more secure. Furthermore, change default configurations and implement limits upon the maximum number of 2FA/MFA request prompts that can be sent to users in period of time.{}".format(
                insert
            )
        )
        t1621html.write("User Training</td>\n        <td>")
        t1621html.write(
            "Train users to only accept 2FA/MFA requests from login attempts they initiated, to review source location of the login attempt prompting the 2FA/MFA requests, and to report suspicious/unsolicited prompts.{}".format(
                footer
            )
        )
    with open(sd + "t1552.html", "w") as t1552html:
        # description
        t1552html.write(
            "Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. Bash History), operating system or application-specific repositories (e.g. Credentials in Registry), or other specialized files/artifacts (e.g. Private Keys)."
        )
        # information
        t1552html.write("{}T1552</td>\n        <td>".format(headings))  # id
        t1552html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>"
        )  # platforms
        t1552html.write("Credential Access</td>\n        <td>")  # tactics
        t1552html.write(
            "T1552.001: Credentials In Files<br>T1552.002: Credentials In Registry<br>T1552.003: Bash History<br>T1552.004: Private Keys<br>T1552.005: Cloud Instance Metadata API<br>T1552.006: Group Policy Preferences<br>T1552.007: Container API"
        )  # sub-techniques
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
        t1552html.write("bash_history</li>\n        <li>")
        t1552html.write("history</li>\n        <li>")
        t1552html.write("HISTFILE</li>")
        # related techniques
        t1552html.write("{}-</a></td>\n        <td>".format(related))
        t1552html.write("-")
        # mitigations
        t1552html.write(
            "{}Active Directory Configuration</td>\n        <td>".format(mitigations)
        )
        t1552html.write("Remove vulnerable Group Policy Preferences.{}".format(insert))
        t1552html.write("Audit</td>\n        <td>")
        t1552html.write(
            "Preemptively search for files containing passwords or other credentials and take actions to reduce the exposure risk when found.{}".format(
                insert
            )
        )
        t1552html.write("Encrypt Sensitive Information</td>\n        <td>")
        t1552html.write(
            "When possible, store keys on separate cryptographic hardware instead of on the local system.{}".format(
                insert
            )
        )
        t1552html.write("Filter Network Traffic</td>\n        <td>")
        t1552html.write(
            "Limit access to the Instance Metadata API using a host-based firewall such as iptables. A properly configured Web Application Firewall (WAF) may help prevent external adversaries from exploiting Server-side Request Forgery (SSRF) attacks that allow access to the Cloud Instance Metadata API.{}".format(
                insert
            )
        )
        t1552html.write("Operating System Configuration</td>\n        <td>")
        t1552html.write(
            "There are multiple methods of preventing a user's command history from being flushed to their .bash_history file, including use of the following commands:set +o history and set -o history to start logging again; unset HISTFILE being added to a user's .bash_rc file; andln -s /dev/null ~/.bash_history to write commands to /dev/nullinstead.{}".format(
                insert
            )
        )
        t1552html.write("Password Policies</td>\n        <td>")
        t1552html.write(
            "Use strong passphrases for private keys to make cracking difficult. Do not store credentials within the Registry. Establish an organizational policy that prohibits password storage in files.{}".format(
                insert
            )
        )
        t1552html.write("Privileged Account Management</td>\n        <td>")
        t1552html.write(
            "If it is necessary that software must store credentials in the Registry, then ensure the associated accounts have limited permissions so they cannot be abused if obtained by an adversary.{}".format(
                insert
            )
        )
        t1552html.write("Restrict File and Directory Permissions</td>\n        <td>")
        t1552html.write(
            "Restrict file shares to specific directories with access only to necessary users.{}".format(
                insert
            )
        )
        t1552html.write("Update Software</td>\n        <td>")
        t1552html.write(
            "Apply patch KB2962486 which prevents credentials from being stored in GPPs.{}".format(
                insert
            )
        )
        t1552html.write("User Training</td>\n        <td>")
        t1552html.write(
            "Ensure that developers and system administrators are aware of the risk associated with having plaintext passwords in software configuration files that may be left on endpoint systems or servers.{}".format(
                footer
            )
        )
