#!/usr/bin/env python3 -tt


def create_discovery_html(
    sd, header, headings, iocs, related, insert, mitigations, footer
):
    with open(sd + "t1087.html", "w") as t1087html:
        # description
        t1087html.write(
            "{}Adversaries may attempt to get a listing of accounts on a system or within an environment. This information can help adversaries determine which accounts exist to aid in follow-on behavior.".format(
                header
            )
        )
        # information
        t1087html.write("{}T1087</td>\n        <td>".format(headings))  # id
        t1087html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>"
        )  # platforms
        t1087html.write("Discovery</td>\n        <td>")  # tactics
        t1087html.write(
            "T1087.001: Local Account<br>T1087.002: Domain Account<br>T1087.003: Email Account<br>T1087.004: Cloud Account"
        )  # sub-techniques
        # indicator regex assignments
        t1087html.write("{}Get-GlobalAddressList</li>\n        <li>".format(iocs))
        t1087html.write(
            "CurrentVersion\Policies\CredUI\EnumerateAdministrators</li>\n        <li>"
        )
        t1087html.write("dscacheutil</li>\n        <li>")
        t1087html.write("ldapsearch</li>\n        <li>")
        t1087html.write("passwd</li>\n        <li>")
        t1087html.write("shadow</li>")
        # related techniques
        t1087html.write("{}-</a></td>\n        <td>".format(related))
        t1087html.write("-")
        # mitigations
        t1087html.write(
            "{}Operating System Configuration</td>\n        <td>".format(mitigations)
        )
        t1087html.write(
            "Prevent administrator accounts from being enumerated when an application is elevating through UAC since it can lead to the disclosure of account names. The Registry key is located HKLM\\ SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI\\EnumerateAdministrators. It can be disabled through GPO: Computer Configuration > [Policies] > Administrative Templates > Windows Components > Credential User Interface: E numerate administrator accounts on elevation.{}".format(
                footer
            )
        )
    with open(sd + "t1010.html", "w") as t1010html:
        # description
        t1010html.write(
            "{}Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used or give context to information collected by a keylogger.".format(
                header
            )
        )
        # information
        t1010html.write("{}T1010</td>\n        <td>".format(headings))  # id
        t1010html.write("Windows, macOS</td>\n        <td>")  # platforms
        t1010html.write("Discovery</td>\n        <td>")  # tactics
        t1010html.write("-")  # sub-techniques
        # indicator regex assignments
        t1010html.write("{}-".format(iocs))
        # related techniques
        t1010html.write("{}-</a></td>\n        <td>".format(related))
        t1010html.write("-")
        # mitigations
        t1010html.write("{}-</td>\n        <td>".format(mitigations))
        t1010html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1217.html", "w") as t1217html:
        # description
        t1217html.write(
            "{}Adversaries may enumerate browser bookmarks to learn more about compromised hosts. Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure.<br>".format(
                header
            )
        )
        t1217html.write(
            "Browser bookmarks may also highlight additional targets after an adversary has access to valid credentials, especially Credentials In Files associated with logins cached by a browser.<br>"
        )
        t1217html.write(
            "Specific storage locations vary based on platform and/or application, but browser bookmarks are typically stored in local files/databases."
        )
        # information
        t1217html.write("{}T1217</td>\n        <td>".format(headings))  # id
        t1217html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1217html.write("Discovery</td>\n        <td>")  # tactics
        t1217html.write("-")  # sub-techniques
        # indicator regex assignments
        t1217html.write("{}-".format(iocs))
        # related techniques
        t1217html.write(
            '<a href="http://127.0.0.1:8000/en-US/app/elrond/t1552 target="_blank"">T1552</a></td>\n        <td>'
        )
        t1217html.write("Unsecured Credentials: Credentials In Files")
        # mitigations
        t1217html.write("{}-</td>\n        <td>".format(mitigations))
        t1217html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1580.html", "w") as t1580html:
        # description
        t1580html.write(
            "{}An adversary may attempt to discover resources that are available within an infrastructure-as-a-service (IaaS) environment. This includes compute service resources such as instances, virtual machines, and snapshots as well as resources of other services including the storage and database services.<br>".format(
                header
            )
        )
        t1580html.write(
            "Cloud providers offer methods such as APIs and commands issued through CLIs to serve information about infrastructure. For example, AWS provides a DescribeInstances API within the Amazon EC2 API that can return information about one or more instances within an account, as well as the ListBuckets API that returns a list of all buckets owned by the authenticated sender of the request. Similarly, GCP's Cloud SDK CLI provides the gcloud compute instances list command to list all Google Compute Engine instances in a project, and Azure's CLI command az vm list lists details of virtual machines.<br>"
        )
        t1580html.write(
            "An adversary may enumerate resources using a compromised user's access keys to determine which are available to that user. The discovery of these available resources may help adversaries determine their next steps in the Cloud environment, such as establishing Persistence. Unlike in Cloud Service Discovery, this technique focuses on the discovery of components of the provided services rather than the services themselves."
        )
        # information
        t1580html.write("{}T1580</td>\n        <td>".format(headings))  # id
        t1580html.write("IaaS</td>\n        <td>")  # platforms
        t1580html.write("Discovery</td>\n        <td>")  # tactics
        t1580html.write("-")  # sub-techniques
        # indicator regex assignments
        t1580html.write("{}-".format(iocs))
        # related techniques
        t1580html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1526 target="_blank"">T1526</a></td>\n        <td>'.format(
                related
            )
        )
        t1580html.write("Cloud Service Discovery")
        # mitigations
        t1580html.write("{}User Account Management</td>\n        <td>")
        t1580html.write(
            "Limit permissions to discover cloud infrastructure in accordance with least privilege. Organizations should limit the number of users within the organization with an IAM role that has administrative privileges, strive to reduce all permanent privileged role assignments, and conduct periodic entitlement reviews on IAM users, roles and policies.{}".format(
                footer
            )
        )
    with open(sd + "t1538.html", "w") as t1538html:
        # description
        t1538html.write(
            "{}An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features.<br>".format(
                header
            )
        )
        t1538html.write(
            "For example, the GCP Command Center can be used to view all assets, findings of potential security risks, and to run additional queries, such as finding public IP addresses and open ports.<br>"
        )
        t1538html.write(
            "Depending on the configuration of the environment, an adversary may be able to enumerate more information via the graphical dashboard than an API. This allows the adversary to gain information without making any API requests."
        )
        # information
        t1538html.write("{}T1538</td>\n        <td>".format(headings))  # id
        t1538html.write("AWS, Azure, GCP, Office 365</td>\n        <td>")  # platforms
        t1538html.write("Discovery</td>\n        <td>")  # tactics
        t1538html.write("-")  # sub-techniques
        # indicator regex assignments
        t1538html.write("{}-".format(iocs))
        # related techniques
        t1538html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t0000 target="_blank"">T0000</a></td>\n        <td>'.format(
                related
            )
        )
        t1538html.write("Scheduled Task/Job")
        # mitigations
        t1538html.write(
            "{}User Account Management</td>\n        <td>".format(mitigations)
        )
        t1538html.write(
            "Enforce the principle of least-privilege by limiting dashboard visibility to only the resources required. This may limit the discovery value of the dashboard in the event of a compromised account.{}".format(
                footer
            )
        )
    with open(sd + "t1526.html", "w") as t1526html:
        # description
        t1526html.write(
            "{}An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS).<br>".format(
                header
            )
        )
        t1526html.write(
            "Many services exist throughout the various cloud providers and can include Continuous Integration and Continuous Delivery (CI/CD), Lambda Functions, Azure AD, etc.<br>"
        )
        t1526html.write(
            "Adversaries may attempt to discover information about the services enabled throughout the environment. Azure tools and APIs, such as the Azure AD Graph API and Azure Resource Manager API, can enumerate resources and services, including applications, management groups, resources and policy definitions, and their relationships that are accessible by an identity.<br>"
        )
        t1526html.write(
            "Stormspotter is an open source tool for enumerating and constructing a graph for Azure resources and services, and Pacu is an open source AWS exploitation framework that supports several methods for discovering cloud services."
        )
        # information
        t1526html.write("{}T1526</td>\n        <td>".format(headings))  # id
        t1526html.write(
            "AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>"
        )  # platforms
        t1526html.write("Discovery</td>\n        <td>")  # tactics
        t1526html.write("-")  # sub-techniques
        # indicator regex assignments
        t1526html.write("{}-".format(iocs))
        # related techniques
        t1526html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1580 target="_blank"">T1580</a></td>\n        <td>'.format(
                related
            )
        )
        t1526html.write("Cloud Infrastructure Discovery")
        # mitigations
        t1526html.write("{}User Account Management</td>\n        <td>")
        t1526html.write(
            "Limit permissions to discover cloud infrastructure in accordance with least privilege. Organizations should limit the number of users within the organization with an IAM role that has administrative privileges, strive to reduce all permanent privileged role assignments, and conduct periodic entitlement reviews on IAM users, roles and policies.{}".format(
                footer
            )
        )
    with open(sd + "t1613.html", "w") as t1613html:
        # description
        t1613html.write(
            "{}Adversaries may attempt to discover containers and other resources that are available within a containers environment. Other resources may include images, deployments, pods, nodes, and other information such as the status of a cluster.<br>".format(
                header
            )
        )
        t1613html.write(
            "These resources can be viewed within web applications such as the Kubernetes dashboard or can be queried via the Docker and Kubernetes APIs. In Docker, logs may leak information about the environment, such as the environment’s configuration, which services are available, and what cloud provider the victim may be utilizing. The discovery of these resources may inform an adversary’s next steps in the environment, such as how to perform lateral movement and which methods to utilize for execution."
        )
        # information
        t1613html.write("{}T1613</td>\n        <td>".format(headings))  # id
        t1613html.write("Containers</td>\n        <td>")  # platforms
        t1613html.write("Discovery</td>\n        <td>")  # tactics
        t1613html.write("-")  # sub-techniques
        # indicator regex assignments
        t1613html.write("{}-".format(iocs))
        # related techniques
        t1613html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1059 target="_blank"">T1059</a></td>\n        <td>'.format(
                related
            )
        )
        t1613html.write("Command and Scripting Interpreter")
        # mitigations
        t1613html.write(
            "{}Limit Access to Resource Over Network</td>\n        <td>".format(
                mitigations
            )
        )
        t1613html.write(
            "Limit communications with the container service to local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API and Kubernetes API Server.{}".format(
                insert
            )
        )
        t1613html.write("Network Segmentation</td>\n        <td>")
        t1613html.write(
            "Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.{}".format(
                insert
            )
        )
        t1613html.write("User Account Management</td>\n        <td>")
        t1613html.write(
            "Enforce the principle of least privilege by limiting dashboard visibility to only the required users.{}".format(
                footer
            )
        )
    with open(sd + "t1482.html", "w") as t1482html:
        # description
        t1482html.write(
            "{}Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain.<br>".format(
                header
            )
        )
        t1482html.write(
            "Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct SID-History Injection, Pass the Ticket, and Kerberoasting.<br>"
        )
        t1482html.write(
            "Domain trusts can be enumerated using the DSEnumerateDomainTrusts() Win32 API call, .NET methods, and LDAP. The Windows utility Nltest is known to be used by adversaries to enumerate domain trusts."
        )
        # information
        t1482html.write("{}T1482</td>\n        <td>".format(headings))  # id
        t1482html.write("Windows</td>\n        <td>")  # platforms
        t1482html.write("Discovery</td>\n        <td>")  # tactics
        t1482html.write("-")  # sub-techniques
        # indicator regex assignments
        t1482html.write("{}DSEnumerateDomainTrusts</li>\n        <li>".format(iocs))
        t1482html.write("GetAllTrustRelationships</li>\n        <li>")
        t1482html.write("Get-AcceptedDomain</li>\n        <li>")
        t1482html.write("Get-NetDomainTrust</li>\n        <li>")
        t1482html.write("Get-NetForestTrust</li>\n        <li>")
        t1482html.write("nltest</li>\n        <li>")
        t1482html.write("dsquery</li>")
        # related techniques
        t1482html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1134 target="_blank"">T1134</a></td>\n        <td>'.format(
                related
            )
        )
        t1482html.write("Access Token Manipulation: SID-History Injection")
        t1482html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1550 target="_blank"">T1550</a></td>\n        <td>'.format(
                insert
            )
        )
        t1482html.write("Use Alternate Authentication Material: Pass the Ticket")
        t1482html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1558 target="_blank"">T1558</a></td>\n        <td>'.format(
                insert
            )
        )
        t1482html.write("Steal or Forge Kerberos Tickets: Kerberoasting")
        # mitigations
        t1482html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1482html.write(
            "Map the trusts within existing domains/forests and keep trust relationships to a minimum.{}".format(
                insert
            )
        )
        t1482html.write("Network Segmentation</td>\n        <td>")
        t1482html.write(
            "Employ network segmentation for sensitive domains.{}".format(footer)
        )
    with open(sd + "t1083.html", "w") as t1083html:
        # description
        t1083html.write(
            "{}Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.<br>".format(
                header
            )
        )
        t1083html.write(
            "Adversaries may use the information from File and Directory Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br>"
        )
        t1083html.write(
            "Many command shell utilities can be used to obtain this information. Examples include dir, tree, ls, find, and locate. Custom tools may also be used to gather file and directory information and interact with the Native API."
        )
        # information
        t1083html.write("{}T1083</td>\n        <td>".format(headings))  # id
        t1083html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1083html.write("Discovery</td>\n        <td>")  # tactics
        t1083html.write("-")  # sub-techniques
        # indicator regex assignments
        t1083html.write("{}dir</li>\n        <li>".format(iocs))
        t1083html.write("tree</li>\n        <li>")
        t1083html.write("ls</li>\n        <li>")
        t1083html.write("find</li>\n        <li>")
        t1083html.write("locate</li>")
        # related techniques
        t1083html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1106 target="_blank"">T1106</a></td>\n        <td>'.format(
                related
            )
        )
        t1083html.write("Native API")
        # mitigations
        t1083html.write("{}-</td>\n        <td>".format(mitigations))
        t1083html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1615.html", "w") as t1615html:
        # description
        t1615html.write(
            "{}Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or used to blend in the environment. Group Policy allows for centralized management of user and computer settings in Active Directory (AD). Group policy objects (GPOs) are containers for group policy settings made up of files stored within a predicable network path \\SYSVOL\\Policies.<br>".format(
                header
            )
        )
        t1615html.write(
            "Adversaries may use commands such as gpresult or various publicly available PowerShell functions, such as Get-DomainGPO and Get-DomainGPOLocalGroup, to gather information on Group Policy settings.[3][4] Adversaries may use this information to shape follow-on behaviors, including determining potential attack paths within the target network as well as opportunities to manipulate Group Policy settings (i.e. Domain Policy Modification) for their benefit."
        )
        # information
        t1615html.write("{}T1615</td>\n        <td>".format(headings))  # id
        t1615html.write("Windows</td>\n        <td>")  # platforms
        t1615html.write("Discovery</td>\n        <td>")  # tactics
        t1615html.write("-")  # sub-techniques
        # indicator regex assignments
        t1615html.write("{}sysvol/policies</li>\n        <li>".format(iocs))
        t1615html.write("gpresult</li>\n        <li>")
        t1615html.write("Get-DomainGPO</li>")
        # related techniques
        t1615html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1484 target="_blank"">T1484</a></td>\n        <td>'.format(
                related
            )
        )
        t1615html.write("Domain Policy Modification")
        # mitigations
        t1615html.write("{}-</td>\n        <td>".format(mitigations))
        t1615html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1046.html", "w") as t1046html:
        # description
        t1046html.write(
            "{}Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods to acquire this information include port scans and vulnerability scans using tools that are brought onto a system.<br>".format(
                header
            )
        )
        t1046html.write(
            "Within cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well."
        )
        # information
        t1046html.write("{}T1046</td>\n        <td>".format(headings))  # id
        t1046html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>"
        )  # platforms
        t1046html.write("Discovery</td>\n        <td>")  # tactics
        t1046html.write("-")  # sub-techniques
        # indicator regex assignments
        t1046html.write("{}-".format(iocs))
        # related techniques
        t1046html.write("{}-</a></td>\n        <td>".format(related))
        t1046html.write("-")
        # mitigations
        t1046html.write(
            "{}Disable or Remove Feature or Program</td>\n        <td>".format(
                mitigations
            )
        )
        t1046html.write(
            "Ensure that unnecessary ports and services are closed to prevent risk of discovery and potential exploitation.{}".format(
                insert
            )
        )
        t1046html.write("Network Intrusion Prevention</td>\n        <td>")
        t1046html.write(
            "Use network intrusion detection/prevention systems to detect and prevent remote service scans.{}".format(
                insert
            )
        )
        t1046html.write("Network Segmentation</td>\n        <td>")
        t1046html.write(
            "Ensure proper network segmentation is followed to protect critical servers and devices.{}".format(
                footer
            )
        )
    with open(sd + "t1135.html", "w") as t1135html:
        # description
        t1135html.write(
            "{}Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement. Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network.<br>".format(
                header
            )
        )
        t1135html.write(
            "File sharing over a Windows network occurs over the SMB protocol. Net can be used to query a remote system for available shared drives using the net view \\remotesystem command. It can also be used to query shared drives on the local system using net share.<br>"
        )
        t1135html.write(
            "Cloud virtual networks may contain remote network shares or file storage services accessible to an adversary after they have obtained access to a system. For example, AWS, GCP, and Azure support creation of Network File System (NFS) shares and Server Message Block (SMB) shares that may be mapped on endpoint or cloud-based systems."
        )
        # information
        t1135html.write("{}T1135</td>\n        <td>".format(headings))  # id
        t1135html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>"
        )  # platforms
        t1135html.write("Discovery</td>\n        <td>")  # tactics
        t1135html.write("-")  # sub-techniques
        # indicator regex assignments
        t1135html.write("{}net.exe share</li>\n        <li>".format(iocs))
        t1135html.write("net1.exe share</li>\n        <li>")
        t1135html.write("net.exe view</li>\n        <li>")
        t1135html.write("net1.exe view</li>\n        <li>")
        t1135html.write("netsh</li>")
        # related techniques
        t1135html.write("{}-</a></td>\n        <td>".format(related))
        t1135html.write("-")
        # mitigations
        t1135html.write(
            "{}Operating System Configuration</td>\n        <td>".format(mitigations)
        )
        t1135html.write(
            'Enable Windows Group Policy "Do Not Allow Anonymous Enumeration of SAM Accounts and Shares" security setting to limit users who can enumerate network shares.{}'.format(
                footer
            )
        )
    with open(sd + "t1201.html", "w") as t1201html:
        # description
        t1201html.write(
            "{}Adversaries may attempt to access detailed information about the password policy used within an enterprise network. Password policies for networks are a way to enforce complex passwords that are difficult to guess or crack through Brute Force.<br>".format(
                header
            )
        )
        t1201html.write(
            "This would help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts).<br>"
        )
        t1201html.write(
            "Password policies can be set and discovered on Windows, Linux, and macOS systems via various command shell utilities such as net accounts (/domain), chage -l , cat /etc/pam.d/common-password, and pwpolicy getaccountpolicies."
        )
        # information
        t1201html.write("{}T1221</td>\n        <td>".format(headings))  # id
        t1201html.write("Windows</td>\n        <td>")  # platforms
        t1201html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1201html.write("-")  # sub-techniques
        # indicator regex assignments
        t1201html.write("{}net.exe accounts</li>\n        <li>".format(iocs))
        t1201html.write("net1.exe accounts</li>\n        <li>")
        t1201html.write("Get-AdDefaultDomainPasswordPolicy</li>\n        <li>")
        t1201html.write("chage</li>\n        <li>")
        t1201html.write("common-password</li>\n        <li>")
        t1201html.write("pwpolicy</li>\n        <li>")
        t1201html.write("getaccountpolicies</li>")
        # related techniques
        t1201html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1110 target="_blank"">T1110</a></td>\n        <td>'.format(
                related
            )
        )
        t1201html.write("Brute Force")
        # mitigations
        t1201html.write("{}Password Policies</td>\n        <td>".format(mitigations))
        t1201html.write(
            "Ensure only valid password filters are registered. Filter DLLs must be present in Windows installation directory (C:\\Windows\\System32\\ by default) of a domain controller and/or local computer with a corresponding entry in HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages.{}".format(
                footer
            )
        )
    with open(sd + "t1120.html", "w") as t1120html:
        # description
        t1120html.write(
            "{}Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage.<br>".format(
                header
            )
        )
        t1120html.write(
            "The information may be used to enhance their awareness of the system and network environment or may be used for further actions."
        )
        # information
        t1120html.write("{}T1120</td>\n        <td>".format(headings))  # id
        t1120html.write("Windows, macOS</td>\n        <td>")  # platforms
        t1120html.write("Discovery</td>\n        <td>")  # tactics
        t1120html.write("-")  # sub-techniques
        # indicator regex assignments
        t1120html.write("{}fsutil</li>\n        <li>".format(iocs))
        t1120html.write("fsinfo</li>")
        # related techniques
        t1120html.write("{}-</a></td>\n        <td>".format(related))
        t1120html.write("-")
        # mitigations
        t1120html.write("{}-</td>\n        <td>".format(mitigations))
        t1120html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1069.html", "w") as t1069html:
        # description
        t1069html.write(
            "Adversaries may attempt to find group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions."
        )
        # information
        t1069html.write("{}T1069</td>\n        <td>".format(headings))  # id
        t1069html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>"
        )  # platforms
        t1069html.write("Discovery</td>\n        <td>")  # tactics
        t1069html.write(
            "T1069.001: Local Groups<br>T1069.002: Domain Groups<br>T1069.003: Cloud Groups"
        )  # sub-techniques
        # indicator regex assignments
        t1069html.write("{}dscacheutil</li>\n        <li>".format(iocs))
        t1069html.write("ldapsearch</li>\n        <li>")
        t1069html.write("dscl</li>\n        <li>")
        t1069html.write("group</li>")
        # related techniques
        t1069html.write("{}-</a></td>\n        <td>".format(related))
        t1069html.write("-")
        # mitigations
        t1069html.write("{}-</td>\n        <td>".format(mitigations))
        t1069html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1057.html", "w") as t1057html:
        # description
        t1057html.write(
            "{}Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Adversaries may use the information from Process Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br>".format(
                header
            )
        )
        t1057html.write(
            "In Windows environments, adversaries could obtain details on running processes using the Tasklist utility via cmd or Get-Process via PowerShell. Information about processes can also be extracted from the output of Native API calls such as CreateToolhelp32Snapshot. In Mac and Linux, this is accomplished with the ps command. Adversaries may also opt to enumerate processes via /proc."
        )
        # information
        t1057html.write("{}T1057</td>\n        <td>".format(headings))  # id
        t1057html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1057html.write("Discovery</td>\n        <td>")  # tactics
        t1057html.write("-")  # sub-techniques
        # indicator regex assignments
        t1057html.write("{}Get-Process</li>\n        <li>".format(iocs))
        t1057html.write("CreateToolhelp32Snapshot</li>\n        <li>")
        t1057html.write("ps</li>")
        # related techniques
        t1057html.write(
            '<a href="http://127.0.0.1:8000/en-US/app/elrond/t1059 target="_blank"">T1059</a></td>\n        <td>'
        )
        t1057html.write("Command and Scripting Interpreter: PowerShell")
        t1057html.write(
            '<a href="http://127.0.0.1:8000/en-US/app/elrond/t1057 target="_blank"">T1057</a></td>\n        <td>'
        )
        t1057html.write("Native API")
        # mitigations
        t1057html.write("{}-</td>\n        <td>".format(mitigations))
        t1057html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1012.html", "w") as t1012html:
        # description
        t1012html.write(
            "{}Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.<br>".format(
                header
            )
        )
        t1012html.write(
            "The Registry contains a significant amount of information about the operating system, configuration, software, and security. Information can easily be queried using the Reg utility, though other means to access the Registry exist. Some of the information may help adversaries to further their operation within a network.<br>"
        )
        t1012html.write(
            "Adversaries may use the information from Query Registry during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions."
        )
        # information
        t1012html.write("{}T1012</td>\n        <td>".format(headings))  # id
        t1012html.write("Windows</td>\n        <td>")  # platforms
        t1012html.write("Discovery</td>\n        <td>")  # tactics
        t1012html.write("-")  # sub-techniques
        # indicator regex assignments
        t1012html.write("{}reg query".format(iocs))
        # related techniques
        t1012html.write("{}-</a></td>\n        <td>".format(related))
        t1012html.write("-")
        # mitigations
        t1012html.write("{}Execution Prevention</td>\n        <td>".format(mitigations))
        t1012html.write(
            "Use read-only containers and minimal images when possible to prevent the execution of commands.{}".format(
                insert
            )
        )
        t1012html.write("Limit Access to Resource Over Network</td>\n        <td>")
        t1012html.write(
            "Limit communications with the container service to local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API and Kubernetes API Server.{}".format(
                insert
            )
        )
        t1012html.write("Privileged Account Management</td>\n        <td>")
        t1012html.write(
            "Ensure containers are not running as root by default.{}".format(footer)
        )
    with open(sd + "t1018.html", "w") as t1018html:
        # description
        t1018html.write(
            "{}Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used such as Ping or net view using Net.<br>".format(
                header
            )
        )
        t1018html.write(
            "Adversaries may also use local host files (ex: C:\\Windows\\System32\\Drivers\\etc\\hosts or /etc/hosts) in order to discover the hostname to IP address mappings of remote systems.<br>"
        )
        t1018html.write(
            "Specific to macOS, the bonjour protocol exists to discover additional Mac-based systems within the same broadcast domain.<br>"
        )
        t1018html.write(
            "Within IaaS (Infrastructure as a Service) environments, remote systems include instances and virtual machines in various states, including the running or stopped state. Cloud providers have created methods to serve information about remote systems, such as APIs and CLIs.<br>"
        )
        t1018html.write(
            "For example, AWS provides a DescribeInstances API within the Amazon EC2 API and a describe-instances command within the AWS CLI that can return information about all instances within an account. Similarly, GCP's Cloud SDK CLI provides the gcloud compute instances list command to list all Google Compute Engine instances in a project, and Azure's CLI az vm list lists details of virtual machines."
        )
        # information
        t1018html.write("{}T1018</td>\n        <td>".format(headings))  # id
        t1018html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>"
        )  # platforms
        t1018html.write("Discovery</td>\n        <td>")  # tactics
        t1018html.write("-")  # sub-techniques
        # indicator regex assignments
        t1018html.write("{}net.exe view</li>\n        <li>".format(iocs))
        t1018html.write("net1.exe view</li>\n        <li>")
        t1018html.write("ping</li>\n        <li>")
        t1018html.write("tracert</li>\n        <li>")
        t1018html.write("traceroute</li>\n        <li>")
        t1018html.write("etc/host</li>\n        <li>")
        t1018html.write("etc/hosts</li>\n        <li>")
        t1018html.write("bonjour</li>")
        # related techniques
        t1018html.write("{}-</a></td>\n        <td>".format(related))
        t1018html.write("-")
        # mitigations
        t1018html.write("{}-</td>\n        <td>".format(mitigations))
        t1018html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1518.html", "w") as t1518html:
        # description
        t1518html.write(
            "{}Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment.<br>".format(
                header
            )
        )
        t1518html.write(
            "Adversaries may use the information from Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br>"
        )
        t1518html.write(
            "Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable to Exploitation for Privilege Escalation."
        )
        # information
        t1518html.write("{}T1518</td>\n        <td>".format(headings))  # id
        t1518html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP, Office 365, Saas</td>\n        <td>"
        )  # platforms
        t1518html.write("Discovery</td>\n        <td>")  # tactics
        t1518html.write("T1518.001: Security Software Discovery")  # sub-techniques
        # indicator regex assignments
        t1518html.write("{}netsh</li>\n        <li>".format(iocs))
        t1518html.write("tasklist</li>")
        # related techniques
        t1518html.write(
            '<a href="http://127.0.0.1:8000/en-US/app/elrond/t1068 target="_blank"">T1068</a></td>\n        <td>'
        )
        t1518html.write("Exploitation for Privilege Escalation")
        # mitigations
        t1518html.write("{}-</td>\n        <td>".format(mitigations))
        t1518html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1082.html", "w") as t1082html:
        # description
        t1082html.write(
            "{}An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.<br>".format(
                header
            )
        )
        t1082html.write(
            "Adversaries may use the information from System Information Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br>"
        )
        t1082html.write(
            "Tools such as Systeminfo can be used to gather detailed system information. A breakdown of system data can also be gathered through the macOS systemsetup command, but it requires administrative privileges.<br>"
        )
        t1082html.write(
            "Infrastructure as a Service (IaaS) cloud providers such as AWS, GCP, and Azure allow access to instance and virtual machine information via APIs. Successful authenticated API calls can return data such as the operating system platform and status of a particular instance or the model view of a virtual machine."
        )
        # information
        t1082html.write("{}T1082</td>\n        <td>".format(headings))  # id
        t1082html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>"
        )  # platforms
        t1082html.write("Defense Evasion</td>\n        <td>")  # tactics
        t1082html.write("-")  # sub-techniques
        # indicator regex assignments
        t1082html.write("{}systemsetup".format(iocs))
        # related techniques
        t1082html.write("{}-</a></td>\n        <td>".format(related))
        t1082html.write("-")
        # mitigations
        t1082html.write("{}-</td>\n        <td>".format(mitigations))
        t1082html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1614.html", "w") as t1614html:
        # description
        t1614html.write(
            "{}Adversaries may gather information in an attempt to calculate the geographical location of a victim host. Adversaries may use the information from System Location Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br>".format(
                header
            )
        )
        t1614html.write(
            "Adversaries may attempt to infer the location of a system using various system checks, such as time zone, keyboard layout, and/or language settings. Windows API functions such as GetLocaleInfoW can also be used to determine the locale of the host. In cloud environments, an instance's availability zone may also be discovered by accessing the instance metadata service from the instance.<br>"
        )
        t1614html.write(
            "Adversaries may also attempt to infer the location of a victim host using IP addressing, such as via online geolocation IP-lookup services."
        )
        # information
        t1614html.write("{}T1614</td>\n        <td>".format(headings))  # id
        t1614html.write("Windows, macOS, Linux, IaaS</td>\n        <td>")  # platforms
        t1614html.write("Discovery</td>\n        <td>")  # tactics
        t1614html.write("T1614.001: System Language Discovery")  # sub-techniques
        # indicator regex assignments
        t1614html.write("{}hklm/system/currentcontrolset/control/nls/language</li>\n        <li>".format(iocs))
        t1614html.write("GetUserDefaultUILanguage</li>\n        <li>")
        t1614html.write("GetSystemDefaultUILanguage</li>\n        <li>")
        t1614html.write("GetKeyboardLayoutList</li>\n        <li>")
        t1614html.write("GetUserDefaultLangID</li>")
        # related techniques
        t1614html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1053 target="_blank"">T1124</a></td>\n        <td>'.format(
                related
            )
        )
        t1614html.write("System Time Discovery")
        t1614html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1012 target="_blank"">T1012</a></td>\n        <td>'.format(
                insert
            )
        )
        t1614html.write("Query Registry")
        t1614html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1106 target="_blank"">T1106</a></td>\n        <td>'.format(
                insert
            )
        )
        t1614html.write("Native API")
        # mitigations
        t1614html.write("{}-</td>\n        <td>".format(mitigations))
        t1614html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1016.html", "w") as t1016html:
        # description
        t1016html.write(
            "{}Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include Arp, ipconfig/ifconfig, nbtstat, and route.<br>".format(
                header
            )
        )
        t1016html.write(
            "Adversaries may use the information from System Network Configuration Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions."
        )
        # information
        t1016html.write("{}T1016</td>\n        <td>".format(headings))  # id
        t1016html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1016html.write("Discovery</td>\n        <td>")  # tactics
        t1016html.write("T1016:001: Internet Connection Discovery")  # sub-techniques
        # indicator regex assignments
        t1016html.write("{}ipconfig</li>\n        <li>".format(iocs))
        t1016html.write("ifconfig</li>\n        <li>")
        t1016html.write("ping</li>\n        <li>")
        t1016html.write("traceroute</li>\n        <li>")
        t1016html.write("etc/host</li>\n        <li>")
        t1016html.write("etc/hosts</li>\n        <li>")
        t1016html.write("bonjour</li>")
        # related techniques
        t1016html.write("{}-</a></td>\n        <td>".format(related))
        t1016html.write("-")
        # mitigations
        t1016html.write("{}-</td>\n        <td>".format(mitigations))
        t1016html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1049.html", "w") as t1049html:
        # description
        t1049html.write(
            "{}Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.<br>".format(
                header
            )
        )
        t1049html.write(
            "An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected<br>"
        )
        t1049html.write(
            "The actions performed are likely the same types of discovery techniques depending on the operating system, but the resulting information may include details about the networked cloud environment relEvent to the adversary's goals. Cloud providers may have different ways in which their virtual networks operate.<br>"
        )
        t1049html.write(
            'Utilities and commands that acquire this information include netstat, "net use," and "net session" with Net. In Mac and Linux, netstat and lsof can be used to list current connections. who -a and w can be used to show which users are currently logged in, similar to "net session".'
        )
        # information
        t1049html.write("{}T1049</td>\n        <td>".format(headings))  # id
        t1049html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>"
        )  # platforms
        t1049html.write("Discovery</td>\n        <td>")  # tactics
        t1049html.write("-")  # sub-techniques
        # indicator regex assignments
        t1049html.write("{}net use</li>\n        <li>".format(iocs))
        t1049html.write("net1 use</li>\n        <li>")
        t1049html.write("net session</li>\n        <li>")
        t1049html.write("net1 session</li>\n        <li>")
        t1049html.write("netsh</li>\n        <li>")
        t1049html.write("lsof</li>\n        <li>")
        t1049html.write("who</li>")
        # related techniques
        t1049html.write("{}-</a></td>\n        <td>".format(related))
        t1049html.write("-")
        # mitigations
        t1049html.write("{}-</td>\n        <td>".format(mitigations))
        t1049html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1033.html", "w") as t1033html:
        # description
        t1033html.write(
            "{}Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using OS Credential Dumping.<br>".format(
                header
            )
        )
        t1033html.write(
            "The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs.<br>"
        )
        t1033html.write(
            "Adversaries may use the information from System Owner/User Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br>"
        )
        t1033html.write(
            "Utilities and commands that acquire this information include whoami. In Mac and Linux, the currently logged in user can be identified with w and who."
        )
        # information
        t1033html.write("{}T1033</td>\n        <td>".format(headings))  # id
        t1033html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1033html.write("Discovery</td>\n        <td>")  # tactics
        t1033html.write("-")  # sub-techniques
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
        t1033html.write("ifconfig</li>")
        # related techniques
        t1033html.write(
            '<a href="http://127.0.0.1:8000/en-US/app/elrond/t1003 target="_blank"">T1003</a></td>\n        <td>'
        )
        t1033html.write("OS Credential Dumping")
        # mitigations
        t1033html.write("{}-</td>\n        <td>".format(mitigations))
        t1033html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1007.html", "w") as t1007html:
        # description
        t1007html.write(
            '{}Adversaries may try to get information about registered services. Commands that may obtain information about services using operating system utilities are "sc," "tasklist /svc" using Tasklist, and "net start" using Net, but adversaries may also use other tools as well. Adversaries may use the information from System Service Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.'.format(
                header
            )
        )
        # information
        t1007html.write("{}T1007</td>\n        <td>".format(headings))  # id
        t1007html.write("Windows</td>\n        <td>")  # platforms
        t1007html.write("Discovery</td>\n        <td>")  # tactics
        t1007html.write("-")  # sub-techniques
        # indicator regex assignments
        t1007html.write("{}services.exe</li>\n        <li>".format(iocs))
        t1007html.write("sc.exe</li>\n        <li>")
        t1007html.write("tasklist</li>\n        <li>")
        t1007html.write("net start</li>\n        <li>")
        t1007html.write("net1 start</li>\n        <li>")
        t1007html.write("net stop</li>\n        <li>")
        t1007html.write("net1 stop</li>")
        # related techniques
        t1007html.write("{}-</a></td>\n        <td>".format(related))
        t1007html.write("-")
        # mitigations
        t1007html.write("{}-</td>\n        <td>".format(mitigations))
        t1007html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1124.html", "w") as t1124html:
        # description
        t1124html.write(
            "{}An adversary may gather the system time and/or time zone from a local or remote system. The system time is set and stored by the Windows Time Service within a domain to maintain time synchronization between systems and services in an enterprise network.<br>".format(
                header
            )
        )
        t1124html.write(
            "System time information may be gathered in a number of ways, such as with Net on Windows by performing net time \\hostname to gather the system time on a remote system. The victim's time zone may also be inferred from the current system time or gathered by using w32tm /tz.<br>"
        )
        t1124html.write(
            "The information could be useful for performing other techniques, such as executing a file with a Scheduled Task/Job, or to discover locality information based on time zone to assist in victim targeting."
        )
        # information
        t1124html.write("{}T1124</td>\n        <td>".format(headings))  # id
        t1124html.write("Windows</td>\n        <td>")  # platforms
        t1124html.write("Discovery</td>\n        <td>")  # tactics
        t1124html.write("-")  # sub-techniques
        # indicator regex assignments
        t1124html.write("{}net time</li>\n        <li>".format(iocs))
        t1124html.write("net1 time</li>")
        # related techniques
        t1124html.write(
            '<a href="http://127.0.0.1:8000/en-US/app/elrond/t1053 target="_blank"">T1053</a></td>\n        <td>'
        )
        t1124html.write("Scheduled Task/Job")
        t1124html.write(
            '<a href="http://127.0.0.1:8000/en-US/app/elrond/t1053 target="_blank"">T1614</a></td>\n        <td>'
        )
        t1124html.write("System Location Discovery")
        # mitigations
        t1124html.write("{}-</td>\n        <td>".format(mitigations))
        t1124html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
