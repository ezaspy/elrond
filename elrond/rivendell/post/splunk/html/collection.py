#!/usr/bin/env python3 -tt


def create_collection_html(sd, header, headings, iocs, related, insert, mitigations, footer):
    with open(sd + "t1560.html", "w") as t1560html:
        # description
        t1560html.write(
            "{}An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network.<br>".format(
                header
            )
        )
        t1560html.write(
            "Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender.<br>"
        )
        t1560html.write(
            "Both compression and encryption are done prior to exfiltration, and can be performed using a utility, 3rd party library, or custom method."
        )
        # information
        t1560html.write("{}T1560</td>\n        <td>".format(headings))  # id
        t1560html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1560html.write("Collection</td>\n        <td>")  # tactics
        t1560html.write(
            "T1560.001: Archive via Utility<br>T1560.002: Archive via Library<br>T1560.003: Archive via Custom Method"
        )  # sub-techniques
        # indicator regex assignments
        t1560html.write("{}.7z</li>\n        <li>".format(iocs))
        t1560html.write(".arj</li>\n        <li>")
        t1560html.write(".tar</li>\n        <li>")
        t1560html.write(".tgz</li>\n        <li>")
        t1560html.write(".zip</li>\n        <li>")
        t1560html.write("libzip</li>\n        <li>")
        t1560html.write("zlib</li>\n        <li>")
        t1560html.write("rarfile</li>\n        <li>")
        t1560html.write("bzip2</li>")
        # related techniques
        t1560html.write("{}-</a></td>\n        <td>".format(related))
        t1560html.write("-")
        # mitigations
        t1560html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1560html.write(
            "System scans can be performed to identify unauthorized archival utilities.{}".format(
                footer
            )
        )
    with open(sd + "t1123.html", "w") as t1123html:
        # description
        t1123html.write(
            "{}Adversaries may abuse shared modules to execute malicious payloads. The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths.<br>".format(
                header
            )
        )
        t1123html.write(
            "This functionality resides in NTDLL.dll and is part of the Windows Native API which is called from functions like CreateProcess, LoadLibrary, etc. of the Win32 API."
        )
        # information
        t1123html.write("{}T1129</td>\n        <td>".format(headings))  # id
        t1123html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1123html.write("Collection</td>\n        <td>")  # tactics
        t1123html.write("-")  # sub-techniques
        # indicator regex assignments
        t1123html.write("{}.mp3</li>\n        <li>".format(iocs))
        t1123html.write(".wav</li>\n        <li>")
        t1123html.write(".aac</li>\n        <li>")
        t1123html.write(".m4a</li>\n        <li>")
        t1123html.write("microphone</li>")
        # related techniques
        t1123html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1106 target="_blank"">T1106</a></td>\n        <td>'.format(
                related
            )
        )
        t1123html.write("Native API")
        # mitigations
        t1123html.write("{}-</td>\n        <td>".format(mitigations))
        t1123html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1119.html", "w") as t1119html:
        # description
        t1119html.write(
            "{}Once established within a system or network, an adversary may use automated techniques for collecting internal data.<br>".format(
                header
            )
        )
        t1119html.write(
            "Methods for performing this technique could include use of a Command and Scripting Interpreter to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. This functionality could also be built into remote access tools.<br>"
        )
        t1119html.write(
            "This technique may incorporate use of other techniques such as File and Directory Discovery and Lateral Tool Transfer to identify and move files."
        )
        # information
        t1119html.write("{}T1119</td>\n        <td>".format(headings))  # id
        t1119html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1119html.write("Collection</td>\n        <td>")  # tactics
        t1119html.write("-")  # sub-techniques
        # indicator regex assignments
        t1119html.write("{}-".format(iocs))
        # related techniques
        t1119html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1059 target="_blank"">T1059</a></td>\n        <td>'.format(
                related
            )
        )
        t1119html.write("Command and Scripting Interpreter")
        t1119html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1083 target="_blank"">T1083</a></td>\n        <td>'.format(
                insert
            )
        )
        t1119html.write("File and Directory Discovery")
        t1119html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1570 target="_blank"">T1570</a></td>\n        <td>'.format(
                insert
            )
        )
        t1119html.write("Lateral Tool Transfer")
        # mitigations
        t1119html.write(
            "{}Encrypt Sensitive Information</td>\n        <td>".format(mitigations)
        )
        t1119html.write(
            "Encryption and off-system storage of sensitive information may be one way to mitigate collection of files, but may not stop an adversary from acquiring the information if an intrusion persists over a long period of time and the adversary is able to discover and access the data through other means. Strong passwords should be used on certain encrypted documents that use them to prevent offline cracking through Brute Force techniques.{}".format(
                insert
            )
        )
        t1119html.write("Remote Data Storage</td>\n        <td>")
        t1119html.write(
            "Encryption and off-system storage of sensitive information may be one way to mitigate collection of files, but may not stop an adversary from acquiring the information if an intrusion persists over a long period of time and the adversary is able to discover and access the data through other means.{}".format(
                footer
            )
        )
    with open(sd + "t1115.html", "w") as t1115html:
        # description
        t1115html.write(
            "{}Adversaries may collect data stored in the clipboard from users copying information within or between applications.<br>".format(
                header
            )
        )
        t1115html.write(
            "In Windows, Applications can access clipboard data by using the Windows API. OSX provides a native command, pbpaste, to grab clipboard contents."
        )
        # information
        t1115html.write("{}T1115</td>\n        <td>".format(headings))  # id
        t1115html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1115html.write("Collection</td>\n        <td>")  # tactics
        t1115html.write("-")  # sub-techniques
        # indicator regex assignments
        t1115html.write("{}clipboard</li>\n        <li>".format(iocs))
        t1115html.write("pbpaste</li>")
        # related techniques
        t1115html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1106 target="_blank"">T1106</a></td>\n        <td>'.format(
                related
            )
        )
        t1115html.write("Native API")
        # mitigations
        t1115html.write("{}-</td>\n        <td>".format(mitigations))
        t1115html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1530.html", "w") as t1530html:
        # description
        t1530html.write(
            "{}Adversaries may access data objects from improperly secured cloud storage.<br>".format(
                header
            )
        )
        t1530html.write(
            "Many cloud service providers offer solutions for online data storage such as Amazon S3, Azure Storage, and Google Cloud Storage. These solutions differ from other storage solutions (such as SQL or Elasticsearch) in that there is no overarching application.<br>"
        )
        t1530html.write(
            "Data from these solutions can be retrieved directly using the cloud provider's APIs. Solution providers typically offer security guides to help end users configure systems.<br>"
        )
        t1530html.write(
            "Misconfiguration by end users is a common problem. There have been numerous incidents where cloud storage has been improperly secured (typically by unintentionally allowing public access by unauthenticated users or overly-broad access by all users), allowing open access to credit cards, personally identifiable information, medical records, and other sensitive information.<br>"
        )
        t1530html.write(
            "Adversaries may also obtain leaked credentials in source repositories, logs, or other means as a way to gain access to cloud storage objects that have access permission controls."
        )
        # information
        t1530html.write("{}T1530</td>\n        <td>".format(headings))  # id
        t1530html.write("AWS, Azure, GCP</td>\n        <td>")  # platforms
        t1530html.write("Collection</td>\n        <td>")  # tactics
        t1530html.write("-")  # sub-techniques
        # indicator regex assignments
        t1530html.write("{}-".format(iocs))
        # related techniques
        t1530html.write("{}-</a></td>\n        <td>".format(related))
        t1530html.write("-")
        # mitigations
        t1530html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1530html.write(
            "Frequently check permissions on cloud storage to ensure proper permissions are set to deny open or unprivileged access to resources.{}".format(
                insert
            )
        )
        t1530html.write("Encrypt Sensitive Information</td>\n        <td>")
        t1530html.write(
            "Encrypt data stored at rest in cloud storage. Managed encryption keys can be rotated by most providers. At a minimum, ensure an incident response plan to storage breach includes rotating the keys and test for impact on client applications.{}".format(
                insert
            )
        )
        t1530html.write("Filter Network Traffic</td>\n        <td>")
        t1530html.write(
            "Cloud service providers support IP-based restrictions when accessing cloud resources. Consider using IP allowlisting along with user account management to ensure that data access is restricted not only to valid users but only from expected IP ranges to mitigate the use of stolen credentials to access data.{}".format(
                insert
            )
        )
        t1530html.write("Multi-factor Authentication</td>\n        <td>")
        t1530html.write(
            "Consider using multi-factor authentication to restrict access to resources and cloud storage APIs.{}".format(
                insert
            )
        )
        t1530html.write("Restrict File and Directory Permissions</td>\n        <td>")
        t1530html.write(
            "Use access control lists on storage systems and objects.{}".format(insert)
        )
        t1530html.write("User Account Management</td>\n        <td>")
        t1530html.write(
            "Configure user permissions groups and roles for access to cloud storage. Implement strict Identity and Access Management (IAM) controls to prevent access to storage solutions except for the applications, users, and services that require access. Ensure that temporary access tokens are issued rather than permanent credentials, especially when access is being granted to entities outside of the internal security boundary.{}".format(
                footer
            )
        )
    with open(sd + "t1602.html", "w") as t1602html:
        # description
        t1602html.write(
            "{}Adversaries may collect data related to managed devices from configuration repositories. Configuration repositories are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may also facilitate remote access and administration of devices.<br>".format(
                header
            )
        )
        t1602html.write(
            "Adversaries may target these repositories in order to collect large quantities of sensitive system administration data. Data from configuration repositories may be exposed by various protocols and software and can store a wide variety of data, much of which may align with adversary Discovery objectives."
        )
        # information
        t1602html.write("{}T1602</td>\n        <td>".format(headings))  # id
        t1602html.write("Network</td>\n        <td>")  # platforms
        t1602html.write("Collection</td>\n        <td>")  # tactics
        t1602html.write(
            "T1602.001: SNMP (MIB Dump)<br>T1602.002: Network Device Configuration Dump"
        )  # sub-techniques
        # indicator regex assignments
        t1602html.write("{}-".format(iocs))
        # related techniques
        t1602html.write("{}-</a></td>\n        <td>".format(related))
        t1602html.write("-")
        # mitigations
        t1602html.write(
            "{}Encrypt Sensitive Information</td>\n        <td>".format(mitigations)
        )
        t1602html.write(
            "Configure SNMPv3 to use the highest level of security (authPriv) available.{}".format(
                insert
            )
        )
        t1602html.write("Filter Network Traffic</td>\n        <td>")
        t1602html.write(
            "Apply extended ACLs to block unauthorized protocols outside the trusted network.{}".format(
                insert
            )
        )
        t1602html.write("Network Intrusion Prevention</td>\n        <td>")
        t1602html.write(
            "Configure intrusion prevention devices to detect SNMP queries and commands from unauthorized sources.{}".format(
                insert
            )
        )
        t1602html.write("Network Segmentation</td>\n        <td>")
        t1602html.write(
            "Segregate SNMP traffic on a separate management network.{}".format(insert)
        )
        t1602html.write("Software Configuration</td>\n        <td>")
        t1602html.write(
            "Allowlist MIB objects and implement SNMP views.{}".format(insert)
        )
        t1602html.write("UpdateSoftware</td>\n        <td>")
        t1602html.write(
            "Keep system images and software updated and migrate to SNMPv3.{}".format(
                footer
            )
        )
    with open(sd + "t1213.html", "w") as t1213html:
        # description
        t1213html.write(
            "{}Adversaries may leverage information repositories to mine valuable information. Information repositories are tools that allow for storage of information, typically to facilitate collaboration or information sharing between users, and can store a wide variety of data that may aid adversaries in further objectives, or direct access to the target information.<br>".format(
                header
            )
        )
        t1213html.write(
            "Adversaries may also collect information from shared storage repositories hosted on cloud infrastructure or in software-as-a-service (SaaS) applications, as storage is one of the more fundamental requirements for cloud services and systems.<br>"
        )
        t1213html.write(
            "The following is a brief list of example information that may hold potential value to an adversary and may also be found on an information repository:</li>\n        <ul>\n          <li>Policies, procedures, and standards</li>\n          <li>Physical / logical network diagrams</li>\n          <li>System architecture diagrams</li>\n          <li>Technical system documentation</li>\n          <li>Testing / development credentials</li>\n          <li>Work / project schedules</li>\n          <li>Source code snippets</li>\n          <li>Links to network shares and other internal resources</li>\n        </ul><br>Information stored in a repository may vary based on the specific instance or environment. Specific common information repositories include Sharepoint, Confluence, and enterprise databases such as SQL Server."
        )
        # information
        t1213html.write("{}T1213</td>\n        <td>".format(headings))  # id
        t1213html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>"
        )  # platforms
        t1213html.write("Collection</td>\n        <td>")  # tactics
        t1213html.write(
            "T1213.001: Confluence<br>T1213.002: Sharepoint"
        )  # sub-techniques
        # indicator regex assignments
        t1213html.write("{}-".format(iocs))
        # related techniques
        t1213html.write("{}-</a></td>\n        <td>".format(related))
        t1213html.write("-")
        # mitigations
        t1213html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1213html.write(
            "Consider periodic review of accounts and privileges for critical and sensitive repositories.{}".format(
                insert
            )
        )
        t1213html.write("User Account Management</td>\n        <td>")
        t1213html.write(
            "Enforce the principle of least-privilege. Consider implementing access control mechanisms that include both authentication and authorization.{}".format(
                insert
            )
        )
        t1213html.write("User Training</td>\n        <td>")
        t1213html.write(
            "Develop and publish policies that define acceptable information to be stored in repositories.{}".format(
                footer
            )
        )
    with open(sd + "t1005.html", "w") as t1005html:
        # description
        t1005html.write(
            "{}Adversaries may search local system sources, such as file systems or local databases, to find files of interest and sensitive data prior to Exfiltration.<br>".format(
                header
            )
        )
        t1005html.write(
            "Adversaries may do this using a Command and Scripting Interpreter, such as cmd, which has functionality to interact with the file system to gather information. Some adversaries may also use Automated Collection on the local system."
        )
        # information
        t1005html.write("{}T1005</td>\n        <td>".format(headings))  # id
        t1005html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1005html.write("Collection</td>\n        <td>")  # tactics
        t1005html.write("-")  # sub-techniques
        # indicator regex assignments
        t1005html.write("{}-".format(iocs))
        # related techniques
        t1005html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1059 target="_blank"">T1059</a></td>\n        <td>'.format(
                related
            )
        )
        t1005html.write("Command and Scripting Interpreter")
        t1005html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1119 target="_blank"">T1119</a></td>\n        <td>'.format(
                insert
            )
        )
        t1005html.write("Automated Collection")
        # mitigations
        t1005html.write("{}-</td>\n        <td>".format(mitigations))
        t1005html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1039.html", "w") as t1039html:
        # description
        t1039html.write(
            "{}Adversaries may search network shares on computers they have compromised to find files of interest.<br>".format(
                header
            )
        )
        t1039html.write(
            "Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration.<br>"
        )
        t1039html.write(
            "Interactive command shells may be in use, and common functionality within cmd may be used to gather information."
        )
        # information
        t1039html.write("{}T1039</td>\n        <td>".format(headings))  # id
        t1039html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1039html.write("Collection</td>\n        <td>")  # tactics
        t1039html.write("-")  # sub-techniques
        # indicator regex assignments
        t1039html.write("{}-".format(iocs))
        # related techniques
        t1039html.write("{}-</a></td>\n        <td>".format(related))
        t1039html.write("-")
        # mitigations
        t1039html.write("{}-</td>\n        <td>".format(mitigations))
        t1039html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1025.html", "w") as t1025html:
        # description
        t1025html.write(
            "{}Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration.<br>".format(
                header
            )
        )
        t1025html.write(
            "Interactive command shells may be in use, and common functionality within cmd may be used to gather information.<br>"
        )
        t1025html.write(
            "Some adversaries may also use Automated Collection on removable media."
        )
        # information
        t1025html.write("{}T1025</td>\n        <td>".format(headings))  # id
        t1025html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1025html.write("Collection</td>\n        <td>")  # tactics
        t1025html.write("-")  # sub-techniques
        # indicator regex assignments
        t1025html.write("{}DISPLAY</li>\n        <li>".format(iocs))
        t1025html.write("HID</li>\n        <li>")
        t1025html.write("PCI</li>\n        <li>")
        t1025html.write("UMB</li>\n        <li>")
        t1025html.write("FDC</li>\n        <li>")
        t1025html.write("SCSI</li>\n        <li>")
        t1025html.write("STORAGE</li>\n        <li>")
        t1025html.write("USB</li>\n        <li>")
        t1025html.write("WpdBusEnumRoot</li>")
        # related techniques
        t1025html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1119 target="_blank"">T1119</a></td>\n        <td>'.format(
                related
            )
        )
        t1025html.write("Automated Collection")
        # mitigations
        t1025html.write("{}-</td>\n        <td>".format(mitigations))
        t1025html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1074.html", "w") as t1074html:
        # description
        t1074html.write(
            "{}Adversaries may stage collected data in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location.<br>".format(
                header
            )
        )
        t1074html.write(
            "In cloud environments, adversaries may stage data within a particular instance or virtual machine before exfiltration. An adversary may Create Cloud Instance and stage data in that instance.<br>"
        )
        t1074html.write(
            "Adversaries may choose to stage data from a victim network in a centralized location prior to Exfiltration to minimize the number of connections made to their C2 server and better evade detection."
        )
        # information
        t1074html.write("{}T1074</td>\n        <td>".format(headings))  # id
        t1074html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>"
        )  # platforms
        t1074html.write("Collection</td>\n        <td>")  # tactics
        t1074html.write(
            "T1074.001: Local Data Staging<br>T1074.002: Remote Data Staging"
        )
        # indicator regex assignments
        t1074html.write("{}-".format(iocs))
        # related techniques
        t1074html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1560 target="_blank"">T1560</a></td>\n        <td>'.format(
                related
            )
        )
        t1074html.write("Archive Collected Data")
        t1074html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1578 target="_blank"">T1578</a></td>\n        <td>'.format(
                insert
            )
        )
        t1074html.write("Modify Cloud Compute Infrastructure: Create Cloud Instance")
        # mitigations
        t1074html.write("{}-</td>\n        <td>".format(mitigations))
        t1074html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1114.html", "w") as t1114html:
        # description
        t1114html.write(
            "{}Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries. Adversaries can collect or forward email from mail servers or clients.".format(
                header
            )
        )
        # information
        t1114html.write("{}T1114</td>\n        <td>".format(headings))  # id
        t1114html.write("Windows, Office 365</td>\n        <td>")  # platforms
        t1114html.write("Collection</td>\n        <td>")  # tactics
        t1114html.write(
            "T1114.001: Local Email Collection<br>T1114.002: Remote Email Collection<br>T1114.003: Email Forwarding Rule"
        )  # sub-techniques
        # indicator regex assignments
        t1114html.write("{}.ost</li>\n        <li>".format(iocs))
        t1114html.write(".pst</li>\n        <li>")
        t1114html.write(".msg</li>\n        <li>")
        t1114html.write(".eml</li>\n        <li>")
        t1114html.write("*MailboxExportEequest</li>\n        <li>")
        t1114html.write("X-MS-Exchange-Organization-AutoForwarded</li>\n        <li>")
        t1114html.write("X-MailFwdBy</li>\n        <li>")
        t1114html.write("X-Forwarded-To</li>\n        <li>")
        t1114html.write("ForwardingSMTPAddress</li>")
        # related techniques
        t1114html.write("{}-</a></td>\n        <td>".format(related))
        t1114html.write("-")
        # mitigations
        t1114html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1114html.write(
            "Enterprise email solutions have monitoring mechanisms that may include the ability to audit auto-forwarding rules on a regular basis. In an Exchange environment, Administrators can use Get-InboxRule to discover and remove potentially malicious auto-forwarding rules.{}".format(
                insert
            )
        )
        t1114html.write("Encrypt Sensitive Information</td>\n        <td>")
        t1114html.write(
            "Use of encryption provides an added layer of security to sensitive information sent over email. Encryption using public key cryptography requires the adversary to obtain the private certificate along with an encryption key to decrypt messages.{}".format(
                insert
            )
        )
        t1114html.write("Multi-factor Authentication</td>\n        <td>")
        t1114html.write(
            "Use of multi-factor authentication for public-facing webmail servers is a recommended best practice to minimize the usefulness of usernames and passwords to adversaries.{}".format(
                footer
            )
        )
    with open(sd + "t1185.html", "w") as t1185html:
        # description
        t1185html.write(
            "{}Adversaries can take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify behavior, and intercept information as part of various man in the browser techniques.<br>".format(
                header
            )
        )
        t1185html.write(
            "A specific example is when an adversary injects software into a browser that allows an them to inherit cookies, HTTP sessions, and SSL client certificates of a user and use the browser as a way to pivot into an authenticated intranet.<br>"
        )
        t1185html.write(
            "Browser pivoting requires the SeDebugPrivilege and a high-integrity process to execute. Browser traffic is pivoted from the adversary's browser through the user's browser by setting up an HTTP proxy which will redirect any HTTP and HTTPS traffic.<br>"
        )
        t1185html.write(
            "This does not alter the user's traffic in any way. The proxy connection is severed as soon as the browser is closed. Whichever browser process the proxy is injected into, the adversary assumes the security context of that process. Browsers typically create a new process for each tab that is opened and permissions and certificates are separated accordingly.<br>"
        )
        t1185html.write(
            "With these permissions, an adversary could browse to any resource on an intranet that is accessible through the browser and which the browser has sufficient permissions, such as Sharepoint or webmail. Browser pivoting also eliminates the security provided by 2-factor authentication."
        )
        # information
        t1185html.write("{}T1185</td>\n        <td>".format(headings))  # id
        t1185html.write("Windows</td>\n        <td>")  # platforms
        t1185html.write("Collection</td>\n        <td>")  # tactics
        t1185html.write("-")  # sub-techniques
        # indicator regex assignments
        t1185html.write("{}-".format(iocs))
        # related techniques
        t1185html.write("{}-</a></td>\n        <td>".format(related))
        t1185html.write("-")
        # mitigations
        t1185html.write(
            "{}User Account Management</td>\n        <td>".format(mitigations)
        )
        t1185html.write(
            "Since browser pivoting requires a high integrity process to launch from, restricting user permissions and addressing Privilege Escalation and Bypass User Account Control opportunities can limit the exposure to this technique.{}".format(
                insert
            )
        )
        t1185html.write("User Training</td>\n        <td>")
        t1185html.write(
            "Close all browser sessions regularly and when they are no longer needed.{}".format(
                footer
            )
        )
    with open(sd + "t1113.html", "w") as t1113html:
        # description
        t1113html.write(
            "{}Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations.<br>".format(
                header
            )
        )
        t1113html.write(
            "Taking a screenshot is also typically possible through native utilities or API calls, such as CopyFromScreen, xwd, or screencapture."
        )
        # information
        t1113html.write("{}T1113</td>\n        <td>".format(headings))  # id
        t1113html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1113html.write("Collection</td>\n        <td>")  # tactics
        t1113html.write("-")  # sub-techniques
        # indicator regex assignments
        t1113html.write("{}CopyFromScreen</li>\n        <li>".format(iocs))
        t1113html.write("xwd</li>\n        <li>")
        t1113html.write("screencapture</li>")
        # related techniques
        t1113html.write("{}-</a></td>\n        <td>".format(related))
        t1113html.write("-")
        # mitigations
        t1113html.write("{}-</td>\n        <td>".format(mitigations))
        t1113html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1125.html", "w") as t1125html:
        # description
        t1125html.write(
            "{}An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files.<br>".format(
                header
            )
        )
        t1125html.write(
            "Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture video or images. Video or image files may be written to disk and exfiltrated later. This technique differs from Screen Capture due to use of specific devices or applications for video recording rather than capturing the victim's screen.<br>"
        )
        t1125html.write(
            "In macOS, there are a few different malware samples that record the user's webcam such as FruitFly and Proton."
        )
        # information
        t1125html.write("{}T1125</td>\n        <td>".format(headings))  # id
        t1125html.write("Windows, macOS</td>\n        <td>")  # platforms
        t1125html.write("Collection</td>\n        <td>")  # tactics
        t1125html.write("-")  # sub-techniques
        # indicator regex assignments
        t1125html.write("{}.mp4</li>\n        <li>".format(iocs))
        t1125html.write("mkv</li>\n        <li>")
        t1125html.write("avi</li>\n        <li>")
        t1125html.write("mov</li>\n        <li>")
        t1125html.write("wmv</li>\n        <li>")
        t1125html.write("mpg</li>\n        <li>")
        t1125html.write("mpeg</li>\n        <li>")
        t1125html.write("m4v</li>\n        <li>")
        t1125html.write("flv</li>")
        # related techniques
        t1125html.write("{}-</a></td>\n        <td>".format(related))
        t1125html.write("-")
        # mitigations
        t1125html.write("{}-</td>\n        <td>".format(mitigations))
        t1125html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
