#!/usr/bin/env python3 -tt


def create_exfiltration_html(sd, header, headings, iocs, related, insert, mitigations, footer):
    with open(sd + "t1020.html", "w") as t1020html:
        # description
        t1020html.write(
            "{}Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection.<br>".format(
                header
            )
        )
        t1020html.write(
            "When automated exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as Exfiltration Over C2 Channel and Exfiltration Over Alternative Protocol."
        )
        # information
        t1020html.write("{}T1030</td>\n        <td>".format(headings))  # id
        t1020html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1020html.write("Exfiltration</td>\n        <td>")  # tactics
        t1020html.write("T1020.001: Traffic Duplication")
        # indicator regex assignments
        t1020html.write("{}-".format(iocs))
        # related techniques
        t1020html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1041 target="_blank"">T1041</a></td>\n        <td>'.format(
                related
            )
        )
        t1020html.write("Exfiltration Over C2 Channel")
        t1020html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1048 target="_blank"">T1048</a></td>\n        <td>'.format(
                insert
            )
        )
        t1020html.write("Exfiltration Over Alternative Protocol")
        # mitigations
        t1020html.write("{}-</td>\n        <td>".format(mitigations))
        t1020html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1030.html", "w") as t1030html:
        # description
        t1030html.write(
            "{}An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.".format(
                header
            )
        )
        # information
        t1030html.write("{}T1030</td>\n        <td>".format(headings))  # id
        t1030html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1030html.write("Exfiltration</td>\n        <td>")  # tactics
        t1030html.write("-")  # sub-techniques
        # indicator regex assignments
        t1030html.write("{}-".format(iocs))
        # related techniques
        t1030html.write("{}-</a></td>\n        <td>".format(related))
        t1030html.write("-")
        # mitigations
        t1030html.write(
            "{}Network Intrusion Prevention</td>\n        <td>".format(mitigations)
        )
        t1030html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level.{}".format(
                footer
            )
        )
    with open(sd + "t1048.html", "w") as t1048html:
        # description
        t1048html.write(
            "{}Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.<br>".format(
                header
            )
        )
        t1048html.write(
            "Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Different protocol channels could also include Web services such as cloud storage. Adversaries may also opt to encrypt and/or obfuscate these alternate channels.<br>"
        )
        t1048html.write(
            "Exfiltration Over Alternative Protocol can be done using various common operating system utilities such as Net/SMB or FTP."
        )
        # information
        t1048html.write("{}T1048</td>\n        <td>".format(headings))  # id
        t1048html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1048html.write("Exfiltration</td>\n        <td>")  # tactics
        t1048html.write(
            "T1048.001: Exfiltration Over Symmetric Encrypted Non-C2 Protocol<br>T1048.002: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol<br>T1048.003: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol"
        )  # sub-techniques
        # indicator regex assignments
        t1048html.write(
            "{}Ports: 20, 21, 22, 23, 25, 53, 69, 80, 110, 135, 143, 443, 465, 989, 990, 993, 995, 3389, 5355, 5800, 5895, 5900, 5938, 5984, 5986, 8200".format(
                iocs
            )
        )
        # related techniques
        t1048html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1029 target="_blank"">T1029</td>\n        <td>'.format(
                related
            )
        )
        t1048html.write("Scheduled Transfer")
        # mitigations
        t1048html.write(
            "{}Filter Network Traffic</td>\n        <td>".format(mitigations)
        )
        t1048html.write(
            "Enforce proxies and use dedicated servers for services such as DNS and only allow those systems to communicate over respective ports/protocols, instead of all systems within a network.{}".format(
                insert
            )
        )
        t1048html.write("Network Intrusion Prevention</td>\n        <td>")
        t1048html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level.{}".format(
                insert
            )
        )
        t1048html.write("Network Segmentation</td>\n        <td>")
        t1048html.write(
            "Follow best practices for network firewall configurations to allow only necessary ports and traffic to enter and exit the network.{}".format(
                footer
            )
        )
    with open(sd + "t1041.html", "w") as t1041html:
        # description
        t1041html.write(
            "{}Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.".format(
                header
            )
        )
        # information
        t1041html.write("{}T1041</td>\n        <td>".format(headings))  # id
        t1041html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1041html.write("Exfiltration</td>\n        <td>")  # tactics
        t1041html.write("-")  # sub-techniques
        # indicator regex assignments
        t1041html.write("{}Ports: 20, 21, 25, 445, 53, 80, 443, 445".format(iocs))
        # related techniques
        t1041html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1029 target="_blank"">T1029</td>\n        <td>'.format(
                related
            )
        )
        t1041html.write("Scheduled Transfer")
        # mitigations
        t1041html.write(
            "{}Network Intrusion Prevention</td>\n        <td>".format(mitigations)
        )
        t1041html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool command and control signatures over time or construct protocols in such a way to avoid detection by common defensive tools.{}".format(
                footer
            )
        )
    with open(sd + "t1011.html", "w") as t1011html:
        # description
        t1011html.write(
            "{}Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel.<br>".format(
                header
            )
        )
        t1011html.write(
            "Adversaries may choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network."
        )
        # information
        t1011html.write("{}T1011</td>\n        <td>".format(headings))  # id
        t1011html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1011html.write("Exfiltration</td>\n        <td>")  # tactics
        t1011html.write("T1011.001: Exfiltration Over Bluetooth")  # sub-techniques
        # indicator regex assignments
        t1011html.write("{}bluetooth".format(iocs))
        # related techniques
        t1011html.write("{}-</a></td>\n        <td>".format(related))
        t1011html.write("-")
        # mitigations
        t1011html.write(
            "{}Operating System Configuration</td>\n        <td>".format(mitigations)
        )
        t1011html.write(
            "Prevent the creation of new network adapters where possible.{}".format(
                footer
            )
        )
    with open(sd + "t1052.html", "w") as t1052html:
        # description
        t1052html.write(
            "{}Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user.<br>".format(
                header
            )
        )
        t1052html.write(
            "Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems."
        )
        # information
        t1052html.write("{}T1052</td>\n        <td>".format(headings))  # id
        t1052html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1052html.write("Exfiltration</td>\n        <td>")  # tactics
        t1052html.write("T1052.001: Exfiltration over USB")  # sub-techniques
        # indicator regex assignments
        t1052html.write("{}DISPLAY</li>\n        <li>".format(iocs))
        t1052html.write("HID</li>\n        <li>")
        t1052html.write("PCI</li>\n        <li>")
        t1052html.write("UMB</li>\n        <li>")
        t1052html.write("FDC</li>\n        <li>")
        t1052html.write("SCSI</li>\n        <li>")
        t1052html.write("STORAGE</li>\n        <li>")
        t1052html.write("USB</li>\n        <li>")
        t1052html.write("WpdBusEnumRoot</li>")
        # related techniques
        t1052html.write("{}-</a></td>\n        <td>".format(related))
        t1052html.write("-")
        # mitigations
        t1052html.write(
            "{}Disable or Remove Feature or Program</td>\n        <td>".format(
                mitigations
            )
        )
        t1052html.write(
            "Disable Autorun if it is unnecessary. Disallow or restrict removable media at an organizational policy level if they are not required for business operations.{}".format(
                insert
            )
        )
        t1052html.write("Limit Hardware Installation</td>\n        <td>")
        t1052html.write(
            "Limit the use of USB devices and removable media within a network.{}".format(
                footer
            )
        )
    with open(sd + "t1567.html", "w") as t1567html:
        # description
        t1567html.write(
            "{}Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel.<br>".format(
                header
            )
        )
        t1567html.write(
            "Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise.<br>"
        )
        t1567html.write(
            "Firewall rules may also already exist to permit traffic to these services.<br>"
        )
        t1567html.write(
            "Web service providers also commonly use SSL/TLS encryption, giving adversaries an added level of protection."
        )
        # information
        t1567html.write("{}T1567</td>\n        <td>".format(headings))  # id
        t1567html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1567html.write("Execution</td>\n        <td>")  # tactics
        t1567html.write(
            "T1567.001: Exfiltration to Code Repository<br>T1567.002: Exfiltration to Cloud Storage"
        )  # sub-techniques
        # indicator regex assignments
        t1567html.write("{}github</li>\n        <li>".format(iocs))
        t1567html.write("gitlab</li>\n        <li>")
        t1567html.write("bitbucket</li>\n        <li>")
        t1567html.write("dropbox</li>\n        <li>")
        t1567html.write("onedrive</li>\n        <li>")
        t1567html.write("4shared</li>")
        # related techniques
        t1567html.write("{}-</a></td>\n        <td>".format(related))
        t1567html.write("-")
        # mitigations
        t1567html.write(
            "{}Restrict Web-Based Content</td>\n        <td>".format(mitigations)
        )
        t1567html.write(
            "Web proxies can be used to enforce an external network communication policy that prevents use of unauthorized external services.{}".format(
                footer
            )
        )
    with open(sd + "t1029.html", "w") as t1029html:
        # description
        t1029html.write(
            "{}Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.".format(
                header
            )
        )
        # information
        t1029html.write("{}T1029</td>\n        <td>".format(headings))  # id
        t1029html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1029html.write("Exfiltration</td>\n        <td>")  # tactics
        t1029html.write("-")
        # indicator regex assignments
        t1029html.write("{}-".format(iocs))
        # related techniques
        t1029html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1041 target="_blank"">T1041</a></td>\n        <td>'.format(
                related
            )
        )
        t1029html.write("Exfiltration Over C2 Channel")
        t1029html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1048 target="_blank"">T1048</a></td>\n        <td>'.format(
                insert
            )
        )
        t1029html.write("Exfiltration Over Alternative Protocol")
        # mitigations
        t1029html.write(
            "{}Network Intrusion Prevention</td>\n        <td>".format(mitigations)
        )
        t1029html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool command and control signatures over time or construct protocols in such a way to avoid detection by common defensive tools.{}".format(
                footer
            )
        )
    with open(sd + "t1537.html", "w") as t1537html:
        # description
        t1537html.write(
            "{}Adversaries may exfiltrate data by transferring the data, including backups of cloud environments, to another cloud account they control on the same service to avoid typical file transfers/downloads and network-based exfiltration detection.<br>".format(
                header
            )
        )
        t1537html.write(
            "A defender who is monitoring for large transfers to outside the cloud environment through normal file transfers or over command and control channels may not be watching for data transfers to another account within the same cloud provider.<br>"
        )
        t1537html.write(
            "Such transfers may utilize existing cloud provider APIs and the internal address space of the cloud provider to blend into normal traffic or avoid data transfers over external network interfaces.<br>"
        )
        t1537html.write(
            "Incidents have been observed where adversaries have created backups of cloud instances and transferred them to separate accounts."
        )
        # information
        t1537html.write("{}T1537</td>\n        <td>".format(headings))  # id
        t1537html.write("AWS, Azure, GCP</td>\n        <td>")  # platforms
        t1537html.write("Exfiltration</td>\n        <td>")  # tactics
        t1537html.write("-")  # sub-techniques
        # indicator regex assignments
        t1537html.write("{}onedrive</li>\n        <li>".format(iocs))
        t1537html.write("1drv</li>\n        <li>")
        t1537html.write("azure</li>\n        <li>")
        t1537html.write("icloud</li>\n        <li>")
        t1537html.write("cloudrive</li>\n        <li>")
        t1537html.write("dropbox</li>\n        <li>")
        t1537html.write("drive\\.google</li>\n        <li>")
        t1537html.write("mediafire</li>\n        <li>")
        t1537html.write("zippyshare</li>\n        <li>")
        t1537html.write("megaupload</li>\n        <li>")
        t1537html.write("4shared</li>")
        # related techniques
        t1537html.write("{}-</a></td>\n        <td>".format(related))
        t1537html.write("-")
        # mitigations
        t1537html.write(
            "{}Filter Network Traffic</td>\n        <td>".format(mitigations)
        )
        t1537html.write(
            "Implement network-based filtering restrictions to prohibit data transfers to untrusted VPCs.{}".format(
                insert
            )
        )
        t1537html.write("Password Policies</td>\n        <td>")
        t1537html.write(
            "Consider rotating access keys within a certain number of days to reduce the effectiveness of stolen credentials.{}".format(
                insert
            )
        )
        t1537html.write("User Account Management</td>\n        <td>")
        t1537html.write(
            "Limit user account and IAM policies to the least privileges required. Consider using temporary credentials for accounts that are only valid for a certain period of time to reduce the effectiveness of compromised accounts.{}".format(
                footer
            )
        )
