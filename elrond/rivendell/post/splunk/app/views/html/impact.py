#!/usr/bin/env python3 -tt


def create_impact_html(
    sd, header, headings, iocs, related, insert, mitigations, footer
):
    with open(sd + "t1531.html", "w") as t1531html:
        # description
        t1531html.write(
            "{}Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts.<br>".format(
                header
            )
        )
        t1531html.write(
            "Adversaries may also subsequently log off and/or reboot boxes to set malicious changes into place."
        )
        # information
        t1531html.write("{}T1531</td>\n        <td>".format(headings))  # id
        t1531html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1531html.write("Impact</td>\n        <td>")  # tactics
        t1531html.write("-")  # sub-techniques
        # indicator regex assignments
        t1531html.write("{}Events IDs: 4723, 4724, 4726, 4740".format(iocs))
        # related techniques
        t1531html.write("{}-</a></td>\n        <td>".format(related))
        t1531html.write("-")
        # mitigations
        t1531html.write("{}-</td>\n        <td>".format(mitigations))
        t1531html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1485.html", "w") as t1485html:
        # description
        t1485html.write(
            "{}Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives.<br>".format(
                header
            )
        )
        t1485html.write(
            "Common operating system file deletion commands such as del and rm often only remove pointers to files without wiping the contents of the files themselves, making the files recoverable by proper forensic methowrite_audit_log_entryy. This behavior is distinct from Disk Content Wipe and Disk Structure Wipe because individual files are destroyed rather than sections of a storage disk or the disk's logical structure.<br>"
        )
        t1485html.write(
            "Adversaries may attempt to overwrite files and directories with randomly generated data to make it irrecoverable. In some cases politically oriented image files have been used to overwrite data.<br>"
        )
        t1485html.write(
            "To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware designed for destroying data may have worm-like features to propagate across a network by leveraging additional techniques like Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares."
        )
        # information
        t1485html.write("{}T1485</td>\n        <td>".format(headings))  # id
        t1485html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1485html.write("Impact</td>\n        <td>")  # tactics
        t1485html.write("-")  # sub-techniques
        # indicator regex assignments
        t1485html.write("{}del</li>\n        <li>".format(iocs))
        t1485html.write("rm</li>\n        <li>")
        t1485html.write("/delete</li>\n        <li>")
        t1485html.write("sdelete</li>")
        # related techniques
        t1485html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1561 target="_blank"">T1561</a></td>\n        <td>'.format(
                related
            )
        )
        t1485html.write("Disk Wipe: Disk Content Wipe")
        t1485html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1561 target="_blank"">T1561</a></td>\n        <td>'.format(
                insert
            )
        )
        t1485html.write("Disk Wipe: Disk Structure Wipe")
        t1485html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1078 target="_blank"">T1078</a></td>\n        <td>'.format(
                insert
            )
        )
        t1485html.write("Valid Accounts")
        t1485html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1003 target="_blank"">T1003</a></td>\n        <td>'.format(
                insert
            )
        )
        t1485html.write("OS Credential Dumping")
        t1485html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1021 target="_blank"">T1021</a></td>\n        <td>'.format(
                insert
            )
        )
        t1485html.write("Remote Services: SMB/Windows Admin Shares")
        # mitigations
        t1485html.write("{}Data Backup</td>\n        <td>".format(mitigations))
        t1485html.write(
            "Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery.{}".format(
                footer
            )
        )
    with open(sd + "t1486.html", "w") as t1486html:
        # description
        t1486html.write(
            "{}Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key.<br>".format(
                header
            )
        )
        t1486html.write(
            "This may be done in order to extract monetary compensation from a victim in exchange for decryption or a decryption key (ransomware) or to render data permanently inaccessible in cases where the key is not saved or transmitted.<br>"
        )
        t1486html.write(
            "In the case of ransomware, it is typical that common user files like Office documents, PDFs, images, videos, audio, text, and source code files will be encrypted. In some cases, adversaries may encrypt critical system files, disk partitions, and the MBR.<br>"
        )
        t1486html.write(
            "To maximize impact on the target organization, malware designed for encrypting data may have worm-like features to propagate across a network by leveraging other attack techniques like Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares."
        )
        # information
        t1486html.write("{}T1486</td>\n        <td>".format(headings))  # id
        t1486html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1486html.write("Impact</td>\n        <td>")  # tactics
        t1486html.write("-")  # sub-techniques
        # indicator regex assignments
        t1486html.write("{}-".format(iocs))
        # related techniques
        t1486html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1078 target="_blank"">T1078</a></td>\n        <td>'.format(
                related
            )
        )
        t1486html.write("Valid Accounts")
        t1486html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1003 target="_blank"">T1003</a></td>\n        <td>'.format(
                insert
            )
        )
        t1486html.write("OS Credential Dumping")
        t1486html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1021 target="_blank"">T1021</a></td>\n        <td>'.format(
                insert
            )
        )
        t1486html.write("Remote Services: SMB/Windows Admin Shares")
        # mitigations
        t1486html.write("{}Data Backup</td>\n        <td>".format(mitigations))
        t1486html.write(
            "Consider implementing IT disaster recovery plans that contain procedures for regularly taking and testing data backups that can be used to restore organizational data.[48] Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery. Consider enabling versioning in cloud environments to maintain backup copies of storage objects.{}".format(
                footer
            )
        )
    with open(sd + "t1565.html", "w") as t1565html:
        # description
        t1565html.write(
            "{}Adversaries may insert, delete, or manipulate data in order to manipulate external outcomes or hide activity. By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.<br>".format(
                header
            )
        )
        t1565html.write(
            "The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary.<br>"
        )
        t1565html.write(
            "For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact."
        )
        # information
        t1565html.write("{}T1565</td>\n        <td>".format(headings))  # id
        t1565html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1565html.write("Impact</td>\n        <td>")  # tactics
        t1565html.write(
            "T1565.001: Stored Data Manipulation<br>T1565.002: Transmitted Data Manipulation<br>T1565.003: Runtime Data Manipulation"
        )  # sub-techniques
        # indicator regex assignments
        t1565html.write("{}-".format(iocs))
        # related techniques
        t1565html.write("{}-</a></td>\n        <td>".format(related))
        t1565html.write("-")
        # mitigations
        t1565html.write(
            "{}Encrypt Sensitive Information</td>\n        <td>".format(mitigations)
        )
        t1565html.write(
            "Consider encrypting important information to reduce an adversary’s ability to perform tailored data modifications.{}".format(
                insert
            )
        )
        t1565html.write("Network Segmentation</td>\n        <td>")
        t1565html.write(
            "Identify critical business and system processes that may be targeted by adversaries and work to isolate and secure those systems against unauthorized access and tampering.{}".format(
                insert
            )
        )
        t1565html.write("Remote Data Storage</td>\n        <td>")
        t1565html.write(
            "Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and manipulate backups.{}".format(
                insert
            )
        )
        t1565html.write("Restrict File and Directory Permissions</td>\n        <td>")
        t1565html.write(
            "Ensure least privilege principles are applied to important information resources to reduce exposure to data manipulation risk.{}".format(
                footer
            )
        )
    with open(sd + "t1491.html", "w") as t1491html:
        # description
        t1491html.write(
            "{}Adversaries may modify visual content available internally or externally to an enterprise network. Reasons for Defacement include delivering messaging, intimidation, or claiming (possibly false) credit for an intrusion.<br>".format(
                header
            )
        )
        t1491html.write(
            "Disturbing or offensive images may be used as a part of Defacement in order to cause user discomfort, or to pressure compliance with accompanying messages."
        )
        # information
        t1491html.write("{}T1491</td>\n        <td>".format(headings))  # id
        t1491html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>"
        )  # platforms
        t1491html.write("Impact</td>\n        <td>")  # tactics
        t1491html.write(
            "T1491.001: Internal Defacement<br>T1491.002: External Defacement"
        )  # sub-techniques
        # indicator regex assignments
        t1491html.write("{}-".format(iocs))
        # related techniques
        t1491html.write("{}-</a></td>\n        <td>".format(related))
        t1491html.write("-")
        # mitigations
        t1491html.write("{}Data Backup</td>\n        <td>".format(mitigations))
        t1491html.write(
            "Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery.{}".format(
                footer
            )
        )
    with open(sd + "t1561.html", "w") as t1561html:
        # description
        t1561html.write(
            "{}Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources.<br>".format(
                header
            )
        )
        t1561html.write(
            "With direct write access to a disk, adversaries may attempt to overwrite portions of disk data. Adversaries may opt to wipe arbitrary portions of disk data and/or wipe disk structures like the master boot record (MBR). A complete wipe of all disk sectors may be attempted.<br>"
        )
        t1561html.write(
            "To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware used for wiping disks may have worm-like features to propagate across a network by leveraging additional techniques like Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares."
        )
        # information
        t1561html.write("{}T1561</td>\n        <td>".format(headings))  # id
        t1561html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1561html.write("Impact</td>\n        <td>")  # tactics
        t1561html.write(
            "T1561.001 Disk Content Wipe<br>T1561.002: Disk Structure Wipe"
        )  # sub-techniques
        # indicator regex assignments
        t1561html.write("{}-".format(iocs))
        # related techniques
        t1561html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1078 target="_blank"">T1078</a></td>\n        <td>'.format(
                related
            )
        )
        t1561html.write("Valid Accounts")
        t1561html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1003 target="_blank"">T1003</a></td>\n        <td>'.format(
                insert
            )
        )
        t1561html.write("OS Credential Dumping")
        t1561html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1021 target="_blank"">T1021</a></td>\n        <td>'.format(
                insert
            )
        )
        t1561html.write("Remote Services: SMB/Windows Admin Shares")
        t1561html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1485 target="_blank"">T1485</a></td>\n        <td>'.format(
                insert
            )
        )
        t1561html.write("Data Destruction")
        # mitigations
        t1561html.write("{}Data Backup</td>\n        <td>".format(mitigations))
        t1561html.write(
            "Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data.[2] Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery.{}".format(
                footer
            )
        )
    with open(sd + "t1499.html", "w") as t1499html:
        # description
        t1499html.write(
            "{}Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Endpoint DoS can be performed by exhausting the system resources those services are hosted on or exploiting the system to cause a persistent crash condition.<br>".format(
                header
            )
        )
        t1499html.write(
            "Example services include websites, email services, DNS, and web-based applications. Adversaries have been observed conducting DoS attacks for political purposes and to support other malicious activities, including distraction, hacktivism, and extortion.<br>"
        )
        t1499html.write(
            "An Endpoint DoS denies the availability of a service without saturating the network used to provide access to the service. Adversaries can target various layers of the application stack that is hosted on the system used to provide the service.<br>"
        )
        t1499html.write(
            "These layers include the Operating Systems (OS), server applications such as web servers, DNS servers, databases, and the (typically web-based) applications that sit on top of them.<br>"
        )
        t1499html.write(
            "Attacking each layer requires different techniques that take advantage of bottlenecks that are unique to the respective components.<br>"
        )
        t1499html.write(
            "A DoS attack may be generated by a single system or multiple systems spread across the internet, which is commonly referred to as a distributed DoS (DDoS). To perform DoS attacks against endpoint resources, several aspects apply to multiple methods, including IP address spoofing and botnets. Adversaries may use the original IP address of an attacking system, or spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection.<br>"
        )
        t1499html.write(
            "This can increase the difficulty defenders have in defending against the attack by reducing or eliminating the effectiveness of filtering by the source address on network defense devices.<br>"
        )
        t1499html.write(
            "Botnets are commonly used to conduct DDoS attacks against networks and services. Large botnets can generate a significant amount of traffic from systems spread across the global internet.<br>"
        )
        t1499html.write(
            "Adversaries may have the resources to build out and control their own botnet infrastructure or may rent time on an existing botnet to conduct an attack.<br>"
        )
        t1499html.write(
            "In some of the worst cases for DDoS, so many systems are used to generate requests that each one only needs to send out a small amount of traffic to produce enough volume to exhaust the target's resources.<br>"
        )
        t1499html.write(
            "In such circumstances, distinguishing DDoS traffic from legitimate clients becomes exceedingly difficult. Botnets have been used in some of the most high-profile DDoS attacks, such as the 2012 series of incidents that targeted major US banks.<br>"
        )
        t1499html.write(
            "In cases where traffic manipulation is used, there may be points in the the global network (such as high traffic gateway routers) where packets can be altered and cause legitimate clients to execute code that directs network packets toward a target in high volume.<br>"
        )
        t1499html.write(
            "This type of capability was previously used for the purposes of web censorship where client HTTP traffic was modified to include a reference to JavaScript that generated the DDoS code to overwhelm target web servers. For attacks attempting to saturate the providing network, see Network Denial of Service."
        )
        # information
        t1499html.write("{}T1499</td>\n        <td>".format(headings))  # id
        t1499html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>"
        )  # platforms
        t1499html.write("Impact</td>\n        <td>")  # tactics
        t1499html.write(
            "T1499.001: OS Exhaustion Flood<br> T1499.002: Service Exhaustion Flood<br> T1499.003: Application Exhaustion Flood<br> T1499.004: Application or System Exploitation"
        )  # sub-techniques
        # indicator regex assignments
        t1499html.write("{}-".format(iocs))
        # related techniques
        t1499html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1498 target="_blank"">T1498</a></td>\n        <td>'.format(
                related
            )
        )
        t1499html.write("Network Denial of Service")
        # mitigations
        t1499html.write(
            "{}Filter Network Traffic</td>\n        <td>".format(mitigations)
        )
        t1499html.write(
            "Leverage services provided by Content Delivery Networks (CDN) or providers specializing in DoS mitigations to filter traffic upstream from services. Filter boundary traffic by blocking source addresses sourcing the attack, blocking ports that are being targeted, or blocking protocols being used for transport. To defend against SYN floods, enable SYN Cookies.{}".format(
                footer
            )
        )
    with open(sd + "t1495.html", "w") as t1495html:
        # description
        t1495html.write(
            "{}Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot.<br>".format(
                header
            )
        )
        t1495html.write(
            "Firmware is software that is loaded and executed from non-volatile memory on hardware devices in order to initialize and manage device functionality.<br>"
        )
        t1495html.write(
            "These devices could include the motherboard, hard drive, or video cards."
        )
        # information
        t1495html.write("{}T1495</td>\n        <td>".format(headings))  # id
        t1495html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1495html.write("Impact</td>\n        <td>")  # tactics
        t1495html.write("-")  # sub-techniques
        # indicator regex assignments
        t1495html.write("{}-".format(iocs))
        # related techniques
        t1495html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t0000 target="_blank"">T0000</a></td>\n        <td>'.format(
                related
            )
        )
        t1495html.write("-")
        # mitigations
        t1495html.write("{}Boot Integrity</td>\n        <td>".format(mitigations))
        t1495html.write(
            "Check the integrity of the existing BIOS and device firmware to determine if it is vulnerable to modification.{}".format(
                insert
            )
        )
        t1495html.write("Privileged Account Management</td>\n        <td>")
        t1495html.write(
            "Prevent adversary access to privileged accounts or access necessary to replace system firmware.{}".format(
                insert
            )
        )
        t1495html.write("Update Software</td>\n        <td>")
        t1495html.write(
            "Patch the BIOS and other firmware as necessary to prevent successful use of known vulnerabilities.{}".format(
                footer
            )
        )
    with open(sd + "t1490.html", "w") as t1490html:
        # description
        t1490html.write(
            "{}Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.<br>".format(
                header
            )
        )
        t1490html.write(
            "Operating systems may contain features that can help fix corrupted systems, such as a backup catalog, volume shadow copies, and automatic repair features.<br>"
        )
        t1490html.write(
            "Adversaries may disable or delete system recovery features to augment the effects of Data Destruction and Data Encrypted for Impact."
        )
        # information
        t1490html.write("{}T1490</td>\n        <td>".format(headings))  # id
        t1490html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1490html.write("Impact</td>\n        <td>")  # tactics
        t1490html.write("-")  # sub-techniques
        # indicator regex assignments
        t1490html.write("{}vssadmin</li>\n        <li>".format(iocs))
        t1490html.write("wbadmin</li>\n        <li>")
        t1490html.write("shadows</li>\n        <li>")
        t1490html.write("shadowcopy</li>")
        # related techniques
        t1490html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1485 target="_blank"">T1485</a></td>\n        <td>'.format(
                related
            )
        )
        t1490html.write("Data Destruction")
        t1490html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1486 target="_blank"">T1486</a></td>\n        <td>'.format(
                insert
            )
        )
        t1490html.write("Data Encrypted for Impact")
        t1490html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1047 target="_blank"">T1047</a></td>\n        <td>'.format(
                insert
            )
        )
        t1490html.write("Windows Management Instrumentation")
        # mitigations
        t1490html.write("{}Data Backup</td>\n        <td>".format(mitigations))
        t1490html.write(
            "Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery.{}".format(
                insert
            )
        )
        t1490html.write("Operating System Configuration</td>\n        <td>")
        t1490html.write(
            "Consider technical controls to prevent the disabling of services or deletion of files involved in system recovery.{}".format(
                footer
            )
        )
    with open(sd + "t1498.html", "w") as t1498html:
        # description
        t1498html.write(
            "{}Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Network DoS can be performed by exhausting the network bandwidth services rely on. Example resources include specific websites, email services, DNS, and web-based applications. Adversaries have been observed conducting network DoS attacks for political purposes and to support other malicious activities, including distraction, hacktivism, and extortion.<br>".format(
                header
            )
        )
        t1498html.write(
            "A Network DoS will occur when the bandwidth capacity of the network connection to a system is exhausted due to the volume of malicious traffic directed at the resource or the network connections and network devices the resource relies on. For example, an adversary may send 10Gbps of traffic to a server that is hosted by a network with a 1Gbps connection to the internet. This traffic can be generated by a single system or multiple systems spread across the internet, which is commonly referred to as a distributed DoS (DDoS).<br>"
        )
        t1498html.write(
            "To perform Network DoS attacks several aspects apply to multiple methods, including IP address spoofing, and botnets.<br>"
        )
        t1498html.write(
            "Adversaries may use the original IP address of an attacking system, or spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection. This can increase the difficulty defenders have in defending against the attack by reducing or eliminating the effectiveness of filtering by the source address on network defense devices.<br>"
        )
        t1498html.write(
            "For DoS attacks targeting the hosting system directly, see Endpoint Denial of Service.".format(
                header
            )
        )
        # information
        t1498html.write("{}T1499</td>\n        <td>".format(headings))  # id
        t1498html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP, Office 365, SaaS</td>\n        <td>"
        )  # platforms
        t1498html.write("Impact</td>\n        <td>")  # tactics
        t1498html.write(
            "T1498.001: Direct Network Flood<br> T1498.002: Reflection Amplification"
        )  # sub-techniques
        # indicator regex assignments
        t1498html.write("{}-".format(iocs))
        # related techniques
        t1498html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1499 target="_blank"">T1499</a></td>\n        <td>'.format(
                related
            )
        )
        t1498html.write("Endpoint Denial of Service")
        # mitigations
        t1498html.write(
            "{}Filter Network Traffic</td>\n        <td>".format(mitigations)
        )
        t1498html.write(
            "When flood volumes exceed the capacity of the network connection being targeted, it is typically necessary to intercept the incoming traffic upstream to filter out the attack traffic from the legitimate traffic. Such defenses can be provided by the hosting Internet Service Provider (ISP) or by a 3rd party such as a Content Delivery Network (CDN) or providers specializing in DoS mitigations. Depending on flood volume, on-premises filtering may be possible by blocking source addresses sourcing the attack, blocking ports that are being targeted, or blocking protocols being used for transport. As immediate response may require rapid engagement of 3rd parties, analyze the risk associated to critical resources being affected by Network DoS attacks and create a disaster recovery plan/business continuity plan to respond to incidents.{}".format(
                footer
            )
        )
    with open(sd + "t1496.html", "w") as t1496html:
        # description
        t1496html.write(
            "{}Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems which may impact system and/or hosted service availability.<br>".format(
                header
            )
        )
        t1496html.write(
            "One common purpose for Resource Hijacking is to validate transactions of cryptocurrency networks and earn virtual currency. Adversaries may consume enough system resources to negatively impact and/or cause affected machines to become unresponsive.<br>"
        )
        t1496html.write(
            "Servers and cloud-based systems are common targets because of the high potential for available resources, but user endpoint systems may also be compromised and used for Resource Hijacking and cryptocurrency mining."
        )
        # information
        t1496html.write("{}T1496</td>\n        <td>".format(headings))  # id
        t1496html.write(
            "Windows, macOS, Linux, AWS, Azure, GCP</td>\n        <td>"
        )  # platforms
        t1496html.write("Impact</td>\n        <td>")  # tactics
        t1496html.write("-")  # sub-techniques
        # indicator regex assignments
        t1496html.write("{}-".format(iocs))
        # related techniques
        t1496html.write("{}-</a></td>\n        <td>".format(related))
        t1496html.write("-")
        # mitigations
        t1496html.write("{}-</td>\n        <td>".format(mitigations))
        t1496html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
    with open(sd + "t1489.html", "w") as t1489html:
        # description
        t1489html.write(
            "{}Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment.<br>".format(
                header
            )
        )
        t1489html.write(
            "Adversaries may accomplish this by disabling individual services of high importance to an organization, such as MSExchangeIS, which will make Exchange content inaccessible. In some cases, adversaries may stop or disable many or all services to render systems unusable.<br>"
        )
        t1489html.write(
            "Services may not allow for modification of their data stores while running. Adversaries may stop services in order to conduct Data Destruction or Data Encrypted for Impact on the data stores of services like Exchange and SQL Server."
        )
        # information
        t1489html.write("{}T1489</td>\n        <td>".format(headings))  # id
        t1489html.write("Windows</td>\n        <td>")  # platforms
        t1489html.write("Impact</td>\n        <td>")  # tactics
        t1489html.write("-")  # sub-techniques
        # indicator regex assignments
        t1489html.write("{}services.exe</li>\n        <li>".format(iocs))
        t1489html.write("sc.exe</li>\n        <li>")
        t1489html.write("kill</li>\n        <li>")
        t1489html.write("MSExchangeIs</li>\n        <li>")
        t1489html.write("ChangeServiceConfigW</li>\n        <li>")
        t1489html.write("net stop</li>\n        <li>")
        t1489html.write("net1 stop</li>")
        # related techniques
        t1489html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1485 target="_blank"">T1485</a></td>\n        <td>'.format(
                related
            )
        )
        t1489html.write("Data Destruction")
        t1489html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1486 target="_blank"">T1486</a></td>\n        <td>'.format(
                insert
            )
        )
        t1489html.write("Data Encrypted for Impact")
        # mitigations
        t1489html.write("{}Network Segmentation</td>\n        <td>".format(mitigations))
        t1489html.write(
            "Operate intrusion detection, analysis, and response systems on a separate network from the production environment to lessen the chances that an adversary can see and interfere with critical response functions.{}".format(
                insert
            )
        )
        t1489html.write("Restrict File and Directory Permissions</td>\n        <td>")
        t1489html.write(
            "Ensure proper process and file permissions are in place to inhibit adversaries from disabling or interfering with critical services.{}".format(
                insert
            )
        )
        t1489html.write("Restrict Registry Permissions</td>\n        <td>")
        t1489html.write(
            "Ensure proper registry permissions are in place to inhibit adversaries from disabling or interfering with critical services.{}".format(
                insert
            )
        )
        t1489html.write("User Account Management</td>\n        <td>")
        t1489html.write(
            "Limit privileges of user accounts and groups so that only authorized administrators can interact with service changes and service configurations.{}".format(
                footer
            )
        )
    with open(sd + "t1529.html", "w") as t1529html:
        # description
        t1529html.write(
            "{}Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine.<br>".format(
                header
            )
        )
        t1529html.write(
            "In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer. Shutting down or rebooting systems may disrupt access to computer resources for legitimate users.<br>"
        )
        t1529html.write(
            "Adversaries may attempt to shutdown/reboot a system after impacting it in other ways, such as Disk Structure Wipe or Inhibit System Recovery, to hasten the intended effects on system availability."
        )
        # information
        t1529html.write("{}T1529</td>\n        <td>".format(headings))  # id
        t1529html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1529html.write("Impact</td>\n        <td>")  # tactics
        t1529html.write("-")
        # indicator regex assignments
        t1529html.write("{}Event IDs: 1074, 6006</li>\n        <li>".format(iocs))
        t1529html.write("shutdown</li>\n        <li>")
        t1529html.write("halt</li>")
        # related techniques
        t1529html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1561 target="_blank"">T1561</a></td>\n        <td>'.format(
                related
            )
        )
        t1529html.write("Disk Structure Wipe")
        t1529html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1490 target="_blank"">T1490</a></td>\n        <td>'.format(
                insert
            )
        )
        t1529html.write("Inhibit System Recovery")
        # mitigations
        t1529html.write("{}-</td>\n        <td>".format(mitigations))
        t1529html.write(
            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.{}".format(
                footer
            )
        )
