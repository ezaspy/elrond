#!/usr/bin/env python3 -tt


def create_command_control_html(sd, header, headings, iocs, related, insert, mitigations, footer):
    with open(sd + "t1071.html", "w") as t1071html:
        # description
        t1071html.write(
            "{}Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.<br>".format(
                header
            )
        )
        t1071html.write(
            "Adversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, or DNS. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are SMB, SSH, or RDP."
        )
        # information
        t1071html.write("{}T1071</td>\n        <td>".format(headings))  # id
        t1071html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1071html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1071html.write(
            "T1071.001: Web Protocols<br>T1071.002: File Transfer Protocols<br>T1071.003: Mail Protocols<br>T1071.004: DNS"
        )  # sub-techniques
        # indicator regex assignments
        t1071html.write(
            "{}Ports: 20, 21, 25, 53, 69, 80, 110, 143, 443, 465, 993, 995, 989, 990".format(
                iocs
            )
        )
        # related techniques
        t1071html.write("{}-</a></td>\n        <td>".format(related))
        t1071html.write("-")
        # mitigations
        t1071html.write(
            "{}Network Intrusion Prevention</td>\n        <td>".format(mitigations)
        )
        t1071html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.{}".format(
                footer
            )
        )
    with open(sd + "t1092.html", "w") as t1092html:
        # description
        t1092html.write(
            "{}Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system.<br>".format(
                header
            )
        )
        t1092html.write(
            "Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by Replication Through Removable Media.<br>"
        )
        t1092html.write(
            "Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access."
        )
        # information
        t1092html.write("{}T1092</td>\n        <td>".format(headings))  # id
        t1092html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1092html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1092html.write("-")  # sub-techniques
        # indicator regex assignments
        t1092html.write("{}-".format(iocs))
        # related techniques
        t1092html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1091 target="_blank"">T1091</a></td>\n        <td>'.format(
                related
            )
        )
        t1092html.write("Replication Through Removable Media")
        # mitigations
        t1092html.write(
            "{}Disable or Remove Feature or Program</td>\n        <td>".format(
                mitigations
            )
        )
        t1092html.write("Disable Autoruns if it is unnecessary.{}".format(insert))
        t1092html.write("Operating System Configuration</td>\n        <td>")
        t1092html.write(
            "Disallow or restrict removable media at an organizational policy level if they are not required for business operations.{}".format(
                footer
            )
        )
    with open(sd + "t1132.html", "w") as t1132html:
        # description
        t1132html.write(
            "{}Adversaries may encode data to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system.<br>".format(
                header
            )
        )
        t1132html.write(
            "Use of data encoding may adhere to existing protocol specifications and includes use of ASCII, Unicode, Base64, MIME, or other binary-to-text and character encoding systems. Some data encoding systems may also result in data compression, such as gzip."
        )
        # information
        t1132html.write("{}T1132</td>\n        <td>".format(headings))  # id
        t1132html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1132html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1132html.write(
            "T1132.001: Standard Encoding<br>T1132.002: Non-Standard Encoding"
        )  # sub-techniques
        # indicator regex assignments
        t1132html.write("{}ASCII</li>\n        <li>".format(iocs))
        t1132html.write("unicode</li>\n        <li>")
        t1132html.write("HEX</li>\n        <li>")
        t1132html.write("base64</li>\n        <li>")
        t1132html.write("MIME</li>")
        # related techniques
        t1132html.write("{}-</a></td>\n        <td>".format(related))
        t1132html.write("-")
        # mitigations
        t1132html.write(
            "{}Network Intrusion Prevention</td>\n        <td>".format(mitigations)
        )
        t1132html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.{}".format(
                footer
            )
        )
    with open(sd + "t1001.html", "w") as t1001html:
        # description
        t1001html.write(
            "{}Adversaries may obfuscate command and control traffic to make it more difficult to detect.<br>".format(
                header
            )
        )
        t1001html.write(
            "Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen.<br>"
        )
        t1001html.write(
            "This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols."
        )
        # information
        t1001html.write("{}T1001</td>\n        <td>".format(headings))  # id
        t1001html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1001html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1001html.write(
            "T1001.001: Junk Data<br>T1001.002: Steganography<br>T1001.003: Protocol Impersonation"
        )  # sub-techniques
        # indicator regex assignments
        t1001html.write("{}Invoke-PSImage".format(iocs))
        # related techniques
        t1001html.write("{}-</a></td>\n        <td>".format(related))
        t1001html.write("-")
        # mitigations
        t1001html.write(
            "{}Network Intrusion Prevention</td>\n        <td>".format(mitigations)
        )
        t1001html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate some obfuscation activity at the network level.{}".format(
                footer
            )
        )
    with open(sd + "t1568.html", "w") as t1568html:
        # description
        t1568html.write(
            "{}Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations.<br>".format(
                header
            )
        )
        t1568html.write(
            "This may be achieved by using malware that shares a common algorithm with the infrastructure the adversary uses to receive the malware's communications.<br>"
        )
        t1568html.write(
            "These calculations can be used to dynamically adjust parameters such as the domain name, IP address, or port number the malware uses for command and control.<br>"
        )
        t1568html.write(
            "Adversaries may use dynamic resolution for the purpose of Fallback Channels.<br>"
        )
        t1568html.write(
            "When contact is lost with the primary command and control server malware may employ dynamic resolution as a means to reestablishing command and control."
        )
        # information
        t1568html.write("{}T1568</td>\n        <td>".format(headings))  # id
        t1568html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1568html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1568html.write(
            "T1568.001: Fast Flux DNS<br>T1568.002: Domain Generation Algorithms<br>T1568.003: DNS Calculation"
        )  # sub-techniques
        # indicator regex assignments
        t1568html.write("{}-".format(iocs))
        # related techniques
        t1568html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1008 target="_blank"">T1008</a></td>\n        <td>'.format(
                related
            )
        )
        t1568html.write("Fallback Channels")
        # mitigations
        t1568html.write(
            "{}Network Intrusion Prevention</td>\n        <td>".format(mitigations)
        )
        t1568html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Malware researchers can reverse engineer malware variants that use dynamic resolution and determine future C2 infrastructure that the malware will attempt to contact, but this is a time and resource intensive effort.{}".format(
                insert
            )
        )
        t1568html.write("Restrict Web-Based Content</td>\n        <td>")
        t1568html.write(
            "In some cases a local DNS sinkhole may be used to help prevent behaviors associated with dynamic resolution.{}".format(
                footer
            )
        )
    with open(sd + "t1573.html", "w") as t1573html:
        # description
        t1573html.write(
            "{}Adversaries may employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.<br>".format(
                header
            )
        )
        t1573html.write(
            "Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files."
        )
        # information
        t1573html.write("{}T1573</td>\n        <td>".format(headings))  # id
        t1573html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1573html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1573html.write(
            "T1573.001: Symmetric Cryptography<br>T1573.002: Asymmetric Cryptography"
        )  # sub-techniques
        # indicator regex assignments
        t1573html.write("{}encrypt".format(iocs))
        # related techniques
        t1573html.write("{}-</a></td>\n        <td>".format(related))
        t1573html.write("-")
        # mitigations
        t1573html.write(
            "{}Network Intrusion Prevention</td>\n        <td>".format(mitigations)
        )
        t1573html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.{}".format(
                insert
            )
        )
        t1573html.write("SSL/TLS Inspection</td>\n        <td>")
        t1573html.write(
            "SSL/TLS inspection can be used to see the contents of encrypted sessions to look for network-based indicators of malware communication protocols.{}".format(
                footer
            )
        )
    with open(sd + "t1008.html", "w") as t1008html:
        # description
        t1008html.write(
            "{}Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.".format(
                header
            )
        )
        # information
        t1008html.write("{}T1008</td>\n        <td>".format(headings))  # id
        t1008html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1008html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1008html.write("-")  # sub-techniques
        # indicator regex assignments
        t1008html.write("{}-".format(iocs))
        # related techniques
        t1008html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1568 target="_blank"">T1568</a></td>\n        <td>'.format(
                related
            )
        )
        t1008html.write("Dynamic Resolution")
        t1008html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1104 target="_blank"">T1104</a></td>\n        <td>'.format(
                insert
            )
        )
        t1008html.write("Multi-Stage Channels")
        # mitigations
        t1008html.write(
            "{}Network Intrusion Prevention</td>\n        <td>".format(mitigations)
        )
        t1008html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific protocol used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.{}".format(
                footer
            )
        )
    with open(sd + "t1105.html", "w") as t1105html:
        # description
        t1105html.write(
            "{}Adversaries may transfer tools or other files from an external system into a compromised environment.<br>".format(
                header
            )
        )
        t1105html.write(
            "Files may be copied from an external adversary controlled system through the command and control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP.<br>"
        )
        t1105html.write(
            "Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp."
        )
        # information
        t1105html.write("{}T1572</td>\n        <td>".format(headings))  # id
        t1105html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1105html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1105html.write("-")  # sub-techniques
        # indicator regex assignments
        t1105html.write("{}scp</li>\n        <li>".format(iocs))
        t1105html.write("rsync</li>\n        <li>")
        t1105html.write("sftp</li>")
        # related techniques
        t1105html.write("{}-</a></td>\n        <td>".format(related))
        t1105html.write("-")
        # mitigations
        t1105html.write(
            "{}Network Intrusion Prevention</td>\n        <td>".format(mitigations)
        )
        t1105html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware or unusual data transfer over known tools and protocols like FTP can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.{}".format(
                footer
            )
        )
    with open(sd + "t1104.html", "w") as t1104html:
        # description
        t1104html.write(
            "{}Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult.<br>".format(
                header
            )
        )
        t1104html.write(
            "Remote access tools will call back to the first-stage command and control server for instructions. The first stage may have automated capabilities to collect basic host information, update tools, and upload additional files.<br>"
        )
        t1104html.write(
            "A second remote access tool (RAT) could be uploaded at that point to redirect the host to the second-stage command and control server. The second stage will likely be more fully featured and allow the adversary to interact with the system through a reverse shell and additional RAT features.<br>"
        )
        t1104html.write(
            "The different stages will likely be hosted separately with no overlapping infrastructure. The loader may also have backup first-stage callbacks or Fallback Channels in case the original first-stage communication path is discovered and blocked."
        )
        # information
        t1104html.write("{}T1104</td>\n        <td>".format(headings))  # id
        t1104html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1104html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1104html.write("-")  # sub-techniques
        # indicator regex assignments
        t1104html.write("{}-".format(iocs))
        # related techniques
        t1104html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1008 target="_blank"">T1008</a></td>\n        <td>'.format(
                related
            )
        )
        t1104html.write("Fallback Channels")
        # mitigations
        t1104html.write(
            "{}Network Intrusion Prevention</td>\n        <td>".format(mitigations)
        )
        t1104html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.{}".format(
                footer
            )
        )
    with open(sd + "t1095.html", "w") as t1095html:
        # description
        t1095html.write(
            "{}Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive.<br>".format(
                header
            )
        )
        t1095html.write(
            "Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL).<br>"
        )
        t1095html.write(
            "ICMP communication between hosts is one example. Because ICMP is part of the Internet Protocol Suite, it is required to be implemented by all IP-compatible hosts; however, it is not as commonly monitored as other Internet Protocols such as TCP or UDP and may be used by adversaries to hide communications."
        )
        # information
        t1095html.write("{}T1095</td>\n        <td>".format(headings))  # id
        t1095html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1095html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1095html.write("-")  # sub-techniques
        # indicator regex assignments
        t1095html.write("{}-".format(iocs))
        # related techniques
        t1095html.write("{}-</a></td>\n        <td>".format(related))
        t1095html.write("-")
        # mitigations
        t1095html.write(
            "{}Filter Network Traffic</td>\n        <td>".format(mitigations)
        )
        t1095html.write(
            "Filter network traffic to prevent use of protocols across the network boundary that are unnecessary.{}".format(
                insert
            )
        )
        t1095html.write("Network Intrusion Prevention</td>\n        <td>")
        t1095html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.{}".format(
                insert
            )
        )
        t1095html.write("Network Segmentation</td>\n        <td>")
        t1095html.write(
            "Properly configure firewalls and proxies to limit outgoing traffic to only necessary ports and through proper network gateway systems. Also ensure hosts are only provisioned to communicate over authorized interfaces.{}".format(
                footer
            )
        )
    with open(sd + "t1571.html", "w") as t1571html:
        # description
        t1571html.write(
            "{}Adversaries may communicate using a protocol and port paring that are typically not associated. For example, HTTPS over port 8088 or port 587 as opposed to the traditional port 443.<br>".format(
                header
            )
        )
        t1571html.write(
            "Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data."
        )
        # information
        t1571html.write("{}T1571</td>\n        <td>".format(headings))  # id
        t1571html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1571html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1571html.write("-")  # sub-techniques
        # indicator regex assignments
        t1571html.write("{}-".format(iocs))
        # related techniques
        t1571html.write("{}-</a></td>\n        <td>".format(related))
        t1571html.write("-")
        # mitigations
        t1571html.write(
            "{}Network Intrusion Prevention</td>\n        <td>".format(mitigations)
        )
        t1571html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.{}".format(
                insert
            )
        )
        t1571html.write("Network Segmentation</td>\n        <td>")
        t1571html.write(
            "Properly configure firewalls and proxies to limit outgoing traffic to only necessary ports for that particular network segment.{}".format(
                footer
            )
        )
    with open(sd + "t1572.html", "w") as t1572html:
        # description
        t1572html.write(
            "{}Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems.<br>".format(
                header
            )
        )
        t1572html.write(
            "Tunneling involves explicitly encapsulating a protocol within another. This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to a VPN).<br>"
        )
        t1572html.write(
            "Tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as SMB, RDP, or other traffic that would be filtered by network appliances or not routed over the Internet.<br>"
        )
        t1572html.write(
            "There are various means to encapsulate a protocol within another protocol. For example, adversaries may perform SSH tunneling (also known as SSH port forwarding), which involves forwarding arbitrary data over an encrypted SSH tunnel.<br>"
        )
        t1572html.write(
            "Protocol Tunneling may also be abused by adversaries during Dynamic Resolution. Known as DNS over HTTPS (DoH), queries to resolve C2 infrastructure may be encapsulated within encrypted HTTPS packets.<br>"
        )
        t1572html.write(
            "Adversaries may also leverage Protocol Tunneling in conjunction with Proxy and/or Protocol Impersonation to further conceal C2 communications and infrastructure."
        )
        # information
        t1572html.write("{}T1572</td>\n        <td>".format(headings))  # id
        t1572html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1572html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1572html.write("-")  # sub-techniques
        # indicator regex assignments
        t1572html.write("{}-".format(iocs))
        # related techniques
        t1572html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1568 target="_blank"">T1568</a></td>\n        <td>'.format(
                related
            )
        )
        t1572html.write("Dynamic Resolution")
        t1572html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1090 target="_blank"">T1090</a></td>\n        <td>'.format(
                insert
            )
        )
        t1572html.write("Proxy")
        t1572html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1001 target="_blank"">T1001</a></td>\n        <td>'.format(
                insert
            )
        )
        t1572html.write("Data Obfuscation: Protocol Impersonation")
        # mitigations
        t1572html.write(
            "{}Filter Network Traffic</td>\n        <td>".format(mitigations)
        )
        t1572html.write(
            "Consider filtering network traffic to untrusted or known bad domains and resources.{}".format(
                insert
            )
        )
        t1572html.write("Network Intrusion Prevention</td>\n        <td>")
        t1572html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.{}".format(
                footer
            )
        )
    with open(sd + "t1090.html", "w") as t1090html:
        # description
        t1090html.write(
            "{}Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap.<br>".format(
                header
            )
        )
        t1090html.write(
            "Adversaries use these types of proxies to manage command and control communications, reduce the number of simultaneous outbound network connections, provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion. Adversaries may chain together multiple proxies to further disguise the source of malicious traffic.<br>"
        )
        t1090html.write(
            "Adversaries can also take advantage of routing schemes in Content Delivery Networks (CDNs) to proxy command and control traffic."
        )
        # information
        t1090html.write("{}T1090</td>\n        <td>".format(headings))  # id
        t1090html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1090html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1090html.write(
            "T1090.001: Internal Proxy<br>T1090.002: External Proxy<br>T1090.003: Multi-hop Proxy<br>T1090.004: Domain Fronting"
        )  # sub-techniques
        # indicator regex assignments
        t1090html.write("{}netsh</li>\n        <li>".format(iocs))
        t1090html.write("portopening</li>")
        # related techniques
        t1090html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1572 target="_blank"">T1572</a></td>\n        <td>'.format(
                related
            )
        )
        t1090html.write("Protocol Tunneling")
        # mitigations
        t1090html.write(
            "{}Filter Network Traffic</td>\n        <td>".format(mitigations)
        )
        t1090html.write(
            "Traffic to known anonymity networks and C2 infrastructure can be blocked through the use of network allow and block lists. It should be noted that this kind of blocking may be circumvented by other techniques like Domain Fronting.{}".format(
                insert
            )
        )
        t1090html.write("Network Intrusion Prevention</td>\n        <td>")
        t1090html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific C2 protocol used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.{}".format(
                insert
            )
        )
        t1090html.write("SSL/TLS Inspection</td>\n        <td>")
        t1090html.write(
            "If it is possible to inspect HTTPS traffic, the captures can be analyzed for connections that appear to be domain fronting.{}".format(
                footer
            )
        )
    with open(sd + "t1219.html", "w") as t1219html:
        # description
        t1219html.write(
            "{}An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks. These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.<br>".format(
                header
            )
        )
        t1219html.write(
            "Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries.<br>"
        )
        t1219html.write(
            "Remote access tools may be established and used post-compromise as alternate communications channel for redundant access or as a way to establish an interactive remote desktop session with the target system. They may also be used as a component of malware to establish a reverse connection or back-connect to a service or adversary controlled system.<br>"
        )
        t1219html.write(
            "Admin tools such as TeamViewer have been used by several groups targeting institutions in countries of interest to the Russian state and criminal campaigns."
        )
        # information
        t1219html.write("{}T1219</td>\n        <td>".format(headings))  # id
        t1219html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1219html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1219html.write("-")  # sub-techniques
        # indicator regex assignments
        t1219html.write(
            "{}Ports: 5800, 5895, 5900, 5938, 5984, 5986, 8200".format(iocs)
        )
        # related techniques
        t1219html.write("{}-</a></td>\n        <td>".format(related))
        t1219html.write("-")
        # mitigations
        t1219html.write("{}Execution Prevention</td>\n        <td>".format(mitigations))
        t1219html.write(
            "Use application control to mitigate installation and use of unapproved software that can be used for remote access.{}".format(
                insert
            )
        )
        t1219html.write("Filter Network Traffic</td>\n        <td>")
        t1219html.write(
            "Properly configure firewalls, application firewalls, and proxies to limit outgoing traffic to sites and services used by remote access tools.{}".format(
                insert
            )
        )
        t1219html.write("Network Intrusion Prevention</td>\n        <td>")
        t1219html.write(
            "Network intrusion detection and prevention systems that use network signatures may be able to prevent traffic to remote access services.{}".format(
                footer
            )
        )
    with open(sd + "t1102.html", "w") as t1102html:
        # description
        t1102html.write(
            "{}Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise.<br>".format(
                header
            )
        )
        t1102html.write(
            "Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.<br>"
        )
        t1102html.write(
            "Use of Web services may also protect back-end C2 infrastructure from discovery through malware binary analysis while also enabling operational resiliency (since this infrastructure may be dynamically changed)."
        )
        # information
        t1102html.write("{}T1102</td>\n        <td>".format(headings))  # id
        t1102html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1102html.write("Command &amp; Control</td>\n        <td>")  # tactics
        t1102html.write(
            "T1102.001: Dead Drop Resolver<br>T1102.002: Bidirectional Communication<br>T1102.003: One-Way Communication"
        )  # sub-techniques
        # indicator regex assignments
        t1102html.write("{}-".format(iocs))
        # related techniques
        t1102html.write("{}-</a></td>\n        <td>".format(related))
        t1102html.write("-")
        # mitigations
        t1102html.write(
            "{}Network Intrusion Prevention</td>\n        <td>".format(mitigations)
        )
        t1102html.write(
            "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.{}".format(
                insert
            )
        )
        t1102html.write("Restrict Web-Based Content</td>\n        <td>")
        t1102html.write(
            "Web proxies can be used to enforce external network communication policy that prevents use of unauthorized external services.{}".format(
                footer
            )
        )
