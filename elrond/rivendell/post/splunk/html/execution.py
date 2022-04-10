#!/usr/bin/env python3 -tt


def create_execution_html(sd, header, headings, iocs, related, insert, mitigations, footer):
    with open(sd + "t1059.html", "w") as t1059html:
        # description
        t1059html.write(
            "{}Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of Unix Shell while Windows installations include the Windows Command Shell and PowerShell.<br>".format(
                header
            )
        )
        t1059html.write(
            "There are also cross-platform interpreters such as Python, as well as those commonly associated with client applications such as JavaScript and Visual Basic.<br>"
        )
        t1059html.write(
            "Adversaries may abuse IPC to execute arbitrary code or commands. IPC mechanisms may differ depending on OS, but typically exists in a form accessible through programming languages/libraries or native interfaces such as Windows Dynamic Data Exchange or Component Object Model.<br>"
        )
        t1059html.write(
            "Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in Initial Access payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells."
        )
        # information
        t1059html.write("{}T1059</td>\n        <td>".format(headings))  # id
        t1059html.write(
            "Windows, macOS, Linux, Network</td>\n        <td>"
        )  # platforms
        t1059html.write("Execution</td>\n        <td>")  # tactics
        t1059html.write(
            "T1059.001: PowerShell<br>T1059.002: AppleScript<br>T1059.003: Windows Command Shell<br>T1059.004: Unix Shell<br>T1059.005: Visual Basic<br>T1059.006: Python<br>T1059.007: JavaScript<br>T1059.008: Network Device CLI"
        )  # sub-techniques
        # indicator regex assignments
        t1059html.write("{}.ps1</li>\n        <li>".format(iocs))
        t1059html.write(".py</li>\n        <li>")
        t1059html.write("PowerShell</li>\n        <li>")
        t1059html.write("cmd</li>\n        <li>")
        t1059html.write("Invoke-Command</li>\n        <li>")
        t1059html.write("Start-Process</li>\n        <li>")
        t1059html.write("vbscript</li>\n        <li>")
        t1059html.write("wscript</li>\n        <li>")
        t1059html.write("system.management.automation</li>")
        # related techniques - unfinished MANY
        t1059html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1559 target="_blank"">T1559</a></td>\n        <td>'.format(
                related
            )
        )
        t1059html.write("Inter-Process Communication")
        t1059html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1106 target="_blank"">T1106</a></td>\n        <td>'.format(
                insert
            )
        )
        t1059html.write("Native API")
        t1059html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1197 target="_blank"">T1197</a></td>\n        <td>'.format(
                insert
            )
        )
        t1059html.write("BITS Job")
        t1059html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1202 target="_blank"">T1202</a></td>\n        <td>'.format(
                insert
            )
        )
        t1059html.write("Indirect Command Execution")
        t1059html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1027 target="_blank"">T1027</a></td>\n        <td>'.format(
                insert
            )
        )
        t1059html.write("Obfuscated Files or Information")
        t1059html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1056 target="_blank"">T1056</a></td>\n        <td>'.format(
                insert
            )
        )
        t1059html.write("Input Capture")
        t1059html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1613 target="_blank"">T1613</a></td>\n        <td>'.format(
                insert
            )
        )
        t1059html.write("Container and Resource Discovery")
        t1059html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1057 target="_blank"">T1057</a></td>\n        <td>'.format(
                insert
            )
        )
        t1059html.write("Process Discovery")
        t1059html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1119 target="_blank"">T1119</a></td>\n        <td>'.format(
                insert
            )
        )
        t1059html.write("Automated Collection")
        t1059html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1005 target="_blank"">T1005</a></td>\n        <td>'.format(
                insert
            )
        )
        t1059html.write("Data from Local System")
        # mitigations
        t1059html.write(
            "{}Antivirus/Antimalware</td>\n        <td>".format(mitigations)
        )
        t1059html.write(
            "Anti-virus can be used to automatically quarantine suspicious files.{}".format(
                insert
            )
        )
        t1059html.write("Code Signing</td>\n        <td>")
        t1059html.write(
            "Where possible, only permit execution of signed scripts.{}".format(insert)
        )
        t1059html.write("Disable or Remove Feature or Program</td>\n        <td>")
        t1059html.write(
            "Disable or remove any unnecessary or unused shells or interpreters.{}".format(
                insert
            )
        )
        t1059html.write("Execution Prevention</td>\n        <td>")
        t1059html.write("Use application control where appropriate.{}".format(insert))
        t1059html.write("Privileged Account Management</td>\n        <td>")
        t1059html.write(
            "When PowerShell is necessary, restrict PowerShell execution policy to administrators. Be aware that there are methods of bypassing the PowerShell execution policy, depending on environment configuration.{}".format(
                insert
            )
        )
        t1059html.write("Restrict Web-Based Content</td>\n        <td>")
        t1059html.write(
            "Script blocking extensions can help prevent the execution of scripts and HTA files that may commonly be used during the exploitation process. For malicious code served up through ads, adblockers can help prevent that code from executing in the first place.{}".format(
                footer
            )
        )
    with open(sd + "t1609.html", "w") as t1609html:
        # description
        t1609html.write(
            "{}Adversaries may abuse a container administration service to execute commands within a container. A container administration service such as the Docker daemon, the Kubernetes API server, or the kubelet may allow remote management of containers within an environment.<br>".format(
                header
            )
        )
        t1609html.write(
            "In Docker, adversaries may specify an entrypoint during container deployment that executes a script or command, or they may use a command such as docker exec to execute a command within a running container.<br>"
        )
        t1609html.write(
            "In Kubernetes, if an adversary has sufficient permissions, they may gain remote execution in a container in the cluster via interaction with the Kubernetes API server, the kubelet, or by running a command such as kubectl exec."
        )
        # indicator regex assignments
        t1609html.write("docker exec</li>\n        <li>")
        t1609html.write("kubectl exec</li>")
        # information
        t1609html.write("{}T1609</td>\n        <td>".format(headings))  # id
        t1609html.write("Windows</td>\n        <td>")  # platforms
        t1609html.write("Execution</td>\n        <td>")  # tactics
        t1609html.write("-")  # sub-techniques
        # related techniques
        t1609html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1610 target="_blank"">T1610</a></td>\n        <td>'.format(
                related
            )
        )
        t1609html.write("Deploy Container")
        # mitigations
        t1609html.write("{}Execution Prevention</td>\n        <td>".format(mitigations))
        t1609html.write(
            "Use read-only containers and minimal images when possible to prevent the execution of commands.{}".format(
                insert
            )
        )
        t1609html.write("Limit Access to Resource Over Network</td>\n        <td>")
        t1609html.write(
            "Limit communications with the container service to local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API and Kubernetes API Server.{}".format(
                insert
            )
        )
        t1609html.write("Privileged Account Management</td>\n        <td>")
        t1609html.write(
            "Ensure containers are not running as root by default.{}".format(footer)
        )
    with open(sd + "t1610.html", "w") as t1610html:
        # description
        t1610html.write(
            "{}Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware. In others, an adversary may deploy a new container configured without network rules, user limitations, etc. to bypass existing defenses within the environment.<br>".format(
                header
            )
        )
        t1610html.write(
            "Containers can be deployed by various means, such as via Docker's create and start APIs or via a web application such as the Kubernetes dashboard or Kubeflow. Adversaries may deploy containers based on retrieved or built malicious images or from benign images that download and execute malicious payloads at runtime."
        )
        # indicator regex assignments
        t1610html.write("docker create</li>\n        <li>")
        t1610html.write("docker start</li>")
        # information
        t1610html.write("{}T1610</td>\n        <td>".format(headings))  # id
        t1610html.write("Containers</td>\n        <td>")  # platforms
        t1610html.write("Execution</td>\n        <td>")  # tactics
        t1610html.write("-")  # sub-techniques
        # related techniques
        t1610html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1609 target="_blank"">T1609</a></td>\n        <td>'.format(
                related
            )
        )
        t1610html.write("Container Administration Command")
        # mitigations
        t1610html.write(
            "{}Limit Access to Resource Over Network</td>\n        <td>".format(
                mitigations
            )
        )
        t1610html.write(
            "Limit communications with the container service to local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API, Kubernetes API Server, and container orchestration web applications.{}".format(
                insert
            )
        )
        t1610html.write("Network Segmentation</td>\n        <td>")
        t1610html.write(
            "Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.{}".format(
                insert
            )
        )
        t1610html.write("User Account Management</td>\n        <td>")
        t1610html.write(
            "Enforce the principle of least privilege by limiting container dashboard access to only the necessary users.{}".format(
                footer
            )
        )
    with open(sd + "t1203.html", "w") as t1203html:
        # description
        t1203html.write(
            "{}Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior.<br>".format(
                header
            )
        )
        t1203html.write(
            "Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution.<br>"
        )
        t1203html.write(
            "Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system.<br>"
        )
        t1203html.write(
            "Users will expect to see files related to the applications they commonly used to do work, so they are a useful target for exploit research and development because of their high utility.<br>"
        )
        t1203html.write(
            "Several types exist:<ul>\n          <li>Browser-based Exploitation</li>\n          <ul>\n            <li>Web browsers are a common target through Drive-by Compromise and Spearphishing Link.</li>\n            <li>Endpoint systems may be compromised through normal web browsing or from certain users being targeted by links in spearphishing emails to adversary controlled sites used to exploit the web browser.</li>\n            <li>These often do not require an action by the user for the exploit to be executed.\n          </ul>\n          <li>Office Applications</li>\n          <ul>\n            <li>Common office and productivity applications such as Microsoft Office are also targeted through Phishing.</li>\n            <li>Malicious files will be transmitted directly as attachments or through links to download them.</li>\n            <li>These require the user to open the document or file for the exploit to run.\n          </ul>\n          <li>Common Third-party Applications</li>\n          <ul>\n            <li>Other applications that are commonly seen or are part of the software deployed in a target network may also be used for exploitation.</li>\n            <li>Applications such as Adobe Reader and Flash, which are common in enterprise environments, have been routinely targeted by adversaries attempting to gain access to systems.</li>\n            <li>Depending on the software and nature of the vulnerability, some may be exploited in the browser or require the user to open a file. For instance, some Flash exploits have been delivered as objects within Microsoft Office documents.</li>\n          </ul>"
        )
        # information
        t1203html.write("{}T1203</td>\n        <td>".format(headings))  # id
        t1203html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1203html.write("Execution</td>\n        <td>")  # tactics
        t1203html.write("-")  # sub-techniques
        # indicator regex assignments
        t1203html.write("{}.doc</li>\n        <li>".format(iocs))
        t1203html.write(".xls</li>\n        <li>")
        t1203html.write(".ppt</li>\n        <li>")
        t1203html.write(".pdf</li>\n        <li>")
        t1203html.write(".msg</li>\n        <li>")
        t1203html.write(".eml</li>\n        <li>")
        t1203html.write("WinWord</li>\n        <li>")
        t1203html.write("Excel</li>\n        <li>")
        t1203html.write("PowerPnt</li>\n        <li>")
        t1203html.write("Acrobat</li>\n        <li>")
        t1203html.write("Acrord32</li>")
        # related techniques
        t1203html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1189 target="_blank"">T1189</a></td>\n        <td>'.format(
                related
            )
        )
        t1203html.write("Drive-by Compromise")
        t1203html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1566 target="_blank"">T1566</a></td>\n        <td>'.format(
                insert
            )
        )
        t1203html.write("Phishing")
        t1203html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1204 target="_blank"">T1204</a></td>\n        <td>'.format(
                insert
            )
        )
        t1203html.write("User Execution")
        # mitigations
        t1203html.write(
            "{}Application Isolation and Sandboxing</td>\n        <td>".format(
                mitigations
            )
        )
        t1203html.write(
            "Browser sandboxes can be used to mitigate some of the impact of exploitation, but sandbox escapes may still exist. Other types of virtualization and application microsegmentation may also mitigate the impact of client-side exploitation. The risks of additional exploits and weaknesses in implementation may still exist for these types of systems.</td>\n      </tr>\n      <tr>\n        <td>".format(
                insert
            )
        )
        t1203html.write("Exploit Protection</td>\n        <td>")
        t1203html.write(
            "Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility."
        )
    with open(sd + "t1559.html", "w") as t1559html:
        # description
        t1559html.write(
            "{}Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution. IPC is also commonly used to avoid situations such as deadlocks, which occurs when processes are stuck in a cyclic waiting pattern.<br>".format(
                header
            )
        )
        t1559html.write(
            "Adversaries may abuse IPC to execute arbitrary code or commands. IPC mechanisms may differ depending on OS, but typically exists in a form accessible through programming languages/libraries or native interfaces such as Windows Dynamic Data Exchange or Component Object Model. Higher level execution mediums, such as those of Command and Scripting Interpreters, may also leverage underlying IPC mechanisms."
        )
        # information
        t1559html.write("{}T1559</td>\n        <td>".format(headings))  # id
        t1559html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1559html.write("Execution</td>\n        <td>")  # tactics
        t1559html.write(
            "T1559.001: Component Object Model<br>T1559.002: Dynamic Data Exchange"
        )  # sub-techniques
        # indicator regex assignments
        t1559html.write("{}.docm</li>\n        <li>".format(iocs))
        t1559html.write(".xlsm</li>\n        <li>")
        t1559html.write(".pptm</li>\n        <li>")
        t1559html.write("IPC$")
        ## itaskservice|itaskdefinition|itasksettings
        ## microsoft\\.office\\.interop
        # related techniques
        t1559html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1059 target="_blank"">T1059</a></td>\n        <td>'.format(
                related
            )
        )
        t1559html.write("Command and Scripting Interpreter")
        t1559html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1106 target="_blank"">T1106</a></td>\n        <td>'.format(
                insert
            )
        )
        t1559html.write("Native API")
        t1559html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1197 target="_blank"">T1197</a></td>\n        <td>'.format(
                insert
            )
        )
        t1559html.write("BITS Jobs")
        # mitigations
        t1559html.write(
            "{}Antivirus/Antimalware</td>\n        <td>".format(mitigations)
        )
        t1559html.write(
            "Anti-virus can be used to automatically quarantine suspicious files.{}".format(
                insert
            )
        )
        t1559html.write("Code Signing</td>\n        <td>")
        t1559html.write(
            "Where possible, only permit execution of signed scripts.{}".format(insert)
        )
        t1559html.write("Disable or Remove Feature or Program</td>\n        <td>")
        t1559html.write(
            "Disable or remove any unnecessary or unused shells or interpreters.{}".format(
                insert
            )
        )
        t1559html.write("Execution Prevention</td>\n        <td>")
        t1559html.write("Use application control where appropriate.{}".format(insert))
        t1559html.write("Privileged Account Management</td>\n        <td>")
        t1559html.write(
            "When PowerShell is necessary, restrict PowerShell execution policy to administrators. Be aware that there are methods of bypassing the PowerShell execution policy, depending on environment configuration.{}".format(
                insert
            )
        )
        t1559html.write("Restrict Web-Based Content</td>\n        <td>")
        t1559html.write(
            "Script blocking extensions can help prevent the execution of scripts and HTA files that may commonly be used during the exploitation process. For malicious code served up through ads, adblockers can help prevent that code from executing in the first place.{}".format(
                footer
            )
        )
    with open(sd + "t1106.html", "w") as t1106html:
        # description
        t1106html.write(
            "{}Adversaries may directly interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes.<br>".format(
                header
            )
        )
        t1106html.write(
            "These native APIs are leveraged by the OS during system boot (when other system components are not yet initialized) as well as carrying out tasks and requests during routine operations.<br>"
        )
        t1106html.write(
            "Functionality provided by native APIs are often also exposed to user-mode applications via interfaces and libraries. For example, functions such as the Windows API CreateProcess() or GNU fork() will allow programs and scripts to start other processes.<br>"
        )
        t1106html.write(
            "This may allow API callers to execute a binary, run a CLI command, load modules, etc. as thousands of similar API functions exist for various system operations.<br>"
        )
        t1106html.write(
            "Higher level software frameworks, such as Microsoft .NET and macOS Cocoa, are also available to interact with native APIs. These frameworks typically provide language wrappers/abstractions to API functionalities and are designed for ease-of-use/portability of code.<br>"
        )
        t1106html.write(
            "Adversaries may abuse these native API functions as a means of executing behaviors. Similar to Command and Scripting Interpreter, the native API and its hierarchy of interfaces, provide mechanisms to interact with and utilize various components of a victimized system."
        )
        # information
        t1106html.write("{}T1106</td>\n        <td>".format(headings))  # id
        t1106html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1106html.write("Execution</td>\n        <td>")  # tactics
        t1106html.write("-")  # sub-techniques
        # indicator regex assignments
        t1106html.write("{}PowerShell</li>\n        <li>".format(iocs))
        t1106html.write("cmd.exe</li>\n        <li>")
        t1106html.write("contentsOfDirectoryAtPath</li>\n        <li>")
        t1106html.write("pathExtension</li>\n        <li>")
        t1106html.write("compare</li>\n        <li>")
        t1106html.write("fork</li>\n        <li>")
        t1106html.write("CreateProcess</li>\n        <li>")
        t1106html.write("CreateRemoteThread</li>\n        <li>")
        t1106html.write("LoadLibrary</li>\n        <li>")
        t1106html.write("ShellExecute</li>\n        <li>")
        t1106html.write("IsDebuggerPresent</li>\n        <li>")
        t1106html.write("OutputDebugString</li>\n        <li>")
        t1106html.write("SetLastError</li>\n        <li>")
        t1106html.write("HttpOpenRequestA</li>\n        <li>")
        t1106html.write("CreatePipe</li>\n        <li>")
        t1106html.write("GetUserNameW</li>\n        <li>")
        t1106html.write("CallWindowProc</li>\n        <li>")
        t1106html.write("EnumResourceTypesA</li>\n        <li>")
        t1106html.write("ConnectNamedPipe</li>\n        <li>")
        t1106html.write("WNetAddConnection2</li>\n        <li>")
        t1106html.write("ZwWriteVirtualMemory</li>\n        <li>")
        t1106html.write("ZwProtectVirtualMemory</li>\n        <li>")
        t1106html.write("ZwQueueApcThread</li>\n        <li>")
        t1106html.write("NtResumeThread</li>\n        <li>")
        t1106html.write("TerminateProcess</li>\n        <li>")
        t1106html.write("GetModuleFileName</li>\n        <li>")
        t1106html.write("lstrcat</li>\n        <li>")
        t1106html.write("CreateFile</li>\n        <li>")
        t1106html.write("ReadFile</li>\n        <li>")
        t1106html.write("GetProcessById</li>\n        <li>")
        t1106html.write("WriteFile</li>\n        <li>")
        t1106html.write("CloseHandle</li>\n        <li>")
        t1106html.write("GetCurrentHwProfile</li>\n        <li>")
        t1106html.write("GetProcAddress</li>\n        <li>")
        t1106html.write("FindNextUrlCacheEntryA</li>\n        <li>")
        t1106html.write("FindFirstUrlCacheEntryA</li>\n        <li>")
        t1106html.write("GetWindowsDirectoryW</li>\n        <li>")
        t1106html.write("MoveFileEx</li>\n        <li>")
        t1106html.write("NtQueryInformationProcess</li>\n        <li>")
        t1106html.write("RegEnumKeyW</li>\n        <li>")
        t1106html.write("SetThreadContext</li>\n        <li>")
        t1106html.write("VirtualAlloc</li>\n        <li>")
        t1106html.write("WinExec</li>\n        <li>")
        t1106html.write("WriteProcessMemory</li>")
        # related techniques
        t1106html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1059 target="_blank"">T1059</a></td>\n        <td>'.format(
                related
            )
        )
        t1106html.write("Command and Scripting Interpreter")
        t1106html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1559 target="_blank"">T1559</a></td>\n        <td>'.format(
                insert
            )
        )
        t1106html.write("Inter-Process Communication")
        t1106html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1129 target="_blank"">T1129</a></td>\n        <td>'.format(
                insert
            )
        )
        t1106html.write("Shared Modules")
        # mitigations
        t1106html.write("{}Execution Prevention</td>\n        <td>".format(mitigations))
        t1106html.write(
            "Identify and block potentially malicious software executed that may be executed through this technique by using application control tools, like Windows Defender Application Control[90], AppLocker, or Software Restriction Policies where appropriate.{}".format(
                footer
            )
        )
    with open(sd + "t1053.html", "w") as t1053html:
        # description
        t1053html.write(
            "{}Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time.<br>".format(
                header
            )
        )
        t1053html.write(
            "A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments).<br>"
        )
        t1053html.write(
            "Scheduling a task on a remote system typically requires being a member of an admin or otherwise privileged group on the remote system.<br>"
        )
        t1053html.write(
            "Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges)."
        )
        # information
        t1053html.write("{}T1133</td>\n        <td>".format(headings))  # id
        t1053html.write("Windows, Linux</td>\n        <td>")  # platforms
        t1053html.write(
            "Execution, Persistence, Privilege Escalation</td>\n        <td>"
        )  # tactics
        t1053html.write(
            "T1053.001: At (Linux)<br>T1053.002: At (Windows)<br>T1053.003: Cron<br>T1053.004: Launchd<br>T1053.005: Scheduled Task<br>T1053.006: Systemd Timers<br>T1053.007: Container Orchestration Job"
        )  # sub-techniques
        # indicator regex assignments
        t1053html.write("{}schtask</li>\n        <li>".format(iocs))
        t1053html.write("at</li>\n        <li>")
        t1053html.write(".job")
        ## timer
        # related techniques
        t1053html.write("{}-</td>\n        <td>".format(related))
        t1053html.write("-")
        # mitigations
        t1053html.write("{}Audit</td>\n        <td>".format(mitigations))
        t1053html.write(
            "Toolkits like the PowerSploit framework contain PowerUp modules that can be used to explore systems for permission weaknesses in scheduled tasks that could be used to escalate privileges.{}".format(
                insert
            )
        )
        t1053html.write("Operating System Configuration</td>\n        <td>")
        t1053html.write(
            "Configure settings for scheduled tasks to force tasks to run under the context of the authenticated account instead of allowing them to run as SYSTEM. The associated Registry key is located at HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\SubmitControl. The setting can be configured through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > Security Options: Domain Controller: Allow server operators to schedule tasks, set to disabled.{}".format(
                insert
            )
        )
        t1053html.write("Privileged Account Management</td>\n        <td>")
        t1053html.write(
            "Configure the Increase Scheduling Priority option to only allow the Administrators group the rights to schedule a priority process. This can be can be configured through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Increase scheduling priority.{}".format(
                insert
            )
        )
        t1053html.write("User Account Management</td>\n        <td>")
        t1053html.write(
            "Limit privileges of user accounts and remediate Privilege Escalation vectors so only authorized administrators can create scheduled tasks on remote systems.{}".format(
                footer
            )
        )
    with open(sd + "t1129.html", "w") as t1129html:
        # description
        t1129html.write(
            "{}Adversaries may abuse shared modules to execute malicious payloads. The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths.<br>".format(
                header
            )
        )
        t1129html.write(
            "This functionality resides in NTDLL.dll and is part of the Windows Native API which is called from functions like CreateProcess, LoadLibrary, etc. of the Win32 API."
        )
        # information
        t1129html.write("{}T1129</td>\n        <td>".format(headings))  # id
        t1129html.write("Windows</td>\n        <td>")  # platforms
        t1129html.write("Execution</td>\n        <td>")  # tactics
        t1129html.write("-")  # sub-techniques
        # indicator regex assignments
        t1129html.write("{}-".format(iocs))
        # related techniques
        t1129html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1106 target="_blank"">T1106</a></td>\n        <td>'.format(
                related
            )
        )
        t1129html.write("Native API")
        # mitigations
        t1129html.write("{}Execution Prevention</td>\n        <td>".format(mitigations))
        t1129html.write(
            "Identify and block potentially malicious software executed through this technique by using application control tools capable of preventing unknown DLLs from being loaded.{}".format(
                footer
            )
        )
    with open(sd + "t1072.html", "w") as t1072html:
        # description
        t1072html.write(
            "{}Adversaries may gain access to and use third-party software suites installed within an enterprise network, such as administration, monitoring, and deployment systems, to move laterally through the network.<br>".format(
                header
            )
        )
        t1072html.write(
            "Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, VNC, HBSS, Altiris, etc.).<br>"
        )
        t1072html.write(
            "Access to a third-party network-wide or enterprise-wide software system may enable an adversary to have remote code execution on all systems that are connected to such a system.<br>"
        )
        t1072html.write(
            "The access may be used to laterally move to other systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.<br>"
        )
        t1072html.write(
            "The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the third-party system, or specific domain credentials may be required.<br>"
        )
        t1072html.write(
            "However, the system may require an administrative account to log in or to perform it's intended purpose."
        )
        # information
        t1072html.write("{}T1072</td>\n        <td>".format(headings))  # id
        t1072html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1072html.write("Execution, Lateral Movement</td>\n        <td>")  # tactics
        t1072html.write("-")  # sub-techniques
        # indicator regex assignments
        t1072html.write("{}-".format(iocs))
        # related techniques
        t1072html.write("{}-</a></td>\n        <td>".format(related))
        t1072html.write("-")
        # mitigations
        t1072html.write(
            "{}Active Directory Configuration</td>\n        <td>".format(mitigations)
        )
        t1072html.write(
            "Ensure proper system and access isolation for critical network systems through use of group policy.{}".format(
                insert
            )
        )
        t1072html.write("Multi-factor Authentication</td>\n        <td>")
        t1072html.write(
            "Ensure proper system and access isolation for critical network systems through use of multi-factor authentication.{}".format(
                insert
            )
        )
        t1072html.write("Network Segmentation</td>\n        <td>")
        t1072html.write(
            "Ensure proper system isolation for critical network systems through use of firewalls.{}".format(
                insert
            )
        )
        t1072html.write("Password Policies</td>\n        <td>")
        t1072html.write(
            "Verify that account credentials that may be used to access deployment systems are unique and not used throughout the enterprise network.{}".format(
                insert
            )
        )
        t1072html.write("Privileged Account Management</td>\n        <td>")
        t1072html.write(
            "Grant access to application deployment systems only to a limited number of authorized administrators.{}".format(
                insert
            )
        )
        t1072html.write("Remote Data Storage</td>\n        <td>")
        t1072html.write(
            "If the application deployment system can be configured to deploy only signed binaries, then ensure that the trusted signing certificates are not co-located with the application deployment system and are instead located on a system that cannot be accessed remotely or to which remote access is tightly controlled.{}".format(
                insert
            )
        )
        t1072html.write("Update Software</td>\n        <td>")
        t1072html.write(
            "Patch deployment systems regularly to prevent potential remote access through Exploitation for Privilege Escalation.{}".format(
                insert
            )
        )
        t1072html.write("User Account Management</td>\n        <td>")
        t1072html.write(
            "Ensure that any accounts used by third-party providers to access these systems are traceable to the third-party and are not used throughout the network or used by other third-party providers in the same environment. Ensure there are regular reviews of accounts provisioned to these systems to verify continued business need, and ensure there is governance to trace de-provisioning of access that is no longer required. Ensure proper system and access isolation for critical network systems through use of account privilege separation.{}".format(
                insert
            )
        )
        t1072html.write("User Training</td>\n        <td>")
        t1072html.write(
            "Have a strict approval policy for use of deployment systems.{}".format(
                footer
            )
        )
    with open(sd + "t1569.html", "w") as t1569html:
        # description
        t1569html.write(
            "{}Adversaries may abuse system services or daemons to execute commands or programs. Adversaries can execute malicious content by interacting with or creating services.<br>".format(
                header
            )
        )
        t1569html.write(
            "Many services are set to run at boot, which can aid in achieving persistence (Create or Modify System Process), but adversaries can also abuse services for one-time or temporary execution."
        )
        # information
        t1569html.write("{}T1569</td>\n        <td>".format(headings))  # id
        t1569html.write("Windows, macOS</td>\n        <td>")  # platforms
        t1569html.write("Execution</td>\n        <td>")  # tactics
        t1569html.write(
            "T1569.001: Launchctl<br>T1569.002: Service Execution"
        )  # sub-techniques
        # indicator regex assignments
        t1569html.write("{}PsExec</li>\n        <li>".format(iocs))
        t1569html.write("services</li>\n        <li>")
        t1569html.write("sc</li>\n        <li>")
        t1569html.write("MSBuild</li>\n        <li>")
        t1569html.write(".service</li>\n        <li>")
        t1569html.write("launchctl</li>")
        # related techniques
        t1569html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1543 target="_blank"">T1543</a></td>\n        <td>'.format(
                related
            )
        )
        t1569html.write("Create or Modify System Process")
        # mitigations
        t1569html.write(
            "{}Privileged Account Management</td>\n        <td>".format(mitigations)
        )
        t1569html.write(
            "Ensure that permissions disallow services that run at a higher permissions level from being created or interacted with by a user with a lower permission level.{}".format(
                insert
            )
        )
        t1569html.write("Restrict File and Directory Permissions</td>\n        <td>")
        t1569html.write(
            "Ensure that high permission level service binaries cannot be replaced or modified by users with a lower permission level.{}".format(
                insert
            )
        )
        t1569html.write("User Account Management</td>\n        <td>")
        t1569html.write(
            "Prevent users from installing their own launch agents or launch daemons.{}".format(
                footer
            )
        )
    with open(sd + "t1204.html", "w") as t1204html:
        # description
        t1204html.write(
            "{}An adversary may rely upon specific actions by a user in order to gain execution.<br>".format(
                header
            )
        )
        t1204html.write(
            "Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link.<br>"
        )
        t1204html.write(
            "These user actions will typically be observed as follow-on behavior from forms of Phishing.<br>"
        )
        t1204html.write(
            "While User Execution frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it.<br>"
        )
        t1204html.write(
            "This activity may also be seen shortly after Internal Spearphishing."
        )
        # information
        t1204html.write("{}T1204</td>\n        <td>".format(headings))  # id
        t1204html.write("Windows, macOS, Linux</td>\n        <td>")  # platforms
        t1204html.write("Execution</td>\n        <td>")  # tactics
        t1204html.write(
            "T1204.001: Malicious Link<br>T1204.002: Malicious File<br>T1204.003: Malicious Image"
        )  # sub-techniques
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
        t1204html.write(".eml</li>")
        # related techniques
        t1204html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1566 target="_blank"">T1566</a></td>\n        <td>'.format(
                related
            )
        )
        t1204html.write("Phishing")
        t1204html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1203 target="_blank"">T1203</a></td>\n        <td>'.format(
                insert
            )
        )
        t1204html.write("Exploitation for Client Execution")
        t1204html.write(
            '{}<a href="http://127.0.0.1:8000/en-US/app/elrond/t1534 target="_blank"">T1534</a></td>\n        <td>'.format(
                insert
            )
        )
        t1204html.write("Internal Spearphishing")
        # mitigations
        t1204html.write("{}Execution Prevention</td>\n        <td>".format(mitigations))
        t1204html.write(
            "Application control may be able to prevent the running of executables masquerading as other files.{}".format(
                insert
            )
        )
        t1204html.write("Network Intrusion Prevention</td>\n        <td>")
        t1204html.write(
            "If a link is being visited by a user, network intrusion prevention systems and systems designed to scan and remove malicious downloads can be used to block activity.{}".format(
                insert
            )
        )
        t1204html.write("Restrict Web-Based Content</td>\n        <td>")
        t1204html.write(
            "If a link is being visited by a user, block unknown or unused files in transit by default that should not be downloaded or by policy from suspicious sites as a best practice to prevent some vectors, such as .scr, .exe, .pif, .cpl, etc. Some download scanning devices can open and analyze compressed and encrypted formats, such as zip and rar that may be used to conceal malicious files.{}".format(
                insert
            )
        )
        t1204html.write("User Training</td>\n        <td>")
        t1204html.write(
            "Use user training as a way to bring awareness to common phishing and spearphishing techniques and how to raise suspicion for potentially malicious events.{}".format(
                footer
            )
        )
    with open(sd + "t1047.html", "w") as t1047html:
        # description
        t1047html.write(
            "{}Adversaries may abuse Windows Management Instrumentation (WMI) to achieve execution. WMI is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components.<br>".format(
                header
            )
        )
        t1047html.write(
            "It relies on the WMI service for local and remote access and the server message block (SMB) and Remote Procedure Call Service (RPCS) for remote access. RPCS operates over port 135.<br>"
        )
        t1047html.write(
            "An adversary can use WMI to interact with local and remote systems and use it as a means to perform many tactic functions, such as gathering information for Discovery and remote Execution of files as part of Lateral Movement."
        )
        # information
        t1047html.write("{}T1047</td>\n        <td>".format(headings))  # id
        t1047html.write("Windows</td>\n        <td>")  # platforms
        t1047html.write("Execution</td>\n        <td>")  # tactics
        t1047html.write("-")  # sub-techniques
        # indicator regex assignments
        t1047html.write("{}Ports: 135</li>\n        <li>".format(iocs))
        t1047html.write("wmic</li>\n        <li>")
        t1047html.write("Invoke-Wmi</li>\n        <li>")
        t1047html.write("msxsl</li>")
        # related techniques
        t1047html.write("{}-</td>\n        <td>".format(related))
        t1047html.write("-")
        # mitigations
        t1047html.write(
            "{}Privileged Account Management</td>\n        <td>".format(mitigations)
        )
        t1047html.write(
            "Prevent credential overlap across systems of administrator and privileged accounts.{}".format(
                insert
            )
        )
        t1047html.write("User Account Management</td>\n        <td>")
        t1047html.write(
            "By default, only administrators are allowed to connect remotely using WMI. Restrict other users who are allowed to connect, or disallow all users to connect remotely to WMI.{}".format(
                footer
            )
        )
