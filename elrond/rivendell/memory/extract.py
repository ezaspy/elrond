#!/usr/bin/env python3 -tt
import os
import re
import subprocess
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.memory.plugins import use_plugins


import time


def extract_memory_artefacts(
    verbosity,
    output_directory,
    volver,
    volprefix,
    artefact,
    profile,
    mempath,
    memext,
    vssimage,
    memtimeline,
    mesginsrt,
):
    def print_extraction(
        verbosity,
        output_directory,
        artefact,
        volprefix,
        volversion,
        profile,
        mesginsrt,
        vssimage,
    ):
        if artefact.split("/")[-1] == vssimage:
            print(
                "{}{} is extracting artefacts from '{}' with {} '{}'...".format(
                    volprefix,
                    volversion,
                    artefact.split("/")[-1],
                    mesginsrt,
                    profile,
                )
            )
            entry, prnt = "{},{},extracting,{} ({})\n".format(
                datetime.now().isoformat(), vssimage, artefact.split("/")[-1], profile
            ), " -> {} -> extracting artefacts from '{}' ({})".format(
                datetime.now().isoformat().replace("T", " "),
                artefact.split("/")[-1],
                profile,
            )
        else:
            print(
                "{}{} is extracting artefacts from '{}' with {} '{}' for {}...".format(
                    volprefix,
                    volversion,
                    artefact.split("/")[-1],
                    mesginsrt,
                    profile,
                    vssimage,
                )
            )
            entry, prnt = "{},{},extracting,{} ({})\n".format(
                datetime.now().isoformat(), vssimage, artefact.split("/")[-1], profile
            ), " -> {} -> extracting artefacts from '{}' ({}) for {}".format(
                datetime.now().isoformat().replace("T", " "),
                artefact.split("/")[-1],
                profile,
                vssimage,
            )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        return profile

    if volver == "3":  # volatility3
        if not artefact.endswith("hiberfil.sys"):
            print_extraction(
                verbosity,
                output_directory,
                artefact,
                volprefix,
                mesginsrt,
                "Windows",
                "symbol table",
                vssimage,
            )
        else:
            print_extraction(
                verbosity,
                output_directory,
                artefact,
                volprefix,
                mesginsrt,
                profile,
                "symbol table",
                vssimage,
            )
        if "Windows" in profile or profile.startswith("Win"):
            volplugins = [
                "windows.cmdline.CmdLine",
                "windows.dlllist.DllList",
                "windows.driverscan.DriverScan",
                "windows.envars.Envars",
                "windows.filescan.Filescan",
                "windows.getservicesids.GetServiceSIDs",
                "windows.getsids.GetSIDs",
                "windows.handles.Handles",
                "windows.info.Info",
                "windows.malfind.Malfind",
                "windows.modscan.ModScan",
                "windows.modules.Modules",
                "windows.mutantscan.MutantScan",
                "windows.netscan.NetScan",
                "windows.netstat.NetStat",
                "windows.privileges.Privileges",
                "windows.pslist.PsList",
                "windows.psscan.PsScan",
                "windows.pstree.PsTree",
                "windows.registry.certificates.Certificates",
                "windows.registry.hivelist.HiveList",
                "windows.registry.hivescan.HiveScan",
                "windows.registry.printkey.PrintKey",
                "windows.registry.userassist.UserAssist",
                "windows.ssdt.SSDT",
                "windows.symlinkscan.SymlinkScan",
                "windows.vadinfo.VadInfo",
            ]
        elif (
            "macOS" in profile or profile.startswith("Mac") or profile.startswith("mac")
        ):
            volplugins = [
                "mac.bash.Bash",
                "mac.check_syscall.Check_syscall",
                "mac.check_sysctl.Check_sysctl",
                "mac.check_trap_table.Check_trap_table",
                "mac.ifconfig.Ifconfig",
                "mac.kauth_listeners.Kauth_listeners",
                "mac.kauth_scopes.Kauth_scopes",
                "mac.kevents.Kevents",
                "mac.lsmod.Lsmod",
                "mac.lsof.Lsof",
                "mac.malfind.Malfind",
                "mac.mount.Mount",
                "mac.netstat.Netstat",
                "mac.proc_maps.Proc_maps",
                "mac.psaux.Psaux",
                "mac.pslist.Pslist",
                "mac.pstree.Pstree",
                "mac.socket_filters.Socket_filters",
                "mac.timers.Timers",
                "mac.trustedbsd.Trustedbsd",
                "mac.vfsevents.Vfsevents",
            ]
        else:
            volplugins = [
                "linux.bash.Bash",
                "linux.check_afinfo.Check_afinfo",
                "linux.check_creds.Check_creds",
                "linux.check_idt.Check_idt",
                "linux.check_modules.Check_modules",
                "linux.check_syscall.Check_syscall",
                "linux.elfs.Elfs",
                "linux.keyboard_notifiers.Keyboard_notifiers",
                "linux.lsmod.Lsmod",
                "linux.lsof.Lsof",
                "linux.malfind.Malfind",
                "linux.proc.Proc",
                "linux.pslist.Pslist",
                "linux.pstree.Pstree",
                "linux.tty_check.tty_check",
            ]
        for plugin in volplugins:
            try:
                use_plugins(
                    output_directory,
                    verbosity,
                    vssimage,
                    artefact,
                    volver,
                    memext,
                    mempath,
                    profile,
                    plugin,
                )
            except:
                pass
        if memtimeline:
            volplugins = ["timeliner.Timeliner"]
            for plugin in volplugins:
                try:
                    use_plugins(
                        output_directory,
                        verbosity,
                        vssimage,
                        artefact,
                        volver,
                        memext,
                        mempath,
                        profile,
                        plugin,
                    )
                except:
                    pass
        else:
            pass
    else:  # volatility2.6
        print_extraction(
            verbosity,
            output_directory,
            artefact,
            volprefix,
            mesginsrt,
            profile,
            "profile",
            vssimage,
        )
        if profile.startswith("Win"):
            volplugins = [
                "apihooks",
                "apihooksdeep",
                "cmdline",
                "cmdscan",
                "consoles",
                "directoryenumerator",
                "dlllist",
                "driverirp",
                "drivermodule",
                "driverscan",
                "envars",
                "filescan",
                "gahti",
                "gditimers",
                "getservicesids",
                "getsids",
                "handles",
                "hashdump",
                "hivelist",
                "ldrmodules",
                "malfind",
                "malprocfind",
                "messagehooks",
                "mimikatz",
                "modscan",
                "modules",
                "mutantscan",
                "ndispktscan",
                "netscan",
                "objtypescan",
                "privs",
                "pslist",
                "psscan",
                "pstree",
                "psxview",
                "shellbags",
                "shimcache",
                "shimcachemem",
                "svcscan",
                "symlinkscan",
                "systeminfo",
                "thrdscan",
                "unloadedmodules",
                "usbstor",
                "userassist",
                "userhandles",
                "vadinfo",
                "win10cookie",
            ]  # plugins
        elif (
            profile.startswith("Mac")
            or profile.startswith("mac")
            or profile.startswith("10.")
            or profile.startswith("11.")
        ):
            volplugins = [
                "mac_apihooks_kernel",
                "mac_apihooks",
                "mac_arp",
                "mac_bash",
                "mac_check_fop",
                "mac_check_mig_table",
                "mac_check_syscalls",
                "mac_check_sysctl",
                "mac_devfs",
                "mac_dyld_maps",
                "mac_ifconfig",
                "mac_kernel_classes",
                "mac_kevents",
                "mac_keychaindump",
                "mac_ldrmodules",
                "mac_list_sessions",
                "mac_lsmod_iokit",
                "mac_malfind",
                "mac_mount",
                "mac_netstat",
                "mac_network_conns",
                "mac_notifiers",
                "mac_orphan_threads",
                "mac_proc_maps",
                "mac_psaux",
                "mac_psenv",
                "mac_pslist",
                "mac_pstree",
                "mac_psxview",
                "mac_socket_filters",
                "mac_tasks",
                "mac_trustedbsd",
            ]
        else:
            volplugins = [
                "linux_arp",
                "linux_bash",
                "linux_bash_env",
                "linux_bash_hash",
                "linux_check_idt",
                "linux_check_syscall",
                "linux_check_tty",
                "linux_dmesg",
                "linux_elfs",
                "linux_enumerate_files",
                "linux_getcwd",
                "linux_ifconfig",
                "linux_info_regs",
                "linux_ldrmodules",
                "linux_library_list",
                "linux_lsof",
                "linux_malfind",
                "linux_mount",
                "linux_netscan",
                "linux_netstat",
                "linux_plthook",
                "linux_proc_maps",
                "linux_proc_maps_rb",
                "linux_psaux",
                "linux_psenv",
                "linux_pslist",
                "linux_psscan",
                "linux_pstree",
                "linux_threads",
            ]
        for plugin in volplugins:
            try:
                use_plugins(
                    output_directory,
                    verbosity,
                    vssimage,
                    artefact,
                    volver,
                    memext,
                    mempath,
                    profile,
                    plugin,
                )
            except:
                entry, prnt = "{},{},evidence extraction failed {},{} ({})\n".format(
                    datetime.now().isoformat(),
                    vssimage,
                    plugin,
                    artefact.split("/")[-1],
                    profile,
                ), " -> {} -> evidence extraction or '{}' failed from {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    plugin,
                    vssimage,
                )
                write_audit_log_entry(
                    verbosity, output_directory, entry, prnt
                )  # failed to extract no evidence of plugin
        if profile.startswith("Win"):
            if memtimeline:
                if not os.path.exists(output_directory + mempath + "timeliner.csv"):
                    with open(
                        output_directory + mempath + "timeliner.csv", "a"
                    ) as timeliner:
                        timeline = str(
                            subprocess.Popen(
                                [
                                    "vol.py",
                                    "-f",
                                    artefact + memext,
                                    "--profile=" + profile,
                                    "timeliner",
                                ],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            ).communicate()[0]
                        )[2:-1].split("\\n")
                        timeliner.write(
                            "LastWriteTime,ActionType,RegistryKey,Process,ProcessName,PID,PPID,Offset,Base,Registry,VolatilityPlugin,VolatilityProfile\n"
                        )
                        for line in timeline:
                            if "/P" in line:
                                entries = re.findall(
                                    r"^(?P<LastWriteTime>[^\|]+)\|(?P<ActionType>[^\|]+)(?:\|(?P<RegistryKey>[\w\-\ \.\&\(\)]+\/[\w\-\ \.\&\(\)\/]+)?)?\|(?P<Process>[^\|]+)(?:\|Process\:\ (?P<ProcessName>[^\|]+))?\|PID\:\ (?P<PID>[^\|]+)\|PPID\:\ (?P<PPID>[^\|]+)\|P(?:rocess)?Offset\:\ (?P<Offset>[^\|]+)(?:\|Base\:\ (?P<Base>0x\S+))?$",
                                    str(
                                        str(line.strip())
                                        .replace("/P", "|P")
                                        .replace(" | ", "|")
                                        .replace("| ", "|")
                                        .replace("\\\\", "/")
                                        .replace(" PID:", "|PID:")
                                        .replace("Process PO", "ProcessO")
                                        .replace("/DLL B", "|B")
                                        .replace("||", "|")
                                    ),
                                )
                                if len(str(entries)) > 2:
                                    if len(entries[0][2]) > 0:
                                        timelinerow = str(entries[0])[1:-1].replace(
                                            "''", "'-'"
                                        ).replace(", ", ",").replace(
                                            "'", ""
                                        ) + ",{},timeliner,{}\n".format(
                                            str(entries[0][2]).lower(), profile
                                        )
                                    else:
                                        timelinerow = str(entries[0])[1:-1].replace(
                                            "''", "'-'"
                                        ).replace(", ", ",").replace(
                                            "'", ""
                                        ) + ",-,timeliner,{}\n".format(
                                            profile
                                        )
                                    timeliner.write(timelinerow)
                                else:
                                    pass
                            else:
                                pass
                else:
                    pass
            else:
                pass
            if not os.path.exists(
                output_directory + mempath + "/memory_" + "iehistory.json"
            ):
                with open(
                    output_directory + mempath + "/memory_" + "iehistory.json", "w"
                ) as plugout:
                    plugoutlist = str(
                        subprocess.Popen(
                            [
                                "vol.py",
                                "-f",
                                artefact + memext,
                                "--profile=" + profile,
                                "iehistory",
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()[0]
                    )[2:-1].split("\\n")
                    for plug in plugoutlist:
                        plugout.write(plug + "\n")
            else:
                pass
            if not os.path.exists(output_directory + mempath + "/dumpreg/"):
                os.makedirs(output_directory + mempath + "/dumpreg/")
                subprocess.Popen(
                    [
                        "vol.py",
                        "-f",
                        os.path.realpath(artefact) + memext,
                        "--profile=" + profile,
                        "dumpregistry",
                        "--dump-dir",
                        output_directory + mempath + "/dumpreg/",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()
            else:
                pass
        else:
            pass
    vssmem = profile
    if artefact.split("/")[-1] == vssimage:
        insertvssimage = " for " + vssimage
    else:
        insertvssimage = ""
    print(
        "{}Extraction of artefacts completed from '{}'{}.".format(
            volprefix, artefact.split("/")[-1], insertvssimage
        )
    )
    entry, prnt = "{},{},artefact extraction complete,{} ({})\n".format(
        datetime.now().isoformat(), vssimage, artefact.split("/")[-1], profile
    ), " -> {} -> artefact extraction from '{}' ({}) completed for {}".format(
        datetime.now().isoformat().replace("T", " "),
        artefact.split("/")[-1],
        profile,
        vssimage,
        insertvssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    return profile, vssmem
