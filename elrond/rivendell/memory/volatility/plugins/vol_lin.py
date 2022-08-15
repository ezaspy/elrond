#!/usr/bin/env python3 -tt
import json
import re


def linux_vol(
    volver,
    profile,
    symbolorprofile,
    plugin,
    plugoutlist,
    jsondict,
    jsonlist,
):
    if plugin == "linux_arp":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"\[(?P<IPAddress>[A-Fa-f\d\.\:]+)\ +\]\ at\ (?P<MACAddress>[A-Fa-f\d\:]+)\ +on\ +(?P<Interface>\S+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 2:
                        print(kv)
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["IPAddress"],
                            jsondict["MACAddress"],
                            jsondict["Interface"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[1],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_bash":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<Environment>\S+)\ +(?P<CommandTime>\d{4}\-\d{2}\-\d{2}\ \d{2}\:\d{2}\:\d{2}(?:\ [\w\+]+)?)\ +(?P<Command>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Command"],
                            jsondict["CommandTime"],
                            jsondict["PID"],
                            jsondict["Environment"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[3],
                            kv[2],
                            kv[0],
                            kv[1],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_bash_env":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<Environment>\S+)\ +(?P<Vars>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 2:
                        print(kv)
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Environment"],
                            jsondict["PID"],
                            Vars,
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            " " + kv[2],
                        )
                    else:
                        pass
                    vardict, varlist = {}, []
                    if kv[2] != " ":
                        Variables = re.sub(r"\ ([A-Z\d\_]+)", r"====\1", Vars)
                        for eachvar in Variables.split("===="):
                            for varkv in re.findall(
                                r"(?P<VarKey>[^\=]+)\=(?P<VarVal>[\S\ ]+)",
                                eachvar,
                            ):
                                if len(varkv) == 2:
                                    vardict[varkv[0]] = (
                                        varkv[1]
                                        .replace(
                                            "\\\\\\\\\\\\\\\\",
                                            "\\\\\\\\",
                                        )
                                        .replace("\\\\\\\\", "\\\\")
                                        .replace("\\\\", "\\")
                                        .replace('\\\\\\"', '\\"')
                                        .replace('\\"', '"')
                                        .replace('"', "'")
                                    )
                                else:
                                    pass
                        varlist.append(json.dumps(vardict))
                        jsondict["Variables"] = varlist
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_bash_hash":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<ProcessName>\S+)\ +(?P<Count>\d+)\ +(?P<Command>\S+)\ +(?P<CommandPath>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["ProcessPath"],
                            jsondict["Environment"],
                            jsondict["PID"],
                            jsondict["Count"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[3],
                            kv[4],
                            kv[1],
                            kv[0],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_check_idt":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<Index>0x[A-Fa-f\d]+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Symbol>\S+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Index"],
                            jsondict["Offset"],
                            jsondict["Symbol"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[1],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_check_syscall":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<Table>\d+bit)\ +(?P<Index>\d+)\ +(?P<SystemCall>\S+)?\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Symbol>\S+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Index"],
                            jsondict["Offset"],
                            jsondict["Symbol"],
                            jsondict["Table"],
                            jsondict["SystemCall"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[3],
                            kv[4],
                            kv[0],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_check_tty":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<TTY>tty\d+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Symbol>\S+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["TTY"],
                            jsondict["Offset"],
                            jsondict["Symbol"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[1],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_dmesg":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^\[(?P<StartTimeDelta>[\d\.]+)\]\s+(?P<Message>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Message"],
                            jsondict["StartTimeDelta"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_elfs":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<ElfName>[\S\-]+)\ +(?P<StartAddress>0x[A-Fa-f\d]+)\ +(?P<EndAddress>0x[A-Fa-f\d]+)\ +(?P<ElfPath>[\S\ ]+\w)\ +(?P<Needed>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ElfName"],
                            jsondict["ElfPath"],
                            jsondict["PID"],
                            jsondict["Needed"],
                            jsondict["StartAddress"],
                            jsondict["EndAddress"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[4],
                            kv[0],
                            kv[5],
                            kv[2],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_enumerate_files":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<InodeAddress>0x[A-Fa-f\d]+)\ +(?P<Inode>[\d\-]+)\ +(?P<Filepath>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Inode"],
                            jsondict["Filepath"],
                            jsondict["InodeAddress"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[2],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_getcwd":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<ProcessName>\S+)\ +(?P<PID>\d+)\ +(?P<CWD>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 1:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["PID"],
                            jsondict["CWD"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[1],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_ifconfig":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<Interface>\S+)\ +(?P<IPAddress>[\d\.]+)\ +(?P<MACAddress>[A-Fa-f\d\:]+)\ +(?P<PromiscousMode>\S+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict[""],
                        ) = (volver, profile, plugin, kv[0])
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_info_regs":
        for plugout in str(plugoutlist).split("Process Name: "):
            for eachkv in re.findall(
                r"^(?:\[(?P<ProcessName>[^\]]+)\])?\ \-\ PID\:\ (?P<PID>\d+)\'\,\ \'Registers\ \(per\ thread\)\:\'\,\ \'\ +Thread\ Name\:\ (?P<ThreadName>[^\']+)\'\,\ \'\ +(?P<RegisterValues>[\S\ ]+)",
                plugout,
            ):
                kv = list(eachkv)
                if len(kv) > 3:
                    (
                        jsondict["VolatilityVersion"],
                        jsondict[symbolorprofile],
                        jsondict["VolatilityPlugin"],
                        jsondict["ProcessName"],
                        jsondict["PID"],
                        jsondict["ThreadName"],
                        RegisterValues,
                    ) = (
                        volver,
                        profile,
                        plugin,
                        kv[0],
                        kv[1],
                        kv[2],
                        kv[3],
                    )
                else:
                    pass
                regdict, reglist = {}, []
                if kv[3] != "', '', '":
                    for eachreg in RegisterValues.split("', '"):
                        for regkv in re.findall(
                            r"(?P<Register>\w+)\ +\:\ +(?P<RegisterValue>[^\\]+)",
                            eachreg,
                        ):
                            if len(regkv) == 2:
                                regdict[regkv[0]] = regkv[1]
                            else:
                                pass
                    reglist.append(json.dumps(regdict))
                    jsondict["Registers"] = reglist
                else:
                    pass
                jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_ldrmodules":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<ModuleName>[\S\ ]+\w)\ +(?P<StartAddress>0x[A-Fa-f\d]+)\ +(?P<Filepath>[\S\ ]+\w)\ +(?P<Kernel>\w+)\ +(?P<Libc>\w+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ModuleName"],
                            jsondict["Filepath"],
                            jsondict["PID"],
                            jsondict["StartAddress"],
                            jsondict["Kernel"],
                            jsondict["Libc"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[3],
                            kv[0],
                            kv[2],
                            kv[4],
                            kv[5],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_library_list":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<Task>\S+)\ +(?P<PID>\d+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Filepath>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Task"],
                            jsondict["Filepath"],
                            jsondict["PID"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[3],
                            kv[1],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_lsof":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<ProcessName>\S+)\ +(?P<PID>\d+)\ +(?P<FileDescriptor>\d+)\ +(?P<Filepath>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["PID"],
                            jsondict["FileDescriptor"],
                            jsondict["Filepath"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[2],
                            kv[3],
                            kv[4],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_malfind":
        for plugout in str(plugoutlist).split("Process"):
            for eachkv in re.findall(
                r"^\:\ (?P<ProcessName>.*)\ Pid\:\ (?P<PID>\d+)\ Address\:\ (?P<Offset>0x[A-Fa-f\d]+)\ File\:\ (?P<File>\w+)\'\,\ \'Protection\:\ (?P<Protection>\w+)\'\,\ \'\'\,\ \'(?P<DataAssembly>[\S\s]+)",
                plugout,
            ):
                kv = list(eachkv)
                if len(kv) > 5:
                    (
                        jsondict["VolatilityVersion"],
                        jsondict[symbolorprofile],
                        jsondict["VolatilityPlugin"],
                        jsondict["ProcessName"],
                        jsondict["PID"],
                        jsondict["Offset"],
                        jsondict["File"],
                        jsondict["Permissions"],
                        DataAssembly,
                    ) = (
                        volver,
                        profile,
                        plugin,
                        kv[0],
                        kv[1],
                        kv[2],
                        kv[3],
                        kv[4],
                        kv[5],
                    )
                else:
                    pass
                (
                    datadict,
                    datalist,
                    hexdata,
                    asciidata,
                    asmdict,
                    asmlist,
                    allasm,
                ) = ({}, [], "", "", {}, [], "")
                for eachdata in DataAssembly.split("', '', '")[0].split("', '"):
                    hexdata = hexdata + str(eachdata)[12:60].replace(" ", "")
                    asciidata = asciidata + str(eachdata)[63:81]
                for eachasm in DataAssembly.split("', '', '")[1].split("', '"):
                    for asmkv in re.findall(
                        r"^(?P<Offset>0x[A-Fa-f\d]+)\s+(?P<Hex>\w+)\s+(?P<Instruction>.*)",
                        eachasm,
                    ):
                        (
                            asmdict["AssemblyOffset"],
                            asmdict["AssemblyHEX"],
                            asmdict["AssemblyInstruction"],
                        ) = (asmkv[0], asmkv[1], asmkv[2])
                        if len(asmkv) > 2:
                            asmlist.append(json.dumps(asmdict))
                        else:
                            pass
                    allasm = allasm + "\n" + eachasm
                (
                    datadict["RawHEXData"],
                    datadict["RawASCIIData"],
                    datadict["FormattedASCIIData"],
                    datadict["AssemblyInstructions"],
                ) = (
                    hexdata,
                    asciidata,
                    asciidata[::2],
                    asmlist,
                )
                datalist.append(json.dumps(datadict))
                jsondict["Data"] = datalist
                jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_mount":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<Device>\S+)\ +(?P<MountPoint>[\S\ ]+\w)\ +(?P<FileSystem>\S+)\ +(?P<Flags>\S+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Device"],
                            jsondict["MountPoint"],
                            jsondict["FileSystem"],
                            jsondict["Flags"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[1],
                            kv[2],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_netscan":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<Offset>[A-Fa-f\d]+)\ +(?P<Protocol>\w+)\ +(?P<SourceIP>[A-Fa-z\d\.\:]+)\ +\:\ *(?P<SourcePort>\d+)\ +(?P<DestinationIP>[A-Fa-z\d\.\:]+)\ +\:\ *(?P<DestinationPort>\d+)\ +(?P<State>\w+)?",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["SourceIP"],
                            jsondict["SourcePort"],
                            jsondict["DestinationIP"],
                            jsondict["DestinationPort"],
                            jsondict["Protocol"],
                            jsondict["State"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[2],
                            kv[3],
                            kv[4],
                            kv[5],
                            kv[1],
                            kv[6],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_netstat":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                if (
                    eachinfo.startswith("UNIX")
                    or eachinfo.startswith("Unix")
                    or eachinfo.startswith("unix")
                ):
                    for eachkv in re.findall(
                        r"(?P<Protocol>UNIX|Unix|unix)\ +(?P<Count>\d+)\ +(?P<Flags>\S+)?\ +(?P<Type>\S+)?\ +(?P<Description>\S+)\ +(?P<Inode>\d+)?\ +(?P<Path>[\S\ ]+)?",
                        eachinfo.replace("\\\\ n", "\\\\n"),
                    ):
                        kv = list(eachkv)
                        if len(kv) > 0:
                            (
                                jsondict["VolatilityVersion"],
                                jsondict[symbolorprofile],
                                jsondict["VolatilityPlugin"],
                                jsondict["Protocol"],
                                jsondict["Desciption"],
                                jsondict["Type"],
                                jsondict["Flags"],
                                jsondict["Path"],
                                jsondict["Inode"],
                                jsondict["Count"],
                            ) = (
                                volver,
                                profile,
                                plugin,
                                kv[0],
                                kv[4],
                                kv[3],
                                kv[2],
                                kv[6],
                                kv[5],
                                kv[1],
                            )
                        else:
                            pass
                        jsonlist.append(json.dumps(jsondict))
                else:
                    for eachkv in re.findall(
                        r"(?P<Protocol>\w+)\ +(?P<SourceIP>[\d\.\:]+)\ +\:\ *(?P<SourcePort>\d+)\ +(?P<DestinationIP>[\d\.\:]+)\ +\:\ *(?P<DestinationPort>\d+)\ +(?P<Description>[\S\ ]+)",
                        eachinfo.replace("\\\\ n", "\\\\n"),
                    ):
                        kv = list(eachkv)
                        if len(kv) > 0:
                            (
                                jsondict["VolatilityVersion"],
                                jsondict[symbolorprofile],
                                jsondict["VolatilityPlugin"],
                                jsondict["Protocol"],
                                jsondict["Desciption"],
                                jsondict["SourceIP"],
                                jsondict["SourcePort"],
                                jsondict["DestinationIP"],
                                jsondict["DestinationPort"],
                            ) = (
                                volver,
                                profile,
                                plugin,
                                kv[0],
                                kv[5],
                                kv[1],
                                kv[2],
                                kv[3],
                                kv[4],
                            )
                        else:
                            pass
                        jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_plthook":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<TaskNumber>\w+)\ +(?P<StartAddress>0x[A-Fa-f\d]+)\ +(?P<ElfName>\S+)\ +(?P<Symbol>\S+)?\ +(?P<EndAddress>0x[A-Fa-f\d]+)(?:\ \S)?\ +(?P<TargetInfo>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ElfName"],
                            jsondict["TaskNumber"],
                            jsondict["Symbol"],
                            jsondict["TargetInfo"],
                            jsondict["StartAddress"],
                            jsondict["EndAddress"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[2],
                            kv[0],
                            kv[3],
                            kv[5],
                            kv[1],
                            kv[4],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_proc_maps" or plugin == "linux_proc_maps_rb":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<PID>\d+)\ +(?P<ProcessName>\w+)\ +(?P<StartAddress>0x[A-Fa-f\d]+)\ +(?P<EndAddress>0x[A-Fa-f\d]+)\ +(?P<Flags>[RWXrwx\-]+)\ +(?P<PageOffset>0x[A-Fa-f\d]+)\ +(?P<Major>\d+)\ +(?P<Minor>\d+)\ +(?P<Inode>\d+)\ +(?P<Filepath>[\S\ ]+)?",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["PID"],
                            jsondict["Filepath"],
                            jsondict["Flags"],
                            jsondict["Inode"],
                            jsondict["Major"],
                            jsondict["Minor"],
                            jsondict["StartAddress"],
                            jsondict["EndAddress"],
                            jsondict["Offset"],
                            jsondict["PageOffset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[2],
                            kv[1],
                            kv[10],
                            kv[5],
                            kv[9],
                            kv[7],
                            kv[8],
                            kv[3],
                            kv[4],
                            kv[0],
                            kv[6],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_psaux":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<UserID>\d+)\ +(?P<GroupID>\d+)\ +(?P<Command>[\S\ ]+)?",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["PID"],
                            jsondict["UserID"],
                            jsondict["GroupID"],
                            jsondict["CommandArguments"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[1],
                            kv[2],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_psenv":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<Item>\S+)\ +(?P<Vars>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Item"],
                            jsondict["PID"],
                            Vars,
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            " " + kv[2],
                        )
                    else:
                        pass
                    vardict, varlist = {}, []
                    if kv[2] != " ":
                        Variables = re.sub(r"\ ([A-Z\d\_]+)", r"====\1", Vars)
                        for eachvar in Variables.split("===="):
                            for varkv in re.findall(
                                r"(?P<VarKey>[^\=]+)\=(?P<VarVal>[\S\ ]+)",
                                eachvar,
                            ):
                                if len(varkv) == 2:
                                    vardict[varkv[0]] = (
                                        varkv[1]
                                        .replace(
                                            "\\\\\\\\\\\\\\\\",
                                            "\\\\\\\\",
                                        )
                                        .replace("\\\\\\\\", "\\\\")
                                        .replace("\\\\", "\\")
                                        .replace('\\\\\\"', '\\"')
                                        .replace('\\"', '"')
                                        .replace('"', "'")
                                    )
                                else:
                                    pass
                        varlist.append(json.dumps(vardict))
                        jsondict["Variables"] = varlist
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_pslist":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<ProcessName>\S+)\ +(?P<PID>\d+)\ +(?P<PPID>\d+)\ +(?P<UID>\d+)\ +(?P<GID>\d+)\ +(?P<DTB>(?:0x[A-Fa-f\d]+|\-+))\ +(?P<Time>\d{4}\-\d{2}\-\d{2}\ \d{2}\:\d{2}\:\d{2}\ \w+\+\d+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["PID"],
                            jsondict["Offset"],
                            jsondict["Time"],
                            jsondict["UserID"],
                            jsondict["GroupID"],
                            jsondict["PPID"],
                            jsondict["DTB"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[2],
                            kv[0],
                            kv[7],
                            kv[4],
                            kv[5],
                            kv[3],
                            kv[6],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_psscan":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<ProcessName>\S+)?\ +(?P<PID>\d+)\ +(?P<PPID>[\d\-]+)\ +(?P<UID>[\d\-]+)\ +(?P<GID>[\d\-]+)\ +(?P<DTB>(?:0x[A-Fa-f\d]+|\-+))\ +(?P<Time>\d{4}\-\d{2}\-\d{2}\ \d{2}\:\d{2}\:\d{2}\ \w+\+\d+)?",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["PID"],
                            jsondict["Offset"],
                            jsondict["Time"],
                            jsondict["UserID"],
                            jsondict["GroupID"],
                            jsondict["PPID"],
                            jsondict["DTB"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[2],
                            kv[0],
                            kv[7],
                            kv[4],
                            kv[5],
                            kv[3],
                            kv[6],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_pstree":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<ProcessName>\S+)\ +(?P<PID>\d+)\ +(?P<UID>[\d\-]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["PID"],
                            jsondict["UserID"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[1],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux_threads":
        for plugout in str(plugoutlist).split("Process Name: "):
            for eachkv in re.findall(
                r"^(?P<ProcessName>[^\]]+)\'\,\ \'Process\ ID\:\ (?P<PID>\d+)\'\,\ \'Thread\ PID\ +Thread\ Name\ +\'\,\ \'\-+\ \-+\'\,\ \'(?P<Threads>[\S\ ]+)",
                plugout,
            ):
                kv = list(eachkv)
                if len(kv) > 0:
                    (
                        jsondict["VolatilityVersion"],
                        jsondict[symbolorprofile],
                        jsondict["VolatilityPlugin"],
                        jsondict["ProcessName"],
                        jsondict["PID"],
                        Threads,
                    ) = (
                        volver,
                        profile,
                        plugin,
                        kv[0],
                        kv[1],
                        kv[2],
                    )
                else:
                    pass
                if kv[2] != "', '', '":
                    for eachthrd in Threads.split("', '"):
                        for thrdkv in re.findall(
                            r"(?P<ThreadID>\d+)\s+(?P<ThreadName>[\S]+)",
                            eachthrd,
                        ):
                            if len(thrdkv) == 2:
                                (
                                    jsondict["ThreadName"],
                                    jsondict["ThreadID"],
                                ) = (thrdkv[1], thrdkv[0])
                                jsonlist.append(json.dumps(jsondict))
                            else:
                                pass
                else:
                    pass
    else:
        pass
    return jsonlist
