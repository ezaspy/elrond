#!/usr/bin/env python3 -tt
import json
import re


def mac_vol(
    volver,
    profile,
    symbolorprofile,
    plugin,
    plugoutlist,
    jsondict,
    jsonlist,
):
    if plugin == "mac_apihooks_kernel":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<TableName>\w+(?:\ \-\>)?)\ +(?P<Index>\d+)\ +(?P<Address>0x[A-Fa-f\d]+)\ +(?P<Symbol>\w+)?\ +(?P<Inlined>\w+)\ +(?P<Shadowed>\w+)\ +(?P<Permissions>\S+)\ +(?P<HookIn>\w+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["TableName"],
                            jsondict["Index"],
                            jsondict["HookIn"],
                            jsondict["Offset"],
                            jsondict["Inlined"],
                            jsondict["Shadowed"],
                            jsondict["Perms"],
                            jsondict["Symbol"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[1],
                            kv[7],
                            kv[2],
                            kv[4],
                            kv[5],
                            kv[6],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_apihooks":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<HookName>[^\d]+)\ +(?P<PID>\d+)\ +(?P<Symbol>\w+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<LazyHook>\w+)\ +(?P<PointerHook>\w+)\ +(?P<APIHook>\w+)\ +(?P<HookType>\w+)?\ +(?P<HookOffset>0x[A-Fa-f\d]+)\ +(?P<HookLibrary>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["HookName"],
                            jsondict["HookLibrary"],
                            jsondict["PID"],
                            jsondict["Offset"],
                            jsondict["Symbol"],
                            jsondict["SymbolOffset"],
                            jsondict["LazyHook"],
                            jsondict["PointerHook"],
                            jsondict["APIHook"],
                            jsondict["HookType"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0].strip(),
                            kv[9],
                            kv[1],
                            kv[8],
                            kv[2],
                            kv[3],
                            kv[4],
                            kv[5],
                            kv[6],
                            kv[7],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_arp":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<SourceIP>[A-Fa-f\d\.\:]+)\ +(?P<DestinationIP>[A-Fa-f\d\.\:]+)\ +(?P<Interface>\w+)\ +(?P<PacketsSent>\d+)\ +(?P<PacketsReceived>\d+)\ +(?P<Time>\d{4}\-\d{2}\-\d{2}\ \d{2}\:\d{2}\:\d{2}\ \w+\+\d+)\ +(?P<Expiration>\w+)\ +(?P<Delta>\w+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Time"],
                            jsondict["SourceIP"],
                            jsondict["DestinationIP"],
                            jsondict["Interface"],
                            jsondict["PacketsSent"],
                            jsondict["PacketsReceived"],
                            jsondict["Expiration"],
                            jsondict["Delta"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[5],
                            kv[0],
                            kv[1],
                            kv[2],
                            kv[3],
                            kv[4],
                            kv[6],
                            kv[7],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_bash":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<Process>\w+)\ +(?P<Time>\d{4}\-\d{2}\-\d{2}\ \d{2}\:\d{2}\:\d{2}\ \w+\+\d+)\ +(?P<Command>.*)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Time"],
                            jsondict["Process"],
                            jsondict["PID"],
                            jsondict["Command"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[2],
                            kv[1],
                            kv[0],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_check_fop":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<HandlerName>[\w\/]+)\ +(?P<Handler>0x[A-Fa-f\d]+)\ +(?P<Module>\w+)\ +(?P<HandlerSymbol>\w+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["HandlerName"],
                            jsondict["Handler"],
                            jsondict["HandlerSymbol"],
                            jsondict["Offset"],
                            jsondict["Module"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[2],
                            kv[4],
                            kv[0],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_check_mig_table":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<Index>\d+)\ +(?P<RoutineName>[\w\/]+)\ +(?P<Handler>0x[A-Fa-f\d]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["RoutineName"],
                            jsondict["Handler"],
                            jsondict["Index"],
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
    elif plugin == "mac_check_syscalls":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<TableName>\w+)\ +(?P<Index>\d+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Symbol>\w+)\ +(?P<Status>\w+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["TableName"],
                            jsondict["Symbol"],
                            jsondict["Offset"],
                            jsondict["Status"],
                            jsondict["Index"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[3],
                            kv[2],
                            kv[4],
                            kv[1],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_check_sysctl":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Name>\w+)\ +(?P<Number>\d+)\ +(?P<Permisssions>[RWLXrwlx\-]+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Value>[\w\-\.\ ]+)?\ +(?P<Module>[\w\.]+)\ +(?P<Status>\w+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Name"],
                            jsondict["Number"],
                            jsondict["Value"],
                            jsondict["Offset"],
                            jsondict["Permisssions"],
                            jsondict["Module"],
                            jsondict["Status"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[1],
                            kv[4].strip(),
                            kv[3],
                            kv[2],
                            kv[5],
                            kv[6],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_devfs":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Path>[\w\/]+)\ +(?P<Member>\w+)\ +(?P<HandlerOffset>0x[A-Fa-f\d]+)\ +(?P<Module>[\w\.]+)?\ +(?P<Handler>\w+)?",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Path"],
                            jsondict["Offset"],
                            jsondict["Member"],
                            jsondict["Module"],
                            jsondict["Handler"],
                            jsondict["HandlerOffset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            kv[2],
                            kv[4],
                            kv[5],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_dyld_maps":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<PID>\d+)\ +(?P<DYLDName>\w+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<MapName>\S+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Name"],
                            jsondict["PID"],
                            jsondict["Offset"],
                            jsondict["MapName"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            kv[2],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_ifconfig":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Interface>[A-Fa-f\d\.\:]+)\ +(?P<SourceIP>[A-Fa-f\d\.\:]+)\ +(?P<MACAddess>\w+)\ +(?P<Promiscuous>\d+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["SourceIP"],
                            jsondict["DestinationIP"],
                            jsondict["Interface"],
                            jsondict["Promiscuous"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[2],
                            kv[0],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_kernel_classes":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Class>\w+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Module>\S+)\ +(?P<Handler>\w+)?",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Class"],
                            jsondict["Module"],
                            jsondict["Handler"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[2],
                            kv[3],
                            kv[1],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_kevents":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<EventName>\S+)\ +(?P<PID>\d+)\ +(?P<Identifier>\w+)\ +(?P<Filter>[\w\.]+)?\ +(?P<Context>.*)?",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["EventName"],
                            jsondict["PID"],
                            jsondict["Identifier"],
                            jsondict["Filter"],
                            jsondict["Context"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[2],
                            kv[3],
                            kv[4],
                            kv[5],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_keychaindump":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Key>[A-Fa-f\d]{48})",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    (
                        jsondict["VolatilityVersion"],
                        jsondict[symbolorprofile],
                        jsondict["VolatilityPlugin"],
                        jsondict["Key"],
                    ) = (volver, profile, plugin, eachkv)
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_ldrmodules":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<ModuleName>.*)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Filepath>\S+)\ +(?P<Kernel>\w+)\ +(?P<DyLibID>[\w\.]+)?",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ModuleName"],
                            jsondict["PID"],
                            jsondict["Filepath"],
                            jsondict["Offset"],
                            jsondict["Kernel"],
                            jsondict["DyLibID"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            kv[3],
                            kv[2],
                            kv[4],
                            kv[5],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_list_sessions":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<SessionName>\S+)\ +(?P<AccountName>[\w\.]+)?",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["SessionName"],
                            jsondict["AccountName"],
                            jsondict["PID"],
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
    elif plugin == "mac_lsmod_iokit":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<ModuleAddress>0x[A-Fa-f\d]+)\ +(?P<Size>\d+)\ +(?P<References>[\d\-]+)\ +(?P<Version>\d+)\ +(?P<ModuleName>[\w\.]+)\ +(?P<Path>\S+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Name"],
                            jsondict["Version"],
                            jsondict["References"],
                            jsondict["Path"],
                            jsondict["Offset"],
                            jsondict["ModuleAddress"],
                            jsondict["Size"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[5],
                            kv[4],
                            kv[3],
                            kv[7],
                            kv[0],
                            kv[1],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_malfind":
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
    elif plugin == "mac_mount":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Device>\/(?:[\w\/]+\w(?:\ \w+)*)?)\ +(?P<MountPoint>[\S\ ]+\w+)\ +(?P<Type>\w+)",
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
                            jsondict["Type"],
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
    elif plugin == "mac_netstat":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Protocol>[\S]+)\ +(?P<LocalAddress>[A-Fa-f\d\.\:]+)\ +(?P<LocalPort>\d+)\ +(?P<ForeignAddress>[A-Fa-f\d\.\:]+)\ +(?P<ForeignPort>\d+)\ +(?P<ConnectionState>\S+)?\ +(?P<ProcessName>\S+)\/(?P<PID>\d+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["LocalAddress"],
                            jsondict["LocalPort"],
                            jsondict["ForeignAddress"],
                            jsondict["ForeignPort"],
                            jsondict["PID"],
                            jsondict["Protocol"],
                            jsondict["ConnectionState"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[6],
                            kv[1],
                            kv[2],
                            kv[3],
                            kv[4],
                            kv[7],
                            kv[0],
                            kv[5],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_network_conns":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Protocol>\w+)\ +(?P<LocalAddress>[\d\.\:\-]+)\ +(?P<LocalPort>\d+)\ +(?P<ForeignAddress>[\d\.\:\-\*]+)\ +(?P<ForeignPort>[\d\*]+)\ +(?P<ConnectionState>\w+)?",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["LocalAddress"],
                            jsondict["LocalPort"],
                            jsondict["ForeignAddress"],
                            jsondict["ForeignPort"],
                            jsondict["Protocol"],
                            jsondict["ConnectionState"],
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
    elif plugin == "mac_notifiers":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Key>\w+)\ +(?P<Matches>\S+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Module>[\w\.]+)\ +(?P<Status>\w+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Key"],
                            jsondict["Matches"],
                            jsondict["Module"],
                            jsondict["Status"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[1],
                            kv[3],
                            kv[4],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_orphan_threads":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<ProcessName>\S+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Mapping>[\w\.]+)\ +(?P<ThreadName>\w[\S\ ]+\w)?\ +(?P<Status>\S+)$",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ThreadName"],
                            jsondict["Status"],
                            jsondict["Offset"],
                            jsondict["Mapping"],
                            jsondict["ProcessName"],
                            jsondict["PID"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[4],
                            kv[5],
                            kv[2],
                            kv[3],
                            kv[1],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_proc_maps":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<PID>\d+)\ +(?P<ProcessName>\w+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<OffsetEnd>0x[A-Fa-f\d]+)\ +(?P<Permisssions>[RWLXrwlx\-]+)\ +(?P<MapName>[\S\ ]+)?",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Name"],
                            jsondict["PID"],
                            jsondict["Permissions"],
                            jsondict["MapName"],
                            jsondict["Offset"],
                            jsondict["OffsetName"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            kv[4],
                            kv[5],
                            kv[2],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_psaux":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<ProcessName>\S+)\ +(?P<Bits>\w+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Length>\d+)\ +(?P<Status>\d+)\ +(?P<Arguments>.*)",
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
                            jsondict["Status"],
                            jsondict["Arguments"],
                            jsondict["Length"],
                            jsondict["Bits"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            kv[3],
                            kv[5],
                            kv[6],
                            kv[4],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_psenv":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<ProcessName>\S+)\ +(?P<Bits>\w+)\ +(?P<Arguments>.*)",
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
                            jsondict["Arguments"],
                            jsondict["Bits"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            kv[3],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_pslist" or plugin == "mac_tasks":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<ProcessName>[\w\.]+)\ +(?P<PID>\d+)\ +(?P<UID>\d+)\ +(?P<GID>\d+)\ +(?P<PGID>\d+)\ +(?P<Bits>\w+)\ +(?P<DTB>0x[A-Fa-f\d]+)\ +(?P<Time>\d{4}\-\d{2}\-\d{2}\ \d{2}\:\d{2}\:\d{2}\ \w+\+\d+)",
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
                            jsondict["PGID"],
                            jsondict["DTB"],
                            jsondict["Bits"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[2],
                            kv[0],
                            kv[8],
                            kv[3],
                            kv[4],
                            kv[5],
                            kv[7],
                            kv[6],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_pstree":
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
    elif plugin == "mac_psxview":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<ProcessName>[\w\.]+)\ +(?P<PID>\d+)\ +(?P<pslist>\w+)\ +(?P<Parents>\w+)\ +(?P<PIDHash>\w+)\ +(?P<ProcessGroupHashTable>\w+)\ +(?P<SessionLeaders>\w+)\ +(?P<TaskProcesses>\w+)",
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
                            jsondict["pslist"],
                            jsondict["Parents"],
                            jsondict["PIDHash"],
                            jsondict["ProcessGroupHashTable"],
                            jsondict["SessionLeaders"],
                            jsondict["TaskProcesses"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[2],
                            kv[0],
                            kv[3],
                            kv[4],
                            kv[5],
                            kv[6],
                            kv[7],
                            kv[8],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_socket_filters":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<FilterName>[\w\.]+)\ +(?P<FilterNumber>[\w\.]+)\ +(?P<Socket>0x[A-Fa-f\d]+)\ +(?P<Handler>0x[A-Fa-f\d]+)\ +(?P<Module>[\w\.]+)\ +(?P<Status>\w+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["FilterName"],
                            jsondict["FilterNumber"],
                            jsondict["Socket"],
                            jsondict["Handler"],
                            jsondict["Module"],
                            jsondict["Status"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[2],
                            kv[3],
                            kv[4],
                            kv[5],
                            kv[6],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac_trustedbsd":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Check>\w+)\ +(?P<Name>\w+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Module>[\w\.]+)\ +(?P<Status>\w+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Name"],
                            jsondict["Check"],
                            jsondict["Offset"],
                            jsondict["Module"],
                            jsondict["Status"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            kv[2],
                            kv[3],
                            kv[4],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    else:
        pass
    return jsonlist
