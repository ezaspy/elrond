#!/usr/bin/env python3 -tt
import json
import re


def macos_vol3(
    volver, profile, symbolorprofile, plugin, plugoutlist, jsondict, jsonlist
):
    if plugin == "mac.bash.Bash":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<PID>\d+)\\t(?P<ProcessName>[^\\]+)\\t(?P<CommandTime>[^\\]+)\ \\t(?P<CommandLine>[\S\ ]+)",
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
                            jsondict["CommandLine"],
                            jsondict["LastWriteTime"],
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
    elif (
        plugin == "mac.check_syscall.Check_syscall"
        or plugin == "mac.check_trap_table.Check_trap_table"
    ):
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<TableName>[^\\]+)\\t(?P<Index>\d+)\\t(?P<HandlerOffset>0x[A-Fa-f\d]+)\\t(?P<HandlerModule>[^\\]+)\\t(?P<HandlerSymbol>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["TableName"],
                            jsondict["Offset"],
                            jsondict["Index"],
                            jsondict["HandlerModule"],
                            jsondict["HandlerSymbol"],
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
    elif plugin == "mac.check_sysctl.Check_sysctl":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<TableName>[^\\]+)\\t(?P<Index>\d+)\\t(?P<Permissions>[^\\]+)\\t(?P<HandlerOffset>0x[A-Fa-f\d]+)\\t(?P<HandlerValue>[^\\]+)?\\t(?P<HandlerModule>[^\\]+)\\t(?P<HandlerSymbol>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["TableName"],
                            jsondict["Permissions"],
                            jsondict["Index"],
                            jsondict["HandlerModule"],
                            jsondict["HandlerSymbol"],
                            jsondict["HandlerValue"],
                            jsondict["HandlerOffset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[2],
                            kv[1],
                            kv[5],
                            kv[6],
                            kv[4],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac.ifconfig.Ifconfig":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Interface>\w+)\\t(?P<IPAddress>[A-Fa-f\d\:\.]+)?\\t(?P<MACAddress>[A-Fa-f\d\:\.]+)?\\t(?P<PromiscuousMode>\w+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Interface"],
                            jsondict["IPAddress"],
                            jsondict["MACAddress"],
                            jsondict["PromiscuousMode"],
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
    elif (
        plugin == "mac.kauth_listeners.Kauth_listeners"
    ):  # outstanding (no artefacts available)
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                pass
    elif plugin == "mac.kauth_scopes.Kauth_scopes":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<ProcessName>[^\\]+)\\t(?P<ProcessData>[^\\]+)\\t(?P<Listeners>\d+)\\t(?P<CallbackAddress>0x[A-Fa-f\d]+)\\t(?P<ModuleName>[^\\]+)\\t(?P<Symbol>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["ProcessData"],
                            jsondict["Listeners"],
                            jsondict["CallbackAddress"],
                            jsondict["ModuleName"],
                            jsondict["Symbol"],
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
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac.kevents.Kevents":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<PID>\d+)\\t(?P<ProcessName>[^\\]+)\\t(?P<Identifier>\d+)\\t(?P<Filter>[^\\]+)\\t(?P<Context>\w+)?",
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
                            jsondict["Identifier"],
                            jsondict["Filter"],
                            jsondict["Context"],
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
    elif plugin == "mac.lsmod.Lsmod":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<ProcessName>[^\\]+)\\t(?P<Size>\d+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["Offset"],
                            jsondict["Size"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac.lsof.Lsof":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<PID>\d+)\\t(?P<FileDescriptor>\d+)\\t(?P<Filepath>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Filepath"],
                            jsondict["PID"],
                            jsondict["FileDescriptor"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[2],
                            kv[0],
                            kv[1],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac.malfind.Malfind":
        for plugout in str(
            re.sub(
                r"(\'\,\ \'\d+\\\\)",
                r"********************\1",
                str(plugoutlist),
            )
        ).split("********************', '"):
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<PID>\d+)[\s\\t]{3}(?P<ProcessName>[^\\]+)[\s\\t]{3}(?P<StartOffset>0x[A-Fa-f\d]+)[\s\\t]{3}(?P<EndOffset>0x[A-Fa-f\d]+)[\s\\t]{3}(?P<Protection>\S+)[\s\\t]{3}\'\,\ \'(?P<Data>[\S\ ]+)",
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
                            jsondict["Protection"],
                            jsondict["StartOffset"],
                            jsondict["EndOffset"],
                            DataAssembly,
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            kv[4],
                            kv[2],
                            kv[3],
                            kv[5],
                        )
                    else:
                        pass
                    datadict, datalist, hexdata, asciidata = (
                        {},
                        [],
                        "",
                        "",
                    )
                    for eachdata in DataAssembly.split("', '"):
                        hexdata = hexdata + str(eachdata)[0:23].replace(" ", "")
                        asciidata = asciidata + str(eachdata)[26:32]
                    (
                        datadict["RawHEXData"],
                        datadict["RawASCIIData"],
                        datadict["FormattedASCIIData"],
                    ) = (hexdata, asciidata, asciidata[::2])
                    datalist.append(json.dumps(datadict))
                    jsondict["Data"] = datalist
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac.mount.Mount":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Device>[^\\]+)\\t(?P<MountPoint>[^\\]+)\\t(?P<MountType>[\S\ ]+)",
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
                            jsondict["MountType"],
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
    elif plugin == "mac.netstat.Netstat":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<Protocol>\w+)\\t(?P<LocalAddress>[\w\d\:\.\-\*\/]+)\\t(?P<LocalPort>\d+)\\t(?P<ForeignAddress>[\w\:\.\-\*\/]+)?\\t(?P<ForeignPort>\d+)\\t(?P<State>[^\\]+)?\\t(?P<ProcessName>[\S\ ]+)",
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
                            jsondict["Protocol"],
                            jsondict["State"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[7],
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
    elif plugin == "mac.proc_maps.Proc_maps":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<PID>\d+)\\t(?P<ProcessName>[^\\]+)\\t(?P<StartOffset>0x[A-Fa-f\d]+)\\t(?P<EndOffset>0x[A-Fa-f\d]+)\\t(?P<Protection>[^\\]+)\\t(?P<MapName>[\S\ ]+)?",
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
                            jsondict["MapName"],
                            jsondict["Protection"],
                            jsondict["StartOffset"],
                            jsondict["EndOffset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            kv[5],
                            kv[4],
                            kv[2],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac.psaux.Psaux":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<PID>\d+)\\t(?P<ProcessName>[^\\]+)\\t(?P<ArgC>[^\\]+)\\t(?P<Arguments>[\S\ ]+)",
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
                            jsondict["ArgC"],
                            jsondict["Arguments"],
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
    elif plugin == "mac.pslist.Pslist" or plugin == "mac.pstree.Pstree":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<PID>\d+)\\t(?P<PPID>[^\\]+)\\t(?P<ProcessName>[\S\ ]+)",
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
                            jsondict["PPID"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[2],
                            kv[0],
                            kv[1],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac.socket_filters.Socket_filters":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<ProcessName>[^\\]+)\\t(?P<Member>[^\\]+)\\t(?P<Socket>[^\\]+)\\t(?P<Handler>[^\\]+)\\t(?P<Module>[^\\]+)\\t(?P<Symbol>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["Member"],
                            jsondict["Socket"],
                            jsondict["Handler"],
                            jsondict["Module"],
                            jsondict["Symbol"],
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
    elif plugin == "mac.timers.Timers":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<FunctionOffset>0x[A-Fa-f\d]+)\\t(?P<Parameter0Offset>0x[A-Fa-f\d]+)\\t(?P<Parameter1Offset>0x[A-Fa-f\d]+)\\t(?P<Deadline>[^\\]+)\\t(?P<EntryTime>[^\\]+)\\t(?P<Module>[^\\]+)\\t(?P<Symbol>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["FunctionOffset"],
                            jsondict["Parameter0Offset"],
                            jsondict["Parameter1Offset"],
                            jsondict["Deadline"],
                            jsondict["EntryTime"],
                            jsondict["Module"],
                            jsondict["Symbol"],
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
                            kv[6],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac.trustedbsd.Trustedbsd":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Member>[\S\ ]+)\\t(?P<PolicyName>[^\\]+)\\t(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<Module>[^\\]+)\\t(?P<Symbol>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["PolicyName"],
                            jsondict["Member"],
                            jsondict["Module"],
                            jsondict["Symbol"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            kv[3],
                            kv[4],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mac.vfsevents.Vfsevents":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<ProcessName>[\S\ ]+)\\t(?P<PID>\d+)\\t(?P<Events>[\S\ ]+)",
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
                            jsondict["Events"],
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
    else:
        pass
