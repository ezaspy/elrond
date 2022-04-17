#!/usr/bin/env python3 -tt
import json
import re


def windows_vol(
    volver,
    profile,
    symbolorprofile,
    plugin,
    plugoutlist,
    jsondict,
    jsonlist,
    voldict,
    vollist,
):
    if plugin == "apihooks" or plugin == "apihooksdeep":
        for plugout in str(plugoutlist).split(
            "************************************************************************"
        ):
            for eachkv in re.findall(
                r"Hook\ mode\:\ (?P<HookMode>[^\']+)\'\,\ \'Hook\ type\:\ (?P<HookType>[^\']+)\'\,\ \'Process\:\ (?P<PID>[^\(]+)\ \((?P<ProcessName>[^\']+)\)\'\,\ \'Victim\ module\:\ (?P<VictimModule>[^\(]+)\ \((?P<ModuleAddressStart>[^\-]+)\ \-\ (?P<ModuleAddressEnd>[^\-]+)\)\'\,\ \'Function\:\ (?P<Function>[^\']+)\'\,\ \'Hook\ address\:\ (?P<HookAddress>[^\']+)\'\,\ \'Hooking\ module\:\ (?P<HookModule>[^\']+)\'\,\ \'\'\,\ \'Disassembly\S+\:\'\,\ \'(?P<Assembly>[\S\ ]+)",
                plugout,
            ):
                kv = list(eachkv)
                if len(kv) > 0:
                    (
                        jsondict["VolatilityVersion"],
                        jsondict[symbolorprofile],
                        jsondict["VolatilityPlugin"],
                        jsondict["HookModule"],
                        jsondict["HookMode"],
                        jsondict["HookType"],
                        jsondict["HookAddress"],
                        jsondict["ProcessName"],
                        jsondict["PID"],
                        jsondict["VictimModule"],
                        jsondict["ModuleAddressStart"],
                        jsondict["ModuleAddressEnd"],
                        jsondict["Function"],
                        Assembly,
                    ) = (
                        volver,
                        profile,
                        plugin,
                        kv[9],
                        kv[0],
                        kv[1],
                        kv[8],
                        kv[3],
                        kv[2],
                        kv[4],
                        kv[5],
                        kv[6],
                        kv[7],
                        kv[10],
                    )
                else:
                    pass
                asmdict, asmlist, allasm = {}, [], ""
                for eachasm in Assembly.split("', '"):
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
                    asmdict.clear()
                    allasm = allasm + "\n" + eachasm
                (
                    jsondict["RawAssembly"],
                    jsondict["AssemblyInstructions"],
                ) = (allasm.strip("\\n"), asmlist)
                jsonlist.append(json.dumps(jsondict))
    elif plugin == "cmdline":
        for plugout in str(plugoutlist).split(
            "************************************************************************"
        ):
            for eachkv in re.findall(
                r"^(?P<ProcessName>[\S\ ]+)\ +pid\:\ +(?P<PID>\d+)\'\,\ \'Command\ line\ +\:\ +(?P<CommandLine>[\S\ ]+)",
                plugout[4:-4],
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
    elif plugin == "cmdscan":
        for plugout in str(plugoutlist).split(
            "**************************************************"
        ):
            if len(plugout.strip("']")[1:][2:-3]) > 0:
                for eachkv in re.findall(
                    r"(?P<k>[A-Za-z]+)\:(?P<v>[^\|\']+)",
                    plugout.strip("']")[1:][2:-3]
                    .split("', 'Cmd ")[0]
                    .replace(": ", ":")
                    .replace(", ", ",")
                    .replace(" ", "||"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 1:
                        jsondict[kv[0]] = kv[1]
                    else:
                        pass
                for pluginfo in plugout.strip("']")[1:][2:-3].split("', 'Cmd ")[1:]:
                    for eachkv in re.findall(
                        r"(?P<CommandID>\#\d+)\ \@\ (?P<CommandMemoryOffset>0x[^\:]+)\:\ (?P<CommandLine>[\S\ ]+)",
                        pluginfo,
                    ):
                        kv = list(eachkv)
                        if len(kv) > 2:
                            (
                                jsondict["VolatilityVersion"],
                                jsondict[symbolorprofile],
                                jsondict["VolatilityPlugin"],
                                voldict["Command line"],
                                voldict["CommandID"],
                                voldict["CommandLineMemoryOffset"],
                            ) = (
                                volver,
                                profile,
                                plugin,
                                kv[2],
                                kv[0].replace("#", "Command#"),
                                kv[1],
                            )
                        else:
                            pass
                    if len(voldict) > 0:
                        vollist.append(json.dumps(voldict))
                    else:
                        pass
            else:
                pass
            for volinfo in vollist:
                jsondict.update(json.loads(volinfo))
                jsonlist.append(json.dumps(jsondict))
    elif plugin == "consoles":
        for plugout in str(plugoutlist).split(
            "**************************************************"
        ):
            if "Dump:" in plugout:
                if len(plugout.split("Dump:")[1]) > 8:
                    dumpout = (
                        plugout.split("Dump:")[1]
                        .replace("', '", "")
                        .replace("      ", "")
                    )
                else:
                    dumpout = ""
                if len(plugout.strip("']")[1:][2:-3]) > 0:
                    for eachkv in re.findall(
                        r"(?P<k>[A-Za-z]+)\:(?P<v>\w[^\|\ ]*)",
                        re.sub(
                            r"(\w)\ ([A-Z]\w+\')",
                            r"\1\2",
                            re.sub(
                                r"(AttachedProcess\:\ [^\ ]+\ )",
                                r"\1AttachedProcess",
                                str(plugout.split("Dump:")[0].replace(": ", ":")),
                            ),
                        ),
                    ):
                        kv = list(eachkv)
                        if len(kv) > 1:
                            (
                                jsondict["VolatilityVersion"],
                                jsondict[symbolorprofile],
                                jsondict["VolatilityPlugin"],
                                jsondict[kv[0]],
                            ) = (
                                volver,
                                profile,
                                plugin,
                                kv[1].strip("',"),
                            )
                        else:
                            pass
                    if len(dumpout) > 0:
                        jsondict["Dump"] = dumpout
                    else:
                        pass
                else:
                    pass
            else:
                pass
            if len(jsondict) > 0:
                jsonlist.append(json.dumps(jsondict))
            else:
                pass
    elif plugin == "directoryenumerator" or plugin == "filescan":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Pointer>\d+)\ +(?P<Handles>\d+)\ +(?P<Access>[RWXDrwxd\-]+)\ +(?P<Filename>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["Access"],
                            jsondict["Handles"],
                            jsondict["Offset"],
                            jsondict["Pointer"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[4],
                            kv[3],
                            kv[2],
                            kv[0],
                            kv[1],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "dlllist":
        for plugout in str(plugoutlist).split(
            "************************************************************************"
        ):
            if (
                "', '', 'Base                             Size          LoadCount Path', '------------------ ------------------ ------------------ ----"
                in plugout
            ):
                jsondict["ProcessName"] = re.findall(
                    r"^\'\,\ \'(?P<Process>[^\:\']+)\'\,\ \'",
                    re.sub(
                        r"\ (pid\:)",
                        r"', '\1",
                        plugout.split(
                            "', '', 'Base                             Size          LoadCount Path', '------------------ ------------------ ------------------ ----"
                        )[0],
                    ),
                )[0]
                for eachkv in re.findall(
                    r"\'(?P<k>[^\:\']+\w)\ ?\:\ +(?P<v>[^\']+)",
                    re.sub(
                        r"\ (pid\:)",
                        r"', '\1",
                        plugout.split(
                            "', '', 'Base                             Size          LoadCount Path', '------------------ ------------------ ------------------ ----"
                        )[0],
                    ),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict[kv[0]],
                        ) = (volver, profile, plugin, kv[1])
                        if "=" in kv[1]:
                            for each in re.findall(
                                r"\ (?P<k>[\S]+\w)\=(?P<v>[^\ \']+)",
                                kv[1],
                            ):
                                jsondict[each[0]] = each[1]
                        else:
                            pass
                    else:
                        pass
                for eachinfo in plugout.split(
                    "', '', 'Base                             Size          LoadCount Path', '------------------ ------------------ ------------------ ----"
                )[1].split("', '"):
                    for eachkv in re.findall(
                        r"(?P<Base>[\S]+)\ +(?P<Size>[\S]+)\ +(?P<LoadCount>[\S]+)\ +(?P<Path>[\S\ ]+)",
                        eachinfo.replace("\\\\ n", "\\\\n"),
                    ):
                        kv = list(eachkv)
                        if len(kv) > 0:
                            (
                                jsondict["Base"],
                                jsondict["Size"],
                                jsondict["LoadCount"],
                                jsondict["Path"],
                            ) = (kv[0], kv[1], kv[2], kv[3])
                        else:
                            pass
                        jsonlist.append(json.dumps(jsondict))
            else:
                pass
    elif plugin == "driverirp":
        for plugout in str(plugoutlist).split(
            "--------------------------------------------------"
        ):
            for eachkv in re.findall(
                r"^DriverName\:\ +(?P<DriverName>[^\']+)\'\,\ \'DriverStart\:\ +(?P<DriverStart>[^\']+)\'\,\ \'DriverSize\:\ +(?P<DriverSize>[^\']+)\'\,\ \'DriverStartIo\:\ +(?P<DriverStartIO>[^\']+)\'\,\ \'\ +(?P<DriverData>[\S\ ]+)",
                plugout[4:-4],
            ):
                kv = list(eachkv)
                if len(kv) > 0:
                    (
                        jsondict["VolatilityVersion"],
                        jsondict[symbolorprofile],
                        jsondict["VolatilityPlugin"],
                        jsondict["DriverName"],
                        jsondict["DriverStart"],
                        jsondict["DriverSize"],
                        jsondict["DriverStartIO"],
                        DriverData,
                    ) = (
                        volver,
                        profile,
                        plugin,
                        kv[0],
                        kv[1],
                        kv[2],
                        kv[3],
                        kv[4],
                    )
                else:
                    pass
                driverdict, driverlist, alldriverinfo = (
                    {},
                    [],
                    "",
                )
                for eachdata in DriverData.split("', '"):
                    for datakv in re.findall(
                        r"^(?P<Pointer>\d+)\ +(?P<Function>\w+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<DriverName>.*)",
                        eachdata,
                    ):
                        (
                            driverdict["DriverName"],
                            driverdict["Pointer"],
                            driverdict["Function"],
                            driverdict["Offset"],
                        ) = (
                            datakv[3],
                            datakv[0],
                            datakv[1],
                            datakv[2],
                        )
                    if len(datakv) > 2:
                        driverlist.append(json.dumps(driverdict))
                    else:
                        pass
                    driverdict.clear()
                    alldriverinfo = alldriverinfo + "\n" + eachdata
                (
                    jsondict["AllDriverData"],
                    jsondict["DriverData"],
                ) = (alldriverinfo.strip("\\n"), driverlist)
                jsonlist.append(json.dumps(jsondict))
    elif plugin == "drivermodule":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<ModuleName>[\S\ ]+\.\w+)\ +(?P<DriverName>\S+)\ +(?P<DriverNameAlt>\S+)\ +(?P<ServiceKey>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ModuleName"],
                            jsondict["DriverName"],
                            jsondict["DriverNameAlt"],
                            jsondict["Servicekey"],
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
    elif plugin == "driverscan":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Pointer>\d+)\ +(?P<Handle>\d+)\ +(?P<Base>0x[A-Fa-f\d]+)\ +(?P<Size>0x[A-Fa-f\d]+)\ +(?P<DriverKey>\w+)\ +(?P<DriverName>\w+)\ +(?P<DriverPath>\S+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["DriverName"],
                            jsondict["DriverPath"],
                            jsondict["DriverKey"],
                            jsondict["Pointer"],
                            jsondict["Handle"],
                            jsondict["Size"],
                            jsondict["Offset"],
                            jsondict["Base"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[6],
                            kv[7],
                            kv[5],
                            kv[1],
                            kv[2],
                            kv[4],
                            kv[0],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "envars":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<ProcessName>[\S\ ]+\.\w+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Variable>\S+)\ +(?P<Value>[\S\ ]+)",
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
                            jsondict["Variable"],
                            jsondict["Value"],
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
    elif plugin == "gahti":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Session>\d+)\ +(?P<Type>\w+)\ +(?P<Tag>\w+)?\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Flags>[^\\]+)?",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Session"],
                            jsondict["Type"],
                            jsondict["Tag"],
                            jsondict["Offset"],
                            jsondict["Flags"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[1],
                            kv[2],
                            kv[3],
                            kv[4],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "gditimers":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<Session>\d+)\ +(?P<Handle>0x[A-Fa-f\d]+)\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Thread>\d+)\ +(?P<ProcessName>[^\:]+)\:(?P<PID>\d+)\ +(?P<ID>0x[A-Fa-f\d]+)\ +(?P<Rate>\d+)\ +(?P<Countdown>\d+)\ +(?P<Function>0x[A-Fa-f\d]+)",
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
                            jsondict["Session"],
                            jsondict["Thread"],
                            jsondict["Offset"],
                            jsondict["Handle"],
                            jsondict["Function"],
                            jsondict["ID"],
                            jsondict["Rate"],
                            jsondict["Countdown"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[4],
                            kv[5],
                            kv[0],
                            kv[3],
                            kv[2],
                            kv[1],
                            kv[9],
                            kv[6],
                            kv[7],
                            kv[8],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "getservicesids":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"\'(?P<SecurityID>S\-[\d\-]+)\'\:\ +\'(?P<Service>[^\']+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Service"],
                            jsondict["SecurityID"],
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
    elif plugin == "getsids":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Process>\S+)\ +\((?P<PID>\d+)\)\:\ +(?P<SecurityID>S\-[\d\-]+)\ +\((?P<SecurityGroup>[^\)]+)\)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Process"],
                            jsondict["PID"],
                            jsondict["SecurityID"],
                            jsondict["SecurityGroup"],
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
    elif plugin == "handles":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<PID>\d+)\ +(?P<Handle>0x[A-Fa-f\d]+)\ +(?P<Access>0x[A-Fa-f\d]+)\ +(?P<Type>[\S\ ]+)\ +(?P<Details>[\S\ ]*)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Type"],
                            jsondict["PID"],
                            jsondict["Access"],
                            jsondict["Handle"],
                            jsondict["Offset"],
                            jsondict["Details"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[4],
                            kv[1],
                            kv[3],
                            kv[2],
                            kv[0],
                            kv[5],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "hashdump":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<AccountName>[^\:]+)\:(?P<AccountType>\d+)\:[^\:]+\:(?P<HashedPassword>[^\:]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["AccountName"],
                            jsondict["AccountType"],
                            jsondict["HashedPassword"],
                            jsondict["CrackedPassword"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[1],
                            kv[2],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "hivelist":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<VirtualOffset>0x[A-Fa-f\d]+)\ +(?P<PhysicalOffset>0x[A-Fa-f\d]+)\ +(?P<Filename>[\S\ ]*)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["VirtualOffset"],
                            jsondict["PhysicalOffset"],
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
    elif plugin == "ldrmodules":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<ProcessName>[\w\.\ ]+\w)\ +(?P<Base>0x[A-Fa-f\d]+)\ +(?P<InLoad>\w+)\ +(?P<InInit>\w+)\ +(?P<InMem>\w+)\ +(?P<MappedPath>[\S\ ]+)",
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
                            jsondict["Base"],
                            jsondict["InLoad"],
                            jsondict["InInit"],
                            jsondict["InMem"],
                            jsondict["MappedPath"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            kv[2],
                            kv[3],
                            kv[4],
                            kv[5],
                            kv[6],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "malprocfind":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<ProcessName>[\S\ ]+\w)\ +(?P<PID>\d+)\ +(?P<PPID>\w+)\ +(?P<Name>\w+)\ +(?P<Path>\w+)\ +(?P<Priority>\w+)\ +(?P<CommandLine>\w+)\ +(?P<User>\w+)\ +(?P<Session>\w+)\ +(?P<Time>\w+)\ +(?P<Command>\w+)\ +(?P<ProcessHollow>\w+)\ +(?P<SessionPath>\w+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) == 14:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["PID"],
                            jsondict["PPID"],
                            jsondict["Name"],
                            jsondict["Path"],
                            jsondict["Priority"],
                            jsondict["CommandLine"],
                            jsondict["User"],
                            jsondict["Session"],
                            jsondict["Time"],
                            jsondict["Command"],
                            jsondict["ProcessHollow"],
                            jsondict["SessionPath"],
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
                            kv[7],
                            kv[8],
                            kv[9],
                            kv[10],
                            kv[11],
                            kv[12],
                            kv[13],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
                for eachkv in re.findall(
                    r"^PID\ +(?P<PID>\d+)\ +Offset\:\ +(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<ProcessName>[\S\ ]+\w)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) == 3:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["NoParentProcess"],
                            jsondict["ProcessName"],
                            jsondict["PID"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            "True",
                            kv[2],
                            kv[0],
                            kv[1],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "malfind":
        for plugout in str(plugoutlist).split("Process"):
            for eachkv in re.findall(
                r"^\:\ (?P<ProcessName>.*)\ Pid\:\ (?P<PID>\d+)\ +Address\:\ (?P<Offset>0x[A-Fa-f\d]+)\'\,\ \'Vad Tag\:\ (?P<VadTag>\w+)\ +Protection\:\ (?P<Protection>\w+)\'\,\ \'Flags\:\ (?P<Flags>[^\']+)\'\,\ \'\'\,\ \'(?P<DataAssembly>[\S\s]+)",
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
                        jsondict["Flags"],
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
                        kv[6],
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
    elif plugin == "messagehooks":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Session>\d+)\ +(?P<Desktop>\S+)\ +(?P<Thread>(?:\<any\>|\d+))\ +(?:\((?P<ProcessName>[\w\.\ ]+)\ +(?P<PID>\d+)\))?\ +(?P<Filter>\w+)\ +(?P<Flags>\w+)\ +(?P<Function>0x[A-Fa-f\d]+)\ +(?P<Module>[\S\ ]+)",
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
                            jsondict["Thread"],
                            jsondict["Offset"],
                            jsondict["Desktop"],
                            jsondict["Session"],
                            jsondict["Filter"],
                            jsondict["Flags"],
                            jsondict["Function"],
                            jsondict["Module"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[4],
                            kv[5],
                            kv[3],
                            kv[0],
                            kv[2],
                            kv[1],
                            kv[6],
                            kv[7],
                            kv[8],
                            kv[9],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mimikatz":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Module>\w+)\ +(?P<User>[\w\-\$]+)\ +(?P<Domain>\S+)\ +(?P<Password>[A-Fa-f\d\.]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["User"],
                            jsondict["Password"],
                            jsondict["Domain"],
                            jsondict["Module"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[3],
                            kv[2],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "modscan":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<File>\S+)\ +(?P<Base>0x[A-Fa-f\d]+)\ +(?P<Size>0x[A-Fa-f\d]+)\ +(?P<Filename>[\S\ ]*)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["File"],
                            jsondict["FileSize"],
                            jsondict["Offset"],
                            jsondict["Base"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[4],
                            kv[1],
                            kv[3],
                            kv[2],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "modules":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<ModuleName>[\S\ ]+\.\w+)\ +(?P<Base>0x[A-Fa-f\d]+)\ +(?P<Size>0x[A-Fa-f\d]+)\ +(?P<Filename>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ModuleName"],
                            jsondict["Base"],
                            jsondict["Offset"],
                            jsondict["Size"],
                            jsondict["Filename"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[2],
                            kv[0],
                            kv[3],
                            kv[4],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "mutantscan":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Pointer>\d+)\ +(?P<Handle>\d+)\ +(?P<Signal>\d+)\ +(?P<Thread>0x[A-Fa-f\d]+)\ +(?P<CID>[\d\.]*)\ +(?P<MutexName>[\S\ ]*)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["MutexName"],
                            jsondict["Offset"],
                            jsondict["Thread"],
                            jsondict["CID"],
                            jsondict["Pointer"],
                            jsondict["Handles"],
                            jsondict["Signal"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[6],
                            kv[0],
                            kv[4],
                            kv[5],
                            kv[1],
                            kv[2],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "ndispktscan":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<SourceMAC>[A-Fa-z\d\:]+)\ +(?P<DestinationMAC>[A-Fa-z\d\:]+)\ +(?P<Protocol>0x[A-Fa-z\d]+)\ +(?P<SourceIP>[A-Fa-z\d\.\:]+)\ +(?P<DestinationIP>[A-Fa-z\d\.\:]+)\ +(?P<SourcePort>\w+)\ +(?P<DestinationPort>\w+)\ +(?P<Flags>[\S\ ]+)",
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
                            jsondict["SourceMAC"],
                            jsondict["DestinationIP"],
                            jsondict["DestinationPort"],
                            jsondict["DestinationMAC"],
                            jsondict["Protocol"],
                            jsondict["Flags"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[4],
                            kv[6],
                            kv[1],
                            kv[5],
                            kv[7],
                            kv[2],
                            kv[3],
                            kv[8],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "netscan":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Protocol>\w+)\ +(?P<LocalAddress>[\d\.\:\-]+)\:(?P<LocalPort>\d+)\ +(?P<ForeignAddress>[\d\.\:\-\*]+)\:(?P<ForeignPort>[\d\*]+)\ +(?P<ConnectionState>\w*)\ +(?P<PID>\d+)\ +(?P<ProcessName>[\w\-\.]+)\ +(?P<TimeCreated>[\d\-\:\ ]*)\ ",
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
                            jsondict["TimeCreated"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[8],
                            kv[2],
                            kv[3],
                            kv[4],
                            kv[5],
                            kv[7],
                            kv[1],
                            kv[6],
                            kv[9],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "objtypescan":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Objects>0x[A-Fa-z\d]+)\ +(?P<Handles>0x[A-Fa-z\d]+)\ +(?P<Key>\w+)\ +(?P<ObjectName>\w+)\ +(?P<PoolType>\w+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ObjectName"],
                            jsondict["Key"],
                            jsondict["Offset"],
                            jsondict["Objects"],
                            jsondict["Handles"],
                            jsondict["PoolType"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[5],
                            kv[4],
                            kv[0],
                            kv[1],
                            kv[2],
                            kv[5],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "privs":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<PID>\d+)\ +(?P<ProcessName>[\w\-\.]+)\ +(?P<ProcessValue>\d+)\ +(?P<PrivilegeName>[\w\-\.]+)\ +(?P<PrivilegeAttributes>[\w\,]*)\ +(?P<PrivilegeDescription>[\w\ ]+)",
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
                            jsondict["ProcessValue"],
                            jsondict["PrivilegeName"],
                            jsondict["PrivilegeAttributes"],
                            jsondict["PrivilegeDescription"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            kv[2],
                            kv[3],
                            kv[4],
                            kv[5],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "pslist":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<ProcessName>[\w\-\.]+)\ +(?P<PID>\d+)\ +(?P<PPID>\d+)\ +(?P<Threads>\d+)\ +(?P<Handles>\d+)\ +(?P<Session>[\d\-]+)\ +(?P<WoW64>\d+)\ +(?P<StartTime>[\d\-\:\ ]+)\ \w+\+\d+\ +(?P<EndTime>[\d\-\:\ ]+)\ ",
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
                            jsondict["StartTime"],
                            jsondict["EndTime"],
                            jsondict["Threads"],
                            jsondict["Handles"],
                            jsondict["Session"],
                            jsondict["WoW64"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[2],
                            kv[3],
                            kv[8],
                            kv[9],
                            kv[4],
                            kv[5],
                            kv[6],
                            kv[7],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "psscan":  # outstanding (no artefacts available)
        pass
    elif plugin == "pstree":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<Offset>0x[A-Fa-f\d]+)\:(?P<ProcessName>[\w\-\.]+)\ +(?P<PID>\d+)\ +(?P<PPID>\d+)\ +(?P<Threads>\d+)\ +(?P<Handles>\d+)\ +(?P<StartTime>[\d\-\:\ ]+)\ ",
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
                            jsondict["StartTime"],
                            jsondict["Threads"],
                            jsondict["Handles"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[2],
                            kv[3],
                            kv[6],
                            kv[4],
                            kv[5],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "psxview":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<ProcessName>[\w\-\.]+)\ +(?P<PID>\d+)\ +(?P<InPSList>\w+)\ +(?P<InPSScan>\w+)\ +(?P<Thread>\w+)\ +(?P<PspCid>\w+)\ +(?P<CSRSS>\w+)\ +(?P<Session>\w+)\ +(?P<DesktopThread>\w+)\ +(?P<EndTime>[\d\-\:\ ]*)",
                    plugout.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["PID"],
                            jsondict["EndTime"],
                            jsondict["InPSList"],
                            jsondict["InPSScan"],
                            jsondict["Thread"],
                            jsondict["DesktopThread"],
                            jsondict["Session"],
                            jsondict["PspCid"],
                            jsondict["CSRSS"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[2],
                            kv[10],
                            kv[3],
                            kv[4],
                            kv[5],
                            kv[9],
                            kv[8],
                            kv[6],
                            kv[7],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "shellbags":
        for plugout in str(plugoutlist).split(
            "***************************************************************************"
        ):
            for eachkv in re.findall(
                r"[A-Za-z\ ]+\:\ +(?P<RegistryHive>[^\']+)\'\,\ \'[A-Za-z\ ]+\:\ +(?P<RegistryKey>[^\']+)\'\,\ \'[A-Za-z\ ]+\:\ +(?P<LastWriteTime>[^\']+)\ ",
                plugout.split(
                    "', 'Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs', '------- ----- -------------- ---------------------------------------- -------------------- ----------', '"
                )[0],
            ):
                kv = list(eachkv)
                if len(kv) > 1:
                    (
                        jsondict["VolatilityVersion"],
                        jsondict[symbolorprofile],
                        jsondict["VolatilityPlugin"],
                        jsondict["RegistryHivePath"],
                        jsondict["RegistryHive"],
                        jsondict["LastWriteTime"],
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
            if (
                len(
                    plugout.split(
                        "', 'Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs', '------- ----- -------------- ---------------------------------------- -------------------- ----------', '"
                    )
                )
                > 1
            ):
                for eachinfo in plugout.split(
                    "', 'Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs', '------- ----- -------------- ---------------------------------------- -------------------- ----------', '"
                )[1].split("', '"):
                    if (
                        "Folder (unsupported) This property is not yet supported"
                        not in eachinfo
                    ):
                        for eachkv in re.findall(
                            r"^(?P<RegistryKeyValue>\d+)\ +(?P<MRU>\d+)\ +(?P<EntryType>[\w\ ]+\w)\ +(?P<GUID>[A-Za-z\d\-]+)\ +(?P<GUIDDescription>[\w\ ]+\w)\ +(?P<FolderIDs>[A-Z\_\,\ ]+)\ ",
                            eachinfo,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 3:
                                (
                                    voldict["RegistryKeyValue"],
                                    voldict["MRU"],
                                    voldict["FolderIDs"],
                                    voldict["EntryType"],
                                    voldict["GUID"],
                                    voldict["GUIDDescription"],
                                ) = (
                                    kv[0],
                                    kv[1],
                                    kv[5],
                                    kv[2],
                                    kv[3],
                                    kv[4],
                                )
                            else:
                                pass
                        if len(voldict) > 0:
                            vollist.append(json.dumps(voldict))
                        else:
                            pass
                    for volinfo in vollist:
                        jsondict.update(json.loads(volinfo))
                        jsonlist.append(json.dumps(jsondict))
            else:
                pass
    elif plugin == "shimcache":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<LastWriteTime>[\d\-\:\ ]+)\ \w+\+\d+\ +(?P<Filepath>.+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Filepath"],
                            jsondict["LastWriteTime"],
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
    elif plugin == "shimcachemem":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<Order>\d+)\ +(?P<LastModified>\d{4}\-\d{2}\-\d{2}\ \d{2}\:\d{2}\:\d{2})(?P<LastUpdated>\d{4}\-\d{2}\-\d{2}\ \d{2}\:\d{2}\:\d{2})?\ +(?P<ExecFlag>\w+)\ +(?P<FileSize>[\w]+)?\ +(?P<Filepath>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Order"],
                            jsondict["Filepath"],
                            jsondict["FileSize"],
                            jsondict["ExecFlag"],
                            jsondict["LastModified"],
                            jsondict["LastUpdated"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[0],
                            kv[5],
                            kv[4],
                            kv[3],
                            kv[1],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "svcscan":
        for plugout in str(plugoutlist).split("', '', '"):
            for eachkv in re.findall(
                r"Offset\:\ +(?P<Offset>0x[A-Fa-f\d]+)\'\,\ \'Order\:\ (?P<Order>[^\']+)\'\,\ \'Start\:\ (?P<StartType>[^\']+)\'\,\ \'Process\ ID\:\ (?P<PID>[^\']+)\'\,\ \'Service\ Name\:\ (?P<ServiceName>[^\']+)\'\,\ \'Display\ Name\:\ (?P<DisplayName>[^\']+)\'\,\ \'Service\ Type\:\ (?P<ServiceType>[^\']+)\'\,\ \'Service\ State\:\ (?P<ServiceState>[^\']+)\'\,\ \'Binary\ Path\:\ (?P<BinaryPath>[\S\ ]+)",
                plugout,
            ):
                kv = list(eachkv)
                if len(kv) > 0:
                    (
                        jsondict["VolatilityVersion"],
                        jsondict[symbolorprofile],
                        jsondict["VolatilityPlugin"],
                        jsondict["ServiceName"],
                        jsondict["ServiceType"],
                        jsondict["DisplayName"],
                        jsondict["ServiceState"],
                        jsondict["StartType"],
                        jsondict["PID"],
                        jsondict["BinaryPath"],
                        jsondict["Order"],
                        jsondict["Offset"],
                    ) = (
                        volver,
                        profile,
                        plugin,
                        kv[4],
                        kv[6],
                        kv[5],
                        kv[7],
                        kv[2],
                        kv[3],
                        kv[8],
                        kv[1],
                        kv[0],
                    )
                else:
                    pass
                jsonlist.append(json.dumps(jsondict))
    elif plugin == "symlinkscan":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Pointer>\d+)\ +(?P<Handles>\d+)\ +(?P<StartTime>[\d\-\:\ ]+)\ \w+\+\d+\ +(?P<Source>\S+)\ +(?P<Destination>\S+)\ +",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Source"],
                            jsondict["Destination"],
                            jsondict["StartTime"],
                            jsondict["Pointer"],
                            jsondict["Handles"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[4],
                            kv[5],
                            kv[3],
                            kv[1],
                            kv[2],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "systeminfo":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"(?P<LastModified>\d{4}\-\d{2}\-\d{2}\ \d{2}\:\d{2}\:\d{2}(?:\ [\w\+]+)?)\\t(?P<Type>[^\\]+)\\t(?P<Summary>[\w\-\ ]+)?[^t]+t(?P<Source>[\S\ ]+)?",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["Summary"],
                            jsondict["Type"],
                            jsondict["Source"],
                            jsondict["LastModified"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[2],
                            kv[1],
                            kv[3],
                            kv[0],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "thrdscan":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<PID>\d+)\ +(?P<TID>\S+)\ +(?P<Base>0x[A-Fa-f\d]+)\ +(?P<StartTime>\d{4}\-\d{2}\-\d{2}\ \d{2}\:\d{2}\:\d{2}(?:\ [\w\+]+)?)\ +(?P<ExitTime>\d{4}\-\d{2}\-\d{2}\ \d{2}\:\d{2}\:\d{2}(?:\ [\w\+]+)?)?",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["PID"],
                            jsondict["TID"],
                            jsondict["Offset"],
                            jsondict["Base"],
                            jsondict["StartTime"],
                            jsondict["ExitTime"],
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
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "unloadedmodules":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<ModuleName>[\w\.]+)\ +(?P<StartAddress>0x[A-Fa-f\d]+)\ +(?P<EndAddress>0x[A-Fa-f\d]+)\ +(?P<StartTime>\d{4}\-\d{2}\-\d{2}\ \d{2}\:\d{2}\:\d{2}(?:\ [\w\+]+)?)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ModuleName"],
                            jsondict["StartAddress"],
                            jsondict["EndAddress"],
                            jsondict["StartTime"],
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
    elif plugin == "usbstor":
        for plugout in (
            str(plugoutlist).replace("\\\\", "\\").split("Found USB Drive: ")
        ):
            for eachkv in re.findall(
                r"(?P<DeviceName>[^\']+)\'\,\ \'\\tSerial\ Number\:\\t(?P<SerialNumber>[^\']+)\'\,\ \'\\tVendor\:\\t(?P<Vendor>[^\']+)\'\,\ \'\\tProduct\:\\t(?P<Product>[^\']+)\'\,\ \'\\tRevision\:\\t(?P<Revision>[^\']+)\'\,\ \'\\tClassGUID\:\\t(?P<ClassGUID>[^\']+)\'\,\ \'\'\,\ \'\\tContainerID\:\\t(?P<ContainerID>[^\']+)\'\,\ \'\\tMounted\ Volume\:\\t(?P<MountedVolume>[^\']+)\'\,\ \'\\tDrive\ Letter\:\\t(?P<DriveLetter>[^\']+)\'\,\ \'\\tFriendly\ Name\:\\t(?P<FriendlyName>[^\']+)\'\,\ \'\\tUSB\ Name\:\\t(?P<USBName>[^\']+)\'\,\ \'\\tDevice\ Last\ Connected\:\\t(?P<LastConnected>[^\']+)\'\,\ \'\'\,\ \'\\tClass\:\\t(?P<Class>[^\']+)\'\,\ \'\\tService\:\\t(?P<Service>[^\']+)\'\,\ \'\\tDeviceDesc\:\\t(?P<DeviceDescription>[^\']+)\'\,\ \'\\tCapabilities\:\\t(?P<Capabilities>[^\']+)\'\,\ \'\\tMfg\:\\t(?P<Mfg>[^\']+)\'\,\ \'\\tConfigFlags\:\\t(?P<ConfigFlags>[^\']+)\'\,\ \'\\tDriver\:\\t(?P<Driver>[^\']+)\'\,\ \'\\tCompatible\ IDs\:\'\,\ \'\\t\\t(?P<CompatibleIDs>[\S\ ]+)\'\,\ \'\\t\\t\'\,\ \'\\t\\t\'\,\ \'\\tHardwareID\:\'\,\ \'\\t\\t(?P<HardwareIDs>[\S\ ]+)\'\,\ \'\\t\\t\'\,\ \'\\t\\t\'\,\ \'Windows\ Portable\ Devices[^\\]+\\t[^\\]+\\t(?P<WindowsPortableDevices>[\S\ ]+)",
                plugout,
            ):
                kv = list(eachkv)
                if len(kv) > 0:
                    (
                        jsondict["VolatilityVersion"],
                        jsondict[symbolorprofile],
                        jsondict["VolatilityPlugin"],
                        jsondict["USBName"],
                        jsondict["FriendlyName"],
                        jsondict["DeviceName"],
                        jsondict["MountedVolume"],
                        jsondict["DriveLetter"],
                        jsondict["SerialNumber"],
                        jsondict["LastConnected"],
                        jsondict["Vendor"],
                        jsondict["Product"],
                        jsondict["Revision"],
                        jsondict["DeviceDescription"],
                        jsondict["Manufacturer"],
                        jsondict["Driver"],
                        jsondict["Capabilities"],
                        jsondict["ConfigFlags"],
                        jsondict["Class"],
                        jsondict["ClassGUID"],
                        jsondict["ContainerID"],
                        jsondict["Service"],
                        jsondict["CompatibleIDs"],
                        jsondict["HardwareIDs"],
                        WindowsPortableDevices,
                    ) = (
                        volver,
                        profile,
                        plugin,
                        kv[10],
                        kv[9],
                        kv[0],
                        kv[7],
                        kv[8],
                        kv[1],
                        kv[11],
                        kv[2],
                        kv[3],
                        kv[4],
                        kv[14],
                        kv[16],
                        kv[18],
                        kv[15],
                        kv[17],
                        kv[12],
                        kv[5],
                        kv[6],
                        kv[13],
                        kv[19]
                        .replace("\\\\", "\\")
                        .replace("\\t", "")
                        .replace("', '", ";"),
                        kv[20]
                        .replace("\\\\", "\\")
                        .replace("\\t", "")
                        .replace("', '", ";"),
                        kv[21],
                    )
                    wpddict, wpdlist = {}, []
                    if "', '" in WindowsPortableDevices:
                        for eachwpd in WindowsPortableDevices.split("', '"):
                            if ":" in eachwpd:
                                wpddict[
                                    eachwpd.replace(":\\t", "|")
                                    .replace("\\t", "")
                                    .replace(":", "|")
                                    .split("|")[0]
                                ] = (
                                    eachwpd.replace(":\\t", "|")
                                    .replace("\\t", "")
                                    .split("|")[1]
                                )
                            else:
                                pass
                        wpdlist.append(json.dumps(wpddict))
                        wpddict.clear()
                        jsondict["WindowsPortableDevices"] = wpdlist
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
                else:
                    pass
    elif plugin == "userassist":
        for plugout in str(plugoutlist).split("__--------------------------"):
            for eachkv in re.findall(
                r"^Registry\:\ (?P<RegistryHive>[^\']+)\ +\'\,\ \'Path\:\ (?P<RegistryKey>[^\']+)\'\,\ \'Last\ updated\:\ +(?P<LastWriteTime>[\d\-\:\ ]+)\ ",
                plugout.split("REG_BINARY    ")[0][4:],
            ):
                kv = list(eachkv)
                if len(kv) > 0:
                    (
                        jsondict["VolatilityVersion"],
                        jsondict[symbolorprofile],
                        jsondict["VolatilityPlugin"],
                        jsondict["RegistryHive"],
                        jsondict["RegistryKey"],
                        jsondict["LastWriteTime"],
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
            for eachinfo in plugout.split("REG_BINARY    ")[1:]:
                for eachkv in re.findall(
                    r"(?P<RegistryKeyValue>[^\']+)\ \:\ \'\,\ \'Count\:\ +(?P<ValueCount>\d+)\'\,\ \'Focus\ Count\:\ +(?P<FocusCount>\d+)\'\,\ \'Time Focused\:\ +(?P<TimeFocused>[\d\:\.]+)\'\,\ \'Last updated\:\ +(?P<LastWriteTime>[\d\-\:\ ]+)\ ",
                    eachinfo,
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            voldict["RegistryKeyValue"],
                            voldict["LastWriteTimeValue"],
                            voldict["ValueCount"],
                            voldict["FocusCount"],
                            voldict["TimeFocused"],
                        ) = (kv[0], kv[4], kv[1], kv[2], kv[3])
                    else:
                        pass
                datadict, datalist, hexdata, asciidata = (
                    {},
                    [],
                    "",
                    "",
                )
                for data in eachinfo.split("', 'Raw Data:', '")[1:]:
                    for eachdata in data.split("', '"):
                        hexdata = hexdata + str(eachdata)[12:60].replace(" ", "")
                        asciidata = asciidata + str(eachdata)[62:81]
                        alldata = alldata + "\n" + eachdata
                    (
                        datadict["RawHEXData"],
                        datadict["ParsedASCIIData"],
                        datadict["FormattedASCIIData"],
                        datadict["RawASCIIData"],
                    ) = (
                        str(hexdata).replace('"', "").replace("\n", ""),
                        str(asciidata[::2]).replace('"', "").replace("\n", ""),
                        str(asciidata[::2]).lower().replace('"', "").replace("\n", ""),
                        str(asciidata).replace('"', "").replace("\n", ""),
                    )
                    if len(datadict) > 0:
                        datalist.append(json.dumps(datadict))
                    else:
                        pass
                for datainfo in datalist:
                    voldict.update(json.loads(datainfo))
                    vollist.append(json.dumps(voldict))
                voldict.clear()
                datalist.clear()
            for volinfo in vollist:
                jsondict.update(json.loads(volinfo))
                jsonlist.append(json.dumps(jsondict))
    elif plugin == "userhandles":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\ +(?P<Handle>0x[A-Fa-f\d]+)\ +(?P<Type>\w+)\ +(?P<Flags>\d+)\ +(?P<TID>[\d\-]+)\ +(?P<PID>[\d\-]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["PID"],
                            jsondict["TID"],
                            jsondict["Type"],
                            jsondict["Flags"],
                            jsondict["Offset"],
                            jsondict["Handle"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[5],
                            kv[4],
                            kv[2],
                            kv[3],
                            kv[0],
                            kv[1],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "vadinfo":
        for plugout in str(plugoutlist).split(
            "************************************************************************"
        ):
            if plugout.startswith("', '") and plugout.endswith("', '"):
                (
                    jsondict["VolatilityVersion"],
                    jsondict[symbolorprofile],
                    jsondict["VolatilityPlugin"],
                    jsondict[
                        plugout.split("VAD node @ ")[0]
                        .replace(" ", "")
                        .replace("','", "")
                        .split(":")[0]
                    ],
                ) = (
                    volver,
                    profile,
                    plugin,
                    plugout.split("VAD node @ ")[0]
                    .replace(" ", "")
                    .replace("','", "")
                    .split(":")[1],
                )
                for eachinfo in plugout.split("VAD node @ ")[1:]:
                    for eachkv in re.findall(
                        r"^(?P<VADNode>0x[A-Fa-f\d]+)\ +Start\ +(?P<Start>0x[A-Fa-f\d]+)\ +End\ +(?P<End>0x[A-Fa-f\d]+)\ +Tag\ +(?P<Tag>[^\'\ ]+)\ ?\'\,\ \'Flags\:\ +(?P<Flags>[\S\ ]+)?\'\,\ \'Protection\:\ +(?P<Protection>[\S\ ]+)\'\,\ \'Vad\ Type\:\ +(?P<VADType>[\S\ ]+)\'\,\ \'ControlArea\ +(?P<ControlArea>[\S\ ]+)\ +Segment\ +(?P<Segment>[A-Fa-f\d]+)\'\,\ \'NumberOfSectionReferences\:\ +(?P<NumberofSectionReferences>\d+)\ +NumberOfPfnReferences\:\ +(?P<NumberofPfnReferences>\d+)\'\,\ \'NumberOfMappedViews\:\ +(?P<NumberofMappedViews>\d+)\ +NumberOfUserReferences\:\ +(?P<NumberofUserReferences>\d+)\'\,\ \'Control\ Flags\:\ +(?P<ControlFlags>[\S\ ]+)?\'\,\ \'First\ prototype\ PTE\:\ +(?P<FirstPrototypePTE>[A-Fa-f\d]+)\ +Last\ contiguous\ PTE\:\ +(?P<LastContiguousPTE>[A-Fa-f\d]+)\'\,\ \'Flags2\:\ +(?P<Flags2>[^\']+)?",
                        eachinfo,
                    ):
                        kv = list(eachkv)
                        if len(kv) > 0:
                            (
                                jsondict["VADInfo"],
                                jsondict["Start"],
                                jsondict["End"],
                                jsondict["Tag"],
                                jsondict["Protection"],
                                jsondict["VADType"],
                                jsondict["ControlArea"],
                                jsondict["Segment"],
                                jsondict["SectionReferences"],
                                jsondict["PFNReferences"],
                                jsondict["MappedViews"],
                                jsondict["UserReferences"],
                                jsondict["FirstContiguousPTE"],
                                jsondict["LastContiguousPTE"],
                                ControlFlags,
                                Flags,
                            ) = (
                                kv[0],
                                kv[1],
                                kv[2],
                                kv[3],
                                kv[5],
                                kv[6],
                                kv[7],
                                kv[8],
                                kv[9],
                                kv[10],
                                kv[11],
                                kv[12],
                                kv[14],
                                kv[15],
                                kv[13],
                                kv[4] + ", " + kv[16],
                            )
                        else:
                            pass
                        (
                            flagdict,
                            flaglist,
                            cflagdict,
                            cflaglist,
                        ) = ({}, [], {}, [])
                        if ": " in Flags.strip(", "):
                            for eachflag in Flags.strip(", ").split(", "):
                                flagdict[
                                    eachflag.replace("\\ n", "\\n")
                                    .replace(" ", ":")
                                    .replace("::", ":")
                                    .replace("\\n", "\\ n")
                                    .replace("'", "")
                                    .split(":")[0]
                                ] = (
                                    eachflag.replace("\\ n", "\\n")
                                    .replace(" ", ":")
                                    .replace("::", ":")
                                    .replace("\\n", "\\ n")
                                    .replace("'", "")
                                    .split(":")[1]
                                    .replace("\\\\", "\\")
                                )
                            flaglist.append(json.dumps(flagdict))
                            flagdict.clear()
                            jsondict["Flags"] = flaglist
                        else:
                            pass
                        if ": " in ControlFlags:
                            for eachcflag in ControlFlags.split(", "):
                                cflagdict[
                                    eachcflag.replace("\\ n", "\\n")
                                    .replace(" ", ":")
                                    .replace("::", ":")
                                    .replace("\\n", "\\ n")
                                    .replace("'", "")
                                    .split(":")[0]
                                ] = (
                                    eachcflag.replace("\\ n", "\\n")
                                    .replace(" ", ":")
                                    .replace("::", ":")
                                    .replace("\\n", "\\ n")
                                    .replace("'", "")
                                    .split(":")[1]
                                    .replace("\\\\", "\\")
                                )
                            cflaglist.append(json.dumps(cflagdict))
                            cflagdict.clear()
                            jsondict["ControlFlags"] = cflaglist
                        else:
                            pass
                        jsonlist.append(json.dumps(jsondict))
    else:
        pass
