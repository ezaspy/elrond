#!/usr/bin/env python3 -tt
import json
import re


def linux_vol3(
    volver, profile, symbolorprofile, plugin, plugoutlist, jsondict, jsonlist
):
    if plugin == "linux.bash.Bash":
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
        plugin == "linux.check_afinfo.Check_afinfo"
    ):  # in-development (no artefacts available during testing)
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                pass
    elif (
        plugin == "linux.check_creds.Check_creds"
    ):  # in-development (no artefacts available during testing)
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                pass
    elif plugin == "linux.check_idt.Check_idt":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Index>0x[A-Fa-f\d]+)\\t(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<ModuleName>[^\\]+)\\t(?P<Symbol>[\S\ ]+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ModuleName"],
                            jsondict["Symbol"],
                            jsondict["Index"],
                            jsondict["Offset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[2],
                            kv[3],
                            kv[0],
                            kv[1],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif (
        plugin == "linux.check_modules.Check_modules"
    ):  # in-development (no artefacts available during testing)
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                pass
    elif plugin == "linux.check_syscall.Check_syscall":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<TableName>[^\\]+)\\t(?P<Index>\d+)\\t(?P<HandlerOffset>0x[A-Fa-f\d]+)\\t(?P<HandlerSymbol>[\S\ ]+)",
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
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux.elfs.Elfs":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<PID>\d+)\\t(?P<ProcessName>[^\\]+)\\t(?P<StartOffset>[^\\]+)\\t(?P<EndOffset>[^\\]+)\\t(?P<Filepath>[\S\ ]+)",
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
                            jsondict["StartOffset"],
                            jsondict["EndOffset"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[0],
                            kv[4],
                            kv[2],
                            kv[3],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif (
        plugin == "linux.keyboard_notifiers.Keyboard_notifiers"
    ):  # in-development (no artefacts available during testing)
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                pass
    elif plugin == "linux.lsmod.Lsmod":
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
    elif plugin == "linux.lsof.Lsof":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<PID>\d+)\\t(?P<ProcessName>[^\\]+)\\t(?P<FileDescriptor>\d+)\\t(?P<Filepath>\S+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["ProcessName"],
                            jsondict["Filepath"],
                            jsondict["PID"],
                            jsondict["FileDescriptor"],
                        ) = (
                            volver,
                            profile,
                            plugin,
                            kv[1],
                            kv[3],
                            kv[0],
                            kv[2],
                        )
                    else:
                        pass
                    jsonlist.append(json.dumps(jsondict))
    elif plugin == "linux.malfind.Malfind":
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
    elif (
        plugin == "linux.proc.Proc"
    ):  # in-development (no artefacts available during testing)
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                pass
    elif (
        plugin == "linux.pslist.Pslist"
    ):  # in-development (no artefacts available during testing)
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                pass
    elif (
        plugin == "linux.pstree.Pstree"
    ):  # in-development (no artefacts available during testing)
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                pass
    elif plugin == "linux.tty_check.tty_check":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<TTYName>tty\d+)\\t(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<ModuleName>\w+)\\t(?P<Symbol>\S+)",
                    eachinfo.replace("\\\\ n", "\\\\n"),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["VolatilityVersion"],
                            jsondict[symbolorprofile],
                            jsondict["VolatilityPlugin"],
                            jsondict["TTYName"],
                            jsondict["ModuleName"],
                            jsondict["Symbol"],
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
    else:
        pass
