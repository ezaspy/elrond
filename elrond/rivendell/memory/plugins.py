#!/usr/bin/env python3 -tt
import json
import os
import re
import shutil
import subprocess

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry
from rivendell.memory.vol_plugins import plugin


def use_plugins(output_directory, artefact, volver, memext, mempath, profile, plugin):
    if not os.path.exists(output_directory + mempath + "/memory_" + plugin + ".json"):
        with open(
            output_directory + mempath + "/memory_" + plugin + ".json", "w"
        ) as voljson:
            (
                jsondict,
                voldict,
                voljsonlist,
                jsonlist,
                vollist,
                symbolorprofile,
            ) = ({}, {}, [], [], [], "VolatilitySymbolTable")
            if volver == "3":
                plugoutlist = (
                    str(
                        subprocess.Popen(
                            [
                                "python3",
                                "/usr/local/lib/python3.8/dist-packages/volatility3/vol.py",
                                "-f",
                                artefact + memext,
                                plugin,
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()[0]
                    )[2:-1]
                    .replace("\\\\n", "\\\\ n")
                    .split("\\n")
                )
                if "Windows" in profile or profile.startswith("Win"):
                    if plugin == "windows.cmdline.CmdLine":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<PID>\d+)\\t(?P<ProcessName>\S+)\\t(?P<CommandLine>.*)",
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
                    elif plugin == "windows.dlllist.DllList":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<PID>\d+)\\t(?P<ProcessName>\S+)\\t(?P<Base>0x[A-Fa-f\d]+)\\t(?P<Size>0x[A-Fa-f\d]+)\\t(?P<Filename>\S+)\\t(?P<Filepath>[\S\ ]+)\\t(?P<LoadTime>[\S\ ]+)\\t(?P<FileOutput>\w+)",
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
                                            jsondict["Filename"],
                                            jsondict["Filepath"],
                                            jsondict["FileOutput"],
                                            jsondict["LoadTime"],
                                            jsondict["Base"],
                                            jsondict["Size"],
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[1],
                                            kv[0],
                                            kv[4],
                                            kv[5],
                                            kv[7],
                                            kv[6],
                                            kv[2],
                                            kv[3],
                                        )
                                    else:
                                        pass
                                    jsonlist.append(json.dumps(jsondict))
                    elif plugin == "windows.driverscan.DriverScan":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<StartAddress>0x[A-Fa-f\d]+)\\t(?P<Size>0x[A-Fa-f\d]+)\\t(?P<ServiceKey>[\S\ ]+)\\t(?P<DriverName>[\S\ ]+)\\t(?P<ServiceName>[\S\ ]+)",
                                    eachinfo.replace("\\\\ n", "\\\\n"),
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        (
                                            jsondict["VolatilityVersion"],
                                            jsondict[symbolorprofile],
                                            jsondict["VolatilityPlugin"],
                                            jsondict["DriverName"],
                                            jsondict["ServiceName"],
                                            jsondict["ServiceKey"],
                                            jsondict["Offset"],
                                            jsondict["StartAddress"],
                                            jsondict["Size"],
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[4],
                                            kv[5],
                                            kv[3],
                                            kv[0],
                                            kv[1],
                                            kv[2],
                                        )
                                    else:
                                        pass
                                    jsonlist.append(json.dumps(jsondict))
                    elif plugin == "windows.envars.Envars":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<PID>\d+)\\t(?P<ProcessName>\S+)\\t(?P<Block>0x[A-Fa-f\d]+)\\t(?P<Variable>\S+)\\t(?P<Value>.*)",
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
                                            jsondict["Variable"],
                                            jsondict["Value"],
                                            jsondict["Block"],
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
                    elif plugin == "windows.filescan.FileScan":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<Filename>[\S\ ]+)\\t(?P<FileSize>\d+)",
                                    eachinfo.replace("\\\\ n", "\\\\n"),
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        (
                                            jsondict["VolatilityVersion"],
                                            jsondict[symbolorprofile],
                                            jsondict["VolatilityPlugin"],
                                            jsondict["Filename"],
                                            jsondict["FileSize"],
                                            jsondict["Offset"],
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
                    elif plugin == "windows.getservicesids.GetServiceSIDs":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<SecurityID>S\-[\d\-]+)\\t(?P<ServiceName>[\S\ ]+)",
                                    eachinfo.replace("\\\\ n", "\\\\n"),
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        (
                                            jsondict["VolatilityVersion"],
                                            jsondict[symbolorprofile],
                                            jsondict["VolatilityPlugin"],
                                            jsondict["ServiceName"],
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
                    elif plugin == "windows.getsids.GetSIDs":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<PID>\d+)\\t(?P<ProcessName>\S+)\\t(?P<SecurityID>S\-[\d\-]+)\\t(?P<GroupName>[\S\ ]+)",
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
                                            jsondict["GroupName"],
                                            jsondict["SecurityID"],
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
                    elif plugin == "windows.handles.Handles":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<PID>\d+)\\t(?P<ProcessName>\S+)\\t(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<HandleValue>0x[A-Fa-f\d]+)\\t(?P<Type>[\w\ ]+)\\t(?P<GrantedAccess>0x[A-Fa-f\d]+)\\t?(?P<HandleName>[\S\ ]+)?",
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
                                            jsondict["HandleName"],
                                            jsondict["HandleValue"],
                                            jsondict["Type"],
                                            jsondict["GrantedAccess"],
                                            jsondict["Offset"],
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[1],
                                            kv[0],
                                            kv[6],
                                            kv[3],
                                            kv[4],
                                            kv[5],
                                            kv[2],
                                        )
                                    else:
                                        pass
                                    jsonlist.append(json.dumps(jsondict))
                    elif plugin == "windows.info.Info":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<Variable>[\S\ ]+)\\t(?P<Value>[\S\ ]+)",
                                    eachinfo.replace("\\\\ n", "\\\\n"),
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        (
                                            jsondict["VolatilityVersion"],
                                            jsondict[symbolorprofile],
                                            jsondict["VolatilityPlugin"],
                                            jsondict["Variable"],
                                            jsondict["Value"],
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[0],
                                            kv[1],
                                        )
                                    else:
                                        pass
                                    jsonlist.append(json.dumps(jsondict))
                    elif plugin == "windows.malfind.Malfind":
                        for plugout in str(
                            re.sub(
                                r"(\'\,\ \'\d+\\\\)",
                                r"********************\1",
                                str(plugoutlist),
                            )
                        ).split("********************', '"):
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<PID>\d+)[\s\\t]{3}(?P<ProcessName>[^\\]+)[\s\\t]{3}(?P<StartOffset>0x[A-Fa-f\d]+)[\s\\t]{3}(?P<EndOffset>0x[A-Fa-f\d]+)[\s\\t]{3}(?P<Tag>\S+)[\s\\t]{3}(?P<Protection>\S+)[\s\\t]{3}(?P<CommitCharge>\S+)[\s\\t]{3}(?P<PrivateMemory>\S+)[\s\\t]{3}(?P<FileOutput>\S+)[\s\\t]{3}\'\,\ \'(?P<Data>[\S\ ]+)",
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
                                            jsondict["FileOutput"],
                                            jsondict["Tag"],
                                            jsondict["Protection"],
                                            jsondict["CommitCharge"],
                                            jsondict["PrivateMemory"],
                                            jsondict["StartOffset"],
                                            jsondict["EndOffset"],
                                            DataAssembly,
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[1],
                                            kv[0],
                                            kv[8],
                                            kv[4],
                                            kv[5],
                                            kv[6],
                                            kv[7],
                                            kv[2],
                                            kv[3],
                                            kv[9],
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
                                        hexdata = hexdata + str(eachdata)[0:23].replace(
                                            " ", ""
                                        )
                                        asciidata = asciidata + str(eachdata)[26:32]
                                    (
                                        datadict["RawHEXData"],
                                        datadict["RawASCIIData"],
                                        datadict["FormattedASCIIData"],
                                    ) = (hexdata, asciidata, asciidata[::2])
                                    datalist.append(json.dumps(datadict))
                                    jsondict["Data"] = datalist
                                    jsonlist.append(json.dumps(jsondict))
                    elif plugin == "windows.modscan.ModScan":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<Base>0x[A-Fa-f\d]+)\\t(?P<Size>0x[A-Fa-f\d]+)\\t(?P<ModuleName>[\S\ ]+)?\\t(?P<ModulePath>[\S\ ]+)?\\t(?P<FileOutput>\w+)",
                                    eachinfo.replace("\\\\ n", "\\\\n"),
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        (
                                            jsondict["VolatilityVersion"],
                                            jsondict[symbolorprofile],
                                            jsondict["VolatilityPlugin"],
                                            jsondict["ModuleName"],
                                            jsondict["ModulePath"],
                                            jsondict["FileOutput"],
                                            jsondict["Offset"],
                                            jsondict["Base"],
                                            jsondict["Size"],
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[3],
                                            kv[4],
                                            kv[5],
                                            kv[0],
                                            kv[1],
                                            kv[2],
                                        )
                                    else:
                                        pass
                                    jsonlist.append(json.dumps(jsondict))
                    elif plugin == "windows.modules.Modules":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<Base>0x[A-Fa-f\d]+)\\t(?P<Size>0x[A-Fa-f\d]+)\\t(?P<Filename>[\S\ ]+)\\t(?P<Filepath>[\S\ ]+)\\t(?P<FileOutput>\w+)",
                                    eachinfo.replace("\\\\ n", "\\\\n"),
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        (
                                            jsondict["VolatilityVersion"],
                                            jsondict[symbolorprofile],
                                            jsondict["VolatilityPlugin"],
                                            jsondict["Filename"],
                                            jsondict["Filepath"],
                                            jsondict["FileOutput"],
                                            jsondict["Offset"],
                                            jsondict["Base"],
                                            jsondict["Size"],
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[3],
                                            kv[4],
                                            kv[5],
                                            kv[0],
                                            kv[1],
                                            kv[2],
                                        )
                                    else:
                                        pass
                                    jsonlist.append(json.dumps(jsondict))
                    elif plugin == "windows.mutantscan.MutantScan":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<MutantName>[\S\ ]+)",
                                    eachinfo.replace("\\\\ n", "\\\\n"),
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        (
                                            jsondict["VolatilityVersion"],
                                            jsondict[symbolorprofile],
                                            jsondict["VolatilityPlugin"],
                                            jsondict["MutantName"],
                                            jsondict["Offset"],
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
                    elif (
                        plugin == "windows.netscan.NetScan"
                        or plugin == "windows.netstat.NetStat"
                    ):
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<Protocol>\w+)\\t(?P<LocalAddress>[A-Fa-f\d\:\.\-\*]+)\\t(?P<LocalPort>\d+)\\t(?P<ForeignAddress>[A-Fa-f\d\:\.\-\*]+)\\t(?P<ForeignPort>\d+)\\t(?P<State>[^\\]+)?\\t(?P<PID>\d+)\\t(?P<ProcessName>[^\\]+)\\t(?P<LastWriteTime>[\S\ ]*\S)",
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
                                            jsondict["LocalAddress"],
                                            jsondict["LocalPort"],
                                            jsondict["ForeignAddress"],
                                            jsondict["ForeignPort"],
                                            jsondict["Protocol"],
                                            jsondict["State"],
                                            jsondict["LastWriteTime"],
                                            jsondict["Offset"],
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[8],
                                            kv[7],
                                            kv[2],
                                            kv[3],
                                            kv[4],
                                            kv[5],
                                            kv[1],
                                            kv[6],
                                            kv[9],
                                            kv[0],
                                        )
                                    else:
                                        pass
                                    jsonlist.append(json.dumps(jsondict))
                    elif plugin == "windows.privileges.Privileges":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<PID>\d+)\\t(?P<ProcessName>\w+)\\t(?P<Value>\d+)\\t(?P<Privilege>\w+)\\t(?P<Attributes>[\S\ ]+)?\\t(?P<Description>[\S\ ]+)",
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
                                            jsondict["Privilege"],
                                            jsondict["Attributes"],
                                            jsondict["Value"],
                                            jsondict["Description"],
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[1],
                                            kv[0],
                                            kv[3],
                                            kv[4],
                                            kv[2],
                                            kv[5],
                                        )
                                    else:
                                        pass
                                    jsonlist.append(json.dumps(jsondict))
                    elif (
                        plugin == "windows.pslist.PsList"
                        or plugin == "windows.psscan.PsScan"
                    ):
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<PID>\d+)\\t(?P<PPID>\d+)\\t(?P<ProcessName>\S+)\\t(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<Threads>\S+)\\t(?P<Handles>\S+)?\\t(?P<SessionID>\S+)\\t(?P<WoW64>\S+)\\t(?P<LastWriteTime>[\S\ ]+)\\t(?P<ExitTime>[\S\ ]+)\\t(?P<FileOutput>\S+)",
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
                                            jsondict["LastWriteTime"],
                                            jsondict["ExitTime"],
                                            jsondict["FileOutput"],
                                            jsondict["Threads"],
                                            jsondict["Handles"],
                                            jsondict["SessionID"],
                                            jsondict["WoW64"],
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[2],
                                            kv[0],
                                            kv[1],
                                            kv[8],
                                            kv[9],
                                            kv[10],
                                            kv[4],
                                            kv[5],
                                            kv[6],
                                            kv[7],
                                        )
                                    else:
                                        pass
                                    jsonlist.append(json.dumps(jsondict))
                    elif plugin == "windows.pstree.PsTree":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"(?P<PID>\S+)\\t(?P<PPID>\S+)\\t(?P<ProcessName>\S+)\\t(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<Threads>\d+)\\t(?P<Handles>\S+)?\\t(?P<SessionID>\S+)\\t(?P<WoW64>\S+)\\t(?P<LastWriteTime>[\S\ ]+)\\t(?P<ExitTime>[\S\ ]+)",
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
                                            jsondict["LastWriteTime"],
                                            jsondict["ExitTime"],
                                            jsondict["Threads"],
                                            jsondict["Handles"],
                                            jsondict["SessionID"],
                                            jsondict["WoW64"],
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[2],
                                            kv[0],
                                            kv[1],
                                            kv[8],
                                            kv[9],
                                            kv[4],
                                            kv[5],
                                            kv[6],
                                            kv[7],
                                        )
                                    else:
                                        pass
                                    jsonlist.append(json.dumps(jsondict))
                    elif plugin == "windows.registry.certificates.Certificates":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<CertificatePath>[\S\ ]+)\\t(?P<CertificateSection>\S+)\\t(?P<CertificateID>\S+)\\t(?P<CertificateName>[\S\ ]+)$",
                                    eachinfo.replace("\\\\ n", "\\\\n"),
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        (
                                            jsondict["VolatilityVersion"],
                                            jsondict[symbolorprofile],
                                            jsondict["VolatilityPlugin"],
                                            jsondict["CertificateName"],
                                            jsondict["CertificatePath"],
                                            jsondict["CertificateID"],
                                            jsondict["CertificateSection"],
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[3],
                                            kv[0],
                                            kv[2],
                                            kv[1],
                                        )
                                    else:
                                        pass
                                    jsonlist.append(json.dumps(jsondict))
                        if not os.path.exists(
                            output_directory + mempath + "/certificates/"
                        ):
                            os.makedirs(output_directory + mempath + "/certificates/")
                        else:
                            pass
                        for certfile in os.listdir("."):
                            if certfile.endswith(".crt"):
                                shutil.move(
                                    certfile,
                                    output_directory + mempath + "/certificates/",
                                )
                            else:
                                pass
                    elif plugin == "windows.registry.hivelist.HiveList":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<Filepath>\S+)\\t(?P<FileOutput>\S+)$",
                                    eachinfo.replace("\\\\ n", "\\\\n"),
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        (
                                            jsondict["VolatilityVersion"],
                                            jsondict[symbolorprofile],
                                            jsondict["VolatilityPlugin"],
                                            jsondict["Filepath"],
                                            jsondict["FileOutput"],
                                            jsondict["Offset"],
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
                    elif (
                        plugin == "windows.registry.hivescan.HiveScan"
                    ):  # outstanding (no artefacts available)
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                pass
                    elif plugin == "windows.registry.printkey.PrintKey":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<LastWriteTime>[\d\-\ \:\.]+)\ \|\|t(?P<Offset>0x[A-Fa-f\d]+)\|\|t(?P<Type>[^\|]+)\|\|t(?P<KeyPath>[\S\ ]+)\|\|t(?P<KeyName>[^\|]+)\|\|t\|\|t(?P<Volatile>\S+)",
                                    eachinfo.replace("\\t", "||t").replace(
                                        "\\\\ n", "\\\\n"
                                    ),
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        (
                                            jsondict["VolatilityVersion"],
                                            jsondict[symbolorprofile],
                                            jsondict["VolatilityPlugin"],
                                            jsondict["KeyName"],
                                            jsondict["KeyPath"],
                                            jsondict["Type"],
                                            jsondict["Volatile"],
                                            jsondict["LastWriteTime"],
                                            jsondict["Offset"],
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[4],
                                            kv[3],
                                            kv[2],
                                            kv[5],
                                            kv[0],
                                            kv[1],
                                        )
                                    else:
                                        pass
                                    jsonlist.append(json.dumps(jsondict))
                    elif (
                        plugin == "windows.registry.userassist.UserAssist"
                    ):  # outstanding (no artefacts available)
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                pass
                    elif plugin == "windows.ssdt.SSDT":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<Index>\d+)\\t(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<ModuleName>\S+)\\t(?P<Symbol>\S+)",
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
                    elif plugin == "windows.symlinkscan.SymlinkScan":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<LastWriteTime>[\d\-\ \:\.]+)\\t(?P<SymLinkName>\S+)\\t(?P<SymLinkDestination>\S+)?",
                                    eachinfo.replace("\\\\ n", "\\\\n"),
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        (
                                            jsondict["VolatilityVersion"],
                                            jsondict[symbolorprofile],
                                            jsondict["VolatilityPlugin"],
                                            jsondict["SymLinkName"],
                                            jsondict["SymLinkDestination"],
                                            jsondict["LastWriteTime"],
                                            jsondict["Offset"],
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[1],
                                            kv[2],
                                            kv[3],
                                            kv[0],
                                        )
                                    else:
                                        pass
                                    jsonlist.append(json.dumps(jsondict))
                    elif plugin == "windows.vadinfo.VadInfo":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                for eachkv in re.findall(
                                    r"^(?P<PID>\d+)\\t(?P<ProcessName>\S+)\\t(?P<Offset>0x[A-Fa-f\d]+)\\t(?P<StartOffset>0x[A-Fa-f\d]+)\\t(?P<EndOffset>0x[A-Fa-f\d]+)\\t(?P<Tag>[\S\ ]+)\\t(?P<Protection>\S+)\\t(?P<CommitCharge>\S+)\\t(?P<PrivateMemory>\S+)\\t(?P<ParentOffset>[\S\ ]+)\\t(?P<Filename>[\S\ ]+)\\t(?P<FileOutput>\S+)",
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
                                            jsondict["Filename"],
                                            jsondict["FileOutput"],
                                            jsondict["Tag"],
                                            jsondict["Protection"],
                                            jsondict["CommitCharge"],
                                            jsondict["PrivateMemory"],
                                            jsondict["Offset"],
                                            jsondict["StartOffset"],
                                            jsondict["EndOffset"],
                                            jsondict["ParentOffset"],
                                        ) = (
                                            volver,
                                            profile,
                                            plugin,
                                            kv[1],
                                            kv[0],
                                            kv[10],
                                            kv[11],
                                            kv[5],
                                            kv[6],
                                            kv[7],
                                            kv[8],
                                            kv[2],
                                            kv[3],
                                            kv[4],
                                            kv[9],
                                        )
                                    else:
                                        pass
                                    jsonlist.append(json.dumps(jsondict))
                    else:
                        pass
                elif (
                    "macOS" in profile
                    or profile.startswith("Mac")
                    or profile.startswith("mac")
                    or profile.startswith("11.")
                    or profile.startswith("10.")
                ):
                    if plugin == "mac.bash.Bash":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                pass
                    elif plugin == "mac.kauth_scopes.Kauth_scopes":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                                        hexdata = hexdata + str(eachdata)[0:23].replace(
                                            " ", ""
                                        )
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                else:
                    if plugin == "linux.bash.Bash":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                    ):  # outstanding (no artefacts available)
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                pass
                    elif (
                        plugin == "linux.check_creds.Check_creds"
                    ):  # outstanding (no artefacts available)
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                pass
                    elif plugin == "linux.check_idt.Check_idt":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                    ):  # outstanding (no artefacts available)
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                pass
                    elif plugin == "linux.check_syscall.Check_syscall":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                    ):  # outstanding (no artefacts available)
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                pass
                    elif plugin == "linux.lsmod.Lsmod":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                                        hexdata = hexdata + str(eachdata)[0:23].replace(
                                            " ", ""
                                        )
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
                    ):  # outstanding (no artefacts available)
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                pass
                    elif (
                        plugin == "linux.pslist.Pslist"
                    ):  # outstanding (no artefacts available)
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                pass
                    elif (
                        plugin == "linux.pstree.Pstree"
                    ):  # outstanding (no artefacts available)
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
                                pass
                    elif plugin == "linux.tty_check.tty_check":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                if plugin == "timeliner.Timeliner":
                    for plugout in plugoutlist:
                        for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                            for eachkv in re.findall(
                                r"^(?P<Plugin>[^\\]+)\\t(?P<Description>[\S\ ]+)\\t(?P<CreatedTime>[^\\]+)\\t(?P<LastWriteTime>[^\\]+)\\t(?P<LastAccessedTime>[^\\]+)\\t(?P<LastChangedTime>[^\\]+)$",
                                eachinfo.replace("\\\\ n", "\\\\n"),
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    (
                                        jsondict["VolatilityVersion"],
                                        jsondict[symbolorprofile],
                                        jsondict["VolatilityPlugin"],
                                        jsondict["Plugin"],
                                        jsondict["Description"],
                                        jsondict["LastWriteTime"],
                                        jsondict["LastAccessedTime"],
                                        jsondict["LastChangedTime"],
                                        jsondict["CreatedTime"],
                                    ) = (
                                        volver,
                                        profile,
                                        plugin,
                                        kv[0],
                                        kv[1],
                                        kv[3],
                                        kv[4],
                                        kv[5],
                                        kv[2],
                                    )
                                else:
                                    pass
                                jsonlist.append(json.dumps(jsondict))
                else:
                    pass
            else:
                plugoutlist = (
                    str(
                        subprocess.Popen(
                            [
                                "vol.py",
                                "-f",
                                artefact + memext,
                                "--profile=" + profile,
                                plugin,
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()[0]
                    )[2:-1]
                    .replace("\\\\n", "\\\\ n")
                    .split("\\n")
                )
                symbolorprofile = "VolatilityProfile"
                if "Windows" in profile or profile.startswith("Win"):
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
                                for pluginfo in plugout.strip("']")[1:][2:-3].split(
                                    "', 'Cmd "
                                )[1:]:
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
                                                str(
                                                    plugout.split("Dump:")[0].replace(
                                                        ": ", ":"
                                                    )
                                                ),
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                                for eachdata in DataAssembly.split("', '', '")[0].split(
                                    "', '"
                                ):
                                    hexdata = hexdata + str(eachdata)[12:60].replace(
                                        " ", ""
                                    )
                                    asciidata = asciidata + str(eachdata)[63:81]
                                for eachasm in DataAssembly.split("', '', '")[1].split(
                                    "', '"
                                ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            str(plugoutlist)
                            .replace("\\\\", "\\")
                            .split("Found USB Drive: ")
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
                                        for eachwpd in WindowsPortableDevices.split(
                                            "', '"
                                        ):
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
                        for plugout in str(plugoutlist).split(
                            "__--------------------------"
                        ):
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
                                        hexdata = hexdata + str(eachdata)[
                                            12:60
                                        ].replace(" ", "")
                                        asciidata = asciidata + str(eachdata)[62:81]
                                        alldata = alldata + "\n" + eachdata
                                    (
                                        datadict["RawHEXData"],
                                        datadict["ParsedASCIIData"],
                                        datadict["FormattedASCIIData"],
                                        datadict["RawASCIIData"],
                                    ) = (
                                        str(hexdata).replace('"', "").replace("\n", ""),
                                        str(asciidata[::2])
                                        .replace('"', "")
                                        .replace("\n", ""),
                                        str(asciidata[::2])
                                        .lower()
                                        .replace('"', "")
                                        .replace("\n", ""),
                                        str(asciidata)
                                        .replace('"', "")
                                        .replace("\n", ""),
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                                            for eachflag in Flags.strip(", ").split(
                                                ", "
                                            ):
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
                elif (
                    "macOS" in profile
                    or profile.startswith("Mac")
                    or profile.startswith("mac")
                    or profile.startswith("11.")
                    or profile.startswith("10.")
                ):
                    if plugin == "mac_apihooks_kernel":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                                for eachdata in DataAssembly.split("', '', '")[0].split(
                                    "', '"
                                ):
                                    hexdata = hexdata + str(eachdata)[12:60].replace(
                                        " ", ""
                                    )
                                    asciidata = asciidata + str(eachdata)[63:81]
                                for eachasm in DataAssembly.split("', '', '")[1].split(
                                    "', '"
                                ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                else:
                    if plugin == "linux_arp":
                        for plugout in plugoutlist:
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                                        Variables = re.sub(
                                            r"\ ([A-Z\d\_]+)", r"====\1", Vars
                                        )
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                                for eachdata in DataAssembly.split("', '', '")[0].split(
                                    "', '"
                                ):
                                    hexdata = hexdata + str(eachdata)[12:60].replace(
                                        " ", ""
                                    )
                                    asciidata = asciidata + str(eachdata)[63:81]
                                for eachasm in DataAssembly.split("', '', '")[1].split(
                                    "', '"
                                ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                                        Variables = re.sub(
                                            r"\ ([A-Z\d\_]+)", r"====\1", Vars
                                        )
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
                            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split(
                                "\n"
                            ):
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
            for eachjson in jsonlist:
                try:
                    eachjson = (
                        str(eachjson)
                        .replace(
                            "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\",
                            "/",
                        )
                        .replace("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\", "/")
                        .replace("\\\\\\\\\\\\\\\\", "/")
                        .replace("\\\\\\\\", "/")
                        .replace("\\\\", "/")
                        .replace("\\", "/")
                        .replace("//", "/")
                        .replace("\\\\ n", "\\\\n")
                        .replace("/ n", "/n")
                        .replace('/"', '"')
                        .replace("'\"", "")
                        .replace("\"'", "")
                        .replace('", ', '", "')
                        .replace('""', '"')
                        .replace('" ', " ")
                        .replace(' "', " ")
                        .replace('": ', '": "')
                        .replace('", ', '", "')
                        .replace(" , ", '", "')
                        .replace('", "', '"; "')
                        .replace('",', ", ")
                        .replace('"; "', '", "')
                        .replace('="', "=")
                        .replace('": ", "', '": "-", "')
                        .replace('""', '"-"')
                        .replace(' "},', ' "-"},')
                        .replace(' }, {"', '"}, {"')
                        .replace(" }]", '"}]')
                        .replace('": "}', '": ""}')
                        .replace(', "__', ', "')
                        .replace('{"__', '{"')
                        .replace('", "/', '", "')
                        .replace("Pid", "PID")
                        .replace("pid", "PID")
                        .replace("Filepath", "Path")
                        .replace("Command line", "CommandLine")
                    )
                    if "Win" in profile:
                        if (
                            '"ProcessName"' in eachjson
                            and '"CommandLine"' in eachjson
                            and '"ShellFolderPath"' in eachjson
                        ):
                            insert = (
                                ', "WinProcess{}, "WinCommand{}, "Registry{}'.format(
                                    str(
                                        str(
                                            re.findall(
                                                r"ProcessName(\"\: \"[^\"]+\")",
                                                eachjson,
                                            )[0]
                                        ).lower()
                                    ).replace(" ", "_"),
                                    str(
                                        str(
                                            re.findall(
                                                r"CommandLine(\"\: \"[^\"]+\")",
                                                eachjson,
                                            )[0]
                                        ).lower()
                                    ).replace(" ", "_"),
                                    str(
                                        str(
                                            re.findall(
                                                r"ShellFolderPath(\"\: \"[^\"]+\")",
                                                eachjson,
                                            )[0]
                                        ).lower()
                                    ).replace(" ", "_"),
                                )
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif (
                            '"ProcessName"' in eachjson
                            and '"CommandLine"' in eachjson
                            and '"RegistryKey"' in eachjson
                        ):
                            insert = (
                                ', "WinProcess{}, "WinCommand{}, "Registry{}'.format(
                                    str(
                                        str(
                                            re.findall(
                                                r"ProcessName(\"\: \"[^\"]+\")",
                                                eachjson,
                                            )[0]
                                        ).lower()
                                    ).replace(" ", "_"),
                                    str(
                                        str(
                                            re.findall(
                                                r"CommandLine(\"\: \"[^\"]+\")",
                                                eachjson,
                                            )[0]
                                        ).lower()
                                    ).replace(" ", "_"),
                                    str(
                                        str(
                                            re.findall(
                                                r"RegistryKey(\"\: \"[^\"]+\")",
                                                eachjson,
                                            )[0]
                                        ).lower()
                                    ).replace(" ", "_"),
                                )
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif '"ProcessName"' in eachjson and '"Path"' in eachjson:
                            insert = ', "WinProcess{}, "WinCommand{}'.format(
                                str(
                                    str(
                                        re.findall(
                                            r"ProcessName(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                                str(
                                    str(
                                        re.findall(r"Path(\"\: \"[^\"]+\")", eachjson)[
                                            0
                                        ]
                                    ).lower()
                                ).replace(" ", "_"),
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif (
                            '"ProcessName"' in eachjson and '"CommandLine"' in eachjson
                        ):
                            insert = ', "WinProcess{}, "WinCommand{}'.format(
                                str(
                                    str(
                                        re.findall(
                                            r"ProcessName(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                                str(
                                    str(
                                        re.findall(
                                            r"CommandLine(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif (
                            '"ProcessName"' in eachjson
                            and '"ShellFolderPath"' in eachjson
                        ):
                            insert = ', "WinProcess{}, "Registry{}'.format(
                                str(
                                    str(
                                        re.findall(
                                            r"ProcessName(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                                str(
                                    str(
                                        re.findall(
                                            r"ShellFolderPath(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif (
                            '"ProcessName"' in eachjson and '"RegistryKey"' in eachjson
                        ):
                            insert = ', "WinProcess{}, "Registry{}'.format(
                                str(
                                    str(
                                        re.findall(
                                            r"ProcessName(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                                str(
                                    str(
                                        re.findall(
                                            r"RegistryKey(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif (
                            '"Path"' in eachjson
                            and '"CommandLine"' in eachjson
                            and '"RegistryKey"' in eachjson
                        ):
                            insert = (
                                ', "WinProcess{}, "WinCommand{}, "Registry{}'.format(
                                    str(
                                        str(
                                            re.findall(
                                                r"Path(\"\: \"[^\"]+\")", eachjson
                                            )[0]
                                        ).lower()
                                    ).replace(" ", "_"),
                                    str(
                                        str(
                                            re.findall(
                                                r"CommandLine(\"\: \"[^\"]+\")",
                                                eachjson,
                                            )[0]
                                        ).lower()
                                    ).replace(" ", "_"),
                                    str(
                                        str(
                                            re.findall(
                                                r"RegistryKey(\"\: \"[^\"]+\")",
                                                eachjson,
                                            )[0]
                                        ).lower()
                                    ).replace(" ", "_"),
                                )
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif '"Path"' in eachjson and '"CommandLine"' in eachjson:
                            insert = ', "WinProcess{}, "WinCommand{}'.format(
                                str(
                                    str(
                                        re.findall(r"Path(\"\: \"[^\"]+\")", eachjson)[
                                            0
                                        ]
                                    ).lower()
                                ).replace(" ", "_"),
                                str(
                                    str(
                                        re.findall(
                                            r"CommandLine(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif '"Path"' in eachjson and '"ShellFolderPath"' in eachjson:
                            insert = ', "WinProcess{}, "Registry{}'.format(
                                str(
                                    str(
                                        re.findall(r"Path(\"\: \"[^\"]+\")", eachjson)[
                                            0
                                        ]
                                    ).lower()
                                ).replace(" ", "_"),
                                str(
                                    str(
                                        re.findall(
                                            r"ShellFolderPath(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif (
                            '"CommandLine"' in eachjson and '"RegistryKey"' in eachjson
                        ):
                            insert = ', "WinCommand{}, "Registry{}'.format(
                                str(
                                    str(
                                        re.findall(
                                            r"CommandLine(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                                str(
                                    str(
                                        re.findall(
                                            r"RegistryKey(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif '"ProcessName"' in eachjson:
                            insert = ', "WinProcess{}'.format(
                                str(
                                    str(
                                        re.findall(
                                            r"ProcessName(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_")
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif '"Path"' in eachjson:
                            insert = ', "WinProcess{}'.format(
                                str(
                                    str(
                                        re.findall(r"Path(\"\: \"[^\"]+\")", eachjson)[
                                            0
                                        ]
                                    ).lower()
                                ).replace(" ", "_")
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif '"CommandLine"' in eachjson:
                            insert = ', "WinCommand{}'.format(
                                str(
                                    str(
                                        re.findall(
                                            r"CommandLine(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_")
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif '"ShellFolderPath"' in eachjson:
                            insert = ', "Registry{}'.format(
                                str(
                                    str(
                                        re.findall(
                                            r"ShellFolderPath(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_")
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif '"RegistryKey"' in eachjson:
                            insert = ', "Registry{}'.format(
                                str(
                                    str(
                                        re.findall(
                                            r"RegistryKey(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_")
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        else:
                            voljsonlist.append(json.dumps(eachjson))
                    else:
                        if '"ProcessName"' in eachjson and '"CommandLine"' in eachjson:
                            insert = ', "nixProcess{}, "nixCommand{}'.format(
                                str(
                                    str(
                                        re.findall(
                                            r"ProcessName(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                                str(
                                    str(
                                        re.findall(
                                            r"CommandLine(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif '"Path"' in eachjson and '"CommandLine"' in eachjson:
                            insert = ', "nixProcess{}, "nixCommand{}'.format(
                                str(
                                    str(
                                        re.findall(r"Path(\"\: \"[^\"]+\")", eachjson)[
                                            0
                                        ]
                                    ).lower()
                                ).replace(" ", "_"),
                                str(
                                    str(
                                        re.findall(
                                            r"CommandLine(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif '"ProcessName"' in eachjson and '"Path"' in eachjson:
                            insert = ', "nixProcess{}, "nixCommand{}'.format(
                                str(
                                    str(
                                        re.findall(
                                            r"ProcessName(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_"),
                                str(
                                    str(
                                        re.findall(r"Path(\"\: \"[^\"]+\")", eachjson)[
                                            0
                                        ]
                                    ).lower()
                                ).replace(" ", "_"),
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif '"ProcessName"' in eachjson:
                            insert = ', "nixProcess{}'.format(
                                str(
                                    str(
                                        re.findall(
                                            r"ProcessName(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_")
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif '"Path"' in eachjson:
                            insert = ', "nixProcess{}'.format(
                                str(
                                    str(
                                        re.findall(r"Path(\"\: \"[^\"]+\")", eachjson)[
                                            0
                                        ]
                                    ).lower()
                                ).replace(" ", "_")
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        elif '"CommandLine"' in eachjson:
                            insert = ', "nixCommand{}'.format(
                                str(
                                    str(
                                        re.findall(
                                            r"CommandLine(\"\: \"[^\"]+\")",
                                            eachjson,
                                        )[0]
                                    ).lower()
                                ).replace(" ", "_")
                            )
                            voljsonlist.append(
                                json.dumps(eachjson[0:-1] + insert + "}")
                            )
                        else:
                            voljsonlist.append(json.dumps(eachjson))
                except:
                    pass
            if len(voljsonlist) > 0:
                voljson.write(
                    str(voljsonlist)
                    .replace('\\\\"', '"')
                    .replace("['\"", "[")
                    .replace("\"']", "]")
                    .replace("}\"', '\"{", "}, {")
                    .replace("'", '"')
                    .replace('\\\\"', '"')
                    .replace('"}", "{"', '"}, {"')
                    .replace(', "{}"', "")
                    .replace('": "\\\\n', '": "')
                    .replace('"}"]', '"}]')
                    .replace('["{"', '[{"')
                    .replace('"[{"', '"[{"')
                    .replace(']}"]}', "]}]}")
                    .replace('"[{"', '[{"')
                    .replace('"}], ', '"}], "')
                    .replace('"["{}"], ', '["{}"], "')
                    .replace('"}", "{"', '"}, {"')
                    .replace("\\\\\\\\", "\\")
                    .replace('"["{}", "{"', '[{"')
                    .replace('}"], ', '"}], "')
                    .replace('": ["{"}], ""', '": [], "')
                    .replace(']"}]', "]}]")
                    .replace('": "[]}]}]', '": []}]}]')
                    .replace(', "Item": "GNOME_KEYRING_PID=', "")
                    .replace('":_"', '": "')
                    .replace(": : ", ": ")
                )
            else:
                pass
        jsonlist.clear()
    else:
        pass
