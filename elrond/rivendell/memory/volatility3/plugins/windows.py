#!/usr/bin/env python3 -tt
import json
import os
import re
import shutil


def windows_vol3(
    output_directory,
    mempath,
    volver,
    profile,
    symbolorprofile,
    plugin,
    plugoutlist,
    jsondict,
    jsonlist,
):
    if plugin == "windows.cmdline.CmdLine":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
    elif plugin == "windows.modscan.ModScan":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
    elif plugin == "windows.netscan.NetScan" or plugin == "windows.netstat.NetStat":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
    elif plugin == "windows.pslist.PsList" or plugin == "windows.psscan.PsScan":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
        if not os.path.exists(output_directory + mempath + "/certificates/"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                pass
    elif plugin == "windows.registry.printkey.PrintKey":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                for eachkv in re.findall(
                    r"^(?P<LastWriteTime>[\d\-\ \:\.]+)\ \|\|t(?P<Offset>0x[A-Fa-f\d]+)\|\|t(?P<Type>[^\|]+)\|\|t(?P<KeyPath>[\S\ ]+)\|\|t(?P<KeyName>[^\|]+)\|\|t\|\|t(?P<Volatile>\S+)",
                    eachinfo.replace("\\t", "||t").replace("\\\\ n", "\\\\n"),
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
                pass
    elif plugin == "windows.ssdt.SSDT":
        for plugout in plugoutlist:
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
            for eachinfo in plugout.replace("\\\\n", "\\\\ n").split("\n"):
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
