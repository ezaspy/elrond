#!/usr/bin/env python3 -tt
import json
import re
import subprocess


def use_system_plugins(
    artefact, jsondict, jsonlist, regjsonlist, rgrplistj, userinfo, sids
):
    for profile in rgrplistj.split("\\n----------------------------------------\\n"):
        if (
            len(profile.split(" v.")) > 1
            and len(profile.split(" v.")[0].replace("\\n", "").strip("-")) < 28
        ):
            if profile.split(" v.")[0].replace("\\n", "").strip("-") == "samparse":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in (
                        eachinfo.replace("\\n  S-1-", "||S-1-")
                        .replace(":||", ": ")
                        .split("\\n")
                    ):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        if "__>" in info:
                            userinfo.append(info.split("__> ")[1])
                        elif "Users :" in info:
                            for sid in info.split(": ")[1].split("||"):
                                sids.append(sid)
                        else:
                            for eachkv in re.findall(
                                r"(?P<k>[A-Z][\w\ ]+\w)\ +\:\ +(?P<v>[^\\]*)",
                                info,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 1:
                                    jsondict[kv[0]] = kv[1]
                    if len(userinfo) > 0:
                        jsondict["account_info"] = (
                            "(" + str(userinfo)[1:-1].replace("'", "") + ")"
                        )
                    elif len(sids) > 0:
                        jsondict["sids"] = "(" + str(sids)[1:-1].replace("'", "") + ")"
                if len(jsondict) > 4:
                    jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "lsasecrets":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        for eachkv in re.findall(
                            r"(?P<k>[\w\ ]+)\ (?:\-|\=)\ (?P<v>[\S\ ]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "auditpol":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for info in eachinfo.split("\\n"):
                        if "     " in info:
                            for eachkv in re.findall(
                                r"^(?P<GPOCategory>[^\:]+)\:(?P<GPOSubcategory>[\S\ ]+\w)\ +(?P<GPOSetting>[\S]{1,3})",
                                info,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    (
                                        jsondict["GPOCategory"],
                                        jsondict["GPOSubcategory"],
                                        jsondict["GPOSetting"],
                                    ) = (
                                        kv[0],
                                        kv[1],
                                        kv[2],
                                    )
                    if len(jsondict) > 0:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "gpohist":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["GPOIdentifier"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        eachinfo.replace("\\n ", "|| ").strip("|| ").strip("\\n")[0:38],
                    )
                    if (
                        eachinfo.replace("\\n ", "|| ").strip("|| ").strip("\\n")[0:38]
                        != ""
                    ):
                        for eachkv in re.findall(
                            r"\ +(?P<k>[A-Za-z\ ]+\w)(?:\ +)?\£(?P<v>[^\|]+)",
                            eachinfo.replace("\\n ", "|| ")
                            .strip("|| ")[42::]
                            .replace(": ", "£"),
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0].replace(" time", "Time")] = kv[1]
                if len(jsondict) > 5:
                    jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "apppaths":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in (
                        eachinfo.replace('"\\n', '"||  ')
                        .replace("\\n  ", "||  ")
                        .split("||  ")[2::]
                    ):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        if "(" in info.replace(" - ", " (") + ")".replace(
                            "))", ""
                        ) and ")" in info.replace(" - ", " (") + ")".replace("))", ""):
                            for eachkv in re.findall(
                                r"^(?P<File>[^\(]+)\ \((?P<Filepath>[\S\ ]+)\)",
                                info.strip(" ").replace(" -", " (").replace("( ", "(")
                                + ")",
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    Filepath = re.sub(
                                        r"\\n\d{4}-\d{2}-\d{2}.*", r"", kv[1]
                                    )
                                    kv_info = re.findall(
                                        r"\S(?:\\n)(\d{4}-\d{2}-\d{2}.*)", kv[1]
                                    )
                                    if len(kv_info) > 0:
                                        Timestamp = kv_info[0]
                                    else:
                                        Timestamp = "-"
                                    if len(Filepath) > 0:
                                        (
                                            jsondict["File"],
                                            jsondict["Filepath"],
                                            jsondict["Timestamp"],
                                        ) = (
                                            kv[0],
                                            Filepath.strip('"')
                                            .strip("/")
                                            .strip('"')
                                            .strip("/")
                                            .replace("\\\\\\\\", "\\\\"),
                                            Timestamp,
                                        )
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif (
                profile.split(" v.")[0].replace("\\n", "").strip("-") == "lastloggedon"
            ):
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        for eachkv in re.findall(
                            r"(?P<k>[\w\.]+)\ +\=\ (?P<v>[\S\ ]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "shellext":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for eachkv in re.findall(
                        r"(?P<GUID>\{[^\}]+\})\ \ (?P<DLLShellDesc>[^\\]*)\\n\ \ DLL\:\ (?P<DLLShellPath>[\S\ ]*)\\n\ \ Timestamp\:\ (?P<Timestamp>[\S\ ]+)",
                        eachinfo.replace("  \\n  DLL\\:", "").strip("\\n"),
                    ):
                        kv = list(eachkv)
                        if len(kv) > 0:
                            (
                                jsondict["GUID"],
                                jsondict["DLLShellDesc"],
                                jsondict["DLLShellPath"],
                                jsondict["Timestamp"],
                            ) = (kv[0], kv[1], kv[2], kv[3])
                if len(jsondict) > 4:
                    jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif (
                profile.split(" v.")[0].replace("\\n", "").strip("-") == "inprocserver"
            ):
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for eachkv in re.findall(
                        r"(?P<MalwareDesc>Possible\ Lurk\ infection)\ found\!\\n\ \ (?P<File>[\S\ ]+)",
                        eachinfo,
                    ):
                        kv = list(eachkv)
                        if len(kv) > 0:
                            (
                                jsondict["File"],
                                jsondict["MalwareDesc"],
                            ) = (kv[1], kv[0])
                if len(jsondict) > 4:
                    jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif (
                profile.split(" v.")[0].replace("\\n", "").strip("-")
                == "Launching direct"
            ):
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for eachkv in re.findall(
                        r"(?P<FileAttributes>\w[\w\\]+\w)\ \-\ (?P<File>[^\\\r\n]+)",
                        eachinfo,
                    ):
                        kv = list(eachkv)
                        if len(kv) > 0:
                            (
                                jsondict["File"],
                                jsondict["FileAttributes"],
                            ) = (kv[1], kv[0])
                if len(jsondict) > 4:
                    jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "wbem":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for eachkv in re.findall(
                        r"^(?P<File>[^\[]+)\[(?P<FileAttributes>[^\]]+)\]\ \-\ LowDateTime\:(?P<LastWriteTime>\-?\d+)\,HighDateTime\:(?P<HighLastWriteTime>\-?\d+)\*\*\*(?P<FileDesc>.*)",
                        eachinfo,
                    ):
                        kv = list(eachkv)
                        if len(kv) > 0:
                            (
                                jsondict["File"],
                                jsondict["FileDesc"],
                                jsondict["FileAttributes"],
                                jsondict["LastWriteTime"],
                                jsondict["HighLastWriteTime"],
                            ) = (
                                kv[1],
                                kv[4],
                                kv[0],
                                kv[2],
                                kv[3],
                            )
                if len(jsondict) > 4:
                    jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "svchost":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        for eachkv in re.findall(
                            r"^(?P<ServiceGroup>\w+)\ +(?P<ServiceList>[\w\,]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if kv[1] != "Time":
                                if len(kv) > 0:
                                    (
                                        jsondict["ServiceGroup"],
                                        jsondict["ServiceList"],
                                    ) = (kv[0], kv[1])
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "drivers32":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        if " - " in info:
                            for eachkv in re.findall(
                                r"\ +(?P<Driver>[^\-]+)\ \-\ (?P<File>[^\-]+)",
                                info,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    (
                                        jsondict["File"],
                                        jsondict["Driver"],
                                    ) = (kv[1], kv[0])
                        elif "\\" in info:
                            jsondict["Filepath"] = info
                    if len(jsondict) > 5:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "emdmgmt":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1::][1::]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["DeviceName"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        eachinfo.split("\\n")[0],
                    )
                    for info in eachinfo.split("\\n")[1:]:
                        for eachkv in re.findall(
                            r"\ \ (?P<k>[^\:]+)\:\ (?P<v>[\S\ ]+)",
                            info.replace(
                                "LastWrite:",
                                "LastWriteTime:",
                            )
                            .replace("SN:", "SerialNumber:")
                            .replace("Vol Name:", "VolumeName:")
                            .replace(
                                "VSN:",
                                "VolumeSerialNumber:",
                            ),
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 6:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif (
                profile.split(" v.")[0].replace("\\n", "").strip("-")
                == "sql_lastconnect"
            ):
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:][1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for eachkv in re.findall(
                        r"(?P<k>\w+)\ +(?P<v>[^\\]+)",
                        eachinfo,
                    ):
                        kv = list(eachkv)
                        if len(kv) > 0:
                            jsondict[kv[0]] = kv[1]
                if len(jsondict) > 4:
                    jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "winlogon":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    if len(eachinfo.split("\\n")) > 2:
                        if "\\" in eachinfo.split("\\n")[0]:
                            for info in eachinfo.split("\\n")[1:]:
                                for eachkv in re.findall(
                                    r"^\ \ (?P<k>[^\=]+)\ \=\ (?P<v>[\S\ ]+)",
                                    info,
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        jsondict[kv[0]] = kv[1]
                if len(jsondict) > 4:
                    jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "win_cv":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1::][1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"\ \ (?P<DirectoryName>[\S\ ]+)\ \:\ (?P<DirectoryPath>[\S\ ]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["DirectoryName"],
                                    jsondict["DirectoryPath"],
                                ) = (kv[0], kv[1])
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "uac":
                for eachinfo in range(
                    len(profile.split(" v.")[1].split("\\n\\n")[1::]) - 1
                ):
                    if (
                        " value = "
                        in profile.split(" v.")[1].split("\\n\\n")[1::][eachinfo]
                    ):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        for info in (
                            profile.split(" v.")[1]
                            .split("\\n\\n")[1::][eachinfo + 1]
                            .split("\\n")
                        ):
                            if (
                                profile.split(" v.")[1]
                                .split("\\n\\n")[1::][eachinfo]
                                .split(" = ")[1]
                                == info.split(" = ")[0]
                            ):
                                for eachkv in re.findall(
                                    r"(?P<UACPolicy>[^\=]+)\ \=\ (?P<UACValue>[\S\ ]+)",
                                    profile.split(" v.")[1].split("\\n\\n")[1::][
                                        eachinfo
                                    ]
                                    + " ["
                                    + info.split(" = ")[1]
                                    + "]",
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        (
                                            jsondict["UACPolicy"],
                                            jsondict["UACValue"],
                                        ) = (kv[0], kv[1])
                        if len(jsondict) > 4:
                            jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "clsid":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for eachkv in re.findall(
                        r"(?P<ClassID>\{[^\}]+\})\ +(?P<ClassApp>[^\\]+)\\n\ +(?P<LastWriteTime>[^\\]+)(?:\\n\ +InprocServer32\:\ (?P<ClassAppDLL>[\S\ ]+))?",
                        eachinfo,
                    ):
                        kv = list(eachkv)
                        if len(kv) > 0:
                            (
                                jsondict["ClassApp"],
                                jsondict["ClassID"],
                                jsondict["ClassAppDLL"],
                                jsondict["LastWriteTime"],
                            ) = (kv[1], kv[0], kv[3], kv[2])
                if len(jsondict) > 4:
                    jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "port_dev":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        for eachkv in re.findall(
                            r"(?P<k>[A-Z]\w+)\ +\:\ +(?P<v>[^\\]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "soft_run":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    if (
                        " has no subkeys." not in eachinfo
                        and " not found." not in eachinfo
                    ):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                            jsondict["RegistryKey"],
                            jsondict["LastWriteTime"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                            eachinfo.split("\\n")[0],
                            eachinfo.split("\\n")[1],
                        )
                        for info in eachinfo.split("\\n")[2:]:
                            for eachkv in re.findall(
                                r"(?P<AppName>[\S\ ]+)\ \-\ (?P<AppLocation>[\S\ ]+)",
                                info,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    (
                                        jsondict["AppName"],
                                        jsondict["AppLocation"],
                                    ) = (kv[0], kv[1])
                        if len(jsondict) > 6:
                            jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "assoc":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"(?P<Fileext>[\S\ ]+)\ \:\ (?P<DefaultApp>[\S\ ]+\.\w{3}\"?)\ (?P<AppAttributes>[\S\ ]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                if "\\" in kv[2]:
                                    (
                                        jsondict["DefaultApp"],
                                        jsondict["AppAttributes"],
                                        jsondict["Fileext"],
                                    ) = (
                                        kv[1],
                                        '"'
                                        + kv[2]
                                        .replace('", ', '",')
                                        .replace('",', ", ")
                                        .replace(", ", ",")
                                        .replace(",", " ")
                                        .replace('"', "")
                                        + '"',
                                        kv[0],
                                    )
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "regback":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"(?P<k>[A-Z][A-Za-z]+)\ +\\?t?\:\s(?P<v>[\S\ ]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 5:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "profilelist":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for info in eachinfo.replace("\\\\n", "\\\\ n").split("\\n"):
                        for eachkv in re.findall(
                            r"(?P<k>[A-Z][A-Za-z]+)\ +\:\ (?P<v>[\S\ ]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "winnt_cv":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"(?P<k>[A-Z][A-Za-z\d]+)\ +\:\ (?P<v>[\S\ ]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "bho":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    if (
                        " not found." not in eachinfo
                        and "Browser Helper Objects\\nLastWrite" not in eachinfo
                    ):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                            jsondict["BrowserHelperObject"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                            eachinfo.split("\\n")[0],
                        )
                        for info in eachinfo.split("\\n")[1:]:
                            for eachkv in re.findall(
                                r"\ \ (?P<k>[\S]+)\ +\=\>\ (?P<v>[\S\ ]+)",
                                info,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    jsondict[kv[0]] = kv[1]
                        if len(jsondict) > 5:
                            jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "ie_version":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"(?P<k>[A-Za-z\ ]+[A-Za-z\d\ \(\)\/]+)\ +\=\ (?P<v>[^\\]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif (
                profile.split(" v.")[0].replace("\\n", "").strip("-")
                == "Launching volinfocache"
            ):
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["DriveLetter"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .strip("Launching "),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        eachinfo.split(":")[0],
                    )
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"(?P<k>[A-Za-z]+)\:\ (?P<v>[A-Z][\S\ ]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 5:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif (
                profile.split(" v.")[0].replace("\\n", "").strip("-")
                == "Launching networklist"
            ):
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .strip("Launching "),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"(?P<NetworkDomain>^\S+[\S\ ]+\S(?P<NetworkAttributes>(?:\n\ \ [\S\ ]+){4})?)",
                            info,
                        ):
                            NetDNetA = list(eachkv)
                            if len(NetDNetA) > 0:
                                jsondict["DeviceName"] = NetDNetA[1]
                                for eachkv in re.findall(
                                    r"\ \ (?P<k>[^\:]+)\:\ (?P<v>[\S\ ]+)",
                                    NetDNetA[1],
                                ):
                                    kvv = list(eachkv)
                                    if len(kvv) > 0:
                                        jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "schedagent":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"(?P<k>[A-Z][^\=]+)\=\ (?P<v>[\S\ ]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "svc":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for info in eachinfo.split("\\n")[1:]:
                        for eachkv in re.findall(
                            r"(?P<LastWriteTime>[^\,]*)\,(?P<ServiceName>[^\,]*)\,(?P<ServiceDisplayName>[^\,]*)\,(?P<ServicePathDLL>[^\,]*)\,(?P<ServiceType>[^\,]*)\,(?P<ServiceStartType>[^\,]*)\,(?P<ServiceObjectName>[^\,]*)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["ServiceName"],
                                    jsondict["ServiceDisplayName"],
                                    jsondict["ServicePathDLL"],
                                    jsondict["ServiceType"],
                                    jsondict["ServiceStartType"],
                                    jsondict["ServiceObjectName"],
                                    jsondict["LastWriteTime"],
                                ) = (
                                    kv[1],
                                    kv[2],
                                    kv[3],
                                    kv[4],
                                    kv[5],
                                    kv[6],
                                    kv[0],
                                )
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "profiler":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"(?P<k>[\w]+)\ \-\>\ (?P<v>[\S\ ]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "netsvcs":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"(?P<LastWriteTime>[^\,]*)\,(?P<ServiceName>[^\,]*)\,(?P<ServicePathDLL>[^\,]*)\,(?P<ServiceStartType>[^\,]*)\,(?P<ServiceType>[^\,]*)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["ServiceName"],
                                    jsondict["ServicePathDLL"],
                                    jsondict["ServiceType"],
                                    jsondict["ServiceStartType"],
                                    jsondict["LastWriteTime"],
                                ) = (
                                    kv[1],
                                    kv[2],
                                    kv[4],
                                    kv[3],
                                    kv[0],
                                )
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "services":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        for eachkv in re.findall(
                            r"(?P<ServiceName>\w+)\ +\=\ +(?P<ServicePathDLL>[\S\ ]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["ServiceName"],
                                    jsondict["ServiceDLL"],
                                ) = (kv[0], kv[1])
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif (
                profile.split(" v.")[0].replace("\\n", "").strip("-") == "ewf_mountev"
                or profile.split(" v.")[0].replace("\\n", "").strip("-")
                == "ewf_mountev2"
            ):
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                    ) = (
                        artefact.split("/")[-1].upper(),
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                    )
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"(?:\ \ (?:\\\\|\_)\?\?(?:\\\\|\_)(?P<DeviceType>[^\#\ ]+)\#(?P<DeviceLabel>[^\#\ ]+)\#(?P<DeviceSerialNumber>[^\#\ ]+)\#(?P<DeviceID>[^\#\ ]+)|\ \ \\\\\?\?\\\\Volume(?P<VolumeID>[^\#\ ]+)|\ \ \\\\DosDevices\\\\(?P<MountLocation>[^\:]+))",
                            info.replace("Device:", " "),
                        ):
                            kv = list(eachkv)
                            if len(list(filter(None, kv))) == 1:
                                (
                                    jsondict["DeviceName"],
                                    jsondict["DeviceType"],
                                    jsondict["DeviceSerialNumber"],
                                    jsondict["DeviceID"],
                                ) = (
                                    kv[1],
                                    kv[0],
                                    kv[2],
                                    kv[3],
                                )
                            else:
                                if len(list(filter(None, kv))[0]) == 1:
                                    jsondict["MountLocation"] = kv[0]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "svc_plus":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in (
                        eachinfo.replace("^^^^", "Non-Standard Type")
                        .replace(
                            "<<<<",
                            "Start Mismatch for Driver",
                        )
                        .replace(
                            "****",
                            "ObjectName Mismatch for Driver",
                        )
                        .replace(
                            ">>>>",
                            "Start Mismatch for Service",
                        )
                        .replace(
                            "++++",
                            "Non-Standard ObjectName for Service",
                        )
                        .split("\\n")
                    ):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        for eachkv in re.findall(
                            r"(?P<LastWriteTime>[\S\ ]*)\,(?P<DriverName>[\S\ ]*)\,(?P<DriverDisplayName>[\S\ ]*)\,(?P<DriverPathDLL>[\S\ ]*)\,(?P<DriverType>[\S\ ]*)\,(?P<DriverStartType>[\S\ ]*)\,(?P<DriverContext>[\S\ ]*)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["DriverName"],
                                    jsondict["DriverDisplayName"],
                                    jsondict["DriverPathDLL"],
                                    jsondict["DriverType"],
                                    jsondict["DriverStartType"],
                                    jsondict["DriverContext"],
                                    jsondict["LastWriteTime"],
                                ) = (
                                    kv[1],
                                    kv[2],
                                    kv[3],
                                    kv[4],
                                    kv[5],
                                    kv[6],
                                    kv[0],
                                )
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "wpdbusenum":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        for eachkv in re.findall(
                            r"(?:(?P<DeviceID>\S+)\ \((?P<DeviceSerialNumber>[^\)]+)\)|\ \ (?P<k>[\S\ ]+[a-z])(?:\ +)?\:\ +(?P<v>[\S\ ]+\S))",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["DeviceID"],
                                    jsondict["DeviceSerialNumber"],
                                    jsondict[kv[2]],
                                ) = (kv[0], kv[1], kv[3])
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "compname":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        for eachkv in re.findall(
                            r"(?P<k>[\S\ ]+[a-z])(?:\ +)?\=\ +(?P<v>[\S\ ]+\S)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "svcdll":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.replace("\\\\n", "\\\\ n").split("\\n"):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        for eachkv in re.findall(
                            r"\ \ (?P<k>[\S\ ]+)\ \-\>\ (?P<v>[\S\ ]+\S)",
                            info.replace("\\\\ n", "\\\\n"),
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif (
                profile.split(" v.")[0].replace("\\n", "").strip("-")
                == "processor_architecture"
            ):
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1]
                            .split("\\n\\n")[0]
                            .split("\\n")[1]
                            .replace("\\\\\\'", ""),
                        )
                        for eachkv in re.findall(
                            r"(?P<k>[\S\ ]+)\ +\=\ +(?P<v>[\S\ ]+\S)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "timezone":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        for eachkv in re.findall(
                            r"(?P<k>[\w]+)\ *\-\>\ (?P<v>[\w\-\ \(\)\.\,\@]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "usb":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                            jsondict["UNKNOWN"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                            eachinfo.split("\\n")[0],
                        )
                        for eachkv in re.findall(
                            r"\ +(?P<k>[\S\ ]+[A-Za-z])(?:\ +)?\:\ +(?P<v>[\w\ \:\&]+\w)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 5:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "nic":
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        (
                            jsondict["RegistryHive"],
                            jsondict["Plugin"],
                            jsondict["PluginVer"],
                            jsondict["PluginDesc"],
                        ) = (
                            artefact.split("/")[-1].upper(),
                            profile.split(" v.")[0]
                            .replace("\\n", "")
                            .strip("-")
                            .replace("Launching ", ""),
                            profile.split(" v.")[1].split("\\n")[0],
                            profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        )
                        for eachkv in re.findall(
                            r"\ +(?P<k>\S+)\ +(?P<v>[\d\.]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
    for eachjson in jsonlist:
        try:
            eachjson = str(eachjson).replace('""', '"-"')
            if '"RegistryKey"' in eachjson:
                insert = ', "Registry{}'.format(
                    str(
                        str(
                            re.findall(
                                r"RegistryKey(\"\: \"[^\"]+\")",
                                eachjson,
                            )[0]
                        ).lower()
                    )
                    .replace(" ", "_")
                    .replace('":_"', '": "')
                )
                regjsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
            else:
                regjsonlist.append(json.dumps(eachjson))
        except:
            pass
    return jsonlist, regjsonlist


def extract_registry_system(
    output_directory,
    img,
    vss_path_insert,
    artefact,
    jsondict,
    jsonlist,
    regjsonlist,
):
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "registry/"
        + artefact.split("/")[-1]
        + ".json",
        "a",
    ) as regjson:
        rgrplistj, userinfo, sids = (
            str(
                subprocess.Popen(
                    [
                        "rip.pl",
                        "-r",
                        artefact,
                        "-f",
                        artefact.split("/")[-1].lower(),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[0]
            )[2:-1],
            [],
            [],
        )
        jsonlist, regjsonlist = use_system_plugins(
            artefact, jsondict, jsonlist, regjsonlist, rgrplistj, userinfo, sids
        )
        if len(regjsonlist) > 0:
            regjson.write(
                str(regjsonlist)
                .replace(
                    "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\",
                    "/",
                )
                .replace("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\", "/")
                .replace("\\\\\\\\\\\\\\\\", "/")
                .replace("\\\\\\\\", "/")
                .replace("\\\\", "/")
                .replace("\\", "/")
                .replace('/"', '"')
                .replace(
                    "                                                                ",
                    " ",
                )
                .replace("                                ", " ")
                .replace("                ", " ")
                .replace("        ", " ")
                .replace("    ", " ")
                .replace("  ", " ")
                .replace("  ", "")
                .replace('" ', '"')
                .replace(' "', '"')
                .replace("//'", "'")
                .replace('":"', '": "')
                .replace('","', '", "')
                .replace('"}"\', \'"{"', '"}, {"')
                .replace('[\'"{"', '[{"')
                .replace('"}"\']', '"}]')
            )
        regjsonlist.clear()
        jsonlist.clear()
