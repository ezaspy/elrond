#!/usr/bin/env python3 -tt
import json
import re
import subprocess


def use_profile_plugins(
    artefact, jsondict, jsonlist, regjsonlist, rgrplistj, regart, regusr
):
    for profile in rgrplistj.split("\\n----------------------------------------\\n"):
        if (
            len(profile.split(" v.")) > 1
            and len(profile.split(" v.")[0].replace("\\n", "").strip("-")) < 28
        ):
            if profile.split(" v.")[0].replace("\\n", "").strip("-") == "gpohist":
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    jsondict["GPOIdentifier"] = (
                        eachinfo.replace("\\n ", "|| ").strip("|| ").strip("\\n")[0:38]
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
                if len(jsondict) > 6:
                    jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif (
                profile.split(" v.")[0].replace("\\n", "").strip("-") == "proxysettings"
            ):
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"\ \ (?P<k>[\w\ ]+\w)\ +(?P<v>\w[\S\ ]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["RegistryHive"],
                                    jsondict["Plugin"],
                                    jsondict["PluginVer"],
                                    jsondict["PluginDesc"],
                                    jsondict[kv[0]],
                                ) = (
                                    regart,
                                    profile.split(" v.")[0]
                                    .replace("\\n", "")
                                    .strip("-")
                                    .replace("Launching ", ""),
                                    profile.split(" v.")[1].split("\\n")[0],
                                    profile.split(" v.")[1]
                                    .split("\\n\\n")[0]
                                    .split("\\n")[1],
                                    kv[1],
                                )
                    if len(jsondict) > 5:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif (
                profile.split(" v.")[0].replace("\\n", "").strip("-")
                == "internet_settings_cu"
                or profile.split(" v.")[0].replace("\\n", "").strip("-")
                == "internet_explorer_cu"
            ):
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    eachinfos = list(filter(None, eachinfo.split("\\n")))
                    jsondict["RegistryKey"] = eachinfos[0].strip(" ").strip("*")
                    for info in eachinfos[1:]:
                        for eachkv in re.findall(
                            r"\ \ (?P<k>[\w\ ]+\w)\ +\=\ (?P<v>[\w\%\:][\S\ ]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["RegistryHive"],
                                    jsondict["Plugin"],
                                    jsondict["PluginVer"],
                                    jsondict["PluginDesc"],
                                    jsondict["InternetSetting"],
                                    jsondict["InternetSettingValue"],
                                ) = (
                                    regart,
                                    kv[0],
                                    profile.split(" v.")[0]
                                    .replace("\\n", "")
                                    .strip("-")
                                    .replace("Launching ", ""),
                                    profile.split(" v.")[1].split("\\n")[0],
                                    profile.split(" v.")[1]
                                    .split("\\n\\n")[0]
                                    .split("\\n")[1],
                                    kv[1],
                                )
                    if len(jsondict) > 6:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "comdlg32":
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachkv in re.findall(
                    r"(?:\\n|')(?P<MRUGroup>[A-Z][^\\]+(?:[a-z\\\*]+)?)\\\\nLastWrite(?: Time)?\:\ (?P<LastWriteTime>[^\\]+)\\\\nNote\:\ [^\,]+\,[\ \']+(?P<MRUEntries>[^\,]+)",
                    str(profile.split(" v.")[1].split("\\n\\n")[1:]),
                ):
                    kv = list(eachkv)
                    if len(kv) > 0:
                        (
                            jsondict["MRUGroup"],
                            jsondict["LastWriteTime"],
                        ) = (
                            kv[0].replace("\\\\", "\\"),
                            kv[1],
                        )
                    for info in kv[2].replace("\\\\\\\\n", "\\\\\\\\ n").split("\\n"):
                        if "\\" in info.strip("'").strip("\\").replace(
                            "\\\\", "\\"
                        ).replace("\\ n", "\\n"):
                            jsondict["MRUEntry"] = (
                                info.strip("")
                                .strip("'")
                                .strip("\\")
                                .replace("\\\\", "\\")
                                .replace("\\ n", "\\n")
                            )
                if len(jsondict) > 7:
                    jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif (
                profile.split(" v.")[0].replace("\\n", "").strip("-") == "shellfolders"
            ):
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.replace("\\\\n", "\\\\ n").split("\\n"):
                        for eachkv in re.findall(
                            r"^(?P<ShellFolder>\S+(?:\ \w+)?)\ +(?P<ShellFolderPath>[\S\ ]+\S+)",
                            info.replace("\\\\ n", "\\\\n"),
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["RegistryHive"],
                                    jsondict["Plugin"],
                                    jsondict["PluginVer"],
                                    jsondict["PluginDesc"],
                                    jsondict["ShellFolder"],
                                    jsondict["ShellFolderPath"],
                                ) = (
                                    regart,
                                    profile.split(" v.")[0]
                                    .replace("\\n", "")
                                    .strip("-")
                                    .replace("Launching ", ""),
                                    profile.split(" v.")[1].split("\\n")[0],
                                    profile.split(" v.")[1]
                                    .split("\\n\\n")[0]
                                    .split("\\n")[1],
                                    kv[0],
                                    kv[1],
                                )
                    if len(jsondict) > 5:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "mixer":
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"^(?P<LastWriteTime>[\w\ ]+(?:\d+\:){2}[\w\ ]+)\,(?P<App>[^\,]+)\,(?P<DeviceGUID>[\S\ ]+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["RegistryHive"],
                                    jsondict["Plugin"],
                                    jsondict["PluginVer"],
                                    jsondict["PluginDesc"],
                                    jsondict["App"],
                                    jsondict["DeviceGUID"],
                                    jsondict["LastWriteTime"],
                                ) = (
                                    regart,
                                    profile.split(" v.")[0]
                                    .replace("\\n", "")
                                    .strip("-")
                                    .replace("Launching ", ""),
                                    profile.split(" v.")[1].split("\\n")[0],
                                    profile.split(" v.")[1]
                                    .split("\\n\\n")[0]
                                    .split("\\n")[1],
                                    kv[1],
                                    kv[2],
                                    kv[0],
                                )
                    if len(jsondict) > 5:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "ie_settings":
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                if len(profile.split(" v.")[1].split("\\n\\n")) > 3:
                    jsondict["LastWriteTime"] = (
                        profile.split(" v.")[1]
                        .split("\\n\\n")[1]
                        .split("\\n")[1]
                        .replace(" Time", "Time")
                    )
                    for eachinfo in profile.split(" v.")[1].split("\\n\\n")[2:]:
                        for info in eachinfo.replace("\\\\n", "\\\\ n").split("\\n"):
                            if " not found" not in info:
                                for eachkv in re.findall(
                                    r"^(?P<k>[\w+]+(?:\ \w+)?)\ (?:\=\ )?(?P<v>[\S\ ]+)",
                                    info.replace("\\\\ n", "\\\\n"),
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        jsondict[kv[0]] = kv[1]
                    if len(jsondict) > 7:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "ie_main":
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"^(?P<k>\w+(?:(?:\ \w+)?)+[A-Za-z])\ {3,}(?P<v>[\S\ ]*\S)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["RegistryHive"],
                                    jsondict["Plugin"],
                                    jsondict["PluginVer"],
                                    jsondict["PluginDesc"],
                                    jsondict["InternetSetting"],
                                    jsondict["InternetSettingValue"],
                                ) = (
                                    regart,
                                    profile.split(" v.")[0]
                                    .replace("\\n", "")
                                    .strip("-")
                                    .replace("Launching ", ""),
                                    profile.split(" v.")[1].split("\\n")[0],
                                    profile.split(" v.")[1]
                                    .split("\\n\\n")[0]
                                    .split("\\n")[1],
                                    kv[0],
                                    kv[1],
                                )
                    if len(jsondict) > 5:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "ie_zones":
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    if len(eachinfo.split("\\n")) > 3:
                        for info in eachinfo.split("\\n")[0:1]:
                            (
                                jsondict["RegistryHive"],
                                jsondict["Plugin"],
                                jsondict["PluginVer"],
                                jsondict["PluginDesc"],
                                jsondict["Zone"],
                                jsondict["ZoneDescription"],
                                jsondict["LongZoneDescription"],
                            ) = (
                                regart,
                                profile.split(" v.")[0]
                                .replace("\\n", "")
                                .strip("-")
                                .replace("Launching ", ""),
                                profile.split(" v.")[1].split("\\n")[0],
                                profile.split(" v.")[1]
                                .split("\\n\\n")[0]
                                .split("\\n")[1],
                                info.replace(":  ", " - ")
                                .replace(
                                    "This zone contains all ",
                                    "",
                                )
                                .replace(
                                    "This zone contains ",
                                    "",
                                )
                                .replace("\\", "")
                                .split(" - ")[0],
                                info.replace(":  ", " - ")
                                .replace(
                                    "This zone contains all ",
                                    "",
                                )
                                .replace(
                                    "This zone contains ",
                                    "",
                                )
                                .replace("\\", "")
                                .split(" - ")[1],
                                info.replace(":  ", " - ")
                                .replace(
                                    "This zone contains all ",
                                    "",
                                )
                                .replace(
                                    "This zone contains ",
                                    "",
                                )
                                .replace("\\", "")
                                .split(" - ")[2],
                            )
                        for info in eachinfo.split("\\n")[2:]:
                            for eachkv in re.findall(
                                r"^\ +(?P<k>[A-Za-z\d]+)\ +(?P<v>0x[\d]+)\ +(?P<d>[\w]*)",
                                info,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    (
                                        jsondict["RegistryKeyValue"],
                                        jsondict["KeyValueDWORD"],
                                        jsondict["Result"],
                                    ) = (
                                        kv[0],
                                        kv[1],
                                        kv[2],
                                    )
                    if len(jsondict) > 8:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "typedurls":
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    if len(eachinfo.split("\\n")) > 3:
                        jsondict["LastWriteTime"] = eachinfo.split("\\n")[2].replace(
                            " Time", "Time"
                        )
                        for info in eachinfo.split("\\n")[3:]:
                            for eachkv in re.findall(
                                r"^\ +url\d+\ \-\>\ (?P<URL>\S+)",
                                info,
                            ):
                                jsondict["URL"] = eachkv
                        if len(jsondict) > 6:
                            jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif (
                profile.split(" v.")[0].replace("\\n", "").strip("-")
                == "appcompatflags"
            ):
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.replace("\\\\n", "\\\\ n").split("\\n"):
                        for eachkv in re.findall(
                            r"^\ +(?P<File>[\S\ ]+)",
                            info.replace("\\\\ n", "\\\\n"),
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["RegistryHive"],
                                    jsondict["Plugin"],
                                    jsondict["PluginVer"],
                                    jsondict["PluginDesc"],
                                    jsondict["File"],
                                ) = (
                                    regart,
                                    profile.split(" v.")[0]
                                    .replace("\\n", "")
                                    .strip("-")
                                    .replace("Launching ", ""),
                                    profile.split(" v.")[1].split("\\n")[0],
                                    profile.split(" v.")[1]
                                    .split("\\n\\n")[0]
                                    .split("\\n")[1],
                                    kv[0],
                                )
                    if len(jsondict) > 4:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif (
                profile.split(" v.")[0].replace("\\n", "").strip("-")
                == "officedocs2010"
            ):
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    if len(eachinfo.replace("\\\\n", "\\\\ n").split("\\n")) > 2:
                        jsondict["RegistryKey"] = eachinfo.replace(
                            "\\\\n", "\\\\ n"
                        ).split("\\n")[1]
                        for info in eachinfo.replace("\\\\n", "\\\\ n").split("\\n")[
                            3:
                        ]:
                            if " not found." not in info and " located." not in info:
                                for eachkv in re.findall(
                                    r"^\ +Item\ \d+\ \-\>\ (?P<File>[^\.]+\.\S+)\ \ (?P<LastWriteTime>[\S\ ]+)",
                                    info,
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        (
                                            jsondict["RegistryHive"],
                                            jsondict["Plugin"],
                                            jsondict["PluginVer"],
                                            jsondict["PluginDesc"],
                                            jsondict["LastWriteTime"],
                                            jsondict["File"],
                                        ) = (
                                            artefact.split("/")[-1]
                                            .upper()
                                            .split("+")[1],
                                            profile.split(" v.")[0]
                                            .replace("\\n", "")
                                            .strip("-")
                                            .replace(
                                                "Launching ",
                                                "",
                                            ),
                                            profile.split(" v.")[1].split("\\n")[0],
                                            profile.split(" v.")[1]
                                            .split("\\n\\n")[0]
                                            .split("\\n")[1],
                                            kv[1],
                                            kv[0],
                                        )
                    if len(jsondict) > 6:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "cached":
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        for eachkv in re.findall(
                            r"^(?P<LastWriteTime>[\S\ ]+)\ \ First\ Load\:\ (?P<CachedShellExtGUID>\S+)\ (?P<CachedShellExtDescription>\S+)",
                            info,
                        ):
                            kv = list(eachkv)
                            if len(kv) > 0:
                                (
                                    jsondict["RegistryHive"],
                                    jsondict["Plugin"],
                                    jsondict["PluginVer"],
                                    jsondict["PluginDesc"],
                                    jsondict["CachedShellExtDescription"],
                                    jsondict["CachedShellExtGUID"],
                                    jsondict["LastWriteTime"],
                                ) = (
                                    regart,
                                    profile.split(" v.")[0]
                                    .replace("\\n", "")
                                    .strip("-")
                                    .replace("Launching ", ""),
                                    profile.split(" v.")[1].split("\\n")[0],
                                    profile.split(" v.")[1]
                                    .split("\\n\\n")[0]
                                    .split("\\n")[1],
                                    kv[2],
                                    kv[1],
                                    kv[0],
                                )
                    if len(jsondict) > 5:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "reveton":
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        if ": " in info or "LastWrite Time" in info:
                            for eachkv in re.findall(
                                r"^(?P<k>[^\:\=]+)(?:\:|\=| Time)\ (?P<v>[\S\ ]+)",
                                info,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    if "LastWrite" in kv[0]:
                                        (
                                            jsondict["RegistryHive"],
                                            jsondict["Plugin"],
                                            jsondict["PluginVer"],
                                            jsondict["PluginDesc"],
                                            jsondict[
                                                kv[0].replace(
                                                    "LastWrite",
                                                    "LastWriteTime",
                                                )
                                            ],
                                        ) = (
                                            artefact.split("/")[-1]
                                            .upper()
                                            .split("+")[1],
                                            profile.split(" v.")[0]
                                            .replace("\\n", "")
                                            .strip("-")
                                            .replace(
                                                "Launching ",
                                                "",
                                            ),
                                            profile.split(" v.")[1].split("\\n")[0],
                                            profile.split(" v.")[1]
                                            .split("\\n\\n")[0]
                                            .split("\\n")[1],
                                            kv[1],
                                        )
                                    else:
                                        jsondict["Assessment"] = kv[1].replace(".", "")
                    if len(jsondict) > 5:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "recentdocs":
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    for info in eachinfo.split("\\n"):
                        if "Software\\\\" in info:
                            jsondict["RecentDocsEntry"] = info
                        elif " = " in info or "LastWrite Time" in info:
                            for eachkv in re.findall(
                                r"^(?:\ +)?(?P<k>[^\:\=]+)\ (?:\:|\=|Time)\ (?P<v>[\S\ ]+)",
                                info,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    if "LastWrite" in kv[0]:
                                        (
                                            jsondict["RegistryHive"],
                                            jsondict["Plugin"],
                                            jsondict["PluginVer"],
                                            jsondict["PluginDesc"],
                                            jsondict[
                                                kv[0].replace(
                                                    "LastWrite",
                                                    "LastWriteTime",
                                                )
                                            ],
                                        ) = (
                                            artefact.split("/")[-1]
                                            .upper()
                                            .split("+")[1],
                                            profile.split(" v.")[0]
                                            .replace("\\n", "")
                                            .strip("-")
                                            .replace(
                                                "Launching ",
                                                "",
                                            ),
                                            profile.split(" v.")[1].split("\\n")[0],
                                            profile.split(" v.")[1]
                                            .split("\\n\\n")[0]
                                            .split("\\n")[1],
                                            kv[1],
                                        )
                                    elif "MRUListEx" not in kv[0]:
                                        (
                                            jsondict["RegistryHive"],
                                            jsondict["Plugin"],
                                            jsondict["PluginVer"],
                                            jsondict["PluginDesc"],
                                            jsondict["MRUEntryIndex"],
                                            jsondict["MRUEntry"],
                                        ) = (
                                            artefact.split("/")[-1]
                                            .upper()
                                            .split("+")[1],
                                            profile.split(" v.")[0]
                                            .replace("\\n", "")
                                            .strip("-")
                                            .replace(
                                                "Launching ",
                                                "",
                                            ),
                                            profile.split(" v.")[1].split("\\n")[0],
                                            profile.split(" v.")[1]
                                            .split("\\n\\n")[0]
                                            .split("\\n")[1],
                                            kv[0],
                                            kv[1],
                                        )
                    if len(jsondict) > 6:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "itempos":
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    if len(eachinfo.split("\\n")) > 2:
                        for info in eachinfo.split("\\n"):
                            if " not found." not in info:
                                if "Value: " in info:
                                    (
                                        jsondict["RegistryHive"],
                                        jsondict["Plugin"],
                                        jsondict["PluginVer"],
                                        jsondict["PluginDesc"],
                                        jsondict["FileValue"],
                                    ) = (
                                        regart,
                                        profile.split(" v.")[0]
                                        .replace("\\n", "")
                                        .strip("-")
                                        .replace("Launching ", ""),
                                        profile.split(" v.")[1].split("\\n")[0],
                                        profile.split(" v.")[1]
                                        .split("\\n\\n")[0]
                                        .split("\\n")[1],
                                        info.split(": ")[1],
                                    )
                                else:
                                    for eachkv in re.findall(
                                        r"^(?P<FileSize>\d+)\ +\|(?P<ModifiedTime>[\d\-\:\ ]+)\ \|(?P<AccessedTime>[\d\-\:\ ]+)\ \|(?P<CreatedTime>[\d\-\:\ ]+)\ \|(?P<Filename>[\S\ ]+)",
                                        info,
                                    ):
                                        kv = list(eachkv)
                                        if len(kv) > 0:
                                            (
                                                jsondict["Filename"],
                                                jsondict["FileSize"],
                                                jsondict["ModifiedTime"],
                                                jsondict["AccessedTime"],
                                                jsondict["CreatedTime"],
                                            ) = (
                                                kv[4],
                                                kv[0],
                                                kv[1],
                                                kv[2],
                                                kv[3],
                                            )
                    if len(jsondict) > 6:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "user_run":
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    if len(eachinfo.split("\\n")) > 1:
                        if "'  " in str(eachinfo.split("\\n")):
                            (
                                jsondict["RegistryKey"],
                                jsondict["Plugin"],
                                jsondict["PluginVer"],
                                jsondict["PluginDesc"],
                                jsondict["LastWriteTime"],
                            ) = (
                                regart,
                                profile.split(" v.")[0]
                                .replace("\\n", "")
                                .strip("-")
                                .replace("Launching ", ""),
                                profile.split(" v.")[1].split("\\n")[0],
                                profile.split(" v.")[1]
                                .split("\\n\\n")[0]
                                .split("\\n")[1],
                                eachinfo.split("\\n")[1].split("Time ")[1],
                            )
                            for info in eachinfo.split("\\n")[2:]:
                                for eachkv in re.findall(
                                    r"^\ \ (?P<FileDescription>[^\:]+)\:\ (?P<Filename>[^\.]+\.\w{3})(?:\ (?P<CommandParameters>[\S\ ]+))?",
                                    info.replace('"', ""),
                                ):
                                    kv = list(eachkv)
                                    if len(kv) > 0:
                                        (
                                            jsondict["FileDescription"],
                                            jsondict["Filename"],
                                            jsondict["CommandParameters"],
                                        ) = (
                                            kv[0],
                                            kv[1],
                                            kv[2],
                                        )
                    if len(jsondict) > 7:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "outlook2":
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    if len(eachinfo.split("\\n")) > 1:
                        for info in eachinfo.split("\\n"):
                            for eachkv in re.findall(
                                r"^(?:\_+|\ +)(?P<k>[A-Za-z\d\ \[\]]+)\:\ +(?P<v>[\S\ ]+)",
                                info,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    (
                                        jsondict["RegistryHive"],
                                        jsondict["Plugin"],
                                        jsondict["PluginVer"],
                                        jsondict["PluginDesc"],
                                        jsondict[kv[0]],
                                    ) = (
                                        regart,
                                        profile.split(" v.")[0]
                                        .replace("\\n", "")
                                        .strip("-")
                                        .replace("Launching ", ""),
                                        profile.split(" v.")[1].split("\\n")[0],
                                        profile.split(" v.")[1]
                                        .split("\\n\\n")[0]
                                        .split("\\n")[1],
                                        kv[1],
                                    )
                    if len(jsondict) > 5:
                        jsonlist.append(json.dumps(jsondict))
                jsondict.clear()
            elif profile.split(" v.")[0].replace("\\n", "").strip("-") == "mmc":
                if len(profile.split(" v.")[1].split("\\n\\n")[0]) > 8:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        profile.split(" v.")[1].split("\\n\\n")[0].split("\\n")[1],
                        regusr,
                    )
                else:
                    (
                        jsondict["RegistryHive"],
                        jsondict["Plugin"],
                        jsondict["PluginVer"],
                        jsondict["PluginDesc"],
                        jsondict["AccountProfile"],
                    ) = (
                        regart,
                        profile.split(" v.")[0]
                        .replace("\\n", "")
                        .strip("-")
                        .replace("Launching ", ""),
                        profile.split(" v.")[1].split("\\n")[0],
                        "",
                        regusr,
                    )
                for eachinfo in profile.split(" v.")[1].split("\\n\\n")[1:]:
                    if len(eachinfo.split("\\n")) > 3:
                        jsondict["LastWriteTime"] = eachinfo.split("\\n")[2].replace(
                            " Time", "Time"
                        )
                        for info in eachinfo.split("\\n")[3:]:
                            for eachkv in re.findall(
                                r"^\ +File\d+\ \-\>\ (?P<Filename>[\S]+)",
                                info,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    (
                                        jsondict["RegistryHive"],
                                        jsondict["Plugin"],
                                        jsondict["PluginVer"],
                                        jsondict["PluginDesc"],
                                        jsondict["Filename"],
                                    ) = (
                                        regart,
                                        profile.split(" v.")[0]
                                        .replace("\\n", "")
                                        .strip("-")
                                        .replace("Launching ", ""),
                                        profile.split(" v.")[1].split("\\n")[0],
                                        profile.split(" v.")[1]
                                        .split("\\n\\n")[0]
                                        .split("\\n")[1],
                                        kv[0],
                                    )
                        if len(jsondict) > 6:
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


def extract_registry_profile(
    output_directory,
    img,
    vss_path_insert,
    artefact,
    jsondict,
    jsonlist,
    regjsonlist,
    regusr,
    regart,
):
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "/registry/"
        + regusr
        + "+"
        + regart
        + ".json",
        "a",
    ) as regjson:
        rgrplistj = str(
            subprocess.Popen(
                [
                    "rip.pl",
                    "-r",
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/raw"
                    + vss_path_insert
                    + "/registry/"
                    + regusr
                    + "+"
                    + regart,
                    "-f",
                    regart.split(".")[0].lower(),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()[0]
        )[2:-1]
        jsonlist, regjsonlist = use_profile_plugins(
            artefact,
            jsondict,
            jsonlist,
            regjsonlist,
            rgrplistj,
            artefact.split("/")[-1].upper().split("+")[1],
            regusr,
        )
        if len(regjsonlist) > 0:
            regdata = (
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
            regdata = re.sub(
                r'(", "[^"]+": ")(LastWrite) ?(Time)(", ")([^"]+": ")([\d-]{10} [\d:]{8}Z?")',
                r'\1-\4\5-", "\2\3": "\6',
                regdata,
            )
            regjson.write(regdata)
        regjsonlist.clear()
        jsonlist.clear()
