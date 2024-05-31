#!/usr/bin/env python3 -tt
import json
import os
import re
import subprocess
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.memory.volatility.plugins.vol_lin import linux_vol
from rivendell.memory.volatility.plugins.vol_mac import mac_vol
from rivendell.memory.volatility.plugins.vol_win import windows_vol
from rivendell.memory.volatility3.plugins.vol3_lin import linux_vol3
from rivendell.memory.volatility3.plugins.vol3_mac import macos_vol3
from rivendell.memory.volatility3.plugins.vol3_win import windows_vol3


def use_plugins(
    output_directory,
    verbosity,
    vssimage,
    artefact,
    volver,
    memext,
    mempath,
    profile,
    plugin,
):
    if not os.path.exists(output_directory + mempath + "/memory_" + plugin + ".json"):
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
                jsonlist = windows_vol3(
                    output_directory,
                    mempath,
                    volver,
                    profile,
                    symbolorprofile,
                    plugin,
                    plugoutlist,
                    jsondict,
                    jsonlist,
                )
            elif (
                "macOS" in profile
                or profile.startswith("Mac")
                or profile.startswith("mac")
                or profile.startswith("11.")
                or profile.startswith("10.")
            ):
                jsonlist = macos_vol3(
                    volver,
                    profile,
                    symbolorprofile,
                    plugin,
                    plugoutlist,
                    jsondict,
                    jsonlist,
                )
            else:
                jsonlist = linux_vol3(
                    volver,
                    profile,
                    symbolorprofile,
                    plugin,
                    plugoutlist,
                    jsondict,
                    jsonlist,
                )
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
                            jsonlist.append(json.dumps(jsondict))
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
                jsonlist = windows_vol(
                    volver,
                    profile,
                    symbolorprofile,
                    plugin,
                    plugoutlist,
                    jsondict,
                    jsonlist,
                    voldict,
                    vollist,
                )
            elif (
                "macOS" in profile
                or profile.startswith("Mac")
                or profile.startswith("mac")
                or profile.startswith("11.")
                or profile.startswith("10.")
            ):
                jsonlist = mac_vol(
                    volver,
                    profile,
                    symbolorprofile,
                    plugin,
                    plugoutlist,
                    jsondict,
                    jsonlist,
                )
            else:
                jsonlist = linux_vol(
                    volver,
                    profile,
                    symbolorprofile,
                    plugin,
                    plugoutlist,
                    jsondict,
                    jsonlist,
                )
        for eachjson in jsonlist:
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
                .replace("LoadTime", "LastWriteTime")
            )
            if "Win" in profile:
                if (
                    ', "ProcessName"' in eachjson
                    and ', "CommandLine"' in eachjson
                    and ', "ShellFolderPath"' in eachjson
                ) or (
                    '{ProcessName"' in eachjson
                    and '{"CommandLine"' in eachjson
                    and '{"ShellFolderPath"' in eachjson
                ):
                    insert = ', "Process{}, "Command{}, "Registry{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"ProcessName(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"CommandLine(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"ShellFolderPath(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif (
                    ', "ProcessName"' in eachjson
                    and ', "CommandLine"' in eachjson
                    and ', "RegistryKey"' in eachjson
                ) or (
                    '{"ProcessName"' in eachjson
                    and '{"CommandLine"' in eachjson
                    and '{"RegistryKey"' in eachjson
                ):
                    insert = ', "Process{}, "Command{}, "Registry{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"ProcessName(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"CommandLine(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"RegistryKey(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif (', "ProcessName"' in eachjson and ', "Path"' in eachjson) or (
                    '{"ProcessName"' in eachjson and '{"Path"' in eachjson
                ):
                    insert = ', "Process{}, "Command{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"ProcessName(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"Path(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif (
                    ', "ProcessName"' in eachjson and ', "CommandLine"' in eachjson
                ) or ('{"ProcessName"' in eachjson and '{"CommandLine"' in eachjson):
                    insert = ', "Process{}, "Command{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"ProcessName(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"CommandLine(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif (
                    ', "ProcessName"' in eachjson and ', "ShellFolderPath"' in eachjson
                ) or (
                    '{"ProcessName"' in eachjson and '{"ShellFolderPath"' in eachjson
                ):
                    insert = ', "Process{}, "Registry{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"ProcessName(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"ShellFolderPath(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif (
                    ', "ProcessName"' in eachjson and ', "RegistryKey"' in eachjson
                ) or ('{"ProcessName"' in eachjson and '{"RegistryKey"' in eachjson):
                    insert = ', "Process{}, "Registry{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"ProcessName(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"RegistryKey(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif (
                    ', "Path"' in eachjson
                    and ', "CommandLine"' in eachjson
                    and ', "RegistryKey"' in eachjson
                ) or (
                    '{"Path"' in eachjson
                    and '{"CommandLine"' in eachjson
                    and '{"RegistryKey"' in eachjson
                ):
                    insert = ', "Process{}, "Command{}, "Registry{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"Path(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"CommandLine(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"RegistryKey(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif (', "Path"' in eachjson and ', "CommandLine"' in eachjson) or (
                    '{"Path"' in eachjson and '{"CommandLine"' in eachjson
                ):
                    insert = ', "Process{}, "Command{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"Path(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"CommandLine(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif (', "Path"' in eachjson and ', "ShellFolderPath"' in eachjson) or (
                    '{"Path"' in eachjson and '{"ShellFolderPath"' in eachjson
                ):
                    insert = ', "Process{}, "Registry{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"Path(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"ShellFolderPath(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif (
                    ', "CommandLine"' in eachjson and ', "RegistryKey"' in eachjson
                ) or ('{"CommandLine"' in eachjson and '{"RegistryKey"' in eachjson):
                    insert = ', "Command{}, "Registry{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"CommandLine(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"RegistryKey(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif ', "ProcessName"' in eachjson or '{"ProcessName"' in eachjson:
                    insert = ', "Process{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"ProcessName(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_")
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif ', "Path"' in eachjson or '{"Path"' in eachjson:
                    insert = ', "Process{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"Path(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_")
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif ', "CommandLine"' in eachjson or '{"CommandLine"' in eachjson:
                    insert = ', "Command{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"CommandLine(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_")
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif (
                    ', "ShellFolderPath"' in eachjson
                    or '{"ShellFolderPath"' in eachjson
                ):
                    insert = ', "Registry{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"ShellFolderPath(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_")
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif ', "RegistryKey"' in eachjson or '{"RegistryKey"' in eachjson:
                    insert = ', "Registry{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"RegistryKey(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_")
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                else:
                    voljsonlist.append(json.dumps(eachjson))
            else:
                if (
                    '", "ProcessName"' in eachjson and '", "CommandLine"' in eachjson
                ) or ('{"ProcessName"' in eachjson and '{"CommandLine"' in eachjson):
                    insert = ', "Process{}, "Command{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"ProcessName(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"CommandLine(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif ('", "Path"' in eachjson and '", "CommandLine"' in eachjson) or (
                    '{"Path"' in eachjson and '{"CommandLine"' in eachjson
                ):
                    insert = ', "Process{}, "Command{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"Path(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"CommandLine(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif ('", "ProcessName"' in eachjson and '", "Path"' in eachjson) or (
                    '{"ProcessName"' in eachjson and '{"Path"' in eachjson
                ):
                    insert = ', "Process{}, "Command{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"ProcessName(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                        str(
                            str(
                                re.findall(
                                    r"Path(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_"),
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif '", "ProcessName"' in eachjson or '{"ProcessName"' in eachjson:
                    insert = ', "Process{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"ProcessName(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_")
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif '", "Path"' in eachjson or '{"Path"' in eachjson:
                    insert = ', "Process{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"Path(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_")
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                elif '", "CommandLine"' in eachjson or '{"CommandLine"' in eachjson:
                    insert = ', "Command{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"CommandLine(\": \"(?:(?:[^\"]+\")|(?:[^']+')|(?:[^\,]+,)))",
                                    eachjson,
                                )[0]
                            ).lower()
                        ).replace(" ", "_")
                    )
                    voljsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                else:
                    voljsonlist.append(json.dumps(eachjson))
        if len(voljsonlist) > 0:
            with open(
                output_directory + mempath + "/" + plugin + ".json", "w"
            ) as voljson:
                vol_data = re.sub(
                    r'("[^"]+": \[\{"[^"]+": "[^"]+", "[^\{\]]+\})(, \{"VolatilityVersion")',
                    r"\1]}\2",
                    re.sub(
                        r'(\[\{"[^\[\]]+\})(, \{"VolatilityVersion": ")',
                        r"\1}]\2",
                        re.sub(
                            r'("\}\])"(\}\]$)',
                            r"\1\2",
                            re.sub(
                                r'(\[\{"[^\[\]]+\})(, \{"VolatilityVersion": ")',
                                r"\1}]\2",
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
                                .replace('"----------"', "--")
                                .replace('"--------"', "--")
                                .replace('"------"', "--")
                                .replace('"----"', "--")
                                .replace('""', '"')
                                .replace('", ", "', '", "')
                                .replace('": "-", "\\"', '": "')
                                .replace('": "; ,  ', '": "-", "')
                                .replace('": --, "', '": "--", "')
                                .replace('": ", "', '": "--", "')
                                .replace(', "', '", "')
                                .replace('""', '"')
                                .replace('"}]", "', '"}], "')
                                .replace('\\"}, {"', '}", {"')
                                .replace('\\", ",', '",')
                                .replace('}",', '"},')
                                .replace(',}, {"', '"}, {"')
                                .replace(', ", "', '", "')
                                .replace(",}, {", '"}, {')
                                .replace('": "}, {"', '": "-"}, {"')
                                .replace('}, {"', '"}, {"')
                                .replace('""', '"')
                                .replace('"}]}]", "', '"}]}], "')
                                .replace('"}, "', '"}, {"')
                                .replace('\\", \\"\\"]", "', '", "')
                                .replace('""', '"')
                                .replace('\\",_\\"\\"]}', '"}')
                                .replace('"}]"}, {"', '"}, {"')
                                .replace('"}, "', '"}, {"')
                                .replace('": "}]', '": ""}]')
                                .replace('"}]"}, {"', '"}]}, {"')
                                .replace("}]", '"}]')
                                .replace('""', '"')
                                .replace('"}]", "', '"}], "'),
                            ),
                        )
                        .replace('"}}], {"', '"}, {"')
                        .replace('",", "', '", "')
                        .replace('"}]"}], "', '"}]}], "'),
                    )
                    .replace('": ""]", "', '": "-", "')
                    .replace('"}}], {"', '"}, {"')
                    .replace('": ""]", "', '": "-", "'),
                ).replace('\\", "', '", "')
                vol_data = re.sub(
                    r'(, "ControlFlags": \[[^\[]+"\})(, \{"VolatilityVersion)',
                    r"\1]}\2",
                    str(vol_data),
                )
                voljson.write(vol_data)
            entry, prnt = "{},{},extracted {},{} ({})\n".format(
                datetime.now().isoformat(),
                vssimage,
                plugin,
                artefact.split("/")[-1],
                profile,
            ), " -> {} -> extracted evidence of '{}' from {}".format(
                datetime.now().isoformat().replace("T", " "),
                plugin,
                vssimage,
            )
            write_audit_log_entry(
                verbosity, output_directory, entry, prnt
            )  # evidence of plugin found
        else:
            entry, prnt = "{},{},no evidence of {},{} ({})\n".format(
                datetime.now().isoformat(),
                vssimage,
                plugin,
                artefact.split("/")[-1],
                profile,
            ), " -> {} -> no evidence of '{}' from {}".format(
                datetime.now().isoformat().replace("T", " "),
                plugin,
                vssimage,
            )
            write_audit_log_entry(
                verbosity, output_directory, entry, prnt
            )  # no evidence of plugin
        jsonlist.clear()
