#!/usr/bin/env python3 -tt
import json
import os
import re
import subprocess

from rivendell.memory.volatility.plugins.linux import linux_vol
from rivendell.memory.volatility.plugins.macos import mac_vol
from rivendell.memory.volatility.plugins.windows import windows_vol
from rivendell.memory.volatility3.plugins.linux import linux_vol3
from rivendell.memory.volatility3.plugins.macos import macos_vol3
from rivendell.memory.volatility3.plugins.windows import windows_vol3


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
                    windows_vol3(
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
                    macos_vol3(
                        volver,
                        profile,
                        symbolorprofile,
                        plugin,
                        plugoutlist,
                        jsondict,
                        jsonlist,
                    )
                else:
                    linux_vol3(
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
                    windows_vol(
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
                    mac_vol(
                        volver,
                        profile,
                        symbolorprofile,
                        plugin,
                        plugoutlist,
                        jsondict,
                        jsonlist,
                    )
                else:
                    linux_vol(
                        volver,
                        profile,
                        symbolorprofile,
                        plugin,
                        plugoutlist,
                        jsondict,
                        jsonlist,
                    )
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
