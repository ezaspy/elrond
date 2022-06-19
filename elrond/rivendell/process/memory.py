#!/usr/bin/env python3 -tt
import os
import re
import shutil
import subprocess
import time
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.memory.profiles import identify_profile
from rivendell.memory.vol import (
    assess_volatility_choice,
)
from rivendell.memory.vol import (
    dump_vol3_ziphex,
)
from rivendell.memory.vol import (
    choose_custom_profile,
)
from rivendell.memory.volatility3.Linux import Linux
from rivendell.memory.volatility3.macOS1 import macOS1
from rivendell.memory.volatility3.macOS2 import macOS2


def process_memory(
    output_directory,
    verbosity,
    d,
    stage,
    img,
    artefact,
    volchoice,
    vss,
    vssmem,
    memtimeline,
):
    if artefact.endswith("hiberfil.sys"):
        memext = ".raw"
    else:
        memext = ""
    if stage == "processing":
        if "vss" in artefact:
            mempath, volprefix, vssimage = (
                artefact.split("/")[-5]
                + "/artefacts/cooked/"
                + artefact.split("/")[-2]
                + "/memory/",
                "      ",
                "'"
                + img.split("::")[0]
                + "' ("
                + img.split("::")[1]
                .split("_")[1]
                .replace("vss", "volume shadow copy #")
                + ")",
            )
        else:
            mempath, volprefix, vssimage = (
                img.split("::")[0].split("/")[-1] + "/artefacts/cooked/memory/",
                "      ",
                "'" + img.split("::")[0] + "'",
            )
    else:
        mempath, volprefix, vssimage = (
            artefact.split("/")[-1],
            "   ",
            "'" + img.split("::")[0] + "'",
        )
    if volchoice != "3":
        identify_profile(
            output_directory,
            verbosity,
            d,
            stage,
            vss,
            vssimage,
            volchoice,
            volprefix,
            mempath,
            memext,
            memtimeline,
        )
        profiledirs = []
        for eachfile in os.listdir(
            "/usr/local/lib/python2.7/dist-packages/volatility/plugins/overlays/mac/"
        ):
            if eachfile.endswith(".zip"):
                profiledirs.append(eachfile)
            else:
                pass
        for eachfile in os.listdir(
            "/usr/local/lib/python2.7/dist-packages/volatility/plugins/overlays/linux/"
        ):
            if eachfile.endswith(".zip"):
                profiledirs.append(eachfile)
            else:
                pass
        if len(profiledirs) > 0:
            deleteprofiles = input(
                "\tIt is not good practice to keep too many custom profiles in volatility as it can cause volatility to run extremely slowly\n\tWould you like to remove the following custom profiles?\n\t {}\t Y/n [Y] ".format(
                    str(profiledirs)[2:-2].replace("', '", "\n\t  ")
                )
            )
            if deleteprofiles != "n":
                for eachprofiledir in profiledirs:
                    if os.path.isdir(eachprofiledir):
                        shutil.rmtree(
                            "/usr/lib/python2.7/dist-packages/volatility/plugins/overlays/linux/"
                            + eachprofiledir
                        )
                    else:
                        os.remove(
                            "/usr/lib/python2.7/dist-packages/volatility/plugins/overlays/linux/"
                            + eachprofiledir
                        )
            else:
                pass
        else:
            pass
        vssmem = profile
    else:
        if artefact.endswith("hiberfil.sys"):
            identify_profile(
                output_directory,
                verbosity,
                d,
                stage,
                vss,
                vssimage,
                volchoice,
                volprefix,
                mempath,
                memext,
                memtimeline,
            )
        else:
            pass
        vol3oscheck = str(
            subprocess.Popen(
                [
                    "python3",
                    "/usr/local/lib/python3.8/dist-packages/volatility3/vol.py",
                    "-f",
                    artefact + memext,
                    "windows.info.Info",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()[0]
        )[2:-1]
        if (
            "Windows" in vol3oscheck
            and "windows" in vol3oscheck
            and "ntkrnl" in vol3oscheck
        ):
            profile, profileplatform = "Windows", "Windows"
        else:
            profile, ziphexdump1, ziphexdump2 = "macOS", macOS1(), macOS2()
            dump_vol3_ziphex(d, profile, ziphexdump1 + ziphexdump2)
            vol3oscheck = str(
                subprocess.Popen(
                    [
                        "python3",
                        "/usr/local/lib/python3.8/dist-packages/volatility3/vol.py",
                        "-f",
                        artefact + memext,
                        "mac.list_files.List_Files",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[0]
            )[2:-1]
            if "MacOS" in vol3oscheck and "/System/Library/" in vol3oscheck:
                profileplatform = "macOS"
            else:
                profile, ziphexdump = "Linux", Linux()
                dump_vol3_ziphex(d, profile, ziphexdump)
                profileplatform = "Linux"
                vol3oscheck = str(
                    subprocess.Popen(
                        [
                            "python3",
                            "/usr/local/lib/python3.8/dist-packages/volatility3/vol.py",
                            "-f",
                            artefact + memext,
                            "linux.elfs.Elfs",
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[0]
                )[2:-1]
                if "linux" in vol3oscheck and "sudo" in vol3oscheck:
                    pass
                else:
                    print(
                        "    elrond has assessed that '{}' has likely originated from a Linux host and the symbol table is not currently imported.\n    You will need to create your own symbol table. More information is provided in SUPPORT.md\n    Once you have created the symbol table and placed it in the correct directory (.../volatility3/volatility3/symbols/linux/), return to elrond.".format(
                            artefact
                        )
                    )
                    time.sleep(10)
                    profile = choose_custom_profile(volchoice)
        if os.path.exists(
            "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/__pycache__"
        ):
            shutil.rmtree(
                "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/__pycache__"
            )
        else:
            pass
        if os.path.exists(
            "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/__MACOSX"
        ):
            shutil.rmtree(
                "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/__MACOSX"
            )
        else:
            pass
        entry, prnt = "{},identification,{},{} ({})\n".format(
            datetime.now().isoformat(),
            artefact.split("/")[-1],
            profileplatform,
            profile,
        ), " -> {} -> identified platform as '{}' for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            profileplatform,
            artefact.split("/")[-1],
        )
        print(
            "   Identified platform of '{}' for '{}'.".format(
                profile, artefact.split("/")[-1]
            )
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        assess_volatility_choice(
            verbosity,
            output_directory,
            volchoice,
            volprefix,
            artefact,
            profile,
            mempath,
            memext,
            vssimage,
            memtimeline,
        )
    return profile, vssmem
