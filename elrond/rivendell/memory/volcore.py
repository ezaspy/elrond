#!/usr/bin/env python3 -tt
import os
import random
import re
import shutil
import subprocess
import time
from zipfile import ZipFile

from rivendell.memory.plugins import (
    extract_memory_artefacts,
)
from rivendell.memory.volatility.CentOS73 import CentOS73
from rivendell.memory.volatility.Debian94 import Debian94
from rivendell.memory.volatility.macOS10126 import (
    macOS10126,
)
from rivendell.memory.volatility.macOS10136 import (
    macOS10136,
)
from rivendell.memory.volatility.RHELServer59 import (
    RHELServer59,
)
from rivendell.memory.volatility.RHELServer67 import (
    RHELServer67,
)
from rivendell.memory.volatility.Ubuntu16045 import (
    Ubuntu16045,
)
from rivendell.memory.volatility.Ubuntu18043 import (
    Ubuntu18043,
)


def assess_volatility_choice(
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
):
    if volchoice == "2.6":
        profile, vssmem = extract_memory_artefacts(
            verbosity,
            output_directory,
            "2.6",
            volprefix,
            artefact,
            profile,
            mempath,
            memext,
            vssimage,
            memtimeline,
            "volatility2.6",
        )
    elif volchoice == "3":
        profile, vssmem = extract_memory_artefacts(
            verbosity,
            output_directory,
            "3",
            volprefix,
            artefact,
            profile,
            mempath,
            memext,
            vssimage,
            memtimeline,
            "volatility3",
        )
    else:
        profile, vssmem = extract_memory_artefacts(
            verbosity,
            output_directory,
            "2.6",
            volprefix,
            artefact,
            profile,
            mempath,
            memext,
            vssimage,
            memtimeline,
            "volatility2.6",
        )
        profile, vssmem = extract_memory_artefacts(
            verbosity,
            output_directory,
            "3",
            volprefix,
            artefact,
            profile,
            mempath,
            memext,
            vssimage,
            memtimeline,
            "volatility3",
        )
    return profile, vssmem


def select_profile(volchoice, artefact):
    ziphexdump = ""
    profileselect = input(
        "\t   1) Win10x64_15063\t    2) Win10x86_15063\t  3) Win10x64_14393\t  4) Win10x86_14393\t  5) Win10x64_10586\t  6) Win10x86_10586\n\t   7) Win8SP1x64_18340\t    8) Win7SP1x64_24000\t  9) Win7SP1x86_24000\t 10) Win7SP1x64_23418\t 11) Win7SP1x86_23418\n\t  12) Win2012R2x64_18340   13) Win2008R2SP1x64_23418\n\t  14) macOS10.13.6\t   15) macOS10.12.6\n\t  16) RHELServer6.7x64\t   17) RHELServer5.9x64\t 18) CentOS7.3x64\n\t  19) Ubuntu18.04.3x64\t   20) Ubuntu16.04.5x64\t 21) Debian9.4x64\n\t  22) Custom macOS/Linux profile\t\t\t "
    )
    if (
        profileselect == "1"
        or profileselect == "2"
        or profileselect == "3"
        or profileselect == "4"
        or profileselect == "5"
        or profileselect == "6"
        or profileselect == "3"
        or profileselect == "4"
        or profileselect == "7"
        or profileselect == "8"
        or profileselect == "9"
        or profileselect == "10"
        or profileselect == "11"
        or profileselect == "12"
        or profileselect == "13"
        or profileselect == "14"
        or profileselect == "15"
        or profileselect == "16"
        or profileselect == "17"
        or profileselect == "18"
        or profileselect == "19"
        or profileselect == "20"
        or profileselect == "21"
        or profileselect == "22"
    ):
        if profileselect == "1":
            profile = "Win10x64_15063"
        elif profileselect == "2":
            profile = "Win10x86_15063"
        elif profileselect == "3":
            profile = "Win10x64_14393"
        elif profileselect == "4":
            profile = "Win10x86_14393"
        elif profileselect == "5":
            profile = "Win10x64_10586"
        elif profileselect == "6":
            profile = "Win10x86_10586"
        elif profileselect == "7":
            profile = "Win8SP1x64_18340"
        elif profileselect == "8":
            profile = "Win7SP1x64_24000"
        elif profileselect == "9":
            profile = "Win7SP1x86_24000"
        elif profileselect == "10":
            profile = "Win7SP1x64_23418"
        elif profileselect == "11":
            profile = "Win7SP1x86_23418"
        elif profileselect == "12":
            profile = "Win2012R2x64_18340"
        elif profileselect == "13":
            profile = "Win2008R2SP1x64_23418"
        elif profileselect == "14":
            profile = "macOS10.13.6"
            ziphexdump = macOS10136()
        elif profileselect == "15":
            profile = "macOS10.12.6"
            ziphexdump = macOS10126()
        elif profileselect == "16":
            profile = "LinuxRHELServer67x64"
            ziphexdump = RHELServer67()
        elif profileselect == "17":
            profile = "LinuxRHELServer59x64"
            ziphexdump = RHELServer59()
        elif profileselect == "18":
            profile = "LinuxCentOS73x64"
            ziphexdump = CentOS73()
        elif profileselect == "19":
            profile = "LinuxUbuntu18043x64"
            ziphexdump = Ubuntu18043()
        elif profileselect == "20":
            profile = "LinuxUbuntu16045x64"
            ziphexdump = Ubuntu16045()
        elif profileselect == "21":
            profile = "Debian94x64"
            ziphexdump = Debian94()
        else:
            print(
                "\tOK. You will need to now create your own profile. More information is provided in SUPPORT.md\n\tOnce you have created the profile and placed it in the respective directory (.../volatility/plugins/overlays/[mac|linux]/), return to elrond."
            )
            time.sleep(10)
            profile = choose_custom_profile(volchoice)
    else:
        print("\tInvalid selection, please try again.\n")
        select_profile(volchoice, artefact)
    return profileselect, profile, ziphexdump


def dump_vol3_ziphex(d, profile, ziphexdump):
    with open(d + "/..profile.hex", "w") as profilehex:
        profilehex.write(ziphexdump)
    subprocess.call(
        [
            "xxd",
            "-plain",
            "-revert",
            d + "/..profile.hex",
            d + "/.profile.zip",
        ]
    )  # produce hexdump: xxd -p <file_name>
    if profile == "macOS":
        osdir = "mac"
    else:
        osdir = "linux"
    if not os.path.exists(
        "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/"
        + osdir
    ):
        with ZipFile(d + "/.profile.zip") as vol3_symbols:
            vol3_symbols.extractall(
                "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/"
            )
    os.remove(d + "/..profile.hex")
    os.remove(d + "/.profile.zip")


def dump_nix_ziphex(d, profileselect, profile, ziphexdump):
    if profileselect != "22":  # number of Other/Custom option in profile selection
        if profile.startswith("mac") or profile.startswith("Mac"):
            if not os.path.exists(
                "/usr/lib/python2.7/dist-packages/volatility/plugins/overlays/mac/"
                + profile.split("OS")[1]
                + "/"
            ):
                os.makedirs(
                    "/usr/lib/python2.7/dist-packages/volatility/plugins/overlays/mac/"
                    + profile.split("OS")[1]
                    + "/"
                )
                with open(d + "/..profile.hex", "w") as profilehex:
                    profilehex.write(ziphexdump)
                subprocess.call(
                    [
                        "xxd",
                        "-plain",
                        "-revert",
                        d + "/..profile.hex",
                        d + "/.profile.zip",
                    ]
                )  # produce hexdump: xxd -p <file_name>
                os.remove(d + "/..profile.hex")
                shutil.move(
                    d + "/.profile.zip",
                    "/usr/lib/python2.7/dist-packages/volatility/plugins/overlays/mac/"
                    + profile.split("OS")[1]
                    + "/"
                    + profile
                    + ".zip",
                )
                if os.path.exists("./__MACOSX"):
                    os.remove(d + "/.profile.zip")
        elif (
            profile.startswith("Linux")
            or profile.startswith("linux")
            or profile.startswith("RHEL")
            or profile.startswith("rhel")
            or profile.startswith("RedHat")
            or profile.startswith("CentOS")
            or profile.startswith("centos")
            or profile.startswith("Ubuntu")
            or profile.startswith("ubuntu")
            or profile.startswith("Debian")
            or profile.startswith("debian")
        ):
            if not os.path.exists(
                "/usr/lib/python2.7/dist-packages/volatility/plugins/overlays/linux/"
                + profile.split("inux")[1]
                + "/"
            ):
                os.makedirs(
                    "/usr/lib/python2.7/dist-packages/volatility/plugins/overlays/linux/"
                    + profile.split("inux")[1]
                    + "/"
                )
                with open(d + "/..profile.hex", "w") as profilehex:
                    profilehex.write(ziphexdump)
                subprocess.call(
                    [
                        "xxd",
                        "-plain",
                        "-revert",
                        d + "/..profile.hex",
                        d + "/.profile.zip",
                    ]
                )  # produce hexdump: xxd -p <file_name>
                os.remove(d + "/..profile.hex")
                shutil.move(
                    d + "/.profile.zip",
                    "/usr/lib/python2.7/dist-packages/volatility/plugins/overlays/linux/"
                    + profile.split("inux")[1]
                    + "/"
                    + profile
                    + ".zip",
                )
        if os.path.exists(d + "/..profile.hex"):
            os.remove(d + "/..profile.hex")
        if os.path.exists(d + "/.profile.zip"):
            os.remove(d + "/.profile.zip")


def choose_custom_profile(volchoice):
    customready, waitingquotes = input("     Ready? Yes(Y)/No(N)/Skip(S) [Y] "), [
        "Ready when you are",
        "Take you time",
        "No rush",
        "No pressure",
        "Standing by",
        "Awaiting input",
    ]
    if volchoice == "3":
        symbolorprofile, pattern = "symbol table", re.compile(
            r"\ [^\ ]+\ [A-Z][a-z]{2}\ [\d\ +]{2}\ [^\ ]+\ (.*)\.json",
            re.IGNORECASE,
        )
        imported = str(
            re.findall(
                pattern,
                str(
                    subprocess.Popen(
                        [
                            "ls",
                            "-lah",
                            "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/",
                            "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/windows/ntkrpamp.pdb/",
                            "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/windows/tcpip.pdb/",
                            "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/mac/",
                            "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/linux/",
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[0]
                ),
            )
        ).replace(".json.xz", "")
    else:
        symbolorprofile, pattern = "profile", re.compile(
            r"\w([^\\]+\w)\s+\-\sA Profile for (?:Mac|Linux)\s[^\s]+", re.IGNORECASE
        )
        imported = re.findall(
            pattern,
            str(
                subprocess.Popen(
                    ["vol.py", "--info"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[0]
            ),
        )
    if customready != "Y" and customready != "N" and customready != "S":
        print("Invalid selection. You can select either Yes (Y), No (N) or Skip (S).")
        choose_custom_profile(volchoice)
    else:
        if customready == "N":
            print("    OK. {}...".format(random.choice(waitingquotes)))
            time.sleep(5)
            choose_custom_profile(volchoice)
        elif customready == "Y":
            customsymbolorprofile = process_custom_profile(
                imported, symbolorprofile, " you have just created:"
            )
            if "windows" in customsymbolorprofile:
                profileplatform = "Windows"
            elif "mac" in customsymbolorprofile:
                profileplatform = "macOS"
            else:
                profileplatform = "Linux"
            customprofile = "{}::{}".format(customsymbolorprofile, profileplatform)
        else:
            customprofile = "SKIPPED"
    return customprofile


def process_custom_profile(imported, symbolorprofile, customprofileinsert):
    if customprofileinsert != "":
        customsymbolorprofile = input(
            "    If importing a Windows symbol table, enter 'Windows' otherwise please provide the name of the custom {}{} ".format(
                symbolorprofile, customprofileinsert
            )
        )
        if customsymbolorprofile != "Windows" and customsymbolorprofile not in str(
            imported
        ):
            print(
                "      Invalid {}. This {} does not match any which have been imported into volatility.".format(
                    symbolorprofile, symbolorprofile
                )
            )
            if len(imported) > 0:
                print(
                    "       These are the currently imported and selectable {}s: {}".format(
                        symbolorprofile, str(imported)[2:-2].replace("'", "")
                    )
                )
            else:
                print(
                    "      No valid {}s have been imported into volatility, please try again...".format(
                        symbolorprofile
                    )
                )
            customsymbolorprofile = process_custom_profile(
                imported, symbolorprofile, ":"
            )
    return customsymbolorprofile
