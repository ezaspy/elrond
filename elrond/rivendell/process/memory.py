#!/usr/bin/env python3 -tt
import os
import random
import re
import shutil
import subprocess
import time
from datetime import datetime
from zipfile import ZipFile

from rivendell.audit import write_audit_log_entry
from rivendell.memory.extract import (
    extract_memory_artefacts,
)
from rivendell.memory.profiles import (
    suggest_volatility_profile,
)
from rivendell.memory.profiles import convert_memory_image
from rivendell.memory.volatility3.Linux import Linux
from rivendell.memory.volatility3.macOS1 import macOS1
from rivendell.memory.volatility3.macOS2 import macOS2
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
    def choose_custom_profile(volchoice):
        def process_custom_profile(imported, symbolorprofile, customprofileinsert):
            customsymbolorprofile = input(
                "    Please provide the name of the custom {}{} ".format(
                    symbolorprofile, customprofileinsert
                )
            )
            if customsymbolorprofile not in str(imported):
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
            else:
                pass
            return customsymbolorprofile

        customready, waitingquotes = input("     Ready? Y/n [Y] "), [
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
            imported = re.findall(
                pattern,
                str(
                    subprocess.Popen(
                        [
                            "ls",
                            "-lah",
                            "/usr/local/lib/python3.8/dist-packages/volatility3/volatility3/symbols/linux/",
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[0]
                ),
            )
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
        if customready == "n":
            print("    OK. {}...".format(random.choice(waitingquotes)))
            time.sleep(10)
            choose_custom_profile(volchoice)
        else:
            customsymbolorprofile = process_custom_profile(
                imported, symbolorprofile, " you have just created:"
            )
        return customsymbolorprofile

    if artefact.endswith("hiberfil.sys"):
        memext = ".raw"
    else:
        memext = ""
    if stage == "processing":
        if "vss" in artefact:
            mempath, volprefix, vssimage, vsstext = (
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
                " ("
                + img.split("::")[1]
                .split("_")[1]
                .replace("vss", "volume shadow copy #")
                + ")",
            )
        else:
            mempath, volprefix, vssimage, vsstext = (
                img.split("::")[0].split("/")[-1] + "/artefacts/cooked/memory/",
                "      ",
                "'" + img.split("::")[0] + "'",
                "",
            )
    else:
        mempath, volprefix, vssimage, vsstext = (
            artefact.split("/")[-1],
            "   ",
            "'" + img.split("::")[0] + "'",
            "",
        )
    if volchoice == "3" and not artefact.endswith("hiberfil.sys"):
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

            def doVol3ziphexdump(d, profile, ziphexdump):
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
                else:
                    pass
                os.remove(d + "/..profile.hex")
                os.remove(d + "/.profile.zip")

            profile, ziphexdump1, ziphexdump2 = "macOS", macOS1(), macOS2()
            doVol3ziphexdump(d, profile, ziphexdump1 + ziphexdump2)
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
                doVol3ziphexdump(d, profile, ziphexdump)
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
                        "    elrond has detected this memory image as having originated from a Linux host where the symbol table is not currently imported. You will need to create your own symbol table. More information is provided in SUPPORT.md\n    Once you have created the symbol table and placed it in the correct directory (.../volatility3/volatility3/symbols/linux/), return to elrond."
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
        extract_memory_artefacts(
            verbosity,
            output_directory,
            volchoice,
            volprefix,
            artefact,
            profile,
            mempath,
            memext,
            vssimage,
            vsstext,
            memtimeline,
        )
    else:
        profiles = re.findall(
            r"Suggested Profile\(s\) \: (?P<profiles>[\S\ ]+)",
            str(
                subprocess.Popen(
                    ["vol.py", "-f", os.path.realpath(artefact), "imageinfo"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[0]
            ),
        )
        if "Win" in profiles[0]:
            if vss:
                if (
                    vssmem != "" and len(vssmem) != 0
                ):  # vss invoked - processing volume shadow copies
                    if stage == "processing":
                        convert_memory_image(
                            verbosity,
                            output_directory,
                            stage,
                            artefact,
                            profile,
                            profiles,
                            volchoice,
                            volprefix,
                            mempath,
                            memext,
                            vssimage,
                            vsstext,
                            memtimeline,
                        )
                        print(
                            "      Conversion of '{}' memory file complete.".format(
                                artefact.split("/")[-1]
                            )
                        )
                    else:
                        pass
                    profile, vssmem = extract_memory_artefacts(
                        verbosity,
                        output_directory,
                        stage,
                        volchoice,
                        volprefix,
                        artefact,
                        vssmem,
                        mempath,
                        memext,
                        vssimage,
                        vsstext,
                        memtimeline,
                    )
                else:  # vss invoked - processing original disk image
                    profiles, artefact, profile = suggest_volatility_profile(
                        verbosity,
                        output_directory,
                        stage,
                        profiles,
                        artefact,
                        volchoice,
                        volprefix,
                        mempath,
                        memext,
                        vssimage,
                        vsstext,
                        memtimeline,
                    )
                    if stage == "processing":
                        convert_memory_image(
                            verbosity,
                            output_directory,
                            stage,
                            artefact,
                            profile,
                            profiles,
                            volchoice,
                            volprefix,
                            mempath,
                            memext,
                            vssimage,
                            vsstext,
                            memtimeline,
                        )
                        print(
                            "      Conversion of '{}' memory file complete.".format(
                                artefact.split("/")[-1]
                            )
                        )
                    else:
                        pass
                    profile, vssmem = extract_memory_artefacts(
                        verbosity,
                        output_directory,
                        volchoice,
                        volprefix,
                        artefact,
                        profile,
                        mempath,
                        memext,
                        vssimage,
                        vsstext,
                        memtimeline,
                    )
            else:  # vss not invoked or N/A
                profiles, artefact, profile = suggest_volatility_profile(
                    verbosity,
                    output_directory,
                    stage,
                    profiles,
                    artefact,
                    volchoice,
                    volprefix,
                    mempath,
                    memext,
                    vssimage,
                    vsstext,
                    memtimeline,
                )
                if stage == "processing":
                    convert_memory_image(
                        verbosity,
                        output_directory,
                        stage,
                        artefact,
                        profile,
                        profiles,
                        volchoice,
                        volprefix,
                        mempath,
                        memext,
                        vssimage,
                        vsstext,
                        memtimeline,
                    )
                    print(
                        "      Conversion of '{}' memory file complete.".format(
                            artefact.split("/")[-1]
                        )
                    )
                else:
                    pass
                extract_memory_artefacts(
                    verbosity,
                    output_directory,
                    volchoice,
                    volprefix,
                    artefact,
                    profile,
                    mempath,
                    memext,
                    vssimage,
                    vsstext,
                    memtimeline,
                )
        else:

            def doProfile(volchoice, artefact):
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
                    doProfile(volchoice, artefact)
                return profileselect, profile, ziphexdump

            def doNixProfileDump(d, profileselect, profile, ziphexdump):
                if (
                    profileselect != "22"
                ):  # number of Other/Custom option in profile selection
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
                            else:
                                pass
                        else:
                            pass
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
                        else:
                            pass
                    else:
                        pass
                    if os.path.exists(d + "/..profile.hex"):
                        os.remove(d + "/..profile.hex")
                    else:
                        pass
                    if os.path.exists(d + "/.profile.zip"):
                        os.remove(d + "/.profile.zip")
                    else:
                        pass
                else:
                    pass

            if "Instantiated with no profile" not in profiles[0]:
                profile = re.findall(r"Instantiated\ with\ ([^\)]+)", profiles[0])[0]
                correctprofile = input(
                    "     '{}' has been identified as a potential profile for '{}'.\n       Is this correct? Y/n [Y] ".format(
                        profile, artefact.split("/")[-1]
                    )
                )
                if correctprofile == "n":
                    print("\tOK. Please select a supported profile e.g. 2:")
                    profileselect, profile, ziphexdump = doProfile(volchoice, artefact)
                    doNixProfileDump(d, profileselect, profile, ziphexdump)
                else:
                    pass
            else:
                print(
                    "\tNo profile could be identified for '{}', please select a supported profile e.g. 2:".format(
                        artefact.split("/")[-1]
                    )
                )
                profileselect, profile, ziphexdump = doProfile(volchoice, artefact)
                doNixProfileDump(d, profileselect, profile, ziphexdump)
            extract_memory_artefacts(
                verbosity,
                output_directory,
                volchoice,
                volprefix,
                os.path.realpath(artefact),
                profile,
                mempath,
                memext,
                vssimage,
                vsstext,
                memtimeline,
            )
        if volchoice == "2.6":
            profiledirs = []
            for eachfile in os.listdir(
                "/usr/lib/python2.7/dist-packages/volatility/plugins/overlays/mac/"
            ):
                if eachfile.endswith(".zip"):
                    profiledirs.append(eachfile)
                else:
                    pass
            for eachfile in os.listdir(
                "/usr/lib/python2.7/dist-packages/volatility/plugins/overlays/linux/"
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
        else:
            pass
        vssmem = profile
    return profile, vssmem
