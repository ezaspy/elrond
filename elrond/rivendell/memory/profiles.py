#!/usr/bin/env python3 -tt
import os
import re
import subprocess
import time
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.memory.volcore import (
    assess_volatility_choice,
)
from rivendell.memory.volcore import (
    dump_nix_ziphex,
)
from rivendell.memory.volcore import (
    select_profile,
)


def select_volatility_profile(finalprofiles):
    if " 09)" in str(finalprofiles):
        finalprofiles = (
            str(
                str(finalprofiles.split("             09)"))
                .replace("', '", "\n\t  09)")
                .replace("\\n\\t", "\n\t")[2:-2]
                .split("             05)")
            )
            .replace("', '", "\n\t  05)")
            .replace("\\n\\t", "\n\t")[2:-2]
        )
    elif " 05)" in str(finalprofiles):
        finalprofiles = (
            str(finalprofiles.split("             05)"))
            .replace("', '", "\n\t  05)")
            .replace("\\n\\t", "\n\t")[2:-2]
        )
    profilekey = input("\t  {}\n\t\t\t\t\t ".format(finalprofiles))
    if profilekey + ")" in finalprofiles:
        if (
            profilekey == "1"
            or profilekey == "2"
            or profilekey == "3"
            or profilekey == "4"
            or profilekey == "5"
            or profilekey == "6"
            or profilekey == "7"
            or profilekey == "8"
            or profilekey == "9"
            or profilekey == "01"
            or profilekey == "02"
            or profilekey == "03"
            or profilekey == "04"
            or profilekey == "05"
            or profilekey == "06"
            or profilekey == "07"
            or profilekey == "08"
            or profilekey == "09"
            or profilekey == "10"
            or profilekey == "11"
            or profilekey == "12"
        ):
            if profilekey == "1" or profilekey == "01":
                profile = re.findall(r"1\)\ ([\S]+)", finalprofiles)[0]
            elif profilekey == "2" or profilekey == "02":
                profile = re.findall(r"2\)\ ([\S]+)", finalprofiles)[0]
            elif profilekey == "3" or profilekey == "03":
                profile = re.findall(r"3\)\ ([\S]+)", finalprofiles)[0]
            elif profilekey == "4" or profilekey == "04":
                profile = re.findall(r"4\)\ ([\S]+)", finalprofiles)[0]
            elif profilekey == "5" or profilekey == "0%":
                profile = re.findall(r"5\)\ ([\S]+)", finalprofiles)[0]
            elif profilekey == "6" or profilekey == "06":
                profile = re.findall(r"6\)\ ([\S]+)", finalprofiles)[0]
            elif profilekey == "7" or profilekey == "07":
                profile = re.findall(r"7\)\ ([\S]+)", finalprofiles)[0]
            elif profilekey == "8" or profilekey == "08":
                profile = re.findall(r"8\)\ ([\S]+)", finalprofiles)[0]
            elif profilekey == "9" or profilekey == "09":
                profile = re.findall(r"9\)\ ([\S]+)", finalprofiles)[0]
            elif profilekey == "10":
                profile = re.findall(r"10\)\ ([\S]+)", finalprofiles)[0]
            elif profilekey == "11":
                profile = re.findall(r"11\)\ ([\S]+)", finalprofiles)[0]
            else:
                profile = re.findall(r"12\)\ ([\S]+)", finalprofiles)[0]
    else:
        print("\tInvalid selection, please select a valid profile:")
        profile = select_volatility_profile(finalprofiles)
    return profile


def suggest_volatility_profile(
    profiles,
    artefact,
):
    if "No suggestion " in profiles[0]:
        print(
            "\tWhich of the following profiles applies to '{}'? e.g. 2/02:".format(
                artefact.split("/")[-1]
            )
        )
        profileselect = input(
            "\t   1) Win10x64_15063\t    2) Win10x86_15063\t  3) Win10x64_14393\t  4) Win10x86_14393\t  5) Win10x64_10586\t  6) Win10x86_10586\n\t   7) Win8SP1x64_18340\t    8) Win7SP1x64_24000\t  9) Win7SP1x86_24000\t 10) Win7SP1x64_23418\t 11) Win7SP1x86_23418\n\t  12) Win2012R2x64_18340   13) Win2008R2SP1x64_23418\n\t\t\t\t\t "
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
            else:
                profile = "Win2008R2SP1x64_23418"
    else:
        newprofiles, uadprofpairs, svrprofpairs, profilepairs = (
            [],
            [],
            [],
            {},
        )
        for profile in str(profiles[0].split("\\n")[0]).split(", "):
            eachprofile = re.findall(
                r"(?P<eachprofile>Win[\w]+(?:SP\d)?x[\d\_]+)", profile
            )
            if "Instantiated" in profile:
                preferred_profile = " (likely {})".format(eachprofile[0])
            else:
                preferred_profile = ""
            newprofiles.append(eachprofile[0])
            if len(eachprofile) > 0:
                newprofiles.append(eachprofile[0])
        newprofilelist, counter = list(set(newprofiles)), 1
        for newprofile in sorted(newprofilelist):
            if len(str(counter)) == 1:
                insertzero = "0"
            else:
                insertzero = ""
            if "Win10" in newprofile or "Win8" in newprofile or "Win7" in newprofile:
                uadprofpairs.append(insertzero + str(counter) + ") " + newprofile)
            else:
                svrprofpairs.append(insertzero + str(counter) + ") " + newprofile)
            profilepairs[insertzero + str(counter)] = newprofile
            counter += 1
        if "1)" in str(uadprofpairs):
            finalprofiles = (
                str(uadprofpairs)[2:-2].replace("', '", "             ")
                + "\n\t  "
                + str(svrprofpairs)[2:-2].replace("', '", "        ")
            )
        else:
            finalprofiles = (
                str(svrprofpairs)[2:-2].replace("', '", "        ")
                + "\n\t  "
                + str(uadprofpairs)[2:-2].replace("', '", "             ")
            )
        print(
            "\tWhich of the following profiles applies to '{}'? e.g. 2/02:{}".format(
                artefact.split("/")[-1], preferred_profile
            )
        )
        profile = select_volatility_profile(finalprofiles)
    return profiles, artefact, profile


def convert_memory_image(
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
    memtimeline,
):
    print(
        "      Converting '{}' memory file with profile '{}' for {}...".format(
            artefact.split("/")[-1], profile, vssimage
        )
    )
    entry, prnt = "{},{},converting,{} ({})\n".format(
        datetime.now().isoformat(),
        mempath.split("/")[0],
        artefact.split("/")[-1],
        profile,
    ), " -> {} -> converting '{}' ({}) for '{}'".format(
        datetime.now().isoformat().replace("T", " "),
        artefact.split("/")[-1],
        profile,
        mempath.split("/")[0],
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    profileout = str(
        subprocess.Popen(
            [
                "vol.py",
                "-f",
                os.path.realpath(artefact),
                "--profile=" + profile,
                "imagecopy",
                "-O",
                os.path.realpath(artefact) + memext,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
    )
    if "Invalid profile " in profileout:
        print(
            "      Invalid profile of {} selected for {}.".format(
                profile, artefact.split("/")[-1]
            )
        )
        profiles, artefact, profile = suggest_volatility_profile(profiles, artefact)
        convert_memory_image(
            stage,
            artefact,
            profile,
            profiles,
            volchoice,
            volprefix,
            mempath,
            memext,
            vssimage,
            memtimeline,
        )


def extract_profiles(artefact):
    if not artefact.endswith("hiberfil.sys"):
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
    else:
        profiles = []
        profiles.append("Win - No suggestion ")
    return profiles


def process_profiles(
    output_directory,
    verbosity,
    stage,
    d,
    img,
    profiles,
    volchoice,
    volprefix,
    artefact,
    mempath,
    memext,
    vssimage,
    memtimeline,
):
    profiles = extract_profiles(artefact)
    if "Win" in profiles[0]:
        profiles, artefact, profile = suggest_volatility_profile(
            profiles,
            artefact,
        )
        time.sleep(1)
        profile = check_profile(
            output_directory,
            verbosity,
            stage,
            d,
            img,
            volchoice,
            volprefix,
            mempath,
            memext,
            vssimage,
            memtimeline,
            "notvss",
            profile,
            artefact,
        )
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
            memtimeline,
        )
        print(
            "      Conversion of '{}' memory file complete.".format(
                artefact.split("/")[-1]
            )
        )
        profile = assess_volatility_choice(
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
    else:
        if "Instantiated with no profile" not in profiles[0]:
            profile = re.findall(r"Instantiated\ with\ ([^\)]+)", profiles[0])[0]
            correctprofile = input(
                "     '{}' has been identified as a potential profile for '{}'.\n       Is this correct? Y/n [Y] ".format(
                    profile, artefact.split("/")[-1]
                )
            )
            if correctprofile == "n":
                print("\tOK. Please select a supported profile e.g. 2:")
                profileselect, profile, ziphexdump = select_profile(volchoice, artefact)
                dump_nix_ziphex(d, profileselect, profile, ziphexdump)
        else:
            print(
                "\tNo profile could be identified for '{}', please select a supported profile e.g. 2:".format(
                    artefact.split("/")[-1]
                )
            )
            profileselect, profile, ziphexdump = select_profile(volchoice, artefact)
            dump_nix_ziphex(d, profileselect, profile, ziphexdump)
        assess_volatility_choice(
            verbosity,
            output_directory,
            volchoice,
            volprefix,
            os.path.realpath(artefact),
            profile,
            mempath,
            memext,
            vssimage,
            memtimeline,
        )
    return profiles, profile


def check_profile(
    output_directory,
    verbosity,
    stage,
    d,
    img,
    volchoice,
    volprefix,
    mempath,
    memext,
    vssimage,
    memtimeline,
    state,
    profile,
    artefact,
):
    if state == "notvss":  # not vss image
        with open("/opt/elrond/elrond/tools/.profiles", "a") as temp_profiles:
            temp_profiles.write(img.split("::")[0] + ">>" + profile + "\n")
    else:  # vss image
        with open("/opt/elrond/elrond/tools/.profiles", "r") as temp_profiles:
            savedprofiles = str(temp_profiles.readlines())[2:-4]
            if (
                img.split("::")[0] in savedprofiles
            ):  # hiberfil exists in original and vss
                orig_and_vss = "orig_and_vss"
                for img_profile in savedprofiles.split("\\n', '"):
                    original_img, original_profile = img_profile.split(">>")
                    if original_img in img:
                        profile = original_profile
            else:  # hiberfil exists only in vss
                orig_and_vss = "only_vss"
                profiles = extract_profiles(artefact)
                profiles, profile = process_profiles(
                    output_directory,
                    verbosity,
                    stage,
                    d,
                    img,
                    profiles,
                    volchoice,
                    volprefix,
                    artefact,
                    mempath,
                    memext,
                    vssimage,
                    memtimeline,
                )
        if orig_and_vss == "only_vss":
            with open("/opt/elrond/elrond/tools/.profiles", "a") as temp_profiles:
                if img.split("::")[0] not in temp_profiles.readlines():
                    temp_profiles.write(img.split("::")[0] + ">>" + profile + "\n")
    return profile


def identify_profile(
    output_directory,
    verbosity,
    d,
    stage,
    img,
    vss,
    vssimage,
    vssmem,
    artefact,
    volchoice,
    volprefix,
    mempath,
    memext,
    memtimeline,
):
    if "vss" not in img and "/vss" not in artefact:
        print(
            "      volatility2.6 is identifying likely profiles for '{}'...".format(
                artefact.split("/")[-1]
            )
        )
        profiles = extract_profiles(artefact)
    else:
        profiles = ""
    time.sleep(1)
    if stage == "processing":
        if vss and "vss" in img and "/vss" in artefact:
            profile = check_profile(
                output_directory,
                verbosity,
                stage,
                d,
                img,
                volchoice,
                volprefix,
                mempath,
                memext,
                vssimage,
                memtimeline,
                "vss",
                "",
                artefact,
            )
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
                memtimeline,
            )
            print(
                "      Conversion of '{}' memory file complete.".format(
                    artefact.split("/")[-1]
                )
            )
            profile, vssmem = assess_volatility_choice(
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
        else:
            profiles = extract_profiles(artefact)
            profiles, profile = process_profiles(
                output_directory,
                verbosity,
                stage,
                d,
                img,
                profiles,
                volchoice,
                volprefix,
                artefact,
                mempath,
                memext,
                vssimage,
                memtimeline,
            )
    else:  # vss not invoked or N/A
        profiles, artefact, profile = suggest_volatility_profile(
            profiles,
            artefact,
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
                memtimeline,
            )
            print(
                "      Conversion of '{}' memory file complete.".format(
                    artefact.split("/")[-1]
                )
            )
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
