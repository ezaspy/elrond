#!/usr/bin/env python3 -tt
import os
import shutil
import sys
import time
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.core.identify import print_identification


def reorganise_artefacts(
    output_directory, verbosity, d, allimgs, flags, auto, volatility
):
    def organise_artefacts(
        verbosity, allimgs, d, output_directory, img
    ):  # reorganise artefacts
        def doCopy(source, destination):
            try:
                shutil.copy2(source, destination)
            except:
                pass

        for reorgroot, _, reorgfiles in os.walk(d):
            for reorgfile in reorgfiles:
                eachartefact = os.path.join(reorgroot, reorgfile)
                if str(img) in str(eachartefact):
                    dest = os.path.join(output_directory, img, "artefacts/raw/")
                    if not os.path.exists(dest):
                        os.mkdir(os.path.join(output_directory, img, "artefacts/"))
                        os.mkdir(dest)
                    if (
                        eachartefact.endswith("$MFT")
                        or eachartefact.endswith("$LogFile")
                        or eachartefact.endswith("$UsnJrnl")
                        or eachartefact.endswith("$ObjId")
                        or eachartefact.endswith("$Reparse")
                        or eachartefact.endswith("hiberfil.sys")
                        or eachartefact.endswith("pagefile.sys")
                        or eachartefact.endswith("setupapi.dev.log")
                        or eachartefact.endswith("RecentFileCache.bcf")
                        or eachartefact.endswith("Amcache.hve")
                        or eachartefact.endswith("SAM")
                        or eachartefact.endswith("SECURITY")
                        or eachartefact.endswith("SOFTWARE")
                        or eachartefact.endswith("SYSTEM")
                        or eachartefact.endswith("SAM.LOG")
                        or eachartefact.endswith("SECURITY.LOG")
                        or eachartefact.endswith("SOFTWARE.LOG")
                        or eachartefact.endswith("SYSTEM.LOG")
                        or eachartefact.endswith("SAM.LOG1")
                        or eachartefact.endswith("SECURITY.LOG1")
                        or eachartefact.endswith("SOFTWARE.LOG1")
                        or eachartefact.endswith("SYSTEM.LOG1")
                        or eachartefact.endswith("SAM.LOG2")
                        or eachartefact.endswith("SECURITY.LOG2")
                        or eachartefact.endswith("SOFTWARE.LOG2")
                        or eachartefact.endswith("SYSTEM.LOG2")
                        or eachartefact.endswith("NTUSER.DAT")
                        or eachartefact.endswith("UsrClass.dat")
                        or eachartefact.endswith(".evtx")
                        or eachartefact.endswith(".automaticDestinations-ms")
                        or eachartefact.endswith(".customDestinations-ms")
                        or eachartefact.endswith("index.dat")
                    ):
                        osguess = "Windows"
                    elif (
                        eachartefact.endswith(".plist")
                        or eachartefact.endswith("History.db")
                    ) or (
                        (
                            eachartefact.endswith("bash_history")
                            or eachartefact.endswith("bash_logout")
                            or eachartefact.endswith("bashrc")
                            or eachartefact.endswith("/etc/passwd")
                            or eachartefact.endswith("/etc/shadow")
                            or eachartefact.endswith("/etc/group")
                            or eachartefact.endswith("/etc/hosts")
                            or eachartefact.endswith("crontab")
                        )
                        and ("plist" in eachartefact or "History.db" in eachartefact)
                    ):
                        osguess = "macOS"
                    elif (
                        eachartefact.endswith(".conf")
                        or eachartefact.endswith("places.sqlite")
                    ) or (
                        (
                            eachartefact.endswith("bash_history")
                            or eachartefact.endswith("bash_logout")
                            or eachartefact.endswith("bashrc")
                            or eachartefact.endswith("/etc/passwd")
                            or eachartefact.endswith("/etc/shadow")
                            or eachartefact.endswith("/etc/group")
                            or eachartefact.endswith("/etc/hosts")
                            or eachartefact.endswith("crontab")
                        )
                        and (
                            "conf" in eachartefact
                            or "places.sqlite" in eachartefact
                            or "shadow" in eachartefact
                        )
                    ):
                        osguess = "Linux"
                    elif (
                        eachartefact.endswith("bash_history")
                        or eachartefact.endswith("bash_logout")
                        or eachartefact.endswith("bashrc")
                        or eachartefact.endswith("/etc/passwd")
                        or eachartefact.endswith("/etc/shadow")
                        or eachartefact.endswith("/etc/group")
                        or eachartefact.endswith("/etc/hosts")
                        or eachartefact.endswith("crontab")
                    ):
                        osguess = "Unix"
                    else:
                        osguess = ""
                    if not os.path.exists(output_directory + "/" + img + "/artefacts/"):
                        os.makedirs(output_directory + "/" + img + "/artefacts/")
                    if not os.path.exists(
                        output_directory + "/" + img + "/artefacts/raw/"
                    ):
                        os.makedirs(output_directory + "/" + img + "/artefacts/raw/")
                    if (
                        eachartefact.endswith("$MFT")
                        or eachartefact.endswith("$LogFile")
                        or eachartefact.endswith("$UsnJrnl")
                        or eachartefact.endswith("$ObjId")
                        or eachartefact.endswith("$Reparse")
                        or eachartefact.endswith("hiberfil.sys")
                        or eachartefact.endswith("pagefile.sys")
                        or eachartefact.endswith("setupapi.dev.log")
                        or eachartefact.endswith("RecentFileCache.bcf")
                        or eachartefact.endswith("Amcache.hve")
                        or eachartefact.endswith("groups")
                        or eachartefact.endswith("hosts")
                        or eachartefact.endswith("passwd")
                        or eachartefact.endswith("shadow")
                    ):
                        doCopy(
                            eachartefact,
                            dest + eachartefact.split("/")[-1],
                        )
                    elif (
                        eachartefact.endswith("SAM")
                        or eachartefact.endswith("SECURITY")
                        or eachartefact.endswith("SOFTWARE")
                        or eachartefact.endswith("SYSTEM")
                        or eachartefact.endswith("SAM.LOG")
                        or eachartefact.endswith("SECURITY.LOG")
                        or eachartefact.endswith("SOFTWARE.LOG")
                        or eachartefact.endswith("SYSTEM.LOG")
                        or eachartefact.endswith("SAM.LOG1")
                        or eachartefact.endswith("SECURITY.LOG1")
                        or eachartefact.endswith("SOFTWARE.LOG1")
                        or eachartefact.endswith("SYSTEM.LOG1")
                        or eachartefact.endswith("SAM.LOG2")
                        or eachartefact.endswith("SECURITY.LOG2")
                        or eachartefact.endswith("SOFTWARE.LOG2")
                        or eachartefact.endswith("SYSTEM.LOG2")
                    ):
                        if not os.path.exists(os.path.join(dest, "registry")):
                            os.makedirs(os.path.join(dest, "registry"))
                        doCopy(
                            eachartefact,
                            os.path.join(dest, "registry", eachartefact.split("/")[-1]),
                        )
                        if os.path.exists(
                            os.path.join(dest, "registry", eachartefact.split("/")[-1])
                        ) and os.path.join(
                            dest, "registry", eachartefact.split("/")[-1]
                        ).endswith(
                            "SYSTEM"
                        ):
                            doCopy(
                                os.path.join(
                                    dest, "registry", eachartefact.split("/")[-1]
                                ),
                                os.path.join(dest, ".SYSTEM"),
                            )
                    elif eachartefact.endswith("NTUSER.DAT") or eachartefact.endswith(
                        "UsrClass.dat"
                    ):
                        if not os.path.exists(os.path.join(dest, "registry")):
                            os.makedirs(os.path.join(dest, "registry"))
                        doCopy(
                            eachartefact,
                            os.path.join(
                                dest,
                                "registry",
                                eachartefact.split("/")[-2]
                                + "+"
                                + eachartefact.split("/")[-1],
                            ),
                        )
                    elif eachartefact.endswith(".evtx"):
                        if not os.path.exists(os.path.join(dest, "evtx")):
                            os.makedirs(os.path.join(dest, "evtx"))
                        doCopy(
                            eachartefact,
                            os.path.join(
                                dest,
                                "evtx",
                                eachartefact.split("/")[-1],
                            ),
                        )
                    elif eachartefact.endswith(
                        ".automaticDestinations-ms"
                    ) or eachartefact.endswith(".customDestinations-ms"):
                        if not os.path.exists(os.path.join(dest, "jumplists")):
                            os.makedirs(os.path.join(dest, "jumplists"))
                        doCopy(
                            eachartefact,
                            os.path.join(
                                dest,
                                "jumplists",
                                eachartefact.split("/")[-2]
                                + "+"
                                + eachartefact.split("/")[-1],
                            ),
                        )
                    elif (
                        eachartefact.endswith("bash_aliases")
                        or eachartefact.endswith("bash_history")
                        or eachartefact.endswith("bash_logout")
                        or eachartefact.endswith("bashrc")
                        or eachartefact.endswith("login.keyring")
                        or eachartefact.endswith("user.keystore")
                    ):
                        doCopy(
                            eachartefact,
                            os.path.join(
                                dest,
                                eachartefact.split("/")[-2]
                                + "+"
                                + eachartefact.split("/")[-1],
                            ),
                        )
                    elif eachartefact.endswith(".keychain-db"):
                        if not os.path.exists(os.path.join(dest, "keychain")):
                            os.makedirs(os.path.join(dest, "keychain"))
                        doCopy(
                            eachartefact,
                            dest + "/keychain/" + eachartefact,
                        )
                    elif eachartefact.endswith(".plist"):
                        if not os.path.exists(os.path.join(dest, "plists")):
                            os.makedirs(os.path.join(dest, "plists"))
                        doCopy(
                            eachartefact,
                            dest + "/plists/" + eachartefact,
                        )
                    elif eachartefact.endswith(".log"):
                        if not os.path.exists(os.path.join(dest, "logs")):
                            os.makedirs(os.path.join(dest, "logs"))
                        doCopy(
                            eachartefact,
                            dest + "/logs/" + eachartefact,
                        )
                    elif eachartefact.endswith(".conf"):
                        if not os.path.exists(os.path.join(dest, "conf")):
                            os.makedirs(os.path.join(dest, "conf"))
                        doCopy(
                            eachartefact,
                            dest + "/conf/" + eachartefact,
                        )
                    elif eachartefact.startswith("job."):
                        if not os.path.exists(os.path.join(dest, "jobs")):
                            os.makedirs(os.path.join(dest, "jobs"))
                        doCopy(
                            eachartefact,
                            dest + "/jobs/" + eachartefact,
                        )
                    elif (
                        eachartefact.endswith(".service")
                        or eachartefact.endswith(".target")
                        or eachartefact.endswith(".socket")
                    ):
                        if not os.path.exists(os.path.join(dest, "services")):
                            os.makedirs(os.path.join(dest, "services"))
                        doCopy(
                            eachartefact,
                            os.path.join(dest, "services", eachartefact.split("/")[-1]),
                        )
                    elif eachartefact.endswith(".global-message-db.sqlite"):
                        if not os.path.exists(os.path.join(dest, "mail")):
                            os.makedirs(os.path.join(dest, "mail"))
                        doCopy(
                            eachartefact,
                            os.path.join(dest, "mail", eachartefact.split("/")[-1]),
                        )
                    elif (
                        eachartefact.endswith("History")
                        or eachartefact.endswith("HISTORY")
                        or eachartefact.endswith("History.db")
                        or eachartefact.endswith("places.sqlite")
                        or eachartefact.endswith("index.dat")
                    ):
                        if not os.path.exists(os.path.join(dest, "browsers")):
                            os.makedirs(os.path.join(dest, "browsers"))
                        if not os.path.exists(
                            os.path.join(
                                dest,
                                "browsers",
                                eachartefact.split("/")[-2],
                            )
                        ):
                            os.makedirs(
                                os.path.join(
                                    dest,
                                    "browsers",
                                    eachartefact.split("/")[-2],
                                )
                            )
                        if eachartefact.endswith("History") or eachartefact.endswith(
                            "HISTORY"
                        ):
                            chromeoredge = input(
                                "   As Microsoft Edge and Google Chrome both use chromium (https://en.wikipedia.org/wiki/Chromium_(web_browser))\n    Please confirm if '{}' is from Edge or Chrome:\n     1) Edge   2) Chrome   3) Unsure\n\t[1] ".format(
                                    eachartefact.split("/")[-1]
                                )
                            )
                            if chromeoredge != "2":
                                bwsrdir = "chrome"
                            else:
                                bwsrdir = "Edge"
                        elif eachartefact.endswith("History.db"):
                            bwsrdir = "safari"
                        elif eachartefact.endswith("places.sqlite"):
                            bwsrdir = "firefox"
                        elif eachartefact.endswith("index.dat"):
                            bwsrdir = "ie"
                        if not os.path.exists(
                            os.path.join(
                                dest,
                                "browsers",
                                eachartefact.split("/")[-2],
                                bwsrdir,
                            )
                        ):
                            os.makedirs(
                                os.path.join(
                                    dest,
                                    "browsers",
                                    eachartefact.split("/")[-2],
                                    bwsrdir,
                                )
                            )
                        doCopy(
                            eachartefact,
                            os.path.join(
                                dest,
                                "browsers",
                                eachartefact.split("/")[-2],
                                bwsrdir,
                                eachartefact.split("/")[-1],
                            ),
                        )
                    elif (
                        volatility
                        and os.stat(eachartefact).st_size > 2000000000
                        and (
                            eachartefact.endswith("hiberfil.sys")
                            or eachartefact.endswith("pagefile.sys")
                            or eachartefact.endswith("swapfile.sys")
                            or eachartefact.endswith("MEMORY.DMP")
                        )
                    ):
                        ismem = input(
                            "   '{}' is potentially a memory image. Do you wish to process this as such? Y/n [Y] ".format(
                                eachartefact
                            )
                        )
                        if ismem != "n":
                            print(
                                "    '{}' will be marked for processing as a memory image, please stand by...".format(
                                    eachartefact
                                )
                            )
                            doCopy(
                                eachartefact,
                                dest + "/" + eachartefact.split("/")[-1],
                            )
                            os.rename(
                                dest + "/" + eachartefact.split("/")[-1],
                                dest
                                + "/"
                                + eachartefact.replace(" ", "")
                                + "_MEMORY.DMP",
                            )

                        else:
                            print(
                                "  OK. '{}' will not be processed as a memory image.".format(
                                    eachartefact
                                )
                            )
                            pass
                    if osguess != "" and str(img) not in str(allimgs):
                        allimgs[os.path.join(d, img)] = img + "::" + osguess
        for _, eachimg in allimgs.items():
            print_identification(
                verbosity, output_directory, eachimg.split("::")[0], osguess
            )

    for eachdir in os.listdir(output_directory):
        shutil.rmtree(output_directory + "/" + eachdir)
    show_example = input(
        "   You have provided '{}' as the path containing the artefacts.\n   This directory path must contain all of the hosts (as directories) you wish to process, each with their respective artefacts within\n    If you have multiple files with the same name, for example 'NTUSER.DAT', place them in a directory with the name of that user profile.\n    If these files do not belong to a user profile, prefix the file with '#' and a number. \n   Ignoring the '#' prefix, all artefacts MUST match the original filenames from the original host.\n    Take your time in reorganising the artefacts.\n     Show example directory structure? Y/n [n] ".format(
            d, d.split("/")[-1]
        )
    )
    if show_example == "Y":
        tabbed_insert, sub_insert = "\n\t\t\t\t\t\t", "\n\t\t\t\t\t\t\t\t"
        print(
            "\n   {}\033[1;33m<hostname>\033[1;m/\033[1;36m$MFT{}\033[1;m\033[1;m/\033[1;36m#1$MFT{}\033[1;m\033[1;m/\033[1;36msetupapi.dev.log{}\033[1;m/\033[1;36mAmCache.hve{}\033[1;m/\033[1;36mSOFTWARE{}\033[1;m/\033[1;36mSecurity.evtx{}\033[1;m/\033[1;33m<user_profile1>\033[1;m{}\033[1;m/\033[1;36mNTUSER.DAT{}\033[1;m/\033[1;36mUsrClass.DAT{}\033[1;m/\033[1;36mHistory{}\033[1;m/\033[1;36mindex.dat{}\033[1;m/\033[1;36m#1index.dat{}\033[1;m/\033[1;36mActivitiesCache.db{}\033[1;m/\033[1;33m<user_profile2>\033[1;m{}\033[1;m/\033[1;36mNTUSER.DAT{}\033[1;m/\033[1;36mUsrClass.DAT{}\033[1;m/\033[1;36mHistory{}\033[1;m/\033[1;36mindex.dat{}\033[1;m/\033[1;36m#1index.dat{}\033[1;m/\033[1;36m#2index.dat{}\033[1;m/\033[1;36mActivitiesCache.db\033[1;m".format(
                d,
                tabbed_insert,
                tabbed_insert,
                tabbed_insert,
                tabbed_insert,
                tabbed_insert,
                tabbed_insert,
                sub_insert,
                sub_insert,
                sub_insert,
                sub_insert,
                sub_insert,
                sub_insert,
                tabbed_insert,
                sub_insert,
                sub_insert,
                sub_insert,
                sub_insert,
                sub_insert,
                sub_insert,
                sub_insert,
            )
        )
        time.sleep(10)
    confirm_reorg = input("   Continue? Y/n [Y] ")
    print()
    if confirm_reorg == "n":
        print(
            "\n  OK. Ensure the directory you provide adheres to the required structure specified above. Please try again.\n\n"
        )
        sys.exit()
    d = str(str(d) + "/").replace("//", "/")
    if len(d.split("/")) < 3:
        print(
            "\n  '{}' is an invalid directory structure.\n   If you meant to not invoke the Collect flag (-C), please ensure the file path you provide is as follows:\n    'python3 elrond.py -npaqQvVP casename \033[1;36m./source_directory/\033[1;m'\n\n".format(
                d
            )
        )
        sys.exit()
    if not os.path.exists(d):
        print("    '{}' does not exist. Please try again.\n\n".format(d))
        sys.exit()
    elif len(os.listdir(d)) < 1:
        print(
            "    '{}' is empty thus contains no artefacts. Please try again.\n\n".format(
                d
            )
        )
        sys.exit()
    else:  # confirm reorganisation
        for _, dirs, _ in os.walk(d):
            for f in dirs:
                if os.path.exists(os.path.join(d, f)):
                    if not auto:
                        wtr = input(
                            "    Do you wish to process: '{}'? Y/n [Y] ".format(f)
                        )
                    else:
                        wtr = "y"
                    if wtr != "n":
                        if not os.path.exists(os.path.join(output_directory, f)):
                            os.makedirs(os.path.join(output_directory, f))
                        entry, prnt = (
                            "LastWriteTime,elrond_host,elrond_stage,elrond_log_entry\n",
                            " -> {} -> created audit log file for '{}'".format(
                                datetime.now().isoformat().replace("T", " "), f
                            ),
                        )
                        write_audit_log_entry(verbosity, output_directory, entry, prnt)
                        entry, prnt = "{},{},{},commenced\n".format(
                            datetime.now().isoformat(), f, "reorganising"
                        ), " -> {} -> {} artefacts for '{}'".format(
                            datetime.now().isoformat().replace("T", " "),
                            "reorganising",
                            f,
                        )
                        write_audit_log_entry(verbosity, output_directory, entry, prnt)
                        organise_artefacts(verbosity, allimgs, d, output_directory, f)
                    else:
                        print("    OK. '{}' will not be processed.\n".format(f))
        imgs = allimgs.copy()
    print()
    flags.append("01reorganised")
    print(
        "  ----------------------------------------\n  -> Completed Identification Phase.\n"
    )
    time.sleep(1)
    return imgs
