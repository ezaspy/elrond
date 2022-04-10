#!/usr/bin/env python3 -tt
import os
import shutil
from datetime import datetime

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry


def reorganise_artefacts():
    reorgedfiles = [""]
    for eachdir in os.listdir(output_directory):
        shutil.rmtree(output_directory + "/" + eachdir)

    def doReorganise(
        verbosity, stage, allimgs, d, output_directory, f
    ):  # reorganise artefacts
        def doCopy(source, destination):
            try:
                shutil.copy2(source, destination)
            except:
                pass

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
            datetime.now().isoformat().replace("T", " "), "reorganising", f
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        for root, dirs, _ in os.walk(d):
            for img in dirs:
                imgcontent = os.listdir(os.path.join(root, img))
                dest = os.path.join(output_directory, img, "artefacts/raw/")
                for imgroot, _, imgfiles in os.walk(os.path.join(root, img)):
                    for eachfile in imgfiles:
                        for eachreorg in reorgedfiles:
                            if img in os.path.join(imgroot, eachfile) and os.path.join(
                                imgroot, eachfile
                            ) not in str(reorgedfiles):
                                if (
                                    eachfile.startswith("$MFT")
                                    or eachfile.startswith("$LogFile")
                                    or eachfile.startswith("$UsnJrnl")
                                    or eachfile.startswith("$ObjId")
                                    or eachfile.startswith("$Reparse")
                                    or eachfile.startswith("hiberfil.sys")
                                    or eachfile.startswith("pagefile.sys")
                                    or eachfile.endswith("MFT")
                                    or eachfile.endswith("LogFile")
                                    or eachfile.endswith("UsnJrnl")
                                    or eachfile.endswith("ObjId")
                                    or eachfile.endswith("Reparse")
                                    or eachfile.endswith("hiberfil.sys")
                                    or eachfile.endswith("pagefile.sys")
                                    or eachfile.endswith("setupapi.dev.log")
                                    or eachfile.endswith("RecentFileCache.bcf")
                                    or eachfile.endswith("Amcache.hve")
                                    or eachfile.endswith("SAM")
                                    or eachfile.endswith("SECURITY")
                                    or eachfile.endswith("SOFTWARE")
                                    or eachfile.endswith("SYSTEM")
                                    or eachfile.endswith("SAM.LOG")
                                    or eachfile.endswith("SECURITY.LOG")
                                    or eachfile.endswith("SOFTWARE.LOG")
                                    or eachfile.endswith("SYSTEM.LOG")
                                    or eachfile.endswith("SAM.LOG1")
                                    or eachfile.endswith("SECURITY.LOG1")
                                    or eachfile.endswith("SOFTWARE.LOG1")
                                    or eachfile.endswith("SYSTEM.LOG1")
                                    or eachfile.endswith("SAM.LOG2")
                                    or eachfile.endswith("SECURITY.LOG2")
                                    or eachfile.endswith("SOFTWARE.LOG2")
                                    or eachfile.endswith("SYSTEM.LOG2")
                                    or eachfile.startswith("NTUSER.DAT")
                                    or eachfile.startswith("UsrClass.dat")
                                    or eachfile.endswith("NTUSER.DAT")
                                    or eachfile.endswith("UsrClass.dat")
                                    or eachfile.endswith(".evtx")
                                    or eachfile.endswith(".automaticDestinations-ms")
                                    or eachfile.endswith(".customDestinations-ms")
                                ):
                                    osguess = "::Windows"
                                elif (
                                    eachfile.endswith(".plist")
                                    or eachfile.endswith("History.db")
                                ) or (
                                    (
                                        eachfile.endswith("bash_history")
                                        or eachfile.endswith("bash_logout")
                                        or eachfile.endswith("bashrc")
                                        or eachfile.endswith("/etc/passwd")
                                        or eachfile.endswith("/etc/shadow")
                                        or eachfile.endswith("/etc/group")
                                        or eachfile.endswith("/etc/hosts")
                                        or eachfile.endswith("crontab")
                                    )
                                    and (
                                        "plist" in imgcontent
                                        or "History.db" in imgcontent
                                    )
                                ):
                                    osguess = "::macOS"
                                elif (
                                    eachfile.endswith(".conf")
                                    or eachfile.endswith("places.sqlite")
                                ) or (
                                    (
                                        eachfile.endswith("bash_history")
                                        or eachfile.endswith("bash_logout")
                                        or eachfile.endswith("bashrc")
                                        or eachfile.endswith("/etc/passwd")
                                        or eachfile.endswith("/etc/shadow")
                                        or eachfile.endswith("/etc/group")
                                        or eachfile.endswith("/etc/hosts")
                                        or eachfile.endswith("crontab")
                                    )
                                    and (
                                        "conf" in imgcontent
                                        or "places.sqlite" in imgcontent
                                        or "shadow" in imgcontent
                                    )
                                ):
                                    osguess = "::Linux"
                                elif (
                                    eachfile.endswith("bash_history")
                                    or eachfile.endswith("bash_logout")
                                    or eachfile.endswith("bashrc")
                                    or eachfile.endswith("/etc/passwd")
                                    or eachfile.endswith("/etc/shadow")
                                    or eachfile.endswith("/etc/group")
                                    or eachfile.endswith("/etc/hosts")
                                    or eachfile.endswith("crontab")
                                ):
                                    osguess = "::Unix"
                                else:
                                    osguess = ""
                                if osguess != "":
                                    if not os.path.exists(
                                        output_directory + "/" + img + "/artefacts/"
                                    ):
                                        os.makedirs(
                                            output_directory + "/" + img + "/artefacts/"
                                        )
                                    else:
                                        pass
                                    if not os.path.exists(
                                        output_directory + "/" + img + "/artefacts/raw/"
                                    ):
                                        os.makedirs(
                                            output_directory
                                            + "/"
                                            + img
                                            + "/artefacts/raw/"
                                        )
                                    else:
                                        pass
                                    allimgs[img + osguess] = os.path.realpath(
                                        root.split("/")[-3]
                                    )
                                    if (
                                        (imgroot.split("/")[-1] == img)
                                        and (
                                            eachfile.startswith("NTUSER.DAT")
                                            and eachfile.endswith("NTUSER.DAT")
                                        )
                                        or (
                                            eachfile.startswith("UsrClass.dat")
                                            and eachfile.endswith("UsrClass.dat")
                                        )
                                        or (
                                            eachfile.endswith(
                                                ".automaticDestinations-ms"
                                            )
                                            or eachfile.endswith(
                                                ".customDestinations-ms"
                                            )
                                        )
                                        or (
                                            eachfile.startswith("bash_aliases")
                                            and eachfile.endswith("bash_aliases")
                                        )
                                        or (
                                            eachfile.startswith("bash_history")
                                            and eachfile.endswith("bash_history")
                                        )
                                        or (
                                            eachfile.startswith("bash_logout")
                                            and eachfile.endswith("bash_logout")
                                        )
                                        or (
                                            eachfile.startswith("bashrc")
                                            and eachfile.endswith("bashrc")
                                        )
                                        or (
                                            eachfile.startswith("login.keyring")
                                            and eachfile.endswith("login.keyring")
                                        )
                                        or (
                                            eachfile.startswith("user.keystore")
                                            and eachfile.endswith("user.keystore")
                                        )
                                        or (
                                            eachfile.startswith("HISTORY")
                                            and eachfile.endswith("HISTORY")
                                        )
                                        or (
                                            eachfile.startswith("History.db")
                                            and eachfile.endswith("History.db")
                                        )
                                        or (
                                            eachfile.startswith("places.sqlite")
                                            and eachfile.endswith("places.sqlite")
                                        )
                                        and "+" not in eachfile
                                    ):

                                        def doWhichUser(whichuser):
                                            if whichuser == "1":
                                                print("  OK. Thank you.\n\n")
                                                sys.exit()
                                            elif whichuser == "2":
                                                alias = "alias"
                                            else:
                                                alias = whichuser.strip("+")
                                                if alias == "":
                                                    alias = "alias"
                                                else:
                                                    pass
                                            return alias

                                        whichuser = input(
                                            "\n  In order to accurately process and anaylse '{}' for '{}', a username will need to be provided.\n   You have three options:\n    1. Gracefully exit elrond and rename the files accordingly - '<username>+{}'\n    2. Ignore the user name ('alias' will be used instead)\n    3. Provide the user name now: [2] ".format(
                                                eachfile, img, eachfile
                                            )
                                        )
                                        alias = doWhichUser(whichuser)
                                        reorgedfiles.append(
                                            os.path.join(imgroot, eachfile)
                                        )
                                    else:
                                        alias = ""
                                    if (
                                        eachfile.startswith("$MFT")
                                        or eachfile.startswith("$LogFile")
                                        or eachfile.startswith("$UsnJrnl")
                                        or eachfile.startswith("$ObjId")
                                        or eachfile.startswith("$Reparse")
                                        or eachfile.startswith("hiberfil.sys")
                                        or eachfile.startswith("pagefile.sys")
                                        or eachfile.endswith("MFT")
                                        or eachfile.endswith("LogFile")
                                        or eachfile.endswith("UsnJrnl")
                                        or eachfile.endswith("ObjId")
                                        or eachfile.endswith("Reparse")
                                        or eachfile.endswith("hiberfil.sys")
                                        or eachfile.endswith("pagefile.sys")
                                        or eachfile.endswith("setupapi.dev.log")
                                        or eachfile.endswith("RecentFileCache.bcf")
                                        or eachfile.endswith("Amcache.hve")
                                        or (
                                            eachfile.startswith("groups")
                                            and eachfile.endswith("groups")
                                        )
                                        or (
                                            eachfile.startswith("hosts")
                                            and eachfile.endswith("hosts")
                                        )
                                        or (
                                            eachfile.startswith("passwd")
                                            and eachfile.endswith("passwd")
                                        )
                                        or (
                                            eachfile.startswith("shadow")
                                            and eachfile.endswith("shadow")
                                        )
                                    ):
                                        doCopy(
                                            os.path.join(imgroot, eachfile),
                                            dest + "/" + eachfile,
                                        )
                                    elif eachfile.endswith("SYSTEM"):
                                        doCopy(
                                            os.path.join(imgroot, eachfile),
                                            dest + "/" + eachfile,
                                        )
                                        os.rename(
                                            dest + "/" + eachfile,
                                            dest + "/.SYSTEM",
                                        )
                                    elif (
                                        eachfile.endswith("SAM")
                                        or eachfile.endswith("SECURITY")
                                        or eachfile.endswith("SOFTWARE")
                                        or eachfile.endswith("SYSTEM")
                                        or eachfile.endswith("SAM.LOG")
                                        or eachfile.endswith("SECURITY.LOG")
                                        or eachfile.endswith("SOFTWARE.LOG")
                                        or eachfile.endswith("SYSTEM.LOG")
                                        or eachfile.endswith("SAM.LOG1")
                                        or eachfile.endswith("SECURITY.LOG1")
                                        or eachfile.endswith("SOFTWARE.LOG1")
                                        or eachfile.endswith("SYSTEM.LOG1")
                                        or eachfile.endswith("SAM.LOG2")
                                        or eachfile.endswith("SECURITY.LOG2")
                                        or eachfile.endswith("SOFTWARE.LOG2")
                                        or eachfile.endswith("SYSTEM.LOG2")
                                    ):
                                        if not os.path.exists(dest + "/registry"):
                                            os.makedirs(dest + "/registry")
                                        else:
                                            pass
                                        doCopy(
                                            os.path.join(imgroot, eachfile),
                                            dest + "/registry/" + eachfile,
                                        )
                                    elif (
                                        eachfile.startswith("NTUSER.DAT")
                                        or eachfile.endswith("NTUSER.DAT")
                                        or eachfile.startswith("UsrClass.dat")
                                        or eachfile.endswith("UsrClass.dat")
                                    ):
                                        if not os.path.exists(dest + "/registry"):
                                            os.makedirs(dest + "/registry")
                                        else:
                                            pass
                                        if "+" in eachfile:
                                            doCopy(
                                                os.path.join(imgroot, eachfile),
                                                dest + "/registry/" + eachfile,
                                            )
                                        else:
                                            doCopy(
                                                os.path.join(imgroot, eachfile),
                                                dest
                                                + "/registry/"
                                                + alias
                                                + "+"
                                                + eachfile,
                                            )
                                    elif eachfile.endswith(".evtx"):
                                        if not os.path.exists(dest + "/evtx"):
                                            os.makedirs(dest + "/evtx")
                                        else:
                                            pass
                                        doCopy(
                                            os.path.join(imgroot, eachfile),
                                            dest + "/evtx/" + eachfile,
                                        )
                                    elif eachfile.endswith(
                                        ".automaticDestinations-ms"
                                    ) or eachfile.endswith(".customDestinations-ms"):
                                        if not os.path.exists(dest + "/jumplists"):
                                            os.makedirs(dest + "/jumplists")
                                        else:
                                            pass
                                        if "+" in eachfile:
                                            doCopy(
                                                os.path.join(imgroot, eachfile),
                                                dest + "/jumplists/" + eachfile,
                                            )
                                        else:
                                            doCopy(
                                                os.path.join(imgroot, eachfile),
                                                dest
                                                + "/jumplists/"
                                                + alias
                                                + "+"
                                                + eachfile,
                                            )
                                    elif (
                                        eachfile.endswith("bash_aliases")
                                        or eachfile.endswith("bash_history")
                                        or eachfile.endswith("bash_logout")
                                        or eachfile.endswith("bashrc")
                                        or eachfile.endswith("login.keyring")
                                        or eachfile.endswith("user.keystore")
                                    ):
                                        if "+" in eachfile:
                                            doCopy(
                                                os.path.join(imgroot, eachfile),
                                                dest + "/" + eachfile,
                                            )
                                        else:
                                            doCopy(
                                                os.path.join(imgroot, eachfile),
                                                dest + "/" + alias + "+" + eachfile,
                                            )
                                    elif eachfile.endswith(".keychain-db"):
                                        if not os.path.exists(dest + "/keychain"):
                                            os.makedirs(dest + "/keychain")
                                        else:
                                            pass
                                        doCopy(
                                            os.path.join(imgroot, eachfile),
                                            dest + "/keychain/" + eachfile,
                                        )
                                    elif eachfile.endswith(".plist"):
                                        if not os.path.exists(dest + "/plists"):
                                            os.makedirs(dest + "/plists")
                                        else:
                                            pass
                                        doCopy(
                                            os.path.join(imgroot, eachfile),
                                            dest + "/plists/" + eachfile,
                                        )
                                    elif eachfile.endswith(".log"):
                                        if not os.path.exists(dest + "/logs"):
                                            os.makedirs(dest + "/logs")
                                        else:
                                            pass
                                        doCopy(
                                            os.path.join(imgroot, eachfile),
                                            dest + "/logs/" + eachfile,
                                        )
                                    elif eachfile.endswith(".conf"):
                                        if not os.path.exists(dest + "/conf"):
                                            os.makedirs(dest + "/conf")
                                        else:
                                            pass
                                        doCopy(
                                            os.path.join(imgroot, eachfile),
                                            dest + "/conf/" + eachfile,
                                        )
                                    elif eachfile.startswith("job."):
                                        if not os.path.exists(dest + "/jobs"):
                                            os.makedirs(dest + "/jobs")
                                        else:
                                            pass
                                        doCopy(
                                            os.path.join(imgroot, eachfile),
                                            dest + "/jobs/" + eachfile,
                                        )
                                    elif (
                                        eachfile.endswith(".service")
                                        or eachfile.endswith(".target")
                                        or eachfile.endswith(".socket")
                                    ):
                                        if not os.path.exists(dest + "/services"):
                                            os.makedirs(dest + "/services")
                                        else:
                                            pass
                                        doCopy(
                                            os.path.join(imgroot, eachfile),
                                            dest + "/services/" + eachfile,
                                        )
                                    elif eachfile.endswith(".global-message-db.sqlite"):
                                        if not os.path.exists(dest + "/mail"):
                                            os.makedirs(dest + "/mail")
                                        else:
                                            pass
                                        doCopy(
                                            os.path.join(imgroot, eachfile),
                                            dest + "/mail/" + eachfile,
                                        )
                                    elif (
                                        (
                                            eachfile.startswith("HISTORY")
                                            and eachfile.endswith("HISTORY")
                                        )
                                        or eachfile.endswith("History.db")
                                        or eachfile.endswith("places.sqlite")
                                    ):
                                        if not os.path.exists(dest + "/browsers"):
                                            os.makedirs(dest + "browsers")
                                        else:
                                            pass
                                        if alias != "" and not os.path.exists(
                                            dest + "browsers/" + alias
                                        ):
                                            os.makedirs(dest + "browsers/" + alias)
                                        else:
                                            pass
                                        if eachfile == "History":
                                            if not os.path.exists(
                                                dest + "browsers/" + alias + "/chromium"
                                            ):
                                                os.makedirs(
                                                    dest
                                                    + "browsers/"
                                                    + alias
                                                    + "/chromium"
                                                )
                                            else:
                                                pass
                                            bwsrdir = "chromium/"
                                        elif eachfile == "HISTORY":
                                            if not os.path.exists(
                                                dest + "browsers/" + alias + "/edge"
                                            ):
                                                os.makedirs(
                                                    dest + "browsers/" + alias + "/edge"
                                                )
                                            else:
                                                pass
                                            bwsrdir = "edge/"
                                        elif eachfile == "History.db":
                                            if not os.path.exists(
                                                dest + "browsers/" + alias + "/safari"
                                            ):
                                                os.makedirs(
                                                    dest
                                                    + "browsers/"
                                                    + alias
                                                    + "/safari"
                                                )
                                            else:
                                                pass
                                            bwsrdir = "safari/"
                                        elif eachfile == "places.sqlite":
                                            if not os.path.exists(
                                                dest + "browsers/" + alias + "/firefox"
                                            ):
                                                os.makedirs(
                                                    dest
                                                    + "browsers/"
                                                    + alias
                                                    + "/firefox"
                                                )
                                            else:
                                                pass
                                            bwsrdir = "firefox/"
                                        else:
                                            pass
                                        if "+" in eachfile:
                                            doCopy(
                                                os.path.join(imgroot, eachfile),
                                                dest
                                                + "browsers/"
                                                + eachfile.split("/")[-1].split("+")[0]
                                                + "/"
                                                + bwsrdir
                                                + eachfile,
                                            )
                                        else:
                                            doCopy(
                                                os.path.join(imgroot, eachfile),
                                                dest
                                                + "browsers/"
                                                + alias
                                                + "/"
                                                + bwsrdir
                                                + eachfile,
                                            )
                                    elif (
                                        volatility
                                        and os.stat(
                                            os.path.join(root, eachfile)
                                        ).st_size
                                        > 2000000000
                                        and not (
                                            eachfile.startswith("$MFT")
                                            or eachfile.startswith("$LogFile")
                                            or eachfile.startswith("$UsnJrnl")
                                            or eachfile.startswith("$ObjId")
                                            or eachfile.startswith("$Reparse")
                                            or eachfile.startswith("hiberfil.sys")
                                            or eachfile.startswith("pagefile.sys")
                                            or eachfile.endswith("MFT")
                                            or eachfile.endswith("LogFile")
                                            or eachfile.endswith("UsnJrnl")
                                            or eachfile.endswith("ObjId")
                                            or eachfile.endswith("Reparse")
                                            or eachfile.endswith("setupapi.dev.log")
                                            or eachfile.endswith("RecentFileCache.bcf")
                                            or eachfile.endswith("Amcache.hve")
                                            or (
                                                eachfile.startswith("groups")
                                                and eachfile.endswith("groups")
                                            )
                                            or (
                                                eachfile.startswith("hosts")
                                                and eachfile.endswith("hosts")
                                            )
                                            or (
                                                eachfile.startswith("passwd")
                                                and eachfile.endswith("passwd")
                                            )
                                            or (
                                                eachfile.startswith("shadow")
                                                and eachfile.endswith("shadow")
                                            )
                                            or eachfile.endswith("bash_aliases")
                                            or eachfile.endswith("bash_history")
                                            or eachfile.endswith("bash_logout")
                                            or eachfile.endswith("bashrc")
                                            or eachfile.endswith("login.keyring")
                                            or eachfile.endswith("user.keystore")
                                            or eachfile.endswith("SAM")
                                            or eachfile.endswith("SECURITY")
                                            or eachfile.endswith("SOFTWARE")
                                            or eachfile.endswith("SYSTEM")
                                            or eachfile.endswith("SAM.LOG")
                                            or eachfile.endswith("SECURITY.LOG")
                                            or eachfile.endswith("SOFTWARE.LOG")
                                            or eachfile.endswith("SYSTEM.LOG")
                                            or eachfile.endswith("SAM.LOG1")
                                            or eachfile.endswith("SECURITY.LOG1")
                                            or eachfile.endswith("SOFTWARE.LOG1")
                                            or eachfile.endswith("SYSTEM.LOG1")
                                            or eachfile.endswith("SAM.LOG2")
                                            or eachfile.endswith("SECURITY.LOG2")
                                            or eachfile.endswith("SOFTWARE.LOG2")
                                            or eachfile.endswith("SYSTEM.LOG2")
                                            or eachfile.startswith("NTUSER.DAT")
                                            or eachfile.startswith("UsrClass.dat")
                                            or eachfile.endswith("NTUSER.DAT")
                                            or eachfile.endswith("UsrClass.dat")
                                            or eachfile.endswith(".evtx")
                                            or eachfile.endswith(
                                                ".automaticDestinations-ms"
                                            )
                                            or eachfile.endswith(
                                                ".customDestinations-ms"
                                            )
                                            or eachfile.endswith(".plist")
                                            or eachfile.endswith(".log")
                                            or eachfile.endswith(".conf")
                                            or eachfile.startswith("job.")
                                            or eachfile.endswith(".service")
                                            or eachfile.endswith(".target")
                                            or eachfile.endswith(".socket")
                                            or eachfile.endswith(".keychain-db")
                                            or eachfile.endswith(".DS_Store")
                                        )
                                    ):
                                        ismem = input(
                                            "   '{}' is potentially a memory image. Do you wish to process this as such? Y/n [Y] ".format(
                                                eachfile
                                            )
                                        )
                                        if ismem != "n":
                                            print(
                                                "    '{}' will be marked for processing as a memory image, please stand by...".format(
                                                    eachfile
                                                )
                                            )
                                            doCopy(
                                                os.path.join(imgroot, eachfile),
                                                dest + "/" + eachfile,
                                            )
                                            os.rename(
                                                dest + "/" + eachfile,
                                                dest
                                                + "/"
                                                + eachfile.replace(" ", "")
                                                + "_MEMORY.DMP",
                                            )
                                            print_done(verbosity)
                                        else:
                                            print(
                                                "  OK. '{}' will not be processed as a memory image.".format(
                                                    eachfile
                                                )
                                            )
                                            pass
                                    else:
                                        pass
                                else:
                                    pass
                            else:
                                pass

    if not auto:
        confirmd = input(
            "  You have provided '{}' as the path containing the artefacts.\n  The directory must contain all of the hosts (as directories) you wish to process, each with their respective artefacts within (with no subdirectories).\n    Please note that the names of the artefacts MUST match the original filenames as named on the original host.\n  Continue? Y/n [Y] ".format(
                d
            )
        )
        if confirmd == "n":
            print(
                "\n  OK. Please ensure the directory you provide adheres to the required structure.\n\n"
            )
            sys.exit()
        else:
            pass
    else:
        pass
    d = str(str(d) + "/").replace("//", "/")
    if len(d.split("/")) < 3:
        print(
            "\n  '{}' is an invalid directory structure.\n   If you meant to not invoke the Collect flag (-C), please ensure the file path you provide is as follows:\n    'python3 elrond.py -npaqQvVP casename \033[1;36m./source_directory/\033[1;m'\n\n".format(
                d
            )
        )
        sys.exit()
    else:
        pass
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
        for root, dirs, files in os.walk(d):
            for f in dirs:
                if not auto:
                    wtr = input("    Do you wish to process: '{}'? Y/n [Y] ".format(f))
                else:
                    wtr = "y"
                if wtr != "n":
                    if not os.path.exists(output_directory + f):
                        os.makedirs(output_directory + f)
                    else:
                        pass
                    doReorganise(verbosity, stage, allimgs, d, output_directory, f)
                else:
                    print("    OK. '{}' will not be processed.\n".format(f))
        imgs = allimgs.copy()
    flags.append("1reorganised")
    print(
        "  ----------------------------------------\n  -> Completed Identification Phase.\n"
    )
    time.sleep(1)
