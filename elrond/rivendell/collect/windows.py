#!/usr/bin/env python3 -tt
import os
import shutil
from datetime import datetime

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry
from rivendell.collect.users.windows import windows_users


def collect_windows_artefacts(
    artefact_directory,
    dest,
    img,
    item,
    mnt,
    output_directory,
    stage,
    symlinkvalue,
    userprofiles,
    verbosity,
    volatility,
    vssimage,
    vsstext,
):
    if not os.path.isdir(item):  # files
        if (
            "$MFT" in item
            or "$LogFile" in item
            or "$UsnJrnl" in item
            or "$ObjId" in item
            or "$Reparse" in item
        ):
            if verbosity != "":
                print(
                    "     Collecting '{}' for {}...".format(
                        item.split("/")[-1], vssimage
                    )
                )
            else:
                pass
            entry, prnt = "{},{},{},'{}'\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                item.split("/")[-1],
            ), " -> {} -> {} '{}'{} from '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                item.split("/")[-1],
                vsstext.replace("vss", "volume shadow copy #"),
                img.split("::")[0],
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            try:
                shutil.copy2(item, dest)
            except:
                pass
            print_done(verbosity)
        else:
            pass
        if item == mnt + "/Windows/inf/setupapi.dev.log":
            if verbosity != "":
                print("     Collecting 'setupapi.dev.log' for {}...".format(vssimage))
            else:
                pass
            (entry, prnt,) = "{},{},{},'setupapi.dev.log'\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
            ), " -> {} -> {} 'setupapi.dev.log'{} from '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                vsstext.replace("vss", "volume shadow copy #"),
                img.split("::")[0],
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            try:
                shutil.copy2(item, dest)
            except:
                pass
            print_done(verbosity)
        else:
            pass
        if (
            item == mnt + "/Windows/AppCompat/Programs/RecentFileCache.bcf"
            or item == mnt + "/Windows/AppCompat/Programs/Amcache.hve"
        ):
            if verbosity != "":
                print(
                    "     Collecting '{}' for {}...".format(
                        item.split("/")[-1], vssimage
                    )
                )
            else:
                pass
            entry, prnt = "{},{},{},'{}'\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                item.split("/")[-1],
            ), " -> {} -> {} '{}'{} from '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                item.split("/")[-1],
                vsstext.replace("vss", "volume shadow copy #"),
                img.split("::")[0],
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            try:
                shutil.copy2(item, dest)
                if "vss" in mnt:
                    shutil.copy2(
                        mnt + "/Windows/System32/config/SYSTEM",
                        artefact_directory + "/raw/" + mnt.split("/")[-1] + "/.SYSTEM",
                    )
                else:
                    shutil.copy2(
                        mnt + "/Windows/System32/config/SYSTEM",
                        artefact_directory + "/raw/.SYSTEM",
                    )
            except:
                pass
            print_done(verbosity)
        else:
            pass
    elif len(os.listdir(item)) > 0:  # directories
        """if item == mnt + "/Windows/System32/config/":
            dest = dest + "registry/"
            try:
                os.stat(dest)
            except:
                os.makedirs(dest)
            if verbosity != "":
                print(
                    "     Collecting system registry hives{} for {}...".format(
                        vsstext, vssimage
                    )
                )
            else:
                pass
            item_list = os.listdir(item)
            for each in item_list:
                if (
                    each == "SAM"
                    or each == "SECURITY"
                    or each == "SOFTWARE"
                    or each == "SYSTEM"
                    or each == "SAM.LOG"
                    or each == "SECURITY.LOG"
                    or each == "SOFTWARE.LOG"
                    or each == "SYSTEM.LOG"
                    or each == "SAM.LOG1"
                    or each == "SECURITY.LOG1"
                    or each == "SOFTWARE.LOG1"
                    or each == "SYSTEM.LOG1"
                    or each == "SAM.LOG2"
                    or each == "SECURITY.LOG2"
                    or each == "SOFTWARE.LOG2"
                    or each == "SYSTEM.LOG2"
                ):
                    try:
                        (entry, prnt,) = "{},{},{},'{}' registry hive\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} registry hive '{}'{} from '{}'".format(
                            datetime.now().isoformat().replace("T", " "),
                            stage,
                            each,
                            vsstext.replace(
                                "vss",
                                "volume shadow copy #",
                            ),
                            img.split("::")[0],
                        )
                        write_audit_log_entry(
                            verbosity,
                            output_directory,
                            entry,
                            prnt,
                        )
                        shutil.copy2(item + each, dest)
                    except:
                        pass
                else:
                    pass
            print_done(verbosity)
        else:
            pass
        if item == mnt + "/Windows/System32/winevt/Logs/":
            item_list, dest = (
                os.listdir(item),
                dest + "evt/",
            )
            try:
                os.stat(dest)
            except:
                os.makedirs(dest)
            if len(item_list) > 0:
                if verbosity != "":
                    print(
                        "     Collecting Windows Event logs for {}...".format(vssimage)
                    )
                else:
                    pass
                for each in item_list:
                    (entry, prnt,) = "{},{},{},'{}' event log\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                        each,
                    ), " -> {} -> {} event log '{}'{} from '{}'".format(
                        datetime.now().isoformat().replace("T", " "),
                        stage,
                        each,
                        vsstext.replace("vss", "volume shadow copy #"),
                        img.split("::")[0],
                    )
                    write_audit_log_entry(
                        verbosity,
                        output_directory,
                        entry,
                        prnt,
                    )
                    try:
                        shutil.copy2(item + each, dest)
                    except:
                        pass
                print_done(verbosity)
            else:
                pass
        else:
            pass"""
        if item == mnt + "/$Recycle.Bin":
            item_list, dest = (
                os.listdir(item),
                dest + "deleted/",
            )
            try:
                os.makedirs(dest)
            except:
                pass
            if verbosity != "":
                print("     Collecting deleted files for {}...".format(vssimage))
            else:
                pass
            for each in item_list:
                shutil.copytree(
                    item + "/" + each,
                    dest + each,
                    symlinks=symlinkvalue,
                )
                (entry, prnt,) = "{},{},{},'{}' deleted file\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    each,
                ), " -> {} -> {} deleted artefacts for profile '{}'{} from '{}'".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage,
                    each,
                    vsstext.replace("vss", "volume shadow copy #"),
                    img.split("::")[0],
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
            print_done(verbosity)
        else:
            pass
        if item == mnt + "/Windows/Prefetch/":
            item_list, dest = (
                os.listdir(item),
                dest + "prefetch/",
            )
            try:
                os.makedirs(dest)
            except:
                pass
            if len(item_list) > 0:
                if verbosity != "":
                    print("     Collecting prefetch files for {}...".format(vssimage))
                else:
                    pass
                for each in item_list:
                    (entry, prnt,) = "{},{},{},'{}' prefetch file\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                        each,
                    ), " -> {} -> {} prefetch file '{}'{} from '{}'".format(
                        datetime.now().isoformat().replace("T", " "),
                        stage,
                        each,
                        vsstext.replace("vss", "volume shadow copy #"),
                        img.split("::")[0],
                    )
                    write_audit_log_entry(
                        verbosity,
                        output_directory,
                        entry,
                        prnt,
                    )
                    try:
                        shutil.copy2(item + each, dest)
                    except:
                        pass
                print_done(verbosity)
            else:
                pass
        else:
            pass
        if item == mnt + "/Users/":
            windows_users(
                dest,
                img,
                item,
                output_directory,
                stage,
                symlinkvalue,
                userprofiles,
                verbosity,
                vssimage,
                vsstext,
            )
        else:
            pass
        if volatility and item == mnt + "/":
            item_list = os.listdir(item)
            if len(item_list) > 0:
                if verbosity != "":
                    print("     Collecting memory files...")
                else:
                    pass
                for each in item_list:
                    if (
                        item + each == mnt + "/hiberfil.sys"
                        or item + each == mnt + "/pagefile.sys"
                        or item + each == mnt + "/swapfile.sys"
                        or item + each == mnt + "/MEMORY.DMP"
                        or item + each == mnt + "/Windows/MEMORY.DMP"
                    ):
                        if not os.path.exists(dest + each):
                            (entry, prnt,) = "{},{},{},'{}' memory file\n".format(
                                datetime.now().isoformat(),
                                vssimage,
                                stage,
                                each,
                            ), " -> {} -> {} '{}' memory file from {}".format(
                                datetime.now().isoformat().replace("T", " "),
                                stage,
                                each,
                                vssimage,
                            )
                            write_audit_log_entry(
                                verbosity,
                                output_directory,
                                entry,
                                prnt,
                            )
                            shutil.copy2(item + each, dest + each)
                    else:
                        pass
                print_done(verbosity)
            else:
                pass
        else:
            pass
    else:
        pass
