#!/usr/bin/env python3 -tt
import os
import shutil
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.collect.users.windows import windows_users


def check_existence(item, dest, occurance):
    dest = os.path.join(dest, "#{}{}".format(str(occurance), item.split("/")[-1]))
    if os.path.exists(dest):
        occurance += 1
        split_dest = dest.split("/")
        split_dest.pop()
        dest = check_existence(item, "/".join(split_dest), str(occurance))
    return dest


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
            if os.path.exists(os.path.join(dest, item.split("/")[-1])):
                dest = check_existence(item, dest, 1)
            try:
                shutil.copy2(item, dest)
            except:
                pass
        if item == mnt + "/Windows/inf/setupapi.dev.log":
            if verbosity != "":
                print("     Collecting 'setupapi.dev.log' for {}...".format(vssimage))
            (
                entry,
                prnt,
            ) = "{},{},{},'setupapi.dev.log'\n".format(
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
            if os.path.exists(os.path.join(dest, item.split("/")[-1])):
                dest = check_existence(item, dest, 1)
            try:
                shutil.copy2(item, dest)
            except:
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
            if os.path.exists(os.path.join(dest, item.split("/")[-1])):
                dest = check_existence(item, dest, 1)
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
    elif len(os.listdir(item)) > 0:  # directories
        if item == mnt + "/Windows/System32/config/":
            dest = dest + "registry/"
            try:
                os.stat(dest)
            except:
                os.makedirs(dest)
            if verbosity != "":
                print(
                    "     Collecting system registry hives for {}...".format(vssimage)
                )
            item_list = os.listdir(item)
            for each in item_list:
                if (
                    each.endswith("SAM")
                    or each.endswith("SECURITY")
                    or each.endswith("SOFTWARE")
                    or each.endswith("SYSTEM")
                    or each.endswith("SAM.LOG")
                    or each.endswith("SECURITY.LOG")
                    or each.endswith("SOFTWARE.LOG")
                    or each.endswith("SYSTEM.LOG")
                    or each.endswith("SAM.LOG1")
                    or each.endswith("SECURITY.LOG1")
                    or each.endswith("SOFTWARE.LOG1")
                    or each.endswith("SYSTEM.LOG1")
                    or each.endswith("SAM.LOG2")
                    or each.endswith("SECURITY.LOG2")
                    or each.endswith("SOFTWARE.LOG2")
                    or each.endswith("SYSTEM.LOG2")
                ):
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' registry hive\n".format(
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
                        if os.path.exists(
                            os.path.join(dest, item.split("/")[-1], each)
                        ):
                            dest = check_existence(
                                os.path.join(item.split("/")[-1], each), dest, 1
                            )
                        shutil.copy2(item + each, dest)
                    except:
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
                for each in item_list:
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' event log\n".format(
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
                        if os.path.exists(
                            os.path.join(dest, item.split("/")[-1], each)
                        ):
                            dest = check_existence(
                                os.path.join(item.split("/")[-1], each), dest, 1
                            )
                        shutil.copy2(item + each, dest)
                    except:
                        pass
        if (
            item == mnt + "/Windows/System32/wbem/Repository/"
            or item == mnt + "/Windows/System32/wbem/Logs/"
        ):
            item_list, dest = (
                os.listdir(item),
                dest + "wbem/",
            )
            try:
                os.stat(dest)
            except:
                os.makedirs(dest)
            if len(item_list) > 0:
                if verbosity != "":
                    print(
                        "     Collecting Web-Based Enterprise Management (WBEM) evidence for {}...".format(
                            vssimage
                        )
                    )
                for each in item_list:
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' WBEM evidence\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} WBEM evidence '{}'{} from '{}'".format(
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
                        if os.path.exists(
                            os.path.join(dest, item.split("/")[-1], each)
                        ):
                            dest = check_existence(
                                os.path.join(item.split("/")[-1], each), dest, 1
                            )
                        shutil.copy2(item + each, dest)
                    except:
                        pass
        if item == mnt + "/Windows/System32/LogFiles/WMI/":
            item_list, dest = (
                os.listdir(item),
                dest + "wmi/",
            )
            try:
                os.stat(dest)
            except:
                os.makedirs(dest)
            if len(item_list) > 0:
                if verbosity != "":
                    print(
                        "     Collecting Windows Management Instrumentation (WMI) artefacts for {}...".format(
                            vssimage
                        )
                    )
                for each in item_list:
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' WMI artefact\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} WMI artefact '{}'{} from '{}'".format(
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
                        if os.path.exists(
                            os.path.join(dest, item.split("/")[-1], each)
                        ):
                            dest = check_existence(
                                os.path.join(item.split("/")[-1], each), dest, 1
                            )
                        shutil.copy2(item + each, dest)
                    except:
                        pass
                    if os.path.exists(item + "RtBackup"):
                        backup_list = os.listdir(item + "RtBackup")
                        if len(backup_list) > 0:
                            for each_backup in backup_list:
                                try:
                                    (
                                        entry,
                                        prnt,
                                    ) = "{},{},{},'{}' WMI artefact\n".format(
                                        datetime.now().isoformat(),
                                        img.split("::")[0],
                                        stage,
                                        each_backup,
                                    ), " -> {} -> {} WMI artefact '{}'{} from '{}'".format(
                                        datetime.now().isoformat().replace("T", " "),
                                        stage,
                                        each_backup,
                                        vsstext.replace("vss", "volume shadow copy #"),
                                        img.split("::")[0],
                                    )
                                    write_audit_log_entry(
                                        verbosity,
                                        output_directory,
                                        entry,
                                        prnt,
                                    )
                                    if os.path.exists(
                                        os.path.join(dest, item.split("/")[-1], each)
                                    ):
                                        dest = check_existence(
                                            os.path.join(item.split("/")[-1], each),
                                            dest,
                                            1,
                                        )
                                    shutil.copy2(item + each, dest)
                                except:
                                    pass
                            if os.path.exists(item + "RtBackup/EtwRT"):
                                etwrt_list = os.listdir(item + "RtBackup/EtwRT")
                                if len(etwrt_list) > 0:
                                    for each_etwrt in etwrt_list:
                                        try:
                                            (
                                                entry,
                                                prnt,
                                            ) = "{},{},{},'{}' WMI artefact\n".format(
                                                datetime.now().isoformat(),
                                                img.split("::")[0],
                                                stage,
                                                each_etwrt,
                                            ), " -> {} -> {} WMI artefact '{}'{} from '{}'".format(
                                                datetime.now()
                                                .isoformat()
                                                .replace("T", " "),
                                                stage,
                                                each_etwrt,
                                                vsstext.replace(
                                                    "vss", "volume shadow copy #"
                                                ),
                                                img.split("::")[0],
                                            )
                                            write_audit_log_entry(
                                                verbosity,
                                                output_directory,
                                                entry,
                                                prnt,
                                            )
                                            if os.path.exists(
                                                os.path.join(
                                                    dest, item.split("/")[-1], each
                                                )
                                            ):
                                                dest = check_existence(
                                                    os.path.join(
                                                        item.split("/")[-1], each
                                                    ),
                                                    dest,
                                                    1,
                                                )
                                            shutil.copy2(item + each, dest)
                                        except:
                                            pass
        if item == mnt + "/Windows/System32/LogFiles/Sum/":
            item_list, dest = (
                os.listdir(item),
                dest + "ual/",
            )
            try:
                os.stat(dest)
            except:
                os.makedirs(dest)
            if len(item_list) > 0 and ".mdb" in str(os.listdir(item)):
                if verbosity != "":
                    print(
                        "     Collecting User Access Logging (UAL) evidence for {}...".format(
                            vssimage
                        )
                    )
                for each in item_list:
                    if each.endswith(".mdb"):
                        try:
                            (
                                entry,
                                prnt,
                            ) = "{},{},{},'{}' UAL evidence\n".format(
                                datetime.now().isoformat(),
                                img.split("::")[0],
                                stage,
                                each,
                            ), " -> {} -> {} UAL evidence '{}'{} from '{}'".format(
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
                            if os.path.exists(
                                os.path.join(dest, item.split("/")[-1], each)
                            ):
                                dest = check_existence(
                                    os.path.join(item.split("/")[-1], each), dest, 1
                                )
                            shutil.copy2(item + each, dest)
                        except:
                            pass
        if item == mnt + "/Windows/System32/LogFiles/sru/":
            item_list, dest = (
                os.listdir(item),
                dest + "sru/",
            )
            try:
                os.stat(dest)
            except:
                os.makedirs(dest)
            if len(item_list) > 0 and "SRUDB.dat" in str(os.listdir(item)):
                if verbosity != "":
                    print(
                        "     Collecting System Resource Utilization (SRU) evidence for {}...".format(
                            vssimage
                        )
                    )
                for each in item_list:
                    if each.endswith("SRUDB.dat"):
                        try:
                            (
                                entry,
                                prnt,
                            ) = "{},{},{},'{}' SRU evidence\n".format(
                                datetime.now().isoformat(),
                                img.split("::")[0],
                                stage,
                                each,
                            ), " -> {} -> {} SRU evidence '{}'{} from '{}'".format(
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
                            if os.path.exists(
                                os.path.join(dest, item.split("/")[-1], each)
                            ):
                                dest = check_existence(
                                    os.path.join(item.split("/")[-1], each), dest, 1
                                )
                            shutil.copy2(item + each, dest)
                        except:
                            pass
        if item == mnt + "/$Recycle.Bin":
            item_list, dest = (
                os.listdir(item),
                dest + "deleted/",
            )
            if verbosity != "":
                print("     Collecting deleted files for {}...".format(vssimage))
            try:
                os.makedirs(dest)
            except:
                pass
            for each in item_list:
                shutil.copytree(
                    item + "/" + each,
                    dest + each,
                    symlinks=symlinkvalue,
                )
                (
                    entry,
                    prnt,
                ) = "{},{},{},'{}' deleted file\n".format(
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
                for each in item_list:
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' prefetch file\n".format(
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
                        if os.path.exists(
                            os.path.join(dest, item.split("/")[-1], each)
                        ):
                            dest = check_existence(
                                os.path.join(item.split("/")[-1], each), dest, 1
                            )
                        shutil.copy2(item + each, dest)
                    except:
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
        if volatility and item == mnt + "/":
            item_list = os.listdir(item)
            if len(item_list) > 0:
                if (
                    "hiberfil.sys" in str(os.listdir(mnt))
                    or "pagefile.sys" in str(os.listdir(mnt))
                    or "swapfile.sys" in str(os.listdir(mnt))
                    or "MEMORY.DMP" in str(os.listdir(mnt))
                ) and verbosity != "":
                    print("     Collecting memory files...")
                for each in item_list:
                    if (
                        item + each == mnt + "/hiberfil.sys"
                        or item + each == mnt + "/pagefile.sys"
                        or item + each == mnt + "/swapfile.sys"
                        or item + each == mnt + "/MEMORY.DMP"
                        or item + each == mnt + "/Windows/MEMORY.DMP"
                    ):
                        if not os.path.exists(dest + each):
                            (
                                entry,
                                prnt,
                            ) = "{},{},{},'{}' memory file\n".format(
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
