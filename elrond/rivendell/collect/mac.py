#!/usr/bin/env python3 -tt
import os
import shutil
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.collect.users.mac import mac_users


def collect_mac_artefacts(
    dest,
    img,
    item,
    mnt,
    output_directory,
    sha256,
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
            item == mnt + "/etc/passwd"
            or item == mnt + "/etc/shadow"
            or item == mnt + "/etc/group"
        ):
            if verbosity != "":
                print(
                    "     Collecting '/etc/{}' for {}...".format(
                        item.split("/")[-1], vssimage
                    )
                )
            entry, prnt = "{},{},{},'{}'\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                item,
            ), " -> {} -> {} '/etc/{}' file from '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                item.split("/")[-1],
                img.split("::")[0],
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            try:
                shutil.copy2(item, dest)
            except:
                pass

        if item == mnt + "/etc/hosts":
            if verbosity != "":
                print("     Collecting '/etc/hosts' for {}...".format(vssimage))
            entry, prnt = "{},{},{},'/etc/hosts'\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
            ), " -> {} -> {} '/etc/hosts' from '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                img.split("::")[0],
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            try:
                shutil.copy2(item, dest)
            except:
                pass

        if item == mnt + "/etc/crontab":
            if verbosity != "":
                print("     Collecting crontab for {}...".format(vssimage))
            entry, prnt = "{},{},{},'{}'\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                item,
            ), " -> {} -> {} '{}'{} from '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                item,
                vsstext.replace("vss", "volume shadow copy #"),
                img.split("::")[0],
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            try:
                shutil.copy2(item, dest)
            except:
                pass

    elif len(os.listdir(item)) > 0:  # directories
        if (
            item == mnt + "/Library/Logs"
            or item == mnt + "/etc/security"
            or item == mnt + "/var/log"
        ):
            try:
                os.stat(dest + "logs/")
            except:
                os.makedirs(dest + "logs/")
            if verbosity != "":
                if "etc/security" not in item:
                    print(
                        "     Collecting {} logs for {}...".format(
                            item.split("/")[-2].lower(),
                            vssimage,
                        )
                    )
                else:
                    print(
                        "     Collecting {} logs for {}...".format(
                            item.split("/")[-1].lower(),
                            vssimage,
                        )
                    )
            item_list = os.listdir(item)
            for each in item_list:
                try:
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},'{}' file\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                        each,
                    ), " -> {} -> {} log '{}' from '{}'".format(
                        datetime.now().isoformat().replace("T", " "),
                        stage,
                        each,
                        img.split("::")[0],
                    )
                    write_audit_log_entry(
                        verbosity,
                        output_directory,
                        entry,
                        prnt,
                    )
                    if "etc/security" not in item:
                        prefix = item.split("/")[-2].lower() + "+"
                    else:
                        prefix = item.split("/")[-1].lower() + "+"
                    shutil.copy2(
                        item + "/" + each,
                        dest + "logs/" + prefix + each,
                    )
                except:
                    pass

        if (
            item == mnt + "/Library/Preferences"
            or item == mnt + "/Library/LaunchAgents"
            or item == mnt + "/Library/LaunchDaemons"
            or item == mnt + "/Library/StartupItems"
            or item == mnt + "/System/Library/Preferences"
            or item == mnt + "/System/Library/LaunchAgents"
            or item == mnt + "/System/Library/LaunchDaemons"
            or item == mnt + "/System/Library/StartupItems"
        ):
            try:
                os.stat(dest + "plists/")
            except:
                os.makedirs(dest + "plists/")
            if verbosity != "":
                if "System" in item:
                    print(
                        "     Collecting {} for {}...".format(
                            item.split("/")[-3].lower()
                            + " "
                            + item.split("/")[-1].lower(),
                            vssimage,
                        )
                    )
                else:
                    print(
                        "     Collecting {} for {}...".format(
                            item.split("/")[-2].lower()
                            + " "
                            + item.split("/")[-1].lower(),
                            vssimage,
                        )
                    )
            item_list = os.listdir(item)
            for each in item_list:
                if each.endswith(".plist"):
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' plist\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} plist '{}' from '{}'".format(
                            datetime.now().isoformat().replace("T", " "),
                            stage,
                            each,
                            img.split("::")[0],
                        )
                        write_audit_log_entry(
                            verbosity,
                            output_directory,
                            entry,
                            prnt,
                        )
                        if "System" in item:
                            prefix = (
                                item.split("/")[-3].lower()
                                + "+"
                                + item.split("/")[-1].lower()
                                + "-"
                            )
                        else:
                            prefix = item.split("/")[-1].lower() + "+"
                        shutil.copy2(
                            item + "/" + each,
                            dest + "plists/" + prefix + each,
                        )
                    except:
                        pass

        if item == mnt + "/.Trashes":
            dest = dest + "trash/"
            try:
                os.stat(dest + "trash/")
            except:
                os.makedirs(dest + "trash/")
            if verbosity != "":
                print("     Collecting trash files for {}...".format(vssimage))  #
            item_list = os.listdir(item)
            for each in item_list:
                try:
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},'{}' trash file\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                        each,
                    ), " -> {} -> {} trash file '{}'{} from '{}'".format(
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
                    shutil.copy2(item + "/" + each, dest + "trash/")
                except:
                    pass

        if item == mnt + "/tmp":
            try:
                os.stat(dest + "tmp/")
            except:
                os.makedirs(dest + "tmp/")
            if verbosity != "":
                print("     Collecting temp files for {}...".format(vssimage))  #
            item_list = os.listdir(item)
            for each in item_list:
                if not os.path.isdir(each):
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' tmp file\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} tmp file '{}'{} from '{}'".format(
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
                        shutil.copy2(
                            item + "/" + each,
                            dest + "tmp/" + each,
                        )
                    except:
                        pass
                else:
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' tmp directory\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} tmp directory '{}'{} from '{}'".format(
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
                        shutil.copytree(
                            item + "/" + each,
                            dest + "tmp/" + each,
                        )
                    except:
                        pass

        if item == mnt + "/Users/":
            dest = mac_users(
                dest,
                img,
                item,
                output_directory,
                stage,
                sha256,
                symlinkvalue,
                userprofiles,
                verbosity,
                vssimage,
                vsstext,
            )
        if volatility and item == mnt + "/":
            item_list = os.listdir(item)
            if len(item_list) > 0:
                if verbosity != "":
                    print("     Collecting memory files...")
                for each in item_list:
                    if (
                        item == mnt + "/var/vm/sleepimage"
                        or item == mnt + "/var/vm/swapfile"
                    ):
                        if not os.path.exists(dest + each):
                            (
                                entry,
                                prnt,
                            ) = "{},{},{},'{}'\n".format(
                                datetime.now().isoformat(),
                                img.split("::")[0],
                                stage,
                                each,
                            ), " -> {} -> {} '{}'{} from '{}'".format(
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
                            shutil.copy2(item + each, dest + each)
