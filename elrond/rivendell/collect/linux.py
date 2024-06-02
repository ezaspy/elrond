#!/usr/bin/env python3 -tt
import os
import shutil
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.collect.users.linux import linux_users


def collect_linux_artefacts(
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
            item == mnt + "/etc/security"
            or item == mnt + "/etc/systemd"
            or item == mnt + "/etc/modules-load"
        ):
            dest = dest + "conf/"
            try:
                os.stat(dest)
            except:
                os.makedirs(dest)
            if verbosity != "":
                print(
                    "     Collecting {} configuration files for {}...".format(
                        item.split("/")[-1].lower(),
                        vssimage,
                    )
                )
            item_list = os.listdir(item)
            for each in item_list:
                if each.endswith(".conf"):
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' configuration file\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} configuration file '{}'{} from '{}'".format(
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
                            dest + item.split("/")[-1].lower() + "+" + each,
                        )
                    except:
                        pass

        if item == mnt + "/var/log":
            try:
                os.stat(dest + "logs/")
            except:
                os.makedirs(dest + "logs/")
            if verbosity != "":
                print(
                    "     Collecting {} logs for {}...".format(
                        item.split("/")[-2].lower(),
                        vssimage,
                    )
                )
            item_list = os.listdir(item)
            for eachlog in item_list:
                try:
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},'{}' log file\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                        eachlog,
                    ), " -> {} -> {} log file '{}'{} from '{}'".format(
                        datetime.now().isoformat().replace("T", " "),
                        stage,
                        eachlog,
                        vsstext.replace("vss", "volume shadow copy #"),
                        img.split("::")[0],
                    )
                    write_audit_log_entry(
                        verbosity,
                        output_directory,
                        entry,
                        prnt,
                    )
                    shutil.copy2(
                        item + "/" + eachlog,
                        dest + "logs/" + item.split("/")[-2].lower() + "+" + eachlog,
                    )
                except:
                    pass

        if item == mnt + "/var/log/journal":
            try:
                os.stat(dest + "journal/")
            except:
                os.makedirs(dest + "journal/")
            if verbosity != "":
                print(
                    "     Collecting journal logs for {}...".format(
                        vssimage,
                    )
                )
            item_list = os.listdir(item)
            for eachdir in item_list:
                if os.path.isdir(os.path.join(item, eachdir)) and "journal" in os.path.join(item, eachdir):
                    try:
                        os.stat(dest + "journal/")
                    except:
                        os.makedirs(dest + "journal/")
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},systemd journal files\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                    ), " -> {} -> {} systemd journal files{} from '{}'".format(
                        datetime.now().isoformat().replace("T", " "),
                        stage,
                        vsstext.replace("vss", "volume shadow copy #"),
                        img.split("::")[0],
                    )
                    write_audit_log_entry(
                        verbosity,
                        output_directory,
                        entry,
                        prnt,
                    )
                    shutil.copytree(
                        os.path.join(item, eachdir),
                        dest + "journal/" + eachdir,
                    )

        if item == mnt + "/usr/lib/systemd/user":
            try:
                os.stat(dest + "services/")
            except:
                os.makedirs(dest + "services/")
            if verbosity != "":
                print(
                    "     Collecting {} services for {}...".format(
                        item.split("/")[-2].lower(),
                        vssimage,
                    )
                )
            item_list = os.listdir(item)
            for each in item_list:
                if (
                    each.endswith(".service")
                    or each.endswith(".target")
                    or each.endswith(".socket")
                ):
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' service file\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} service file '{}'{} from '{}'".format(
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
                            dest + "services/" + each,
                        )
                    except:
                        pass

        if item == mnt + "/var/cache/cups" or item == mnt + "/var/cups":
            try:
                os.stat(dest + "jobs/")
            except:
                os.makedirs(dest + "jobs/")
            if verbosity != "":
                print(
                    "     Collecting {} jobs for {}...".format(
                        item.split("/")[-1].lower(),
                        vssimage,
                    )
                )
            item_list = os.listdir(item)
            for each in item_list:
                if each.startswith("job."):
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' job file\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} job file '{}'{} from '{}'".format(
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
                            dest + "jobs/" + each,
                        )
                    except:
                        pass

        if item == mnt + "/tmp":
            try:
                os.stat(dest + "tmp/")
            except:
                os.makedirs(dest + "tmp/")
            if verbosity != "":
                print("     Collecting content of /tmp for {}...".format(vssimage))  #
            item_list = os.listdir(item)
            for each in item_list:
                if not os.path.isdir(each):
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' temp file\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} temp file '{}'{} from '{}'".format(
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
                        ) = "{},{},{},'{}' /tmp directory\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            each,
                        ), " -> {} -> {} /tmp directory '{}'{} from '{}'".format(
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

        if item == mnt + "/root":
            if os.path.exists(item + "/.bash_history"):
                if verbosity != "":
                    print(
                        "     Collecting bash files for '{}' for {}...".format(
                            item.split("/")[-1], vssimage
                        )
                    )
                (
                    entry,
                    prnt,
                ) = "{},{},{},'{}' bash files\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    item.split("/")[-1],
                ), " -> {} -> {} '{}'{} bash files from '{}'".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage,
                    item.split("/")[-1],
                    vsstext.replace("vss", "volume shadow copy #"),
                    img.split("::")[0],
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                try:
                    shutil.copy2(
                        item + "/.bash_aliases",
                        dest + item.split("/")[-1] + "+bash_aliases",
                    )
                    shutil.copy2(
                        item + "/.bash_history",
                        dest + item.split("/")[-1] + "+bash_history",
                    )
                    shutil.copy2(
                        item + "/.bash_logout",
                        dest + item.split("/")[-1] + "+bash_logout",
                    )
                    shutil.copy2(
                        item + "/.bashrc",
                        dest + item.split("/")[-1] + "+bashrc",
                    )
                    shutil.copy2(
                        item + "/.bash_session",
                        dest + item.split("/")[-1] + "+bash_session",
                    )
                except:
                    pass
            if os.path.exists(item + "/.local/share/keyrings/"):
                if verbosity != "":
                    print(
                        "     Collecting keys for 'root' for {}...".format(vssimage)
                    )  #
                for keytype in os.listdir(item + "/.local/share/keyrings/"):
                    if keytype.endswith(".keyring") or keytype.endswith(".keystore"):
                        try:
                            (
                                entry,
                                prnt,
                            ) = "{},{},{},'root' {}\n".format(
                                datetime.now().isoformat(),
                                img.split("::")[0],
                                stage,
                                keytype.split(".key")[1],
                            ), " -> {} -> {} {} for profile 'root'{} from '{}'".format(
                                datetime.now().isoformat().replace("T", " "),
                                stage,
                                keytype.split(".key")[1],
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
                                item + "/.local/share/keyrings/" + keytype,
                                dest + "root--" + keytype,
                            )
                        except:
                            pass
        if item == mnt + "/home":
            dest = linux_users(
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
