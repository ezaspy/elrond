#!/usr/bin/env python3 -tt
import os
import shutil
from datetime import datetime

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry


def linux_users(
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
):
    (item_list, bwsrdest, userdest, bashfiles, usedfiles,) = (
        os.listdir(item),
        dest + "browsers/",
        dest + "user_profiles",
        [
            "bash_aliases",
            "bash_history",
            "bash_logout",
            "bashrc",
            "bash_session",
        ],
        ["recently-used.xbel"],
    )
    for each in item_list:
        if os.path.isdir(item + "/" + each):
            if os.path.exists(item + "/" + each + "/.local/share/recently-used.xbel"):
                if verbosity != "":
                    print(
                        "     Collecting recently used files for '{}' for {}...".format(
                            each, vssimage
                        )
                    )
                else:
                    pass
                for eachused in usedfiles:
                    try:
                        shutil.copy2(
                            item + "/" + each + "/.local/share/" + eachused,
                            dest + each + "+" + eachused,
                        )
                        (entry, prnt,) = "{},{},{},'{}' ({})\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            eachused,
                            each,
                        ), " -> {} -> {} '{}' ({}) file for '{}'".format(
                            datetime.now().isoformat().replace("T", " "),
                            stage,
                            eachused,
                            each,
                            img.split("::")[0],
                        )
                        write_audit_log_entry(
                            verbosity,
                            output_directory,
                            entry,
                            prnt,
                        )
                    except:
                        pass
                print_done(verbosity)
            else:
                pass
            if (
                os.path.exists(item + "/" + each + "/.bash_aliases")
                or os.path.exists(item + "/" + each + "/.bash_history")
                or os.path.exists(item + "/" + each + "/.bash_logout")
                or os.path.exists(item + "/" + each + "/.bashrc")
                or os.path.exists(item + "/" + each + "/.bash_session")
            ):
                if verbosity != "":
                    print(
                        "     Collecting bash files for '{}' for {}...".format(
                            each, vssimage
                        )
                    )
                else:
                    pass
                for eachbash in bashfiles:
                    try:
                        shutil.copy2(
                            item + "/" + each + "/." + eachbash,
                            dest + each + "+" + eachbash,
                        )
                        (entry, prnt,) = "{},{},{},'{}' ({})\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            eachbash,
                            each,
                        ), " -> {} -> {} '{}' ({}) file for '{}'".format(
                            datetime.now().isoformat().replace("T", " "),
                            stage,
                            eachbash,
                            each,
                            img.split("::")[0],
                        )
                        write_audit_log_entry(
                            verbosity,
                            output_directory,
                            entry,
                            prnt,
                        )
                    except:
                        pass
                print_done(verbosity)
            else:
                pass
            if os.path.exists(item + "/" + each + "/.local/share/keyrings/"):
                if verbosity != "":
                    print(
                        "     Collecting keys for '{}' for {}...".format(each, vssimage)
                    )
                else:
                    pass
                for keytype in os.listdir(
                    item + "/" + each + "/.local/share/keyrings/"
                ):
                    if keytype.endswith(".keyring") or keytype.endswith(".keystore"):
                        try:
                            (entry, prnt,) = "{},{},{},key{} ({})\n".format(
                                datetime.now().isoformat(),
                                img.split("::")[0],
                                stage,
                                keytype.split(".key")[1],
                                each,
                            ), " -> {} -> {} 'key{}' ({}) for '{}'".format(
                                datetime.now().isoformat().replace("T", " "),
                                stage,
                                keytype.split(".key")[1],
                                each,
                                img.split("::")[0],
                            )
                            write_audit_log_entry(
                                verbosity,
                                output_directory,
                                entry,
                                prnt,
                            )
                            shutil.copy2(
                                item + "/" + each + "/.local/share/keyrings/" + keytype,
                                dest + each + "+" + keytype,
                            )
                        except:
                            pass
                    else:
                        pass
                print_done(verbosity)
            else:
                pass
            if os.path.exists(item + "/" + each + "/.ssh/"):
                if verbosity != "":
                    print(
                        "     Collecting '{}' ssh files for {}...".format(
                            each, vssimage
                        )
                    )
                else:
                    pass
                (entry, prnt,) = "{},{},{},ssh files\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                ), " -> {} -> {} ssh files for profile '{}'{} for '{}'".format(
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
                for eachssh in os.listdir(item + "/" + each + "/.ssh/"):
                    try:
                        shutil.copy2(
                            item + "/" + each + "/.ssh/" + eachssh,
                            dest + "/" + each + "+" + eachssh,
                        )
                    except:
                        pass
                print_done(verbosity)
            else:
                pass
            if os.path.exists(item + "/" + each + "/.config/autostart/"):
                if verbosity != "":
                    print(
                        "     Collecting '{}' autostart files for {}...".format(
                            each, vssimage
                        )
                    )
                else:
                    pass
                (entry, prnt,) = "{},{},{},autostart files\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                ), " -> {} -> {} autostart files for profile '{}'{} for '{}'".format(
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
                for eachauto in os.listdir(item + "/" + each + "/.config/autostart/"):
                    try:
                        shutil.copy2(
                            item + "/" + each + "/.config/autostart/" + eachauto,
                            dest + "/" + each + "+" + eachauto,
                        )
                    except:
                        pass
                print_done(verbosity)
            else:
                pass
            if os.path.exists(
                item + "/" + each + "/.local/share/Trash/files"
            ) or os.path.exists(item + "/" + each + "/.local/share/Trash/info"):
                if not os.path.exists(dest + "/deleted/"):
                    os.makedirs(dest + "/deleted/")
                else:
                    pass
                if verbosity != "":
                    print(
                        "     Collecting '{}' deleted files for {}...".format(
                            each, vssimage
                        )
                    )
                else:
                    pass
                (entry, prnt,) = "{},{},{},deleted files\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                ), " -> {} -> {} deleted files for profile '{}'{} for '{}'".format(
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
                for eachdelfile in os.listdir(
                    item + "/" + each + "/.local/share/Trash/files"
                ):
                    try:
                        shutil.copy2(
                            item
                            + "/"
                            + each
                            + "/.local/share/Trash/files/"
                            + eachdelfile,
                            dest + "/deleted/" + each + "+" + eachdelfile,
                        )
                    except:
                        pass
                for eachdelinfo in os.listdir(
                    item + "/" + each + "/.local/share/Trash/info"
                ):
                    try:
                        shutil.copy2(
                            item
                            + "/"
                            + each
                            + "/.local/share/Trash/info/"
                            + eachdelinfo,
                            dest + "/deleted/" + each + "+" + eachdelinfo,
                        )
                    except:
                        pass
                print_done(verbosity)
            else:
                pass
            if os.path.exists(item + "/" + each + "/.thunderbird"):
                if not os.path.exists(dest + "/mail/"):
                    os.makedirs(dest + "/mail/")
                else:
                    pass
                if verbosity != "":
                    print(
                        "     Collecting '{}' mail artefacts for {}...".format(
                            each, vssimage
                        )
                    )
                else:
                    pass
                (entry, prnt,) = "{},{},{},mail artefacts\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                ), " -> {} -> {} mail artefacts for profile '{}'{} for '{}'".format(
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
                for eachmail in os.listdir(item + "/" + each + "/.thunderbird"):
                    if eachmail.endswith(".default"):
                        try:
                            shutil.copytree(
                                item + "/" + each + "/.thunderbird/" + eachmail,
                                dest + "/mail/" + each + "+" + eachmail,
                            )
                        except:
                            pass
                    else:
                        pass
                    mailfiles = [
                        "global-messages-db.sqlite",
                        "places.sqlite",
                        "downloads.sqlite",
                        "panacea.dat",
                    ]
                    for mailfile in mailfiles:
                        if os.path.exists(
                            item
                            + "/"
                            + each
                            + "/.thunderbird/"
                            + eachmail
                            + "/"
                            + mailfile
                        ):
                            try:
                                shutil.copy2(
                                    item
                                    + "/"
                                    + each
                                    + "/.thunderbird/"
                                    + eachmail
                                    + "/"
                                    + mailfile,
                                    dest + "/mail/" + each + "+" + mailfile,
                                )
                            except:
                                pass
                        else:
                            pass
                print_done(verbosity)
            if not each.startswith("."):
                try:
                    os.stat(bwsrdest + each + "/firefox/")
                except:
                    os.makedirs(bwsrdest + each + "/firefox/")
                if verbosity != "":
                    print(
                        "     Collecting Mozilla Firefox browser artefacts for '{}' for {}...".format(
                            each, vssimage
                        )
                    )
                else:
                    pass
                if os.path.exists(item + "/" + each + "/.mozilla/firefox"):
                    for defaultdir in os.listdir(
                        item + "/" + each + "/.mozilla/firefox"
                    ):
                        if ".default" in defaultdir:
                            try:
                                (
                                    entry,
                                    prnt,
                                ) = "{},{},{},'{}' Mozilla Firefox browser artefacts\n".format(
                                    datetime.now().isoformat(),
                                    img.split("::")[0],
                                    stage,
                                    each,
                                ), " -> {} -> {} '{}' Mozilla Firefox browser artefacts{} for '{}'".format(
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
                                    item
                                    + "/"
                                    + each
                                    + "/.mozilla/firefox/"
                                    + defaultdir
                                    + "/places.sqlite",
                                    bwsrdest + each + "/firefox/",
                                )
                                shutil.copy2(
                                    item
                                    + "/"
                                    + each
                                    + "/.mozilla/firefox/"
                                    + defaultdir
                                    + "/downloads.sqlite",
                                    bwsrdest + each + "/firefox/",
                                )
                            except:
                                pass
                        else:
                            pass
                    print_done(verbosity)
                else:
                    pass
                try:
                    os.stat(bwsrdest + each + "/chrome/")
                except:
                    os.makedirs(bwsrdest + each + "/chrome/")
                if verbosity != "":
                    print(
                        "     Collecting Google Chrome browser artefacts for '{}' for {}...".format(
                            each, vssimage
                        )
                    )
                else:
                    pass
                if os.path.exists(item + "/" + each + "/.config/google-chrome"):
                    for defaultdir in os.listdir(
                        item + "/" + each + "/.config/google-chrome"
                    ):
                        if defaultdir == "Default":
                            try:
                                (
                                    entry,
                                    prnt,
                                ) = "{},{},{},'{}' Google Chrome browser artefacts\n".format(
                                    datetime.now().isoformat(),
                                    img.split("::")[0],
                                    stage,
                                    each,
                                ), " -> {} -> {} '{}' Google Chrome browser artefacts{} for '{}'".format(
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
                                    item
                                    + "/"
                                    + each
                                    + "/.config/google-chrome"
                                    + defaultdir
                                    + "/History",
                                    bwsrdest + each + "/chrome/",
                                )
                                shutil.copy2(
                                    item
                                    + "/"
                                    + each
                                    + "/.config/google-chrome"
                                    + defaultdir
                                    + "/History",
                                    bwsrdest + each + "/chrome/",
                                )
                            except:
                                pass
                        else:
                            pass
                    print_done(verbosity)
                else:
                    pass
            else:
                pass

            if os.path.exists(
                item + each + "/Library/Application Support/Google/Chrome/Default/"
            ):
                if (
                    len(
                        os.listdir(
                            item
                            + each
                            + "/Library/Application Support/Google/Chrome/Default/"
                        )
                    )
                    > 0
                ):
                    if verbosity != "":
                        print(
                            "     Collecting Google Chrome browser artefacts for '{}' for {}...".format(
                                each, vssimage
                            )
                        )
                    else:
                        pass
                    (entry, prnt,) = "{},{},{},Google Chrome artefacts\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                    ), " -> {} -> {} Google Chrome artefacts{} for '{}'".format(
                        datetime.now().isoformat().replace("T", " "),
                        stage,
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
                    for every in os.listdir(
                        item
                        + each
                        + "/Library/Application Support/Google/Chrome/Default/"
                    ):
                        try:
                            os.stat(bwsrdest + each + "/chrome/")
                        except:
                            os.makedirs(bwsrdest + each + "/chrome/")
                        try:
                            if every == "History":
                                shutil.copy2(
                                    item
                                    + each
                                    + "/Library/Application Support/Google/Chrome/Default/"
                                    + every,
                                    bwsrdest + each + "/chrome/",
                                )
                            elif every == "Local Storage":
                                shutil.copytree(
                                    item
                                    + each
                                    + "/Library/Application Support/Google/Chrome/Default/"
                                    + every,
                                    bwsrdest + each + "/chrome/Local Settings",
                                    symlinks=symlinkvalue,
                                )
                            else:
                                pass
                        except:
                            pass
                    print_done(verbosity)
                else:
                    pass
            else:
                pass

            if userprofiles:
                try:
                    os.stat(userdest)
                except:
                    os.makedirs(userdest)
                if verbosity != "":
                    print(
                        "     Collecting user profile for '{}' for {}...".format(
                            each, vssimage
                        )
                    )
                else:
                    pass
                (entry, prnt,) = "{},{},{},'{}' user profile\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    each,
                ), " -> {} -> {} '{}' user profile{} for '{}'".format(
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
                try:
                    shutil.copytree(
                        item + "/" + each,
                        userdest + "/" + each,
                        symlinks=symlinkvalue,
                    )
                except:
                    pass
                print_done(verbosity)
            else:
                pass
        else:
            pass
