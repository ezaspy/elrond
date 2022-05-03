#!/usr/bin/env python3 -tt
import os
import shutil
from datetime import datetime

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry


def windows_users(
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
    (item_list, regdest, jumpdest, maildest, bwsrdest, userdest, mail_dirs,) = (
        os.listdir(item),
        dest + "registry/",
        dest + "jumplists",
        dest + "mail/",
        dest + "browsers/",
        dest + "user_profiles/",
        [],
    )
    for each in item_list:
        if os.path.isdir(item + each):
            try:
                os.stat(regdest)
            except:
                os.makedirs(regdest)
            if verbosity != "":
                print(
                    "     Collecting 'NTUSER.DAT' registry hive for '{}' for {}...".format(
                        each, vssimage
                    )
                )
            else:
                pass
            (entry, prnt,) = "{},{},{},'{}' (NTUSER.DAT) registry hive\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                each,
            ), " -> {} -> {} NTUSER.DAT registry hive from profile '{}'{} for '{}'".format(
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
                shutil.copy2(
                    item + each + "/NTUSER.DAT",
                    regdest + "/" + each + "+NTUSER.DAT",
                )
            except:
                pass
            print_done(verbosity)
            try:
                os.stat(regdest)
            except:
                os.makedirs(regdest)
            if verbosity != "":
                print(
                    "     Collecting 'UsrClass.dat' registry hive for '{}' for {}...".format(
                        each, vssimage
                    )
                )
            else:
                pass
            (entry, prnt,) = "{},{},{},'{}' (UsrClass.dat) registry hive\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                each,
            ), " -> {} -> {} UsrClass.dat registry hive from profile '{}'{} for '{}'".format(
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
                shutil.copy2(
                    item + each + "/AppData/Local/Microsoft/Windows/UsrClass.dat",
                    regdest + "/" + each + "+UsrClass.dat",
                )
            except:
                pass
            print_done(verbosity)
            try:
                os.stat(jumpdest)
            except:
                os.makedirs(jumpdest)
            if verbosity != "":
                print(
                    "     Collecting jumplists for '{}' for {}...".format(
                        each, vssimage
                    )
                )
            else:
                pass
            (entry, prnt,) = "{},{},{},'{}' jumplists\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                each,
            ), " -> {} -> {} jumplist artefacts for profile '{}'{} for '{}'".format(
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
                item
                + each
                + "/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/"
            ):
                for jump in os.listdir(
                    item
                    + each
                    + "/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/"
                ):
                    try:
                        shutil.copy2(
                            item
                            + each
                            + "/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/"
                            + jump,
                            jumpdest + "/" + each + "+" + jump,
                        )
                    except:
                        pass
            else:
                pass
            if os.path.exists(
                item
                + each
                + "/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/"
            ):
                for jump in os.listdir(
                    item
                    + each
                    + "/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/"
                ):
                    try:
                        shutil.copy2(
                            item
                            + each
                            + "/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/"
                            + jump,
                            jumpdest + "/" + each + "+" + jump,
                        )
                    except:
                        pass
            else:
                pass
            print_done(verbosity)
            try:
                os.stat(maildest)
            except:
                os.makedirs(maildest)
            if os.path.exists(
                item
                + each
                + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.Outlook/"
            ):
                if (
                    len(
                        os.listdir(
                            item
                            + each
                            + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.Outlook/"
                        )
                    )
                    > 0
                ):
                    for every in os.listdir(
                        item
                        + each
                        + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.Outlook/"
                    ):
                        if (
                            len(
                                os.listdir(
                                    item
                                    + each
                                    + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.Outlook/"
                                    + every
                                )
                            )
                            > 0
                        ):
                            mail_dirs.append(
                                item
                                + each
                                + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.Outlook/"
                                + every
                            )
                        else:
                            pass
                else:
                    pass
            else:
                pass
            if os.path.exists(item + each + "/Documents/Outlook Files/"):
                mail_dirs.append(item + each + "/Documents/Outlook Files/")
            else:
                pass
            if len(mail_dirs) > 0:
                if verbosity != "":
                    print(
                        "     Collecting Outlook artefacts for '{}' for {}...".format(
                            each, vssimage
                        )
                    )
                else:
                    pass
                (entry, prnt,) = "{},{},{},'{}' outlook artefacts\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    each,
                ), " -> {} -> {} outlook artefacts for '{}'{} for '{}'".format(
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
                for every in mail_dirs:
                    try:
                        os.stat(maildest + each + "/" + every.split("/")[-1])
                    except:
                        os.makedirs(maildest + each + "/" + every.split("/")[-1])
                    for everyfile in os.listdir(every):
                        try:
                            shutil.copy2(
                                every + "/" + everyfile,
                                maildest
                                + each
                                + "/"
                                + every.split("/")[-1]
                                + "/"
                                + everyfile.split("/")[-1],
                            )
                        except:
                            pass
                print_done(verbosity)
            else:
                pass
            try:
                os.stat(bwsrdest)
            except:
                os.makedirs(bwsrdest)
            if (
                os.path.exists(
                    item + each + "/AppData/Local/Microsoft/Edge/User Data/Default/"
                )
                or os.path.exists(
                    item + each + "/AppData/Local/Microsoft/Windows/History/"
                )
                or os.path.exists(
                    item
                    + each
                    + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/"
                )
            ):
                if os.path.exists(
                    item + each + "/AppData/Local/Microsoft/Edge/User Data/Default/"
                ):
                    if verbosity != "":
                        print(
                            "     Collecting Edge browser artefacts for '{}' for {}...".format(
                                each, vssimage
                            )
                        )
                    else:
                        pass
                    (entry, prnt,) = "{},{},{},Edge artefacts\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                    ), " -> {} -> {} Edge artefacts{} for '{}'".format(
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
                        item + each + "/AppData/Local/Microsoft/Edge/User Data/Default/"
                    ):
                        if every == "History":
                            try:
                                os.stat(bwsrdest + each + "/Edge/")
                            except:
                                os.makedirs(bwsrdest + each + "/Edge/")
                            if os.path.exists(
                                item
                                + each
                                + "/AppData/Local/Microsoft/Edge/User Data/Default/"
                                + every
                            ):
                                try:
                                    shutil.copy2(
                                        item
                                        + each
                                        + "/AppData/Local/Microsoft/Edge/User Data/Default/"
                                        + every,
                                        bwsrdest + each + "/Edge/" + every,
                                    )
                                except:
                                    pass
                            else:
                                pass
                        else:
                            pass
                elif os.path.exists(
                    item + each + "/AppData/Local/Microsoft/Windows/History/"
                ):
                    if verbosity != "":
                        print(
                            "     Collecting Internet Explorer browser artefacts for '{}' for {}...".format(
                                each, vssimage
                            )
                        )
                    else:
                        pass
                    (entry, prnt,) = "{},{},{},Internet Explorer artefacts\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                    ), " -> {} -> {} Internet Explorer artefacts{} for '{}'".format(
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
                        item + each + "/AppData/Local/Microsoft/Windows/History/"
                    ):
                        if (
                            every == "Content.IE5"
                            or every == "History.IE5"
                            or every == "Low"
                        ):
                            try:
                                os.stat(bwsrdest + each + "/IE/")
                            except:
                                os.makedirs(bwsrdest + each + "/IE/")
                            if (
                                len(
                                    os.listdir(
                                        item
                                        + each
                                        + "/AppData/Local/Microsoft/Windows/History/"
                                        + every
                                    )
                                )
                                > 0
                            ):
                                try:
                                    shutil.copytree(
                                        item
                                        + each
                                        + "/AppData/Local/Microsoft/Windows/History/"
                                        + every,
                                        bwsrdest + each + "/IE/" + every,
                                        symlinks=symlinkvalue,
                                    )
                                except:
                                    pass
                            else:
                                pass
                        else:
                            pass
                else:
                    for every in os.path.exists(
                        item
                        + each
                        + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/"
                    ):
                        if (
                            every == "Content.IE5"
                            or every == "History.IE5"
                            or every == "Low"
                        ):
                            try:
                                os.stat(dest + each + "/IE/Temporary Internet Files/")
                            except:
                                os.makedirs(
                                    dest + each + "/IE/Temporary Internet Files/"
                                )
                            if (
                                len(
                                    os.listdir(
                                        item
                                        + each
                                        + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/"
                                        + every
                                    )
                                )
                                > 0
                            ):
                                try:
                                    shutil.copytree(
                                        item
                                        + each
                                        + "/AppData/Local/Microsoft/Windows/Temporary Internet Files/"
                                        + every,
                                        dest
                                        + each
                                        + "/IE/Temporary Internet Files/"
                                        + every,
                                        symlinks=symlinkvalue,
                                    )
                                except:
                                    pass
                            else:
                                pass
                        else:
                            pass
                print_done(verbosity)
            else:
                pass
            if os.path.exists(
                item + each + "/AppData/Local/Google/Chrome/User Data/Default/"
            ):
                if (
                    len(
                        os.listdir(
                            item
                            + each
                            + "/AppData/Local/Google/Chrome/User Data/Default/"
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
                        item + each + "/AppData/Local/Google/Chrome/User Data/Default/"
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
                                    + "/AppData/Local/Google/Chrome/User Data/Default/"
                                    + every,
                                    bwsrdest + each + "/chrome/",
                                )
                            elif every == "Local Storage":
                                shutil.copytree(
                                    item
                                    + each
                                    + "/AppData/Local/Google/Chrome/User Data/Default/"
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
            if os.path.exists(item + each + "/AppData/Local/Mozilla/Firefox/Profiles/"):
                if (
                    len(
                        os.listdir(
                            item + each + "/AppData/Local/Mozilla/Firefox/Profiles/"
                        )
                    )
                    > 0
                ):
                    if verbosity != "":
                        print(
                            "     Collecting Mozilla Firefox browser artefacts for '{}' for {}...".format(
                                each, vssimage
                            )
                        )
                    else:
                        pass
                    (entry, prnt,) = "{},{},{},Mozilla Firefox artefacts\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                    ), " -> {} -> {} Mozilla Firefox artefacts{} for '{}'".format(
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
                        item + each + "/AppData/Local/Mozilla/Firefox/Profiles/"
                    ):
                        try:
                            os.stat(bwsrdest + each + "/firefox/")
                        except:
                            os.makedirs(bwsrdest + each + "/firefox/")
                        try:
                            if os.path.exists(
                                item
                                + each
                                + "/AppData/Local/Mozilla/Firefox/Profiles/"
                                + every
                                + "/places.sqlite"
                            ):
                                shutil.copy2(
                                    item
                                    + each
                                    + "/AppData/Local/Mozilla/Firefox/Profiles/"
                                    + every
                                    + "/places.sqlite",
                                    bwsrdest + each + "/firefox/",
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
        else:
            pass
    if userprofiles:
        for each in item_list:
            try:
                os.stat(userdest)
            except:
                os.makedirs(userdest)
            if os.path.isdir(item + each):
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
                        item + each,
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
