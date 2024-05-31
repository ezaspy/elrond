#!/usr/bin/env python3 -tt
import os
import re
import shutil
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def mac_users(
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
):
    item_list, bwsrdest, userdest, bashfiles = (
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
    )
    for each in item_list:
        if os.path.isdir(item + "/" + each):
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
                for eachbash in bashfiles:
                    try:
                        shutil.copy2(
                            item + "/" + each + "/." + eachbash,
                            dest + each + "+" + eachbash,
                        )
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' ({})\n".format(
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
            if os.path.exists(item + "/" + each + "/Library/keychains/"):
                if verbosity != "":
                    print(
                        "     Collecting '{}' keychain for {}...".format(each, vssimage)
                    )
                (
                    entry,
                    prnt,
                ) = "{},{},{},keychain ({})\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    each,
                ), " -> {} -> {} '{}' keychain for '{}'".format(
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
                for keychain in os.listdir(item + "/" + each + "/Library/keychains/"):
                    if keychain.endswith(".keychain-db"):
                        try:
                            shutil.copy2(
                                item + "/" + each + "/Library/keychains/" + keychain,
                                dest + each + "+" + keychain,
                            )
                        except:
                            pass
            if os.path.exists(
                item + "/" + each + "/Library/Preferences/"
            ) or os.path.exists(item + "/" + each + "/Library/Safari/"):
                if not os.path.exists(dest + "plists"):
                    os.makedirs(dest + "plists")
                if verbosity != "":
                    print(
                        "     Collecting plists for '{}' for {}...".format(
                            each, vssimage
                        )
                    )
                for eachplist in os.listdir(item + each + "/Library/Preferences/"):
                    try:
                        (
                            entry,
                            prnt,
                        ) = "{},{},{},'{}' ({})\n".format(
                            datetime.now().isoformat(),
                            img.split("::")[0],
                            stage,
                            eachplist,
                            each,
                        ), " -> {} -> {} '{}' ({}) for '{}'".format(
                            datetime.now().isoformat().replace("T", " "),
                            stage,
                            eachplist,
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
                            item + each + "/Library/Preferences/" + eachplist,
                            dest + "plists/" + each + "+" + eachplist,
                        )
                    except:
                        pass
                for eachplist in os.listdir(item + each + "/Library/Safari/"):
                    if eachplist.endswith(".plist"):
                        try:
                            (
                                entry,
                                prnt,
                            ) = "{},{},{},'{}' ({})\n".format(
                                datetime.now().isoformat(),
                                img.split("::")[0],
                                stage,
                                eachplist,
                                each,
                            ), " -> {} -> {} '{}' ({}) for '{}'".format(
                                datetime.now().isoformat().replace("T", " "),
                                stage,
                                eachplist,
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
                                item + each + "/Library/Safari/" + eachplist,
                                dest + "plists/" + each + "+" + eachplist,
                            )
                        except:
                            pass
            if os.path.exists(item + "/" + each + "/.ssh/"):
                if verbosity != "":
                    print(
                        "     Collecting '{}' ssh files for {}...".format(
                            each, vssimage
                        )
                    )
                (
                    entry,
                    prnt,
                ) = "{},{},{},ssh files\n".format(
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
            if os.path.exists(item + "/" + each + "/.Trash/"):
                if not os.path.exists(dest + "/deleted/"):
                    os.makedirs(dest + "/deleted/")
                if verbosity != "":
                    print(
                        "     Collecting '{}' deleted files for {}...".format(
                            each, vssimage
                        )
                    )
                (
                    entry,
                    prnt,
                ) = "{},{},{},deleted files\n".format(
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
                for eachtrash in os.listdir(item + "/" + each + "/.Trash/"):
                    try:
                        shutil.copy2(
                            item + "/" + each + "/.Trash/" + eachtrash,
                            dest + "/deleted/" + each + "+" + eachtrash,
                        )
                    except:
                        pass
            if os.path.exists(item + "/" + each + "/Library/Mail"):
                if not os.path.exists(dest + "/mail/"):
                    os.makedirs(dest + "/mail/")
                if verbosity != "":
                    print(
                        "     Collecting '{}' mail artefacts for {}...".format(
                            each, vssimage
                        )
                    )
                (
                    entry,
                    prnt,
                ) = "{},{},{},'{}' mail artefacts\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    each,
                ), " -> {} -> {} mail artefacts for profile '{}' for '{}'".format(
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
                for (
                    mailroot,
                    _,
                    mailfiles,
                ) in os.walk(item + each + "/Library/Mail"):
                    for mailfile in mailfiles:
                        if mailfile.endswith(".emlx") or "Attachment" in mailroot:
                            mbox = (
                                str(
                                    re.findall(
                                        r"([^\/]+)\.mbox\/",
                                        mailroot,
                                    )
                                )
                                .replace("['", "")
                                .replace("']", "")
                                .replace("', '", "--")
                                .replace(" ", "-")
                            )
                            if mailfile.endswith(".emlx"):
                                if not os.path.exists(dest + "/mail/emails/"):
                                    os.makedirs(dest + "/mail/emails/")
                                if not os.path.exists(dest + "/mail/emails/" + mbox):
                                    os.makedirs(dest + "/mail/emails/" + mbox)
                                try:
                                    (
                                        entry,
                                        prnt,
                                    ) = "{},{},{},'{}' ({}) Mail artefact\n".format(
                                        datetime.now().isoformat(),
                                        vssimage.replace("'", ""),
                                        stage,
                                        mailfile,
                                        mbox,
                                    ), " -> {} -> {} Mail artefact '{}' ({}) for {}".format(
                                        datetime.now().isoformat().replace("T", " "),
                                        stage,
                                        mailfile,
                                        mbox,
                                        vssimage,
                                    )
                                    write_audit_log_entry(
                                        verbosity,
                                        output_directory,
                                        entry,
                                        prnt,
                                    )
                                    shutil.copy2(
                                        os.path.join(
                                            mailroot,
                                            mailfile,
                                        ),
                                        dest + "/mail/emails/" + mbox + "/" + mailfile,
                                    )
                                except:
                                    pass
                            elif "Attachment" in mailroot:
                                if not os.path.exists(dest + "/mail/attachments/"):
                                    os.makedirs(dest + "/mail/attachments/")
                                if not os.path.exists(
                                    dest + "/mail/attachments/" + mbox
                                ):
                                    os.makedirs(dest + "/mail/attachments/" + mbox)
                                with open(
                                    os.path.join(
                                        mailroot,
                                        mailfile,
                                    ),
                                    "rb",
                                ) as mailhash:
                                    buffer = mailhash.read(262144)
                                    while len(buffer) > 0:
                                        sha256.update(buffer)
                                        buffer = mailhash.read(262144)
                                try:
                                    (
                                        entry,
                                        prnt,
                                    ) = "{},{},{},'{}' ({}) Mail attachment\n".format(
                                        datetime.now().isoformat(),
                                        vssimage.replace("'", ""),
                                        stage,
                                        mailfile,
                                        mbox,
                                    ), " -> {} -> {} Mail attachment '{}' ({}) for {}".format(
                                        datetime.now().isoformat().replace("T", " "),
                                        stage,
                                        mailfile,
                                        mbox,
                                        vssimage,
                                    )
                                    write_audit_log_entry(
                                        verbosity,
                                        output_directory,
                                        entry,
                                        prnt,
                                    )
                                    shutil.copy2(
                                        os.path.join(
                                            mailroot,
                                            mailfile,
                                        ),
                                        dest
                                        + "/mail/attachments/"
                                        + mbox
                                        + "/"
                                        + sha256.hexdigest()
                                        + "+"
                                        + mailfile,
                                    )
                                except:
                                    pass
            if not each.startswith("."):
                try:
                    os.stat(bwsrdest + each + "/safari/")
                except:
                    os.makedirs(bwsrdest + each + "/safari/")
                if verbosity != "":
                    print(
                        "     Collecting Safari browser artefacts for '{}' for {}...".format(
                            each, vssimage
                        )
                    )
                try:
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},'{}' Safari browser artefacts\n".format(
                        datetime.now().isoformat(),
                        img.split("::")[0],
                        stage,
                        each,
                    ), " -> {} -> {} '{}' Safari browser artefacts{} for '{}'".format(
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
                        item + each + "/Library/Safari/History.db",
                        bwsrdest + each + "/safari/",
                    )
                except:
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
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},Google Chrome artefacts\n".format(
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
                        except:
                            pass
            if os.path.exists(
                item + each + "/Library/Application Support/Firefox/Profiles/"
            ):
                if (
                    len(
                        os.listdir(
                            item + each + "/AppData/Local/Mozilla/Firefox/Profiles/"
                        )
                    )
                    > 0
                ):
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
                        for every in os.listdir(
                            item
                            + each
                            + "/Library/Application Support/Firefox/Profiles/"
                        ):
                            try:
                                os.stat(bwsrdest + each + "/firefox/")
                            except:
                                os.makedirs(bwsrdest + each + "/firefox/")
                            try:
                                if os.path.exists(
                                    item
                                    + each
                                    + "/Library/Application Support/Firefox/Profiles/"
                                    + every
                                    + "/places.sqlite"
                                ):
                                    shutil.copy2(
                                        item
                                        + each
                                        + "/Library/Application Support/Firefox/Profiles/"
                                        + every
                                        + "/places.sqlite",
                                        bwsrdest + each + "/firefox/",
                                    )
                            except:
                                pass
                    except:
                        pass
            if userprofiles:
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
                    (
                        entry,
                        prnt,
                    ) = "{},{},{},'{}' user profile\n".format(
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
