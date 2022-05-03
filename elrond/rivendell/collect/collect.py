#!/usr/bin/env python3 -tt
import os
import shutil
import sys
import time
from collections import OrderedDict
from datetime import datetime

from rivendell.analysis.keywords import prepare_keywords
from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry
from rivendell.collect.linux import collect_linux_artefacts
from rivendell.collect.mac import collect_mac_artefacts
from rivendell.collect.files.select import select_files
from rivendell.collect.windows import collect_windows_artefacts
from rivendell.meta import extract_metadata
from rivendell.process.memory import process_memory


def collect_artefacts(
    auto,
    vss,
    collectfiles,
    nsrl,
    keywords,
    volatility,
    hashcollected,
    superquick,
    quick,
    recover,
    symlinks,
    userprofiles,
    verbose,
    d,
    cwd,
    sha256,
    flags,
    system_artefacts,
    output_directory,
    verbosity,
    f,
    imgs,
    path,
    volchoice,
    vssmem,
    memtimeline,
    stage,
):
    volume_shadow_copies = []
    if not volatility and len(imgs) <= 0:
        print(
            "  ----------------------------------------\n  No disk images exist in the provided directory.\n   If you are confident there are valid images in this directory, maybe try with the Memory flag (-M)?\n   Otherwise review the path location and ensure the images are supported by elrond.\n  ----------------------------------------\n\n\n"
        )
        sys.exit()
    else:
        if vss:
            for image, _ in imgs.items():
                for shdw in sorted(os.listdir("/mnt/shadow_mount")):
                    if shdw == image.split("::")[0]:
                        for eachvss in sorted(
                            os.listdir("/mnt/shadow_mount/" + shdw + "/")
                        ):
                            volume_shadow_copies.append(
                                image
                                + "||"
                                + "/mnt/shadow_mount/"
                                + shdw
                                + "/"
                                + eachvss
                            )
                    else:
                        pass
            for everyshdw in volume_shadow_copies:
                imgs[
                    everyshdw.split("||")[0]
                    + "_"
                    + everyshdw.split("||")[1].split("/")[-1]
                ] = everyshdw.split("||")[1]
        else:
            pass
        imgs = OrderedDict(sorted(imgs.items(), key=lambda x: x[1]))
        if nsrl:
            if not os.path.exists("/opt/elrond/elrond/tools/rds_modernm/NSRLFile.txt"):
                nsrlexit = input(
                    "\n     It doesn't look like '/opt/elrond/elrond/tools/rds_modernm/NSRLFile.txt' exists.\n      Do you want to continue? Y/n [Y] "
                )
                if nsrlexit == "n":
                    print(
                        "     If you wish to utilise the NSRL hash database, run the '.../elrond/tools/scripts/nsrl.sh' script, before running elrond and try again.\n\n"
                    )
                    sys.exit()
                else:
                    pass
            else:
                pass
        else:
            pass
        if not superquick and not quick and not hashcollected:
            print(
                "\n\n  -> \033[1;36mCommencing Metadata Phase...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            stage = "metadata"
            for each in imgs:
                img, mnt = [each, imgs[each]]
                if "vss" in img.split("::")[1]:
                    metaimage, vsstext = "'" + img.split("::")[0] + "' (" + img.split(
                        "::"
                    )[1].split("_")[1].replace(
                        "vss", "volume shadow copy #"
                    ) + ")", " from " + img.split(
                        "::"
                    )[
                        1
                    ].split(
                        "_"
                    )[
                        1
                    ].replace(
                        "vss", "volume shadow copy #"
                    )
                else:
                    metaimage, vsstext = "'" + img.split("::")[0] + "'", ""
                print("    Collecting Metadata for {}...".format(metaimage))
                entry, prnt = "{},{},{},commenced\n".format(
                    datetime.now().isoformat(),
                    metaimage.replace("'", ""),
                    stage,
                ), " -> {} -> collecting {}{} for '{}'".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage,
                    vsstext,
                    img.split("::")[0],
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                extract_metadata(
                    verbosity, output_directory, img, mnt, stage, sha256, nsrl
                )
                entry, prnt = "{},{},{},completed\n".format(
                    datetime.now().isoformat(),
                    metaimage.replace("'", ""),
                    stage,
                ), " -> {} -> {} completed{} for '{}'".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage,
                    vsstext,
                    img.split("::")[0],
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                print("  -> Completed Metadata Phase for {}.\n".format(metaimage))
                flags.append("00metadata")
            print(
                "\n  -> Completed Metadata Phase.\n  ----------------------------------------\n"
            )
            time.sleep(1)
        elif not superquick:
            print(
                "\n\n  -> \033[1;36mCommencing Metadata Phase...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            stage = "metadata"
            for each in imgs:
                img, mnt = [each, imgs[each]]
                if "vss" in img.split("::")[1]:
                    metaimage, vsstext = "'" + img.split("::")[0] + "' (" + img.split(
                        "::"
                    )[1].split("_")[1].replace(
                        "vss", "volume shadow copy #"
                    ) + ")", " from " + img.split(
                        "::"
                    )[
                        1
                    ].split(
                        "_"
                    )[
                        1
                    ].replace(
                        "vss", "volume shadow copy #"
                    )
                else:
                    metaimage, vsstext = "'" + img.split("::")[0] + "'", ""
                print("    Collecting Metadata for {}...".format(metaimage))
                entry, prnt = "{},{},{},commenced\n".format(
                    datetime.now().isoformat(),
                    metaimage.replace("'", ""),
                    stage,
                ), " -> {} -> collecting {}{} for '{}'".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage,
                    vsstext,
                    img.split("::")[0],
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                if verbosity != "":
                    print(
                        "     Ascertaining file timestamps for {}...".format(metaimage)
                    )
                else:
                    pass
                entry, prnt = "{},{},collecting,timestamps\n".format(
                    datetime.now().isoformat(), metaimage
                ), " -> {} -> collecting various timestamps for {}".format(
                    datetime.now().isoformat().replace("T", " "), metaimage
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                with open(
                    output_directory + img.split("::")[0] + "/lat.audit", "a"
                ) as lathef:
                    if "Windows" in img.split("::")[1]:
                        processtype = "WinProcess"
                    else:
                        processtype = "nixProcess"
                    lathef.write(
                        "Filename,CreationTime,LastAccessTime,LastWriteTime,{}\n".format(
                            processtype
                        )
                    )
                    for hr, _, hf in os.walk(mnt):
                        for intgfile in hf:
                            if os.path.exists(os.path.join(hr, intgfile)):
                                try:
                                    iinfo = os.stat(os.path.join(hr, intgfile))
                                    isize = iinfo.st_size
                                except:
                                    pass
                                if isize > 0:
                                    lathef.write(
                                        "{},{},{},{},{}\n".format(
                                            str(
                                                os.path.join(hr, intgfile).split("/")[
                                                    -1
                                                ]
                                            ),
                                            str(
                                                datetime.fromtimestamp(
                                                    os.path.getctime(
                                                        os.path.join(hr, intgfile)
                                                    )
                                                )
                                            ),
                                            str(
                                                datetime.fromtimestamp(
                                                    os.path.getatime(
                                                        os.path.join(hr, intgfile)
                                                    )
                                                )
                                            ),
                                            str(
                                                datetime.fromtimestamp(
                                                    os.path.getmtime(
                                                        os.path.join(hr, intgfile)
                                                    )
                                                )
                                            ),
                                            str(
                                                os.path.join(hr, intgfile).split("/")[
                                                    -1
                                                ]
                                            ).lower(),
                                        )
                                    )
                                else:
                                    pass
                            else:
                                pass
                print_done(verbosity)
                entry, prnt = "{},{},{},completed\n".format(
                    datetime.now().isoformat(),
                    metaimage.replace("'", ""),
                    stage,
                ), " -> {} -> {} completed{} for '{}'".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage,
                    vsstext,
                    img.split("::")[0],
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                print("  -> Completed Metadata Phase for {}.\n".format(metaimage))
                flags.append("00metadata")
            print(
                "  ----------------------------------------\n  -> Completed Metadata Phase.\n"
            )
            time.sleep(1)
        else:
            pass
        if keywords:
            prepare_keywords(
                verbosity, output_directory, auto, flags, imgs, keywords, stage
            )
        else:
            pass
    imgs, stage = (
        OrderedDict(sorted(imgs.items(), key=lambda x: x[1])),
        "collecting",
    )
    print(
        "\n\n  -> \033[1;36mCommencing Collection Phase...\033[1;m\n  ----------------------------------------"
    )
    time.sleep(1)
    if symlinks:
        symlinkvalue = False
    else:
        symlinkvalue = True
    for each in imgs:  # Collection
        img, mnt = [each, imgs[each]]
        if "vss" in img.split("::")[1]:
            vssimage = (
                "'"
                + img.split("::")[0]
                + "' ("
                + img.split("::")[1]
                .split("_")[1]
                .replace("vss", "volume shadow copy #")
                + ")"
            )
        else:
            vssimage = "'" + img.split("::")[0] + "'"
        print("    Collecting artefacts for {}...".format(vssimage))
        entry, prnt = "{},{},{},commenced\n".format(
            datetime.now().isoformat(), vssimage.replace("'", ""), stage
        ), " -> {} -> {} artefacts for {}".format(
            datetime.now().isoformat().replace("T", " "), stage, vssimage
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        artefact_directory = output_directory + img.split("::")[0] + "/artefacts"
        if volatility and img.split("::")[1].startswith("memory"):
            if verbosity != "":
                print("     Identifying profile for {}...".format(vssimage))
            else:
                pass
            process_memory(
                output_directory,
                verbosity,
                d,
                stage,
                f,
                path,
                volchoice,
                vss,
                vssmem,
                memtimeline,
            )
            flags.append("02processing")
            os.chdir(cwd)
        else:  # Collection
            try:
                os.makedirs(artefact_directory)
                os.makedirs(artefact_directory + "/raw")
            except:
                pass
            for system_artefact in system_artefacts:  # Collection
                dest, vsstext = (
                    artefact_directory + "/raw/",
                    "",
                )
                if (
                    img.split("::")[0] in artefact_directory
                    and img.split("::")[1].startswith("Windows")
                    and "memory" not in img.split("::")[1]
                ):  # Windows Collection
                    item = mnt + system_artefact
                    if "vss" in item:
                        dest, vsstext = (
                            artefact_directory + "/raw/" + item.split("/")[4] + "/",
                            " from " + item.split("/")[4],
                        )
                    else:
                        pass
                    if not os.path.exists(dest):
                        os.makedirs(dest)
                    else:
                        pass
                    if os.path.exists(item):  # Collection
                        collect_windows_artefacts(
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
                        )
                    else:
                        pass
                elif (
                    img.split("::")[0] in artefact_directory
                    and img.split("::")[1] == "macOS"
                    and "memory" not in img.split("::")[1]
                ):  # macOS Collection
                    item = mnt + "/root" + system_artefact
                    if not os.path.exists(dest):
                        os.makedirs(dest)
                    else:
                        pass
                    if os.path.exists(item):  # Collection
                        collect_mac_artefacts(
                            dest,
                            img,
                            item,
                            mnt + "/root",
                            output_directory,
                            sha256,
                            stage,
                            symlinkvalue,
                            userprofiles,
                            verbosity,
                            volatility,
                            vssimage,
                            vsstext,
                        )
                    else:
                        pass
                elif (
                    img.split("::")[0] in artefact_directory
                    and img.split("::")[1] == "Linux"
                    and "memory" not in img.split("::")[1]
                ):  # Linux Collection
                    item = mnt + system_artefact
                    if not os.path.exists(dest):
                        os.makedirs(dest)
                    else:
                        pass
                    if os.path.exists(item):  # Collection
                        collect_linux_artefacts(
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
                        )
                    else:
                        pass
                else:
                    pass
        if not auto:
            yes_collect_recover = input(
                "  Do you wish to collect, recover and/or carve files from '{}'? Y/n [Y] ".format(
                    img.split("::")[0]
                )
            )
        else:
            pass
        if auto or yes_collect_recover != "n":
            if collectfiles or recover:
                select_files(
                    output_directory,
                    verbosity,
                    d,
                    mnt,
                    img,
                    vssimage,
                    collectfiles,
                    recover,
                )
            else:
                pass
        else:
            pass
        if symlinks and verbose:
            print(
                "     Tidying artefacts for {}...\n     Please be patient...".format(
                    vssimage
                )
            )
        else:
            pass
        for tyr, tyd, _ in os.walk(img + "/artefacts/"):
            for td in tyd:
                if len(os.listdir(tyr + "/" + td)) == 0:
                    try:
                        shutil.rmtree(tyr + "/" + td)
                    except:
                        pass
                else:
                    pass
        print("  -> Completed Collection Phase for {}".format(vssimage))
        entry, prnt = "{},{},{},completed\n".format(
            datetime.now().isoformat(), vssimage.replace("'", ""), stage
        ), " -> {} -> collection completed for {}".format(
            datetime.now().isoformat().replace("T", " "), vssimage
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        print()
    flags.append("01collection")
    print(
        "  ----------------------------------------\n  -> Completed Collection Phase.\n"
    )
    time.sleep(1)