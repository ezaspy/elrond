#!/usr/bin/env python3 -tt
import os
import random
import re
import shutil
import subprocess
import sys
import time
from collections import OrderedDict
from datetime import datetime

from rivendell.core import collect_process_kw_analysis_timelining
from rivendell.audit import write_audit_log_entry
from rivendell.identify import identify_disk_image
from rivendell.identify import identify_memory_image
from rivendell.meta import collect_metadata
from rivendell.mount import mount_images
from rivendell.mount import unmount_images
from rivendell.post.clean import archive_artefacts
from rivendell.post.clean import delete_artefacts
from rivendell.post.elastic.config import configure_elastic_stack
from rivendell.post.mitre.nav_config import configure_navigator
from rivendell.post.sigma.build import write_sigma_signatures
from rivendell.post.splunk.install import configure_splunk_stack
from rivendell.post.yara.build import write_yara_signatures


def main(
    directory,
    case,
    analysis,
    auto,
    collect,
    vss,
    delete,
    elastic,
    collectfiles,
    sigma,
    nsrl,
    extractiocs,
    imageinfo,
    lotr,
    keywords,
    volatility,
    navigator,
    hashcollected,
    process,
    superquick,
    quick,
    recover,
    carving,
    splunk,
    symlinks,
    timeline,
    memorytimeline,
    userprofiles,
    veryverbose,
    verbose,
    yara,
    archive,
    d,
    cwd,
    sha256,
    allimgs,
    removeimgs,
    flags,
    elrond_mount,
    ewf_mount,
    system_artefacts,
    quotes,
    asciitext,
):
    if not collect and not process:
        if volatility and not process:
            print(
                "\n  If you are just processing memory images, you must invoke the process flag (-P) with the memory flag (-M).\n  Please try again.\n\n"
            )
            sys.exit()
        else:
            print(
                "\n  If you have previously collected artefacts but which to process them, you must invoke the process flag (-P) without the collect flag (-C).\n  Please try again.\n\n"
            )
            sys.exit()
    else:
        pass
    if not collect and (
        vss
        or collectfiles
        or imageinfo
        or recover
        or carving
        or symlinks
        or timeline
        or userprofiles
    ):
        if not collect and vss:
            collectand = "vss flag (-c)"
        elif not collect and collectfiles:
            collectand = "collectfiles flag (-F)"
        elif not collect and imageinfo:
            collectand = "imageinfo flag (-I)"
        elif not collect and recover:
            collectand = "recover flag (-R)"
        elif not collect and carving:
            collectand = "carving flag (-r)"
        elif not collect and symlinks:
            collectand = "symlinks flag (-s)"
        elif not collect and timeline:
            collectand = "timeline flag (-T)"
        elif not collect and userprofiles:
            collectand = "userprofiles flag (-U)"
        else:
            pass
        print(
            "\n\n  In order to use the {}, you must also invoke the collect flag (-C). Please try again.\n\n".format(
                collectand
            )
        )
        sys.exit()
    else:
        pass
    if analysis and not process:
        print(
            "\n\n You cannot provide the Analysis Flag (-A) without provided the Processing Flag (-P). Please try again.\n"
        )
        sys.exit()
    else:
        pass
    if not hashcollected and nsrl and (superquick or quick):
        print(
            "\n\n In order to use the NSRL Flag (-H), you must either provide the hashcollected Flag (-o) - with or without the Superquick (-Q) and Quick Flags (-q).\n  Or, if not using the hashcollected Flag (-o), remove the Superquick (-Q) and Quick Flags (-q) altogether. Please try again.\n"
        )
        sys.exit()
    else:
        pass
    if navigator and not splunk:
        print(
            "\n\n You cannot provide the Navigator Flag (-N) without providing the Splunk Flag (-S). Please try again.\n"
        )
        sys.exit()
    else:
        pass
    subprocess.Popen(["clear"])
    time.sleep(2)
    if lotr:
        print(random.choice(asciitext))
        input("\n\n\n\n\n\n\n\n\n\n     Press Enter to continue... ")
        subprocess.Popen(["clear"])
        print(
            "||                                ..........',:clooddddoolc:;''...   .......  .....'..'''||\n||                             ........'',;:clodxkkkkkkkkkxoc;,'............   ......''''||\n||                         ......',;,,;;:lddxxdxxxxxkkkkOOOkxdl:;'....... ...  ..........||\n||                      .....',;;;::;;:cloddoooodxxkkOOOOOOOOkkkxdolc;'...     ..........||\n||                  .....''',;;;;::c::;:ccllllodxxxxxxk0K000000OOkkkkxo:,'..     ........||\n||                ........',;,,;,,;:llclooooddxkkkxolokkxdk0Oxdxxdodddl:::,....  ........||\n||                ..........'''',,;;:cllddxkkOOOO00xox000KXX0xoolcccodocc:,'''......''''.||\n||               ...''....'''''.',;:coddxxkOOOOOOO0OxkO00K00Okdl:,'',;,';:cc;'.''....''..||\n||              ..........''''''';:cloxxkkkOOOOOO000KXXKKK00Okdol:,'..''...;:c'...''.....||\n||            ...'''''....',,;;;;;:cloxkkOOOOOOOO000KKKKKK00Okdooc;'...''....';,. .'''...||\n||            ..',,,,;;;;;;:::::::ccldxkkOOOOOOOO00KKKKKKK0OOxolc:;'....'.......'..','...||\n||            ..',,,;;;;;:::::::::clodkkOOOOOOOO0000KKKKKK00Okdl:;,'........... .........||\n||             .',;;;;::::::::::::cldxkkOOOOO0000000KKKXXKKKK0kdc;,''. ........    .....'||\n||             .',;;;:ccllcc::::cclodxkkkkkkOO000OOOO0KKKKKKKK0Oxc,'..   .......  ... .;;||\n||             ..,,;;:cllllc:::ccllodxxxxxxxxxxxdodxkO0KKKXKKKK0Oo;...    ......';:oo;...||\n||             ..',;;:cllllc::cclllooddollc:::cldxOO0000KKKKKKKK0x:'..    .....,codxkx:. ||\n||             .',,;;::cclll::clllllc::,'''',:oxOO0000000KKKKKKKKkl,...   .....,;;:okOd'.||\n||             ...',;::::clcc:::c:;,''..'''',,;:cldxkO0000KKKXKKKOo:...   ...'.,,;:cdkk;.||\n||            .......',;;:::::::::;;;,'''.......,:ccldxkO0KKXXXK0Odc'.    ...',;;:cldOk;.||\n||             .....  .....';clddxdlc;,,'',,,'',:loxOOOO00KKXXXKOkdc'........',,;;:lxOd' ||\n||              ...    .....;cok00Oxdoc;,,,,,,;:cldkO0000KKKKXK0Okoc,......'..',,;:okOc. ||\n||                ......','';ldOKKK0Okoc::::::ccloxkO0000KXXXKKOkdo:,..',..'..',;:lxko.. ||\n||                 ....'',',:lx0XXXXKK0kxoccccloodkOOOOO00KKKK0kxdl:'...'.....';ldkko'  .||\n||                 ..''',,,;cxOKXXXXXXXK0OxxdoooodxkkOOO000000Okxdl;'.........,:dOOd'   .||\n||                 ...',,,,:ok0KXXXXKXXXK000OkkkxdxxkkOOO00OOOOkxoc;'.........';oko'     ||\n||                 .,,,,,,;cok0KKKXK00000OOOOOOOOkkkkOOOOOOOOOkxdoc;,.........';l:..     ||\n||                 .,,,,,,;cdO000KKK00K0OdddxkkOOOOOOOO000OOOkxddl:;'...... ..';c;.      ||\n||                 .',,,,,,:lxkOxxxdoxO0OxllloxkkOOOO00000OOOkxdol:;'.....  ..':o:.      ||\n||                  .',,,,''',:lllllccdkOxdoooodxkOOO00000OOkxdolc:,'.....  ..,cxc.      ||\n||                   .''',,'...,:cdkxxkkkkxxxxddxkOO00000OOOkxdolc;,......  ..,oko'      ||\n||                   ...',,,''';::ldxxxxxkkkkkkkxxxkOO000OOOkxolc:;'......  ..;xkd,      ||\n||                    ..'',,'',:c;:ldxxxxkkOOkkkkkxxkOOOOOkkkdlc:;,'.....   ..:xkk:.     ||\n||                     ..''',,,:c::cllloooddddoodxkkkOOOOkkxxol:;,,'''...   ..ckOkl.   ..||\n||                      .''',,,,,,,;;;::cloolllcclodxkOOOkxddlc:;,,,;,..    ..:xxdc'..;ld||\n||                      ..''..''',;:cloodxkkkkkkxdooodxxkxddolc;,,;:c:..    .';lollodkkkx||\n||                       ..'''',,;;:cclloooddddxxddooodxxdddol:;;::clc,.  ...';ldkkkkkxoc||\n||                       .....',,;;;;;;::cccclloooooodxxxxdolc:::cclc:;......'coxkOkxoc;'||\n||                    ...''....',,,;;;;::clccclllllloodxxdolc::::c:::;;'.....,ldxxxdl:,..||\n|| .':lcc;,''',,;:cllloddxko:'..'',;::ccloddddoodoooooooolc:;;;;;;,;;;;,.....:oddooc;,.. ||\n||.:xO0KKK00OOOOOOOOOOkkkkO00Odc,',;:cccloddxxxxddooolcc:;;;,,,'',;:::cc:...'collcc;'..  ||\n||'lxO0KKKKKK0000000000OkOO00000kl:;;::::cllooddddoolc:;;,,,''',,;::clool,...;:cc:;'.. ..||\n||;lxO0KXXXXKKKK0000000OOO0KXKOkOOkdoc;;;;:::cclllc:::;,,''.',;::::cllooc.   .'::,...... ||\n||:ok0KKKKKKKKKKKKKKKK0OO0KXXNXOxdkOOkdlc;;,,,,,,,,,,,'''..',:ccccclooo:..    .,'......  ||\n||cdkO00KKKKKKKKKK0000OO0KXKKXNX0dldxkkOkxl:,.............',:cccclool:,..'.  .''......   ||\n||cdxkOOOO0KKKKKKK0O0K0kkKXXK00XNKd::clodxoc,.............':cccllooo;. ......,,'......   ||\n||coxxk00OkxxxxkkOOO0KK0kk0XXKOOKKKxlcloddol;. .......'''',:ccloooooc'.......'''.....    ||\n||loodk000Oxc'',,,cdk0KXKkk0KX0xxOO00kdol:'...........'''':ccloooololc;'....''......    .||\n||loodxOOxl,.......,cdO0K0kxOKXOooxO00x;... ...........'',cclloollllllc:..'''..'..       ||\n||loxkkO0x;..........,cx0K0dok0Kkccdk00k:...........'..',:llllolllllllc:..',,'','.       ||\n||oxkO000d;,,,,,'''...,cdO0xcok00l';cdO00l.............';llllloollloolc;..',,''..        ||\n\n\n"
        )
        time.sleep(2)
    else:
        pass
    starttime, ot, imgs, d, vssmem = (
        datetime.now().isoformat(),
        {},
        {},
        directory[0],
        "",
    )
    if (veryverbose and verbose) or veryverbose:
        verbosity = "veryverbose"
    elif verbose:
        verbosity = "verbose"
    else:
        verbosity = ""
    print(
        "\n\n    \033[1;36m        .__                               .___\n      ____  |  |  _______   ____    ____    __| _/\n    _/ __ \\ |  |  \\_  __ \\ /  _ \\  /    \\  / __ |\n    \\  ___/ |  |__ |  | \\/(  <_> )|   |  \\/ /_/ |\n     \\___  >|____/ |__|    \\____/ |___|  /\\____ |\n         \\/                            \\/      \\/\n\n     {}\033[1;m\n\n".format(
            random.choice(quotes)
        )
    )
    if len(directory) > 1:
        od = directory[1]
        if not od.endswith("/"):
            od = od + "/"
        else:
            pass
        if not os.path.isdir(od):
            if not auto:
                make_od = input(
                    "  You have specified an output directory that does not currently exist.\n    Would you like to create '{}'? Y/n [Y] ".format(
                        od
                    )
                )
            else:
                make_od = "y"
            if make_od != "n":
                try:
                    os.makedirs(od)
                    print(
                        "  '{}' has been created successfully.\n".format(
                            os.path.realpath(os.path.dirname(od) + "/")
                        )
                    )
                except PermissionError:
                    print(
                        "  A permissions error occured when creating '{}'.\n    Please try again as 'sudo'.\n  ----------------------------------------\n\n".format(
                            od
                        )
                    )
                    sys.exit()
                except:
                    print(
                        "  An unknown error occured when trying to create '{}'.\n    Resart SIFT and try again.\n  ----------------------------------------\n\n".format(
                            od
                        )
                    )
                    sys.exit()
            else:
                print(
                    "\n    You have three choices:\n     -> Specify a directory that exists\n     -> Confirm creation of a specified directory\n     -> Provide no output directory (cwd is default)\n\n  Please try again.\n  ----------------------------------------\n\n"
                )
                sys.exit()
        else:
            pass
        output_directory = os.path.dirname(od) + "/"
    else:
        output_directory = "./"
    if not os.path.isdir(d):
        print(
            "\n  '{}' does not exist and/or is not a directory, please try again.\n\n".format(
                d
            )
        )
        sys.exit()
    else:
        pass
    unmount_images(elrond_mount, ewf_mount)
    if volatility:
        volchoice, volcheck = (
            "2.6",
            str(
                subprocess.Popen(
                    ["locate", "volatility3"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[0]
            )[2:-1],
        )
        if volcheck != "":
            if not auto:
                volchoose = input(
                    "  Which version of volatility do you wish to use? 3/2.6 [3] "
                )
                if volchoose != "2.6":
                    volchoice = "3"
                else:
                    pass
            else:
                volchoice = "3"
        else:
            pass
        if memorytimeline:
            memtimeline = memorytimeline
        else:
            memtimeline = ""
    else:
        volchoice = ""
        memtimeline = ""
    print(
        "\n  -> \033[1;36mCommencing Identification Phase...\033[1;m\n  ----------------------------------------"
    )
    time.sleep(1)
    for root, _, files in os.walk(d):  # Mounting images
        for f in files:
            if os.path.exists(os.path.join(root, f)):  # Mounting images
                stage, path, imgformat, fsize = (
                    "mounting",
                    os.path.join(root, f),
                    str(
                        subprocess.Popen(
                            ["file", os.path.join(root, f)],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()[0]
                    )[2:-3].split(": ")[1],
                    os.stat(os.path.join(root, f)).st_size,
                )
                if fsize > 10000:
                    if not os.path.isdir(output_directory + f):
                        os.mkdir(output_directory + f)
                    else:
                        pass
                    if (
                        "Expert Witness" in imgformat
                        or "VMDK" in imgformat
                        or ("VMware" and " disk image" in imgformat)
                        or (
                            "DOS/MBR boot sector" in imgformat
                            and (
                                f.endswith(".raw")
                                or f.endswith(".dd")
                                or f.endswith(".img")
                            )
                        )
                    ):
                        if not auto:
                            wtm = input(
                                "  Do you wish to mount '{}'? Y/n [Y] ".format(f)
                            )
                        else:
                            wtm = "y"
                        if wtm != "n":
                            if not superquick and not quick:
                                if not os.path.exists(
                                    output_directory + f + "/meta.audit"
                                ):
                                    with open(
                                        output_directory + f + "/meta.audit", "w"
                                    ) as metaimglog:
                                        metaimglog.write(
                                            "Filename,SHA256,known-good,Entropy,Filesize,LastWriteTime,LastAccessTime,LastInodeChangeTime,Permissions,FileType\n"
                                        )
                                else:
                                    pass
                                if verbosity != "":
                                    print(
                                        "    Calculating SHA256 hash for '{}', please stand by...".format(
                                            f
                                        )
                                    )
                                else:
                                    pass
                                with open(path, "rb") as metaimg:
                                    buffer = metaimg.read(262144)
                                    while len(buffer) > 0:
                                        sha256.update(buffer)
                                        buffer = metaimg.read(262144)
                                    metaentry = (
                                        path
                                        + ","
                                        + sha256.hexdigest()
                                        + ",unknown,N/A,N/A,N/A,N/A,N/A,N/A,N/A\n"
                                    )
                                with open(
                                    output_directory + f + "/meta.audit", "a"
                                ) as metaimglog:
                                    metaimglog.write(metaentry)
                                collect_metadata(
                                    verbosity,
                                    output_directory,
                                    f,
                                    path,
                                    "metadata",
                                    sha256,
                                    nsrl,
                                )
                            else:
                                pass
                            entry, prnt = (
                                "LastWriteTime,elrond_host,elrond_stage,elrond_log_entry\n",
                                " -> {} -> created audit log file for '{}'".format(
                                    datetime.now().isoformat().replace("T", " "), f
                                ),
                            )
                            write_audit_log_entry(
                                verbosity, output_directory, entry, prnt
                            )
                            print("   Attempting to mount '{}'...".format(f))
                            entry, prnt = "{},{},{},commenced\n".format(
                                datetime.now().isoformat(), f, stage
                            ), " -> {} -> mounting '{}'".format(
                                datetime.now().isoformat().replace("T", " "), f
                            )
                            write_audit_log_entry(
                                verbosity, output_directory, entry, prnt
                            )
                            mount_images(
                                d,
                                auto,
                                verbosity,
                                output_directory,
                                path,
                                f,
                                elrond_mount,
                                ewf_mount,
                                allimgs,
                                imageinfo,
                                imgformat,
                                vss,
                                "mounting",
                                cwd,
                                quotes,
                                removeimgs,
                            )
                            entry, prnt = "{},{},{},completed\n".format(
                                datetime.now().isoformat(), f, "mounting"
                            ), " -> {} -> mounted '{}'".format(
                                datetime.now().isoformat().replace("T", " "), f
                            )
                            write_audit_log_entry(
                                verbosity, output_directory, entry, prnt
                            )
                        else:
                            print("    OK. '{}' will not be mounted.\n".format(f))
                        print()
                    elif volatility and "data" in imgformat:
                        allimgs[path.split("/")[-1]] = d
                        identify_memory_image(
                            verbosity,
                            output_directory,
                            flags,
                            auto,
                            superquick,
                            quick,
                            hashcollected,
                            cwd,
                            sha256,
                            nsrl,
                            f,
                            ot,
                            d,
                            path,
                            volchoice,
                            vss,
                            vssmem,
                            memtimeline,
                        )
                    else:
                        pass
                else:
                    pass
            else:
                pass
    for rmimg in removeimgs:
        del allimgs[rmimg]
    allimgs = OrderedDict(sorted(allimgs.items(), key=lambda x: x[1]))
    if len(allimgs) > 0:  # Identifying Platform
        identify_disk_image(allimgs, ot)
    else:
        pass
    if len(ot) > 0:
        for osplatform, location in ot.items():
            if osplatform.endswith("memory"):
                print(
                    "   Identified '{}' as {} image.".format(
                        osplatform.split("::")[0], osplatform.split("::")[1]
                    )
                )
                entry, prnt = "{},{},identified platform,{} ({})\n".format(
                    datetime.now().isoformat(),
                    osplatform.split("::")[0],
                    osplatform.split("::")[1],
                    location,
                ), " -> {} -> identified '{}' as a {} image".format(
                    datetime.now().isoformat().replace("T", " "),
                    osplatform.split("::")[0],
                    osplatform.split("::")[1],
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
            else:
                print(
                    "   Identified '{}' as '{}'.".format(
                        osplatform.split("::")[0], osplatform.split("::")[1]
                    )
                )
                entry, prnt = "{},{},identified platform,{} ({})\n".format(
                    datetime.now().isoformat(),
                    osplatform.split("::")[0],
                    osplatform.split("::")[1],
                    location,
                ), " -> {} -> identified platform of '{}' for '{}'".format(
                    datetime.now().isoformat().replace("T", " "),
                    osplatform.split("::")[1],
                    osplatform.split("::")[0],
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
            time.sleep(1)
        print(
            "  ----------------------------------------\n  -> Completed Identification Phase.\n"
        )
        for eachdisk in ot.items():
            edisk = str(eachdisk)
            if (
                "E01" in edisk
                or "e01" in edisk
                or "VMDK" in edisk
                or "vmdk" in edisk
                or ".dd::Linux" in edisk
            ):  # Identifying disk images
                for imgtype, imgpath in ot.items():
                    if "memory" not in imgtype:
                        imgs[imgtype] = imgpath
                    else:
                        pass
    else:
        if not auto:
            nodisks = input(
                "  No disk images exist in the provided directory.\n   Do you wish to continue? Y/n [Y] "
            )
            if nodisks == "n":
                print(
                    "  ----------------------------------------\n  -> Completed Identification Phase.\n\n\n  ----------------------------------------\n   If you are confident there are valid images in this directory, maybe try with the Memory flag (-M)?\n   Otherwise review the path location and ensure the images are supported by elrond.\n  ----------------------------------------\n\n\n"
                )
                sys.exit()
            else:
                pass
        else:
            pass
    time.sleep(1)
    if (
        collect or process
    ):  # Collection/Reorganisation, Processing, Keyword Searching, Analysis & Timelining
        collect_process_kw_analysis_timelining(
            auto,
            collect,
            process,
            analysis,
            extractiocs,
            timeline,
            vss,
            collectfiles,
            nsrl,
            keywords,
            volatility,
            hashcollected,
            superquick,
            quick,
            recover,
            carving,
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
        )
    for emem in ot.items():  # Adding memory images to processed images
        if "memory" in str(emem):
            for imgtype, imgpath in allimgs.items():
                if "memory" in imgtype:
                    imgs[imgtype] = imgpath
                else:
                    pass
        else:
            pass
    imgs, elrond_mount = OrderedDict(sorted(imgs.items(), key=lambda x: x[1])), [
        "/mnt/elrond_mount",
        "/mnt/elrond_mount1",
        "/mnt/elrond_mount2",
        "/mnt/elrond_mount3",
        "/mnt/elrond_mount4",
        "/mnt/elrond_mount5",
    ]
    if len(imgs) > 0:  # Post-processing metadata, Splunk, Elastic, Archive, Deletion
        if not superquick or hashcollected:
            print(
                "\n\n  -> \033[1;36mCommencing Metadata phase for proccessed artefacts...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            if process and analysis:
                insert = "collected, processed & analysed"
            elif process:
                insert = "collected & processed"
            else:
                insert = "collected"
            for img in allimgs:
                print(
                    "\n    Collecting metadata from processed artefacts for '{}'...".format(
                        img.split("::")[0]
                    )
                )
                collect_metadata(
                    verbosity,
                    output_directory,
                    img,
                    output_directory + img.split("::")[0] + "/artefacts/raw/",
                    stage,
                    sha256,
                    nsrl,
                )
                if os.path.exists(
                    output_directory + img.split("::")[0] + "/artefacts/cooked/"
                ):
                    collect_metadata(
                        verbosity,
                        output_directory,
                        img,
                        output_directory + img.split("::")[0] + "/artefacts/cooked/",
                        stage,
                        sha256,
                        nsrl,
                    )
                else:
                    pass
                if os.path.exists(
                    output_directory + img.split("::")[0] + "/artefacts/carved/"
                ):
                    collect_metadata(
                        verbosity,
                        output_directory,
                        img,
                        output_directory + img.split("::")[0] + "/artefacts/carved/",
                        stage,
                        sha256,
                        nsrl,
                    )
                else:
                    pass
                if os.path.exists(output_directory + img.split("::")[0] + "/analysis/"):
                    collect_metadata(
                        verbosity,
                        output_directory,
                        img,
                        output_directory + img.split("::")[0] + "/analysis/",
                        stage,
                        sha256,
                        nsrl,
                    )
                else:
                    pass
                if os.path.exists(output_directory + img.split("::")[0] + "/files/"):
                    collect_metadata(
                        verbosity,
                        output_directory,
                        img,
                        output_directory + img.split("::")[0] + "/files/",
                        stage,
                        sha256,
                        nsrl,
                    )
                else:
                    pass
                print(
                    "\n    Completed collection of metadata from processed artefacts for '{}'...".format(
                        img.split("::")[0]
                    )
                )
            print(
                "  ----------------------------------------\n  -> Completed Metadata phase for proccessed artefacts.\n"
            )
            time.sleep(1)
        else:
            pass
        if splunk:
            splunkuser, splunkpswd = configure_splunk_stack(
                verbosity,
                output_directory,
                case,
                imgs,
                volatility,
                analysis,
                timeline,
            )
            flags.append("06splunk")
            print(
                "  ----------------------------------------\n  -> Completed Splunk Phase.\n"
            )
            time.sleep(1)
        else:
            pass
        if elastic:
            configure_elastic_stack(
                verbosity, output_directory, case, imgs, volatility, analysis, timeline
            )
            print(
                "   Kibana is available at:            127.0.0.1:5601"
            )  # adjust if custom location
            flags.append("07elastic")
            print(
                "  ----------------------------------------\n  -> Completed Elastic Phase.\n"
            )
            time.sleep(1)
        else:
            pass
        if sigma:
            write_sigma_signatures(
                verbosity, output_directory, case, imgs, volatility, analysis, timeline
            )
            flags.append("08sigma")
            print(
                "  ----------------------------------------\n  -> Completed SIGMA Phase.\n"
            )
            time.sleep(1)
        else:
            pass
        if yara:
            write_yara_signatures(
                verbosity, output_directory, case, imgs, volatility, analysis, timeline
            )
            flags.append("09yara")
            print(
                "  ----------------------------------------\n  -> Completed YARA Phase.\n"
            )
            time.sleep(1)
        else:
            pass
        if splunk and navigator:  # mapping to attack-navigator
            print(
                "\n\n  -> \033[1;36mBuilding ATT&CK® Navigator...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            configure_navigator(case, splunkuser, splunkpswd)
            print(
                "\n   ATT&CK® Navigator is available at:     127.0.0.1/attack-navigator\n"
            )
            flags.append("10navigator")
            print(
                "  ----------------------------------------\n  -> Completed ATT&CK® Navigator Phase.\n"
            )
            time.sleep(1)
        else:
            pass
        if archive or delete:
            for img, mntlocation in imgs.items():
                if "vss" not in img and "vss" not in mntlocation:
                    if archive:
                        archive_artefacts(verbosity, output_directory)
                        flags.append("11archiving")
                    else:
                        pass
                    if delete:
                        delete_artefacts(verbosity, output_directory)
                        flags.append("12deletion")
                    else:
                        pass
                else:
                    pass
        else:
            pass
    else:
        pass
    endtime, fmt, timestringprefix = (
        datetime.now().isoformat(),
        "%Y-%m-%dT%H:%M:%S.%f",
        "Total elasped time: ",
    )
    st, et = datetime.strptime(starttime, fmt), datetime.strptime(endtime, fmt)
    totalsecs, secs = int(round((et - st).total_seconds())), int(
        round((et - st).total_seconds() % 60)
    )
    if round((et - st).total_seconds()) > 3600:
        hours, mins = round((et - st).total_seconds() / 60 / 60), round(
            (et - st).total_seconds() / 60 % 60
        )
        if hours > 1 and mins > 1 and secs > 1:
            timetaken = "{} hours, {} minutes and {} seconds.".format(
                str(hours), str(mins), str(secs)
            )
        elif hours > 1 and mins > 1 and secs == 1:
            timetaken = "{} hours, {} minutes and {} second.".format(
                str(hours), str(mins), str(secs)
            )
        elif hours > 1 and mins == 1 and secs > 1:
            timetaken = "{} hours, {} minute and {} seconds.".format(
                str(hours), str(mins), str(secs)
            )
        elif hours == 1 and mins > 1 and secs > 1:
            timetaken = "{} hour, {} minutes and {} seconds.".format(
                str(hours), str(mins), str(secs)
            )
        elif hours > 1 and mins == 1 and secs == 1:
            timetaken = "{} hours, {} minute and {} second.".format(
                str(hours), str(mins), str(secs)
            )
        elif hours == 1 and mins > 1 and secs == 1:
            timetaken = "{} hour, {} minutes and {} seconds.".format(
                str(hours), str(mins), str(secs)
            )
        elif hours == 1 and mins == 1 and secs > 1:
            timetaken = "{} hour, {} minute and {} seconds.".format(
                str(hours), str(mins), str(secs)
            )
        elif hours > 1 and mins > 1 and secs == 0:
            timetaken = "{} hours and {} minutes.".format(str(hours), str(mins))
        elif hours > 1 and mins == 0 and secs > 0:
            timetaken = "{} hours and {} seconds.".format(str(hours), str(secs))
        elif hours == 1 and mins > 1 and secs == 0:
            timetaken = "{} hour and {} minutes.".format(str(hours), str(mins))
        elif hours == 1 and mins == 0 and secs > 0:
            timetaken = "{} hour and {} second.".format(str(hours), str(secs))
        elif hours > 1 and mins == 0 and secs == 0:
            timetaken = "{} hours.".format(str(hours))
        elif hours == 1 and mins == 0 and secs == 0:
            timetaken = "{} hour.".format(str(hours))
        else:
            pass
    elif 3600 > round((et - st).total_seconds()) > 60:
        mins = round((et - st).total_seconds() / 60)
        if mins > 1 and secs > 1:
            timetaken = "{} minutes and {} seconds.".format(str(mins), str(secs))
        elif mins == 1 and secs > 1:
            timetaken = "{} minute and {} seconds.".format(str(mins), str(secs))
        elif mins > 1 and secs == 1:
            timetaken = "{} minutes and {} second.".format(str(mins), str(secs))
        elif mins == 1 and secs == 1:
            timetaken = "{} minute and {} second.".format(str(mins), str(secs))
        else:
            timetaken = "{} minutes.".format(str(mins))
    else:
        if secs > 1:
            timetaken = "{} seconds.".format(str(secs))
        else:
            timetaken = "{} second.".format(str(secs))
    if vss:
        for eachimg, _ in imgs.items():
            if (
                "Windows" in eachimg.split("::")[1]
                and (
                    ".E01" in eachimg.split("::")[0] or ".e01" in eachimg.split("::")[0]
                )
                and "memory" not in eachimg.split("::")[1]
                and "_vss" not in eachimg.split("::")[1]
            ):
                inspectedvss = input(
                    "\n\n  ----------------------------------------\n   Have you reviewed the Volume Shadow Copies for '{}'? Y/n [Y] ".format(
                        eachimg.split("::")[0]
                    )
                )
                if inspectedvss != "n":
                    unmount_images(elrond_mount, ewf_mount)
                    print(
                        "    Unmounted Volume Shadow Copies for '{}'\n  ----------------------------------------\n".format(
                            eachimg.split("::")[0]
                        )
                    )
                else:
                    pass
            else:
                pass
    else:
        unmount_images(elrond_mount, ewf_mount)
    print(
        "\n\n  -> \033[1;36mFinished. {}{}\033[1;m\n  ----------------------------------------".format(
            timestringprefix, timetaken
        )
    )
    time.sleep(1)
    if len(flags) > 0:
        doneimgs, sortedflags = [], re.sub(
            r"', '\d{2}", r", ", str(sorted(set(flags))).title()[4:-2]
        )
        if ", " in sortedflags:
            flags = sortedflags.split(", ")
            lastflag = " and " + flags[-1]
            flags.pop()
            flags = (
                str(flags).replace("[", "").replace("]", "").replace("'", "") + lastflag
            )
        else:
            pass
        if len(allimgs) > 0:
            print("      {} phases completed for...".format(flags))
            for eachimg in allimgs:
                doneimgs.append(eachimg.split("::")[0].split("/")[-1])
        else:
            pass
    else:
        pass
    unmount_images(elrond_mount, ewf_mount)
    for eachimg, _ in allimgs.items():
        for doneroot, donedirs, donefiles in os.walk(
            output_directory + str(eachimg.split("::")[0]).split("/")[-1]
        ):
            for donefile in donefiles:
                if os.path.exists(os.path.join(doneroot, donefile)):
                    if os.stat(os.path.join(doneroot, donefile)).st_size <= 10:
                        try:
                            os.remove(os.path.join(doneroot, donefile))
                        except:
                            pass
                    else:
                        pass
                else:
                    pass
            for donedir in donedirs:
                if os.path.exists(doneroot + "/artefacts/raw/"):
                    for eachdir in os.listdir(doneroot + "/artefacts/raw/"):
                        if os.path.exists(
                            doneroot + "/artefacts/raw/" + eachdir + "/IE/"
                        ):
                            shutil.rmtree(doneroot + "/artefacts/raw/" + eachdir)
                        else:
                            pass
                else:
                    pass
                if len(os.listdir(os.path.join(doneroot, donedir))) < 1:
                    try:
                        shutil.rmtree(os.path.join(doneroot, donedir))
                    except:
                        pass
                else:
                    pass
    for doneimg in doneimgs:
        print("       '{}'".format(doneimg))
        entry, prnt = "{},{},finished,'{}'-'{}': ({} seconds)".format(
            datetime.now().isoformat(), doneimg, st, et, totalsecs
        ), " -> {} -> elrond completed for '{}'".format(
            datetime.now().isoformat().replace("T", " "), doneimg
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        time.sleep(1)
    if len(allimgs.items()) > 0:
        print("  ----------------------------------------")
    else:
        pass
    print("\n\n     \033[1;36m{}\033[1;m".format(random.choice(quotes) + "\n\n\n"))
    os.chdir(cwd)
