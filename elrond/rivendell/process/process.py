#!/usr/bin/env python3 -tt
import os
import re

from rivendell.process.browser import process_browser_index
from rivendell.process.browser import process_browser
from rivendell.process.mac import process_plist
from rivendell.process.linux import process_journal
from rivendell.process.nix import process_bash_history
from rivendell.process.nix import process_email
from rivendell.process.nix import process_group
from rivendell.process.nix import process_logs
from rivendell.process.nix import process_service
from rivendell.process.windows import process_clipboard
from rivendell.process.windows import process_evtx
from rivendell.process.windows import process_hiberfil
from rivendell.process.windows import process_jumplists
from rivendell.process.windows import process_mft
from rivendell.process.windows import process_outlook
from rivendell.process.windows import process_pagefile
from rivendell.process.windows import process_prefetch
from rivendell.process.windows import (
    process_registry_system,
)
from rivendell.process.windows import process_registry_profile
from rivendell.process.windows import process_shimcache
from rivendell.process.windows import process_sru
from rivendell.process.windows import process_ual
from rivendell.process.windows import process_usb
from rivendell.process.windows import process_usn
from rivendell.process.windows import process_wbem
from rivendell.process.windows import process_wmi


def process_artefacts(
    output_directory,
    verbosity,
    volatility,
    d,
    stage,
    imgs,
    img,
    vssimage,
    vss_path_insert,
    artefact,
    vssmem,
    volchoice,
    vss,
    memtimeline,
):
    jsondict = {}
    jsonlist = []
    if img.split("::")[0] in artefact:
        if artefact.endswith("setupapi.dev.log"):
            process_usb(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith("$MFT"):
            process_mft(
                verbosity,
                vssimage,
                output_directory,
                img,
                artefact,
                vss_path_insert,
                stage,
            )
        elif artefact.endswith("$UsnJrnl"):
            process_usn(
                verbosity,
                vssimage,
                output_directory,
                img,
                artefact,
                vss_path_insert,
                stage,
            )
        elif artefact.endswith(".SYSTEM") and not os.path.exists(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "ShimCache.csv"
        ):
            process_shimcache(
                verbosity, vssimage, output_directory, img, vss_path_insert, stage
            )
        elif (
            artefact.endswith("SAM")
            or artefact.endswith("SECURITY")
            or artefact.endswith("SOFTWARE")
            or artefact.endswith("SYSTEM")
            and not artefact.endswith(".SYSTEM")
        ):
            process_registry_system(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith("+NTUSER.DAT") or artefact.endswith("+UsrClass.dat"):
            process_registry_profile(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith(".evtx"):
            process_evtx(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif "/prefetch" in artefact:
            process_prefetch(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                re.findall(r"'([^']+)', '" + re.escape(img), str(imgs))[0],
            )
        elif artefact.endswith("_ActivitiesCache.db"):
            process_clipboard(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith(".etl"):
            process_wmi(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith("OBJECTS.DATA"):
            process_wbem(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif artefact.endswith("SRUDB.dat"):
            process_sru(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif (
            artefact.endswith("Current.mdb")
            or artefact.endswith("SystemIdentity.mdb")
            or artefact.endswith("}}.mdb")
        ):
            process_ual(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif artefact.endswith("-ms") and "+" in artefact:
            process_jumplists(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif artefact.endswith(".pst"):
            process_outlook(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif artefact.endswith(".plist"):
            process_plist(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif artefact.endswith("bash_history"):
            process_bash_history(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif artefact.endswith(".emlx"):
            process_email(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith("/group"):
            process_group(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif "journal" in artefact:
            process_journal(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif (
            artefact.endswith("log") or artefact.endswith("log.1")
        ) and "/logs/" in artefact:  # no year in DateTime field
            process_logs(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif (
            artefact.endswith(".service")
            or artefact.endswith(".target")
            or artefact.endswith(".socket")
            or artefact.endswith(".timer")
        ):
            process_service(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith("index.dat") and os.stat(artefact).st_size > 32768:
            process_browser_index(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif (
            (
                artefact.endswith("History")
                and ("Edge" in artefact or "chrome" in artefact)
            )
            or (artefact.endswith("History.db") and "safari" in artefact)
            or ("places.sqlite" in artefact and "firefox" in artefact)
        ):
            process_browser(
                verbosity,
                vssimage,
                output_directory,
                img,
                vss_path_insert,
                stage,
                artefact,
            )
        elif artefact.endswith("hiberfil.sys") and volatility:
            if not os.path.exists(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "memory"
            ):
                process_hiberfil(
                    d,
                    verbosity,
                    vssimage,
                    output_directory,
                    img,
                    vss_path_insert,
                    stage,
                    artefact,
                    volchoice,
                    vss,
                    vssmem,
                    memtimeline,
                )
        elif artefact.endswith("MEMORY.DMP") and volatility:
            pass
        elif (
            artefact.endswith("pagefile.sys") or artefact.endswith("swapfile.sys")
        ) and volatility:
            process_pagefile(
                verbosity, vssimage, output_directory, img, vss_path_insert, artefact
            )
        elif artefact.endswith("LastAccessTimes.txt"):
            with open(artefact) as last_access_times:
                access_times = last_access_times.read()
            with open(
                output_directory
                + img.split("::")[0]
                + "/artefacts/LastAccessTimes.csv",
                "a",
            ) as access_time_handle:
                for segment in access_times.split("\n\n"):
                    directory = segment.split("\n")[0]
                    blocks = segment.split("\n")[1]
                    for line in segment.split("\n")[2:]:
                        metadata = re.findall(
                            r"^\s*(\d+)\s+([\-dlbcnpsDEOS])([rwxacsht\-\+]+)\s+(\d+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+(\d+)(?:,\s+\d+)?\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+([^\s]+)\s(.*)$",
                            line,
                        )
                        try:  # https://www.mkssoftware.com/docs/man1/ls.1.asp
                            if metadata[0][-1] != '"."' and metadata[0][-1] != '".."':
                                inode = metadata[0][0]
                                item = metadata[0][1]
                                if item == "-":
                                    item = "file"
                                elif item == "d":
                                    item = "directory"
                                elif item == "l":
                                    item = "link"
                                elif item == "b":
                                    item = "block-special"
                                elif item == "c":
                                    item = "character-special"
                                elif item == "n":
                                    item = "network"
                                elif item == "p":
                                    item = "FIFO"
                                elif item == "s":
                                    item = "socket"
                                elif item == "D":
                                    item = "demand-recall"
                                elif item == "E":
                                    item = "encrypted"
                                elif item == "O":
                                    item = "offline"
                                elif item == "S":
                                    item = "sparse"
                                permissions = metadata[0][
                                    2
                                ]  # read (r), write (w), execute (x), archive (a), compressed (c), system (s), hidden (h), temporary (t)
                                links = metadata[0][3]
                                user = metadata[0][4]
                                group = metadata[0][5]
                                author = metadata[0][6]
                                size = metadata[0][7]
                                timestamp = metadata[0][8]
                                timezone = metadata[0][9]
                                name = metadata[0][10]
                                access_time_handle.write(
                                    "{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(
                                        directory,
                                        blocks,
                                        inode,
                                        item,
                                        permissions,
                                        links,
                                        user,
                                        group,
                                        author,
                                        size,
                                        timestamp,
                                        timezone,
                                        name,
                                    )
                                )
                        except:
                            pass
    return vssmem


def determine_vss_image(
    output_directory,
    verbosity,
    volatility,
    d,
    stage,
    imgs,
    img,
    vssimage,
    artefact,
    vssmem,
    volchoice,
    vss,
    memtimeline,
):
    if (
        "_vss" in img
        and "volume shadow c" in vssimage
        and "/vss" + vssimage[-2] in artefact
    ):
        vssmem = process_artefacts(
            output_directory,
            verbosity,
            volatility,
            d,
            stage,
            imgs,
            img,
            vssimage,
            "/"
            + vssimage.split("(")[1].replace("volume shadow copy #", "vss")[:-1]
            + "/",
            artefact,
            vssmem,
            volchoice,
            vss,
            memtimeline,
        )
    elif (
        "_vss" not in img
        and "volume shadow c" not in vssimage
        and "/vss" not in artefact
    ):
        vssmem = process_artefacts(
            output_directory,
            verbosity,
            volatility,
            d,
            stage,
            imgs,
            img,
            vssimage,
            "/",
            artefact,
            vssmem,
            volchoice,
            vss,
            memtimeline,
        )
    return vssmem
