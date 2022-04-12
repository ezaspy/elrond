#!/usr/bin/env python3 -tt
import os
import re
import time
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.processing.browser import process_browser_index
from rivendell.processing.browser import process_browser
from rivendell.processing.mac import process_plist
from rivendell.processing.nix import process_bash_history
from rivendell.processing.nix import process_email
from rivendell.processing.nix import process_group
from rivendell.processing.nix import process_logs
from rivendell.processing.nix import process_service
from rivendell.processing.windows import process_evtx
from rivendell.processing.windows import process_hiberfil
from rivendell.processing.windows import process_jumplists
from rivendell.processing.windows import process_mft
from rivendell.processing.windows import process_pagefile
from rivendell.processing.windows import (
    process_registry_system,
)
from rivendell.processing.windows import process_registry_user
from rivendell.processing.windows import process_shimcache
from rivendell.processing.windows import process_usb


def process_artefacts(
    output_directory,
    verbosity,
    volatility,
    d,
    stage,
    cwd,
    img,
    vssimage,
    vssartefact,
    artefact,
    vssmem,
    volchoice,
    vss,
    memtimeline,
):
    jsondict = {}
    jsonlist = []
    if img.split("::")[0] in artefact:
        if artefact.endswith("$MFT") and not os.path.exists(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + "MFT.csv"
        ):
            process_mft(
                verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
            )
        elif artefact.endswith("setupapi.dev.log") and not os.path.exists(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + "usb.log.json"
        ):
            process_usb(
                verbosity,
                vssimage,
                output_directory,
                img,
                vssartefact,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith(".SYSTEM") and not os.path.exists(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + "ShimCache.csv"
        ):
            process_shimcache(
                verbosity, vssimage, output_directory, img, vssartefact, stage
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
                vssartefact,
                stage,
                artefact,
                jsondict,
                jsonlist,
                cwd,
            )
        elif artefact.endswith("+NTUSER.DAT") or artefact.endswith("+UsrClass.dat"):
            process_registry_user(
                verbosity,
                vssimage,
                output_directory,
                img,
                vssartefact,
                stage,
                artefact,
                jsondict,
                jsonlist,
                cwd,
            )
        elif artefact.endswith(".evtx"):
            process_evtx(
                verbosity,
                vssimage,
                output_directory,
                img,
                vssartefact,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith("-ms") and "+" in artefact:
            process_jumplists(
                verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
            )
        elif artefact.endswith(".plist"):
            process_plist(
                verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
            )
        elif artefact.endswith("bash_history"):
            process_bash_history(
                verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
            )
        elif artefact.endswith(".emlx"):
            process_email(
                verbosity,
                vssimage,
                output_directory,
                img,
                vssartefact,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith("/group"):
            process_group(
                verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
            )
        elif (
            artefact.endswith("log") or artefact.endswith("log.1")
        ) and "/logs/" in artefact:  # missing - year in DateTime field
            process_logs(
                verbosity,
                vssimage,
                output_directory,
                img,
                vssartefact,
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
                vssartefact,
                stage,
                artefact,
                jsondict,
                jsonlist,
            )
        elif artefact.endswith("index.dat") and os.stat(artefact).st_size > 32768:
            process_browser_index(
                verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
            )
        elif (
            (
                artefact.endswith("History")
                and ("Edge" in artefact or "chrome" in artefact)
            )
            or (artefact.endswith("History.db") and "safari" in artefact)
            or ("places.sqlite" in artefact and "firefox" in artefact)
        ):  # outstanding - evidence of browser downloads
            process_browser(
                verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
            )
        elif (
            artefact.endswith("hiberfil.sys") or artefact.endswith("MEMORY.DMP")
        ) and volatility:
            process_hiberfil(
                d,
                verbosity,
                vssimage,
                output_directory,
                img,
                vssartefact,
                stage,
                artefact,
                volatility,
                volchoice,
                vss,
                vssmem,
                memtimeline,
            )
        elif artefact.endswith("pagefile.sys") or artefact.endswith("swapfile.sys"):
            process_pagefile(
                verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
            )
        else:
            pass
    else:
        pass
    return vssmem


def identify_pre_process_artefacts(
    output_directory,
    verbosity,
    d,
    flags,
    stage,
    cwd,
    imgs,
    vssimage,
    artefact,
    vssmem,
    volatility,
    volchoice,
    vss,
    memtimeline,
):

    stage = "processing"
    plist, atfts = [], []
    print(
        "\n\n  -> \033[1;36mCommencing Processing Phase...\033[1;m\n  ----------------------------------------"
    )
    time.sleep(1)
    for img in imgs:  # Identifying artefacts and Processing function
        if not img.split("::")[1].endswith(
            "memory"
        ):  # Identifying artefacts for processing
            for each in os.listdir(output_directory):
                if each + "/" == output_directory or each == img.split("::")[0]:
                    for eachdir in os.listdir(
                        os.path.realpath(output_directory + each + "/artefacts/raw")
                    ):
                        if (
                            "vss" in eachdir
                            and os.path.isdir(
                                os.path.realpath(
                                    output_directory
                                    + each
                                    + "/artefacts/raw/"
                                    + eachdir
                                )
                            )
                            and not os.path.exists(
                                output_directory
                                + img.split("::")[0]
                                + "/artefacts/cooked/"
                                + eachdir
                            )
                        ):
                            os.makedirs(
                                output_directory
                                + img.split("::")[0]
                                + "/artefacts/cooked/"
                                + eachdir
                            )
                        elif not os.path.exists(
                            output_directory + img.split("::")[0] + "/artefacts/cooked/"
                        ):
                            os.makedirs(
                                output_directory
                                + img.split("::")[0]
                                + "/artefacts/cooked/"
                            )
                        else:
                            pass
                    plist.append(output_directory + each)
                else:
                    pass
            try:
                os.remove(".temp.log")
            except:
                pass
            for each in plist:  # Identifying artefacts for processing
                for root, _, files in os.walk(each):
                    for f in files:  # Identifying artefacts for processing
                        if img.split("::")[0] in root:
                            if (
                                f.endswith("MFT")
                                or f.endswith("LogFile")
                                or f.endswith("UsnJrnl")
                                or f.endswith("ObjId")
                                or f.endswith("Reparse")
                                or f.endswith("SAM")
                                or f.endswith("SECURITY")
                                or f.endswith("SOFTWARE")
                                or f.endswith("SYSTEM")
                                or f.endswith("NTUSER.DAT")
                                or f.endswith("UsrClass.dat")
                                or f.endswith(".evtx")
                                or f.endswith("setupapi.dev.log")
                                or f.endswith("hiberfil.sys")
                                or f.endswith("MEMORY.DMP")
                                or f.endswith("pagefile.sys")
                                or f.endswith("swapfile.sys")
                                or f.endswith("-ms")
                                or f.endswith(".pf")
                                or f.endswith(".db")
                                or f.endswith(".bcf")
                                or f.endswith(".hve")
                                or "/S-1-5-21-" in root + "/" + f
                                or f.endswith("+bash_aliases")
                                or f.endswith("+bash_history")
                                or f.endswith("+bash_logout")
                                or f.endswith("+bashrc")
                                or f.endswith("crontab")
                                or f.endswith("hosts")
                                or f.endswith("group")
                                or f.endswith("passwd")
                                or f.endswith("shadow")
                                or f.endswith("log")
                                or "log.1" in f
                                or "__audit_" in f
                                or "+audit_" in f
                                or f.endswith(".plist")
                                or f.endswith(".conf")
                                or f.split("/")[-1].startswith("job.")
                                or f.endswith(".service")
                                or f.endswith(".target")
                                or f.endswith(".socket")
                                or "/raw/mail" in root + "/" + f
                                or "/raw/browsers" in root + "/" + f
                            ):
                                atfts.append(each + ": " + root + "/" + f)
                            else:
                                pass
                        else:
                            pass
            if len(atfts) == 0:
                print("    No artefacts were collected.\n    Please try again.\n\n")
            else:
                pass
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
            print("    Processing artefacts for {}...".format(vssimage))
            entry, prnt = "{},{},{},commenced\n".format(
                datetime.now().isoformat(), vssimage.replace("'", ""), stage
            ), " -> {} -> {} artefacts for {}".format(
                datetime.now().isoformat().replace("T", " "), stage, vssimage
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            for each in atfts:
                ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
                artefact = str(ia[0][1])
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
                        cwd,
                        img,
                        vssimage,
                        "/"
                        + vssimage.split("(")[1].replace("volume shadow copy #", "vss")[
                            :-1
                        ]
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
                        cwd,
                        img,
                        vssimage,
                        "/",
                        artefact,
                        vssmem,
                        volchoice,
                        vss,
                        memtimeline,
                    )
                else:
                    pass
        else:
            pass
        print("  -> Completed Processing Phase for {}".format(vssimage))
        entry, prnt = "{},{},{},completed\n".format(
            datetime.now().isoformat(), vssimage.replace("'", ""), stage
        ), " -> {} -> processing completed for {}".format(
            datetime.now().isoformat().replace("T", " "), vssimage
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        print()
    else:
        pass
    flags.append("02processing")
    os.chdir(cwd)
    print(
        "  ----------------------------------------\n  -> Completed Processing Phase.\n"
    )
    time.sleep(1)
