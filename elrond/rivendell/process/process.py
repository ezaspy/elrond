#!/usr/bin/env python3 -tt
import os

from rivendell.process.browser import process_browser_index
from rivendell.process.browser import process_browser
from rivendell.process.mac import process_plist
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
from rivendell.process.windows import (
    process_registry_system,
)
from rivendell.process.windows import process_registry_profile
from rivendell.process.windows import process_shimcache
from rivendell.process.windows import process_usb
from rivendell.process.windows import process_ual
from rivendell.process.windows import process_wbem
from rivendell.process.windows import process_wmi


def process_artefacts(
    output_directory,
    verbosity,
    volatility,
    d,
    stage,
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
        if artefact.endswith("setupapi.dev.log"):
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
        elif artefact.endswith("$MFT"):
            process_mft(
                verbosity, vssimage, output_directory, img, artefact, vssartefact, stage
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
            )
        elif artefact.endswith("+NTUSER.DAT") or artefact.endswith("+UsrClass.dat"):
            process_registry_profile(
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
        elif artefact.endswith("_ActivitiesCache.db"):
            process_clipboard(
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
        elif artefact.endswith(".etl"):
            process_wmi(
                verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
            )
        elif artefact.endswith("OBJECTS.DATA"):
            process_wbem(
                verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
            )
        elif artefact.endswith(".mdb"):
            process_ual(
                verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
            )
        elif artefact.endswith("-ms") and "+" in artefact:
            process_jumplists(
                verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
            )
        elif artefact.endswith(".pst"):
            process_outlook(
                verbosity,
                vssimage,
                output_directory,
                img,
                vssartefact,
                stage,
                artefact,
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
        ) and "/logs/" in artefact:  # no year in DateTime field
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
        ):
            process_browser(
                verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
            )
        elif artefact.endswith("hiberfil.sys") and volatility:
            if not os.path.exists(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vssartefact
                + "memory"
            ):
                process_hiberfil(
                    d,
                    verbosity,
                    vssimage,
                    output_directory,
                    img,
                    vssartefact,
                    stage,
                    artefact,
                    volchoice,
                    vss,
                    vssmem,
                    memtimeline,
                )
            else:
                pass
        elif artefact.endswith("MEMORY.DMP") and volatility:
            pass
        elif (
            artefact.endswith("pagefile.sys") or artefact.endswith("swapfile.sys")
        ) and volatility:
            process_pagefile(
                verbosity, vssimage, output_directory, img, vssartefact, artefact
            )
        else:
            pass
    else:
        pass
    return vssmem


def determine_vss_image(
    output_directory,
    verbosity,
    volatility,
    d,
    stage,
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
    return vssmem
