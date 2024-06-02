#!/usr/bin/env python3 -tt
import os
import re
import time
from collections import OrderedDict
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.process.process import determine_vss_image
from rivendell.process.process import process_artefacts


def select_artefacts_to_process(img, process_list, artefacts_list, processed_artefacts):
    for each in process_list:
        for root, _, files in os.walk(each):
            for f in files:  # identifying artefacts for processing
                if (img.split("::")[0] in root) and (
                    root + "/" + f not in str(processed_artefacts)
                ): # ensure to check both the file (f) and the path (root) for specific matching strings
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
                        or f.endswith("_ActivitiesCache.db")
                        or f.endswith("setupapi.dev.log")
                        or f.endswith("hiberfil.sys")
                        or f.endswith("MEMORY.DMP")
                        or f.endswith("pagefile.sys")
                        or f.endswith("swapfile.sys")
                        or f.endswith("-ms")
                        or f.endswith(".pf")
                        or f.endswith(".etl")
                        or f.endswith("OBJECTS.DATA")
                        or f.endswith(".mdb")
                        or f.endswith(".db")
                        or f.endswith(".bcf")
                        or f.endswith(".hve")
                        or f.endswith("SRUDB.dat")
                        or "/S-1-5-21-" in root + "/" + f
                        or f.endswith("+bash_aliases")
                        or f.endswith("+bash_history")
                        or f.endswith("+bash_logout")
                        or f.endswith("+bashrc")
                        or f.endswith("crontab")
                        or f.endswith("group")
                        or f.endswith("hosts")
                        or "/journal/" in root
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
                        or "/carved/" in root
                    ):
                        artefacts_list.append(each + ": " + root + "/" + f)
                        processed_artefacts.append(root + "/" + f)
    return artefacts_list


def select_pre_process_artefacts(
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
    collectfiles,
):
    stage = "processing"
    process_list, artefacts_list = [], []
    print(
        "\n\n  -> \033[1;36mCommencing Processing Phase...\033[1;m\n  ----------------------------------------"
    )
    time.sleep(1)
    imgs = OrderedDict(sorted(imgs.items(), key=lambda x: x[1]))
    processed_imgs, processed_artefacts = [], []
    for _, img in imgs.items():  # identifying artefacts and processing function
        if img.split("::")[0] not in str(processed_imgs) and not img.split("::")[
            1
        ].endswith(
            "memory"
        ):  # identifying artefacts for processing
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
                    process_list.append(output_directory + each + "/artefacts/raw/")
            try:
                os.remove(".temp.log")
            except:
                pass
            artefacts_list = select_artefacts_to_process(
                img, process_list, artefacts_list, processed_artefacts
            )  # identifying artefacts for processing
            if len(artefacts_list) == 0:
                print(
                    "    No artefacts were collected for {}.\n    Please try again.\n\n".format(
                        img.split("::")[0]
                    )
                )
            processed_imgs.append(img.split("::")[0])
    for _, img in imgs.items():  # processing identified artefacts
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
        for each in artefacts_list:
            ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
            artefact = str(ia[0][1])
            if not artefact.split("/")[-1].startswith(
                "#"
            ):  # processing primary image artefacts
                vssmem = determine_vss_image(
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
                )
        # below sections are for multi-paritied drives
        for each in artefacts_list:
            ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
            artefact = str(ia[0][1])
            if artefact.split("/")[-1].startswith(
                "#1"
            ):  # processing secondary image artefacts
                vssmem = determine_vss_image(
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
                )
        for each in artefacts_list:
            ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
            artefact = str(ia[0][1])
            if artefact.split("/")[-1].startswith(
                "#2"
            ):  # processing tertiary image artefacts
                vssmem = determine_vss_image(
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
                )
        for each in artefacts_list:
            ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
            artefact = str(ia[0][1])
            if artefact.split("/")[-1].startswith(
                "#3"
            ):  # processing secondary, tertiary etc. image artefacts
                vssmem = determine_vss_image(
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
                )
        for each in artefacts_list:
            ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
            artefact = str(ia[0][1])
            if artefact.split("/")[-1].startswith(
                "#4"
            ):  # processing secondary, tertiary etc. image artefacts
                vssmem = determine_vss_image(
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
                )
        for each in artefacts_list:
            ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
            artefact = str(ia[0][1])
            if artefact.split("/")[-1].startswith(
                "#5"
            ):  # processing secondary, tertiary etc. image artefacts
                vssmem = determine_vss_image(
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
                )
        for each in artefacts_list:
            ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
            artefact = str(ia[0][1])
            if artefact.split("/")[-1].startswith(
                "#6"
            ):  # processing secondary, tertiary etc. image artefacts
                vssmem = determine_vss_image(
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
                )
        for each in artefacts_list:
            ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
            artefact = str(ia[0][1])
            if artefact.split("/")[-1].startswith(
                "#7"
            ):  # processing secondary, tertiary etc. image artefacts
                vssmem = determine_vss_image(
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
                )
        for each in artefacts_list:
            ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
            artefact = str(ia[0][1])
            if artefact.split("/")[-1].startswith(
                "#8"
            ):  # processing secondary, tertiary etc. image artefacts
                vssmem = determine_vss_image(
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
                )
        for each in artefacts_list:
            ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
            artefact = str(ia[0][1])
            if artefact.split("/")[-1].startswith(
                "#9"
            ):  # processing secondary, tertiary etc. image artefacts
                vssmem = determine_vss_image(
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
                )
        if collectfiles:
            process_list.clear()
            if os.path.exists(
                os.path.join(output_directory + img.split("::")[0] + "/carved/")
            ):
                print(
                    "\n      \033[1;33m{} carved files for {}...\033[1;m".format(
                        stage.title(), vssimage
                    )
                )
                process_list.append(
                    os.path.join(output_directory + img.split("::")[0] + "/carved/")
                )
                artefacts_list.clear()
                artefacts_list = select_artefacts_to_process(
                    img, process_list, artefacts_list, processed_artefacts
                )
                for each in artefacts_list:
                    ia = re.findall(r"(?P<i>[^\:]+)\:\ (?P<a>[^\:]+)", each)
                    artefact = str(ia[0][1])
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
                print(
                    "       \033[1;33mProcessed carved files for {}\n\033[1;m".format(
                        vssimage
                    )
                )
        print("  -> Completed Processing Phase for {}".format(vssimage))
        entry, prnt = "{},{},{},completed\n".format(
            datetime.now().isoformat(), vssimage.replace("'", ""), stage
        ), " -> {} -> processing completed for {}".format(
            datetime.now().isoformat().replace("T", " "), vssimage
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        print()
        processed_imgs.append(img.split("::")[0])
    if "02processing" not in str(flags):
        flags.append("02processing")
    os.chdir(cwd)
    print(
        "  ----------------------------------------\n  -> Completed Processing Phase.\n"
    )
    time.sleep(1)
