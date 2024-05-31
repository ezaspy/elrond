#!/usr/bin/env python3 -tt

import os
import re
import time
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.analysis.iocs import compare_iocs


def analyse_artefacts(
    verbosity, output_directory, img, mnt, analysis, extractiocs, vssimage
):
    def analyse_disk_images(stage, vssimage, ar, f, anysd):
        print()
        print(
            "     Analysing MFT for Extended Attributes, Alternate Data Streams & Timestomping for {}...".format(
                vssimage
            )
        )
        with open(ar + "/" + f) as afh:
            for line in afh:
                mftinfo = re.findall(
                    r"[^\,]*\,[^\,]*\,[^\,]*\,([^\,]*)\,[^\,]*\,[^\,]*\,[^\,]*\,([^\,]*)\,([^\,]*)\,[^\,]*\,[^\,]*\,[^\,]*\,([^\,]*)\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,([^\,]*)\,([^\,]*)\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,([^\,]*)\,[^\,]*\,[^\,]*\,[^\,]*",
                    line,
                )
                if len(mftinfo) > 0 and (
                    (
                        mftinfo[0][0] == "File"
                        and mftinfo[0][1] != "NoFNRecord"
                        and (
                            mftinfo[0][4] == "True"
                            or mftinfo[0][5] == "True"
                            or mftinfo[0][6] == "Y"
                        )
                    )
                    or (
                        mftinfo[0][0] == "file"
                        and mftinfo[0][1] != "nofnrecord"
                        and (
                            mftinfo[0][4] == "true"
                            or mftinfo[0][5] == "true"
                            or mftinfo[0][6] == "y"
                        )
                    )
                ):
                    if not os.path.exists(anysd + "/analysis.csv"):
                        with open(anysd + "/analysis.csv", "a") as analysisfile:
                            analysisfile.write(
                                "LastWriteTime,elrond_host,Filename,AnalysisType,AnalysisValue\n"
                            )
                    else:
                        with open(anysd + "/analysis.csv", "a") as analysisfile:
                            if (mftinfo[0][4] == "True" or mftinfo[0][5] == "True") or (
                                mftinfo[0][4] == "true" or mftinfo[0][5] == "true"
                            ):
                                analysisfile.write(
                                    "{},{},{},ExtendedAttributes,Yes\n".format(
                                        datetime.now().isoformat(),
                                        vssimage.replace("'", ""),
                                        mftinfo[0][1],
                                    )
                                )
                                if verbosity != "":
                                    print(
                                        "      Extended Attributes identified for '{}'".format(
                                            mftinfo[0][1].split("/")[-1]
                                        )
                                    )
                                (
                                    entry,
                                    prnt,
                                ) = "{},{},{},extended attribute found in '{}'\n".format(
                                    datetime.now().isoformat(),
                                    vssimage,
                                    stage,
                                    mftinfo[0][1].split("/")[-1],
                                ), " -> {} -> extended attribute found in '{}' for {}".format(
                                    datetime.now().isoformat().replace("T", " "),
                                    mftinfo[0][1].split("/")[-1],
                                    vssimage,
                                )
                                write_audit_log_entry(
                                    verbosity, output_directory, entry, prnt
                                )
                            elif mftinfo[0][6] == "Y" or mftinfo[0][6] == "y":
                                analysisfile.write(
                                    "{},{},{},AlternateDataStream,Yes\n".format(
                                        datetime.now().isoformat(),
                                        vssimage.replace("'", ""),
                                        mftinfo[0][1],
                                    )
                                )
                                if verbosity != "":
                                    print(
                                        "      Alternate Data Stream identified for '{}'".format(
                                            mftinfo[0][1].split("/")[-1]
                                        )
                                    )
                                (
                                    entry,
                                    prnt,
                                ) = "{},{},{},alternate data stream found in '{}'\n".format(
                                    datetime.now().isoformat(),
                                    vssimage,
                                    stage,
                                    mftinfo[0][1].split("/")[-1],
                                ), " -> {} -> alternate data stream found in '{}' for {}".format(
                                    datetime.now().isoformat().replace("T", " "),
                                    mftinfo[0][1].split("/")[-1],
                                    vssimage,
                                )
                                write_audit_log_entry(
                                    verbosity, output_directory, entry, prnt
                                )
                            if (
                                mftinfo[0][2].split(".")[0]
                                != mftinfo[0][3].split(".")[0]
                            ):
                                stdepoch, fnepoch = int(
                                    time.mktime(
                                        time.strptime(
                                            mftinfo[0][2].split(".")[0],
                                            strpformat,
                                        )
                                    )
                                ), int(
                                    time.mktime(
                                        time.strptime(
                                            mftinfo[0][3].split(".")[0],
                                            strpformat,
                                        )
                                    )
                                )
                                if (
                                    stdepoch < fnepoch
                                    or mftinfo[0][2][20:] == "000000"
                                    or mftinfo[0][3][20:] == "000000"
                                ):
                                    with open(
                                        anysd + "/analysis.csv", "a"
                                    ) as analysisfile:
                                        analysisfile.write(
                                            "{},{},{},Timestomp,$SI: {}|$FN: {}\n".format(
                                                datetime.now().isoformat(),
                                                vssimage.replace("'", ""),
                                                mftinfo[0][1],
                                                stdepoch,
                                                fnepoch,
                                            )
                                        )
                                    if verbosity != "":
                                        print(
                                            "      Evidence of Timestomping identified for '{}'".format(
                                                mftinfo[0][1].split("/")[-1]
                                            )
                                        )
                                    (
                                        entry,
                                        prnt,
                                    ) = "{},{},{},evidence of timestomping found in '{}'\n".format(
                                        datetime.now().isoformat(),
                                        vssimage,
                                        stage,
                                        mftinfo[0][1].split("/")[-1],
                                    ), " -> {} -> evidence of timestomping found in '{}' for {}".format(
                                        datetime.now().isoformat().replace("T", " "),
                                        mftinfo[0][1].split("/")[-1],
                                        vssimage,
                                    )
                                    write_audit_log_entry(
                                        verbosity, output_directory, entry, prnt
                                    )
        print(
            "     Completed analysis of Extended Attributes, Alternate Data Streams & Timestomping for {}...".format(
                vssimage
            )
        )
        print()

    stage = "analysing"
    atftd = output_directory + img.split("::")[0] + "/artefacts/cooked/"
    anysd = output_directory + img.split("::")[0] + "/analysis/"
    strpformat = "%Y-%m-%d %H:%M:%S"
    if analysis:
        if "vss" in img.split("::")[1]:
            atftd, vssimage = (
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked/"
                + img.split("::")[1].split("_")[1],
                "'"
                + img.split("::")[0]
                + "' ("
                + img.split("::")[1]
                .split("_")[1]
                .replace("vss", "volume shadow copy #")
                + ")",
            )
        else:
            atftd, vssimage = (
                output_directory + img.split("::")[0] + "/artefacts/cooked/",
                "'" + img.split("::")[0] + "'",
            )
        print("    Analsying artefacts for {}...".format(vssimage))
        entry, prnt = "{},{},{},commenced\n".format(
            datetime.now().isoformat(), vssimage.replace("'", ""), stage
        ), " -> {} -> {} artefacts for {}".format(
            datetime.now().isoformat().replace("T", " "), stage, vssimage
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        if not os.path.exists(anysd):
            os.mkdir(anysd)
        with open(anysd + "/analysis.csv", "a") as analysisfile:
            analysisfile.write(
                "LastWriteTime,hostname,Filename,analysis_type,analysis_value\n"
            )
        print(
            "     Analysing files for file-signature (magic-byte) discrepencies for {}...".format(
                vssimage
            )
        )
        for root, _, files in os.walk(mnt):
            for f in files:
                try:
                    if (
                        os.stat(os.path.join(root, f)).st_size > 0
                        and os.stat(os.path.join(root, f)).st_size < 10000000
                    ):  # 10MB
                        if (
                            os.path.join(root, f) != "/mnt/elrond_mount/hiberfil.sys"
                            and os.path.join(root, f)
                            != "/mnt/elrond_mount/pagefile.sys"
                            and os.path.join(root, f)
                            != "/mnt/elrond_mount1/hiberfil.sys"
                            and os.path.join(root, f)
                            != "/mnt/elrond_mount1/pagefile.sys"
                            and os.path.join(root, f)
                            != "/mnt/elrond_mount2/hiberfil.sys"
                            and os.path.join(root, f)
                            != "/mnt/elrond_mount2/pagefile.sys"
                            and os.path.join(root, f)
                            != "/mnt/elrond_mount3/hiberfil.sys"
                            and os.path.join(root, f)
                            != "/mnt/elrond_mount3/pagefile.sys"
                            and os.path.join(root, f)
                            != "/mnt/elrond_mount4/hiberfil.sys"
                            and os.path.join(root, f)
                            != "/mnt/elrond_mount4/pagefile.sys"
                            and os.path.join(root, f)
                            != "/mnt/elrond_mount5/hiberfil.sys"
                            and os.path.join(root, f)
                            != "/mnt/elrond_mount5/pagefile.sys"
                        ) and (
                            "." in f
                            and (
                                f.endswith(".cab")
                                or f.endswith(".elf")
                                or f.endswith(".doc")
                                or f.endswith(".xls")
                                or f.endswith(".ppt")
                                or f.endswith(".pdf")
                                or f.endswith(".odt")
                                or f.endswith(".odp")
                                or f.endswith(".ott")
                                or f.endswith(".zip")
                                or f.endswith(".rar")
                                or f.endswith(".7z")
                                or f.endswith(".chm")
                                or f.endswith(".docx")
                                or f.endswith(".xlsx")
                                or f.endswith(".pptx")
                                or f.endswith(".com")
                                or f.endswith(".dll")
                                or f.endswith(".exe")
                                or f.endswith(".sys")
                                or f.endswith(".gif")
                                or f.endswith(".jpg")
                                or f.endswith(".jpeg")
                                or f.endswith(".png")
                            )
                        ):
                            try:
                                with open(os.path.join(root, f), "rb") as magic_file:
                                    file_hdr = magic_file.read()
                            except:
                                file_hdr = "0000000000"
                            if (
                                file_hdr != "0000000000"
                                and str(file_hdr)[2:10] != "'"
                                and (
                                    (
                                        f.endswith(".cab")
                                        and str(file_hdr)[2:10] != "\\x4d\\x53"
                                        and str(file_hdr)[2:10] != "MSCF\\x00"
                                    )
                                    or (
                                        f.endswith(".elf")
                                        and str(file_hdr)[2:10] != "\\x7f\\x45"
                                        and str(file_hdr)[2:10] != "\\x7fELF\\"
                                    )
                                    or (
                                        (
                                            f.endswith(".com")
                                            or f.endswith(".dll")
                                            or f.endswith(".exe")
                                            or f.endswith(".sys")
                                        )
                                        and (
                                            str(file_hdr)[2:10] != "\\x4d\\x5a"
                                            and str(file_hdr)[2:10] != "MZ\\x90\\x"
                                            and str(file_hdr)[2:10] != "MZ\\x00\\x"
                                            and str(file_hdr)[2:10] != "MZx\\x00\\"
                                            and str(file_hdr)[2:10] != "MZ\\x9f\\x"
                                            and str(file_hdr)[2:10] != "\\x00\\x02"
                                            and str(file_hdr)[2:10] != "\\x02\\x00"
                                            and str(file_hdr)[2:9] != "DCH\\x01"
                                            and str(file_hdr)[2:9] != "DCD\\x01"
                                            and str(file_hdr)[2:9] != "DCN\\x01"
                                            and str(file_hdr)[2:9] != "DCN\\x01"
                                        )
                                    )
                                    or (
                                        (
                                            f.endswith(".docx")
                                            or f.endswith(".xlsx")
                                            or f.endswith(".pptx")
                                        )
                                        and str(file_hdr)[2:10] != "\\x50\\x4b"
                                        and str(file_hdr)[2:10] != "PK\\x03\\x"
                                    )
                                    or (
                                        (
                                            f.endswith(".doc")
                                            or f.endswith(".xls")
                                            or f.endswith(".ppt")
                                        )
                                        and (str(file_hdr)[2:10] != "\\x50\\x4b")
                                        and str(file_hdr)[2:10] != "\\xd0\\xcf"
                                    )
                                    or (
                                        (
                                            f.endswith(".odt")
                                            or f.endswith(".odp")
                                            or f.endswith(".ott")
                                        )
                                        and str(file_hdr)[2:10] != "\\x50\\x4b"
                                        and str(file_hdr)[2:10] != "PK\\x03\\x"
                                    )
                                    or (
                                        f.endswith(".pdf")
                                        and (
                                            str(file_hdr)[2:9] != "%PDF-1."
                                            and str(file_hdr)[2:10] != "\\x25\\x50"
                                        )
                                    )
                                    or (
                                        f.endswith(".7z")
                                        and (
                                            str(file_hdr)[2:10] != "7z\\xbc\\x"
                                            and str(file_hdr)[2:10] != "\\x37\\x7a"
                                        )
                                    )
                                    or (
                                        (f.endswith(".jar") or f.endswith(".zip"))
                                        and str(file_hdr)[2:10] != "\\x50\\x4b"
                                        and str(file_hdr)[2:10] != "PK\\x03\\x"
                                        and str(file_hdr)[2:9] != "PK\\x03"
                                    )
                                    or (
                                        f.endswith(".rar")
                                        and (
                                            str(file_hdr)[2:10] != "Rar!\\x1a"
                                            and str(file_hdr)[2:10] != "\\x52\\x61"
                                        )
                                    )
                                    or (
                                        (f.endswith(".jpg") or f.endswith(".jpeg"))
                                        and (str(file_hdr)[2:10] != "\\xff\\xd8")
                                        and str(file_hdr)[2:10] != "GIF89a\\x"
                                        and str(file_hdr)[2:9] != "DCH\\x01"
                                    )
                                    or (
                                        f.endswith(".gif")
                                        and (
                                            str(file_hdr)[2:8] != "GIF89a"
                                            and str(file_hdr)[2:8] != "GIF87a"
                                            and str(file_hdr)[2:10] != "\\x47\\x49"
                                        )
                                    )
                                    or (
                                        f.endswith(".png")
                                        and (
                                            str(file_hdr)[2:10] != "\\x89\\x50"
                                            and str(file_hdr)[2:10] != "\\x89PNG\\"
                                            and str(file_hdr)[2:10] != "\\xff\\xd8"
                                        )
                                    )
                                    or (
                                        f.endswith(".chm")
                                        and (
                                            str(file_hdr)[2:10] != "ITSF\\x03"
                                            and str(file_hdr)[2:10] != "\\x49\\x54"
                                        )
                                    )
                                )
                            ):
                                with open(anysd + "/analysis.csv", "a") as analysisfile:
                                    analysisfile.write(
                                        "{},{},{},File-signature (magic-byte) Discrepency,'{}'\n".format(
                                            datetime.now().isoformat(),
                                            vssimage.replace("'", ""),
                                            f,
                                            str(file_hdr)[2:10],
                                        )
                                    )
                                if verbosity != "":
                                    print(
                                        "      File-signature (magic-byte) discrepency of '{}' identified for {}".format(
                                            str(file_hdr)[2:10],
                                            f.split("/")[-1],
                                        )
                                    )
                                (
                                    entry,
                                    prnt,
                                ) = "{},{},{},file-signature (magic-byte) discrepency of '{}' for '{}'\n".format(
                                    datetime.now().isoformat(),
                                    vssimage,
                                    stage,
                                    str(file_hdr)[2:10],
                                    f,
                                ), " -> {} -> identified file-signature (magic-byte) discrepency of '{}' from '{}' for {}".format(
                                    datetime.now().isoformat().replace("T", " "),
                                    str(file_hdr)[2:10],
                                    f,
                                    vssimage,
                                )
                                write_audit_log_entry(
                                    verbosity, output_directory, entry, prnt
                                )
                except:
                    pass
        print(
            "     Completed analysis of file-signature (magic-byte) discrepencies for {}...".format(
                vssimage
            )
        )
        for ar, _, af in os.walk(atftd):
            for f in af:
                if "vss" in img.split("::")[1]:
                    if str(img.split("::")[1].split("_")[1]) in atftd and f.endswith(
                        "MFT.csv"
                    ):
                        analyse_disk_images(stage, vssimage, ar, f, anysd)
                elif (
                    "vss" not in atftd
                    and ar.endswith("cooked/")
                    and f.endswith("MFT.csv")
                ):
                    analyse_disk_images(stage, vssimage, ar, f, anysd)
    if extractiocs:
        iocfilelist, lineno, previous = [], 0, 0.0
        if verbosity != "":
            print(
                "\n    \033[1;33mUndertaking IOC extraction for '{}'...\033[1;m".format(
                    img.split("::")[0]
                )
            )
        print(
            "     Assessing readable files to extract IOCs from, for '{}'...".format(
                img.split("::")[0]
            )
        )
        for root, _, files in os.walk(mnt):
            for f in files:
                try:
                    if (
                        os.stat(os.path.join(root, f)).st_size > 0
                        and os.stat(os.path.join(root, f)).st_size < 10000000
                    ):  # 10MB
                        with open(os.path.join(root, f), "r") as filetest:
                            filetest.readline()
                            iocfilelist.append(os.path.join(root, f))
                except:
                    pass
        if os.path.exists(
            os.path.join(output_directory, img.split("::")[0], "artefacts")
        ):
            for root, _, files in os.walk(
                os.path.join(output_directory, img.split("::")[0], "artefacts")
            ):
                for f in files:
                    try:
                        if (
                            os.stat(os.path.join(root, f)).st_size > 0
                            and os.stat(os.path.join(root, f)).st_size < 10000000
                        ):  # 10MB
                            with open(os.path.join(root, f), "r") as filetest:
                                filetest.readline()
                                iocfilelist.append(os.path.join(root, f))
                    except:
                        pass
        print("       Done.")
        iocfiles = list(set(iocfilelist))
        if not os.path.exists(anysd):
            os.mkdir(anysd)
        if not os.path.exists(
            output_directory + img.split("::")[0] + "/analysis/iocs.csv"
        ):
            with open(
                output_directory + img.split("::")[0] + "/analysis/iocs.csv",
                "w",
            ) as ioccsv:
                ioccsv.write(
                    "CreationTime,LastAccessTime,LastWriteTime,Filename,ioc,indicator_type,line_number,resolvable\n"
                )
        compare_iocs(
            output_directory,
            verbosity,
            img,
            stage,
            vssimage,
            iocfiles,
            lineno,
            previous,
        )
    print(" -> Completed Analysis Phase for {}".format(vssimage))
    entry, prnt = "{},{},{},completed\n".format(
        datetime.now().isoformat(), vssimage, stage
    ), " -> {} -> analysis completed for {}".format(
        datetime.now().isoformat().replace("T", " "), vssimage
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    print()
