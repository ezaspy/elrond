#!/usr/bin/env python3 -tt
import os
import re
import subprocess
from datetime import datetime
from zipfile import ZipFile

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry
from rivendell.collect.files.carve import carve_files
from rivendell.collect.files.compare import compare_include_exclude
from rivendell.collect.files.files import collect_files
from rivendell.collect.files.recover import recover_files

import time


def select_files(
    output_directory, verbosity, d, mnt, img, vssimage, collectfiles, recover
):
    if collectfiles and recover:
        stage = "collecting & recovering"
    elif collectfiles:
        stage = "collecting"
    else:
        stage = "recovering"
    print(
        "\n       \033[1;33m{} files from {}...\033[1;m".format(
            stage.title().replace(",", " &"), vssimage
        )
    )
    if collectfiles == True:
        file_selection = input(
            "        Which file types do you want collected from {}?\n        [A]ll   [H]idden   [B]inaries   [D]ocuments   A[R]chives   [S]cripts   [L]NK   [W]eb   [M]ail   [V]irtual   [U]nallocated   [N]one\n\n        [A]ll ".format(
                vssimage
            )
        )
    else:
        file_selection = "A"
    if "N" not in file_selection:
        print()
        if (
            "A" in file_selection
            or "H" in file_selection
            or "B" in file_selection
            or "D" in file_selection
            or "R" in file_selection
            or "S" in file_selection
            or "L" in file_selection
            or "W" in file_selection
            or "M" in file_selection
            or "V" in file_selection
        ):
            for recovered_file_root, _, recovered_files in os.walk(
                mnt
            ):  # processing file selection
                for recovered_file in recovered_files:
                    if collectfiles and recover:
                        collect_files(
                            output_directory,
                            verbosity,
                            "collected",
                            img,
                            vssimage,
                            recovered_file_root,
                            recovered_file,
                            1,
                            collectfiles,
                            file_selection,
                        )
                        recover_files(
                            output_directory,
                            verbosity,
                            "recovered",
                            img,
                            vssimage,
                            recovered_file_root,
                            recovered_file,
                        )
                    elif collectfiles:
                        collect_files(
                            output_directory,
                            verbosity,
                            "collected",
                            img,
                            vssimage,
                            recovered_file_root,
                            recovered_file,
                            1,
                            collectfiles,
                            file_selection,
                        )
                    else:
                        recover_files(
                            output_directory,
                            verbosity,
                            "recovered",
                            img,
                            vssimage,
                            recovered_file_root,
                            recovered_file,
                        )
            if "L" in file_selection or "A" in file_selection:
                link_files = subprocess.Popen(
                    [
                        "sudo",
                        "find",
                        mnt,
                        "-type",
                        "l",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()
                for lnk_path in str(link_files)[3:-9].split("\\n"):
                    if collect_files:
                        try:
                            os.stat(
                                output_directory + img.split("::")[0] + "/files/lnk"
                            )
                        except:
                            os.makedirs(
                                output_directory + img.split("::")[0] + "/files/lnk"
                            )
                        if os.path.isfile(lnk_path.split("/")[-1]):
                            compare_include_exclude(
                                output_directory,
                                verbosity,
                                stage,
                                img,
                                vssimage,
                                "/files/lnk/",
                                "lnk file",
                                "/".join(lnk_path.split("/")[0:-1]),
                                lnk_path.split("/")[-1],
                                1,
                                collectfiles,
                            )
                        else:
                            pass
                    else:
                        pass
            else:
                pass
            if os.path.exists(
                output_directory + img.split("::")[0] + "/files/archives"
            ):  # extracting collected archives
                recoverpath = output_directory + img.split("::")[0] + "/files/archives"
                if len(os.listdir(recoverpath)) > 0:
                    print(
                        "\n       \033[1;33mExtracting embedded files from files recovered for {}...\033[1;m".format(
                            vssimage
                        )
                    )
                    for recovered_file in os.listdir(recoverpath):
                        zaout = str(
                            subprocess.Popen(
                                [
                                    "7za",
                                    "e",
                                    output_directory
                                    + img.split("::")[0]
                                    + "/files/archives/"
                                    + recovered_file,
                                    "-o"
                                    + output_directory
                                    + img.split("::")[0]
                                    + "/files/archives/"
                                    + recovered_file.split(".")[0]
                                    + "/",
                                    "-y",
                                    "-p ",
                                ],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            ).communicate()
                        )
                        if "Everything is Ok" in zaout:
                            entry, prnt = "{},{},{},{}\n".format(
                                datetime.now().isoformat(),
                                vssimage.replace("'", ""),
                                "extracted content",
                                recovered_file,
                            ), " -> {} -> {} {}, from {}".format(
                                datetime.now().isoformat().replace("T", " "),
                                "extracted content of",
                                recovered_file,
                                vssimage,
                            )
                            write_audit_log_entry(
                                verbosity, output_directory, entry, prnt
                            )
                        else:
                            print(
                                "      '{}' could not be extracted, it may be invalid/corrupted or password protected".format(
                                    recovered_file
                                )
                            )
                    print_done(verbosity)
                    entry, prnt = "{},{},{},completed\n".format(
                        datetime.now().isoformat(),
                        vssimage.replace("'", ""),
                        "extracted",
                    ), " -> {} -> {} artefacts for {}".format(
                        datetime.now().isoformat().replace("T", " "),
                        "extracted",
                        vssimage,
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)
                else:
                    pass
            else:
                pass
            if os.path.exists(
                output_directory + img.split("::")[0] + "/files/documents"
            ):  # extracting collected documents
                recoverpath = output_directory + img.split("::")[0] + "/files/documents"
                if len(os.listdir(recoverpath)) > 0:
                    print(
                        "\n       \033[1;33mExtracting embedded files from files recovered for {}...\033[1;m".format(
                            vssimage
                        )
                    )
                    for recovered_file in os.listdir(recoverpath):
                        if (
                            recovered_file.endswith(".doc")
                            or recovered_file.endswith(".docx")
                            or recovered_file.endswith(".docm")
                            or recovered_file.endswith(".xls")
                            or recovered_file.endswith(".xlsx")
                            or recovered_file.endswith(".xlsm")
                            or recovered_file.endswith(".ppt")
                            or recovered_file.endswith(".pptx")
                            or recovered_file.endswith(".pptm")
                        ):
                            try:
                                filezip, ziptmp = (
                                    ZipFile(recoverpath + "/" + recovered_file),
                                    recoverpath + "/" + recovered_file[:-5],
                                )
                                ZipFile.extractall(filezip, ziptmp)
                                for (
                                    recovered_file_root,
                                    recdirs,
                                    recovered_files,
                                ) in os.walk(recoverpath):
                                    if len(recdirs) > 0:
                                        for eachrecdir in recdirs:
                                            for _, _, contentfiles in os.walk(
                                                recoverpath + eachrecdir
                                            ):
                                                for contentfile in contentfiles:
                                                    if not contentfile.endswith(
                                                        ".xml"
                                                    ) and not contentfile.endswith(
                                                        ".rels"
                                                    ):
                                                        (
                                                            entry,
                                                            prnt,
                                                        ) = "{},{},{},{}\n".format(
                                                            datetime.now().isoformat(),
                                                            vssimage.replace("'", ""),
                                                            "extracted embedded file",
                                                            contentfile,
                                                        ), " -> {} -> {} {} from {}, from {}".format(
                                                            datetime.now()
                                                            .isoformat()
                                                            .replace("T", " "),
                                                            "extracted embedded file",
                                                            contentfile,
                                                            recovered_file,
                                                            vssimage,
                                                        )
                                                        write_audit_log_entry(
                                                            verbosity,
                                                            output_directory,
                                                            entry,
                                                            prnt,
                                                        )
                                                    else:
                                                        pass
                                    else:
                                        pass
                            except:
                                print(
                                    "      '{}' could not be extracted, it may be invalid/corrupted or password protected".format(
                                        recovered_file
                                    )
                                )
                        else:
                            pass
                    else:
                        pass
                    print_done(verbosity)
                    entry, prnt = "{},{},{},completed\n".format(
                        datetime.now().isoformat(),
                        vssimage.replace("'", ""),
                        "extracted",
                    ), " -> {} -> {} artefacts for {}".format(
                        datetime.now().isoformat().replace("T", " "),
                        "extracted",
                        vssimage,
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)
                else:
                    pass
            else:
                pass
            if os.path.exists(output_directory + img.split("::")[0] + "/files/scripts"):
                if (
                    len(
                        os.listdir(
                            output_directory + img.split("::")[0] + "/files/scripts"
                        )
                    )
                    > 0
                ):
                    print(
                        "\n       \033[1;33mIdentifying evidence of script obfuscation in files from {}...\033[1;m".format(
                            vssimage
                        )
                    )
                    recoverpath = (
                        output_directory + img.split("::")[0] + "/files/scripts"
                    )
                    if len(os.listdir(recoverpath)) > 0:
                        for recovered_file in os.listdir(recoverpath):
                            try:
                                with open(
                                    os.path.join(recoverpath, recovered_file),
                                ) as scriptfile:
                                    lineno = 0
                                    for line in scriptfile:
                                        obfuscation_evidence = re.findall(
                                            r"((?:(?:\+|\()0x\d+\+)|_xor\(| xor |charcode|\"\+\"|\w\{\d\}\w|\)\-f|\-f'|\-f\"|(\'\w+\'\,){2,}|base64|compress)",
                                            line.lower(),
                                        )
                                        if len(obfuscation_evidence) > 0:
                                            (
                                                entry,
                                                prnt,
                                            ) = "{},{},{} (line #{}),{}\n".format(
                                                datetime.now().isoformat(),
                                                vssimage.replace("'", ""),
                                                "potential script obfuscation",
                                                str(lineno),
                                                recovered_file,
                                            ), " -> {} -> {} on line {} found in '{}' from {}".format(
                                                datetime.now()
                                                .isoformat()
                                                .replace("T", " "),
                                                "potential script obfuscation",
                                                str(lineno),
                                                recovered_file,
                                                vssimage,
                                            )
                                            write_audit_log_entry(
                                                verbosity, output_directory, entry, prnt
                                            )
                                        else:
                                            pass
                                        lineno += 1
                            except:
                                pass
                            try:
                                with open(
                                    os.path.join(recoverpath, recovered_file),
                                    encoding="ISO-8859-1",
                                ) as scriptfile:
                                    lineno = 0
                                    for line in scriptfile:
                                        obfuscation_evidence = re.findall(
                                            r"((?:(?:\+|\()0x\d+\+)|_xor\(| xor |charcode|\"\+\"|\w{\d}\w|\-f|(\'\w+\'\,){2,}|base64|compress)",
                                            line.lower(),
                                        )
                                        if len(obfuscation_evidence) > 0:
                                            (
                                                entry,
                                                prnt,
                                            ) = "{},{},{} (line #{}),{}\n".format(
                                                datetime.now().isoformat(),
                                                vssimage.replace("'", ""),
                                                "potential script obfuscation",
                                                str(lineno),
                                                recovered_file,
                                            ), " -> {} -> {} on line {} found in '{}' from {}".format(
                                                datetime.now()
                                                .isoformat()
                                                .replace("T", " "),
                                                "potential script obfuscation",
                                                str(lineno),
                                                recovered_file,
                                                vssimage,
                                            )
                                            write_audit_log_entry(
                                                verbosity, output_directory, entry, prnt
                                            )
                                        else:
                                            pass
                                        lineno += 1
                            except:
                                pass
                    else:
                        pass
                    print_done(verbosity)
                    entry, prnt = "{},{},{},completed\n".format(
                        datetime.now().isoformat(),
                        vssimage.replace("'", ""),
                        "identified script obfuscation",
                    ), " -> {} -> {} artefacts for {}".format(
                        datetime.now().isoformat().replace("T", " "),
                        "identified script obfuscation",
                        vssimage,
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)
            else:
                pass
        else:
            pass
        if "U" in file_selection or "A" in file_selection:
            carve_files(
                output_directory,
                verbosity,
                d,
                output_directory + img.split("::")[0],
                img,
                vssimage,
            )
        else:
            pass
        print(
            "       \033[1;33mFinished {} files from {}\033[1;m\n".format(
                stage.replace(",", " &"), vssimage
            )
        )
    else:
        pass
