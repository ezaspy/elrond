#!/usr/bin/env python3 -tt
import os
import re
import subprocess
from datetime import datetime
from zipfile import ZipFile

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry
from rivendell.collecting.files import collect_files
from rivendell.collecting.files import recover_files


def carve_files(output_directory, verbosity, d, artefact_directory, img, vssimage):
    print("\n    \033[1;33mRecovering files using file carving for {}...\033[1;m".format(vssimage))
    subprocess.Popen(
        [
            "foremost",
            d + img.split("::")[0],
            "-o",
            artefact_directory + "/carved",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    if os.path.exists(artefact_directory + "/carved/audit.txt"):
        os.remove(artefact_directory + "/carved/audit.txt")
    else:
        pass
    for eachdir in os.listdir(artefact_directory + "/carved"):
        for eachfile in os.listdir(artefact_directory + "/carved/" + eachdir):
            print(
                "     Successfully carved '{}' from {}".format(
                    eachfile, vssimage
                )
            )
            entry, prnt = "{},{},{},'{}'\n".format(
                datetime.now().isoformat(),
                vssimage.replace("'", ""),
                "carving",
                eachfile,
            ), " -> {} -> {} artefact '{}' for {}".format(
                datetime.now().isoformat().replace("T", " "),
                "carved",
                eachfile,
                vssimage,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
    print_done(verbosity)
    entry, prnt = "{},{},{},completed\n".format(
        datetime.now().isoformat(), vssimage.replace("'", ""), "carving"
    ), " -> {} -> {} artefacts for {}".format(
        datetime.now().isoformat().replace("T", " "),
        "carved",
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)


def collect_recover_files(output_directory, verbosity, mnt, img, vssimage, collectfiles, recover, auto):
    if collectfiles and recover:
        stage = "collecting & recovering"
    elif collectfiles:
        stage = "collecting"
    else:
        stage = "recovering"
    print(
        "\n      \033[1;33m{} files from {}...\033[1;m\n".format(stage.title().replace(",", " &"), vssimage)
    )
    if not auto:
        yestobins = input("     Do you wish to collect binary files from {}? Y/n [Y] ".format(vssimage))
        yestodocs = input("     Do you wish to collect document files from {}? Y/n [Y] ".format(vssimage))
        yestoarcs = input("     Do you wish to collect archive files from {}? Y/n [Y] ".format(vssimage))
        yestoscrs = input("     Do you wish to collect scripts from {}? Y/n [Y] ".format(vssimage))
        yestovmws = input("     Do you wish to collect virtual machine files from {}? Y/n [Y] ".format(vssimage))
        yestoemls = input("     Do you wish to collect email files from {}? Y/n [Y] ".format(vssimage))
    else:
        yestobins, yestodocs, yestoarcs, yestoscrs, yestovmws, yestoemls = "Y", "Y", "Y", "Y", "Y", "Y"
    for recroot, _, recfiles in os.walk(mnt):
        increment = 1
        for recfile in recfiles:
            if collectfiles and recover:
                collect_files(
                    output_directory,
                    verbosity,
                    "collected",
                    img,
                    vssimage,
                    recroot,
                    recfile,
                    increment,
                    yestobins,
                    yestodocs,
                    yestoarcs,
                    yestoscrs,
                    yestovmws,
                    yestoemls,
                )
                recover_files(
                    output_directory,
                    verbosity,
                    "recovered",
                    img,
                    vssimage,
                    recroot,
                    recfile,
                )
            elif collectfiles:
                collect_files(
                    output_directory,
                    verbosity,
                    "collected",
                    img,
                    vssimage,
                    recroot,
                    recfile,
                    increment,
                    yestobins,
                    yestodocs,
                    yestoarcs,
                    yestoscrs,
                    yestovmws,
                    yestoemls,
                )
            else:
                recover_files(
                    output_directory,
                    verbosity,
                    "recovered",
                    img,
                    vssimage,
                    recroot,
                    recfile,
                )
    if os.path.exists(output_directory + img.split("::")[0] + "/files/archives") or os.path.exists(output_directory + img.split("::")[0] + "/files/documents"):
        print("\n    \033[1;33mExtracting embedded files from recovered files {}...\033[1;m".format(vssimage))
        recoverpath = output_directory + img.split("::")[0] + "/files/archives"
        if len(os.listdir(recoverpath)) > 0:
            for eachrecfile in os.listdir(recoverpath):
                zaout = str(subprocess.Popen(
                    [
                        "7za",
                        "e",
                        output_directory + img.split("::")[0] + "/files/archives/" + eachrecfile,
                        "-o" + output_directory + img.split("::")[0] + "/files/archives/" + eachrecfile.split(".")[0] + "/",
                        "-y",
                        "-p "
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate())
                if "Everything is Ok" in zaout:
                    entry, prnt = "{},{},{},{}\n".format(
                        datetime.now().isoformat(), vssimage.replace("'", ""), "extracted content", eachrecfile
                    ), " -> {} -> {} {}, from {}".format(
                        datetime.now().isoformat().replace("T", " "),
                        "extracted content of", eachrecfile, vssimage,
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)
                else:
                    print("      '{}' could not be extracted, it may be invalid/corrupted or password protected.".format(eachrecfile))
        else:
            pass
        recoverpath = output_directory + img.split("::")[0] + "/files/documents"
        if len(os.listdir(recoverpath)) > 0:
            for eachrecfile in os.listdir(recoverpath):
                if not eachrecfile.endswith(".pdf") and not eachrecfile.endswith(".rtf") and not eachrecfile.endswith(".ott") and not eachrecfile.endswith(".odt") and not eachrecfile.endswith(".ods") and not eachrecfile.endswith(".odg"):
                    filezip, ziptmp = ZipFile(recoverpath + "/" + eachrecfile), recoverpath + "/" + eachrecfile[:-5]
                    ZipFile.extractall(filezip, ziptmp)
                    for recroot, recdirs, recfiles in os.walk(recoverpath):
                        if len(recdirs) > 0:
                            for eachrecdir in recdirs:
                                for _, _, contentfiles in os.walk(recoverpath + eachrecdir):
                                    for contentfile in contentfiles:
                                        if not contentfile.endswith(".xml") and not contentfile.endswith(".rels"):
                                            entry, prnt = "{},{},{},{}\n".format(
                                                datetime.now().isoformat(), vssimage.replace("'", ""), "extracted embedded file", contentfile
                                            ), " -> {} -> {} {} from {}, from {}".format(
                                                datetime.now().isoformat().replace("T", " "),
                                                "extracted embedded file", contentfile, eachrecfile, vssimage,
                                            )
                                            write_audit_log_entry(verbosity, output_directory, entry, prnt)
                                        else:
                                            pass
                        else:
                            pass
                else:
                    pass
        else:
            pass
        print_done(verbosity)
        entry, prnt = "{},{},{},completed\n".format(
            datetime.now().isoformat(), vssimage.replace("'", ""), "extracted"
        ), " -> {} -> {} artefacts for {}".format(
            datetime.now().isoformat().replace("T", " "),
            "extracted",
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
    else:
        pass
    if os.path.exists(output_directory + img.split("::")[0] + "/files/scripts"):
        print("\n    \033[1;33mIdentifying evidence of script obfuscation in files from {}...\033[1;m".format(vssimage))
        recoverpath = output_directory + img.split("::")[0] + "/files/scripts"
        if len(os.listdir(recoverpath)) > 0:
            for eachrecfile in os.listdir(recoverpath):
                with open(os.path.join(recoverpath, eachrecfile), encoding="ISO-8859-1") as scriptfile:
                    lineno = 0
                    for line in scriptfile:
                        obfuscation_evidence = re.findall(r"((?:(?:\+|\()0x\d+\+)|_xor\(| xor |CharCode|\"\+\")", line)
                        if len(obfuscation_evidence) > 0:
                            entry, prnt = "{},{},{} (line #{}),{}\n".format(
                                datetime.now().isoformat(), vssimage.replace("'", ""), "potential script obfuscation", str(lineno), eachrecfile
                            ), " -> {} -> {} on line {} found in '{}' from {}".format(
                                datetime.now().isoformat().replace("T", " "),
                                "potential script obfuscation", str(lineno), eachrecfile, vssimage,
                            )
                            write_audit_log_entry(verbosity, output_directory, entry, prnt)
                        else:
                            pass
                        lineno += 1
        else:
            pass
        print_done(verbosity)
        entry, prnt = "{},{},{},completed\n".format(
            datetime.now().isoformat(), vssimage.replace("'", ""), "identified script obfuscation"
        ), " -> {} -> {} artefacts for {}".format(
            datetime.now().isoformat().replace("T", " "),
            "identified script obfuscation",
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
    else:
        pass
    print(
        "\n      \033[1;33mFinished {} files from {}\033[1;m\n".format(stage.replace(",", " &"), vssimage)
    )
