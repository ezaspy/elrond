#!/usr/bin/env python3 -tt
import os
import shutil
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def collect_files(output_directory, verbosity, stage, img, vssimage, recroot, recfile):
    if (
        recfile.startswith(".")
        or recfile.endswith(".exe")
        or recfile.endswith(".dll")
        or recfile.endswith(".elf")
        or recfile.endswith(".docx")
        or recfile.endswith(".doc")
        or recfile.endswith(".docm")
        or recfile.endswith(".xlsx")
        or recfile.endswith(".xls")
        or recfile.endswith(".xlsm")
        or recfile.endswith(".pptx")
        or recfile.endswith(".ppt")
        or recfile.endswith(".pptm")
        or recfile.endswith(".pdf")
        or recfile.endswith(".zip")
        or recfile.endswith(".rar")
        or recfile.endswith(".7z")
        or recfile.endswith(".tar")
        or recfile.endswith(".tar.gz")
        or recfile.endswith(".arj")
        or recfile.endswith(".vmware")
        or recfile.endswith(".vmdk")
        or recfile.endswith(".vmx")
        or recfile.endswith(".ps1")
        or recfile.endswith(".py")
        or recfile.endswith(".vba")
    ):
        try:
            os.stat(output_directory + img.split("::")[0] + "/files/")
        except:
            os.makedirs(output_directory + img.split("::")[0] + "/files/")
        if (
            recfile.startswith(".")
            and recfile != ".localized"
            and recfile != ".DS_Store"
            and recfile != ".CFUserTextEncoding"
        ):
            try:
                os.stat(output_directory + img.split("::")[0] + "/files/hidden")
            except:
                os.makedirs(output_directory + img.split("::")[0] + "/files/hidden")
            try:
                (entry, prnt,) = "{},{},{},hidden file '{}'\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    recfile,
                ), " -> {} -> {} hidden file '{}' for {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage.replace(",", " &"),
                    recfile,
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                shutil.copy2(
                    os.path.join(recroot, recfile),
                    output_directory
                    + img.split("::")[0]
                    + "/files/hidden/"
                    + recfile[1:],
                )
            except:
                pass
        elif (
            recfile.endswith(".exe")
            or recfile.endswith(".dll")
            or recfile.endswith(".elf")
        ):
            try:
                os.stat(output_directory + img.split("::")[0] + "/files/binaries")
            except:
                os.makedirs(output_directory + img.split("::")[0] + "/files/binaries")
            try:
                (entry, prnt,) = "{},{},{},document file '{}'\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    recfile,
                ), " -> {} -> {} document file '{}' for {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage.replace(",", " &"),
                    recfile,
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                shutil.copy2(
                    os.path.join(recroot, recfile),
                    output_directory + img.split("::")[0] + "/files/binaries",
                )
            except:
                pass
        elif (
            recfile.endswith("docx")
            or recfile.endswith("doc")
            or recfile.endswith("docm")
            or recfile.endswith("xlsx")
            or recfile.endswith("xls")
            or recfile.endswith("xlsm")
            or recfile.endswith("pptx")
            or recfile.endswith("ppt")
            or recfile.endswith("pptm")
            or recfile.endswith(".pdf")
        ):
            try:
                os.stat(output_directory + img.split("::")[0] + "/files/documents")
            except:
                os.makedirs(output_directory + img.split("::")[0] + "/files/documents")
            try:
                (entry, prnt,) = "{},{},{},document file '{}'\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    recfile,
                ), " -> {} -> {} document file '{}' for {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage.replace(",", " &"),
                    recfile,
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                shutil.copy2(
                    os.path.join(recroot, recfile),
                    output_directory + img.split("::")[0] + "/files/documents",
                )
            except:
                pass
        elif (
            recfile.endswith("zip")
            or recfile.endswith("rar")
            or recfile.endswith("7z")
            or recfile.endswith("tar")
            or recfile.endswith("gz")
            or recfile.endswith("arj")
        ):
            try:
                os.stat(output_directory + img.split("::")[0] + "/files/archives")
            except:
                os.makedirs(output_directory + img.split("::")[0] + "/files/archives")
            try:
                (entry, prnt,) = "{},{},{},archive file '{}'\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    recfile,
                ), " -> {} -> {} archive file '{}' for {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage.replace(",", " &"),
                    recfile,
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                shutil.copy2(
                    os.path.join(recroot, recfile),
                    output_directory + img.split("::")[0] + "/files/archives",
                )
            except:
                pass
        elif (
            recfile.endswith("ps1") or recfile.endswith("py") or recfile.endswith("vba")
        ):
            try:
                os.stat(output_directory + img.split("::")[0] + "/files/scripts")
            except:
                os.makedirs(output_directory + img.split("::")[0] + "/files/scripts")
            try:
                (entry, prnt,) = "{},{},{},archive file '{}'\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    recfile,
                ), " -> {} -> {} archive file '{}' for {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage.replace(",", " &"),
                    recfile,
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                shutil.copy2(
                    os.path.join(recroot, recfile),
                    output_directory + img.split("::")[0] + "/files/scripts",
                )
            except:
                pass
        elif (
            recfile.endswith("vmware")
            or recfile.endswith("vmdk")
            or recfile.endswith("vmx")
            or recfile.endswith("vdi")
        ):
            try:
                os.stat(
                    output_directory + img.split("::")[0] + "/files/virtual_machines"
                )
            except:
                os.makedirs(
                    output_directory + img.split("::")[0] + "/files/virtual_machines"
                )
            try:
                (entry, prnt,) = "{},{},{},virtual file '{}'\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    recfile,
                ), " -> {} -> {} virtual file '{}' for '{}'".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage.replace(",", " &"),
                    recfile,
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                shutil.copy2(
                    os.path.join(recroot, recfile),
                    output_directory + img.split("::")[0] + "/files/virtual_machines",
                )
            except:
                pass
        else:
            pass
    else:
        pass


def recover_files(output_directory, verbosity, stage, img, vssimage, recroot, recfile):
    if recfile.endswith("$I30"):
        try:
            os.stat(os.path.join(output_directory, img.split("::")[0]) + "/recovered")
        except:
            os.makedirs(
                os.path.join(output_directory, img.split("::")[0]) + "/recovered"
            )
        try:
            shutil.copy2(
                os.path.join(recroot, recfile),
                output_directory + img.split("::")[0] + "/recovered",
            )
            (entry, prnt,) = "{},{},{},virtual file '{}'\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                recfile,
            ), " -> {} -> {} virtual file '{}' for '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                stage.replace(",", " &"),
                recfile,
                vssimage,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
        except:
            pass
    else:
        pass
