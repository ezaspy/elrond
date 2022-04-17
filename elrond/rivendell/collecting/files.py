#!/usr/bin/env python3 -tt
import os
import shutil
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def multiple_files(source, destination, increment):
    if os.path.exists(destination + "." + str(increment)):
        increment += 1
        multiple_files(source, destination, increment)
    else:
        shutil.copy2(source, destination + "." + str(increment))
        increment += 1


def collect_files(output_directory, verbosity, stage, img, vssimage, recroot, recfile, increment, yestobins, yestodocs, yestoarcs, yestoscrs, yestovmws, yestoemls,
):
    """if (
        recfile.startswith(".")
        or recfile.endswith(".exe")
        or recfile.endswith(".dll")
        or recfile.endswith(".elf")
        or recfile.endswith(".bin")
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
        or recfile.endswith(".rtf")
        or recfile.endswith(".ott")
        or recfile.endswith(".odt")
        or recfile.endswith(".ods")
        or recfile.endswith(".odg")
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
        or recfile.endswith(".ost")
        or recfile.endswith(".pst")
        or recfile.endswith(".eml")
    ):"""
    if (
        recfile.startswith(".")
        or recfile.endswith(".ost")
        or recfile.endswith(".pst")
        or recfile.endswith(".eml")
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
                ), " -> {} -> {} hidden file '{}' from {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage.replace(",", " &"),
                    recfile,
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                if os.path.exists(output_directory + img.split("::")[0] + "/files/hidden/" + recfile[1:]):
                    multiple_files(os.path.join(recroot, recfile), output_directory + img.split("::")[0] + "/files/hidden/" + recfile[1:] + "." + str(increment), increment)
                else:
                    shutil.copy2(
                        os.path.join(recroot, recfile),
                        output_directory + img.split("::")[0] + "/files/hidden/" + recfile[1:],
                    )
            except:
                pass
        elif yestobins != "n" and (
            recfile.endswith(".exe")
            or recfile.endswith(".dll")
            or recfile.endswith(".elf")
            or recfile.endswith(".bin")
        ):
            try:
                os.stat(output_directory + img.split("::")[0] + "/files/binaries")
            except:
                os.makedirs(output_directory + img.split("::")[0] + "/files/binaries")
            (entry, prnt,) = "{},{},{},binary file '{}'\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                recfile,
            ), " -> {} -> {} binary file '{}' from {}".format(
                datetime.now().isoformat().replace("T", " "),
                stage.replace(",", " &"),
                recfile,
                vssimage,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            if os.path.exists(output_directory + img.split("::")[0] + "/files/binaries/" + recfile):
                multiple_files(os.path.join(recroot, recfile), output_directory + img.split("::")[0] + "/files/binaries/" + recfile, increment)
            else:
                shutil.copy2(
                    os.path.join(recroot, recfile),
                    output_directory + img.split("::")[0] + "/files/binaries",
                )
        elif yestodocs != "n" and (
            recfile.endswith(".docx")
            or recfile.endswith(".doc")
            or recfile.endswith(".docm")
            or recfile.endswith(".xlsx")
            or recfile.endswith(".xls")
            or recfile.endswith(".xlsm")
            or recfile.endswith(".pptx")
            or recfile.endswith(".ppt")
            or recfile.endswith(".pptm")
            or recfile.endswith(".pdf")
            or recfile.endswith(".rtf")
            or recfile.endswith(".ott")
            or recfile.endswith(".odt")
            or recfile.endswith(".ods")
            or recfile.endswith(".odg")
        ) and not recfile.endswith("eula.rtf") and not recfile.endswith("license.rtf"):
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
                ), " -> {} -> {} document file '{}' from {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage.replace(",", " &"),
                    recfile,
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                if os.path.exists(output_directory + img.split("::")[0] + "/files/documents/" + recfile):
                    multiple_files(os.path.join(recroot, recfile), output_directory + img.split("::")[0] + "/files/documents/" + recfile + "." + str(increment), increment)
                else:
                    shutil.copy2(
                        os.path.join(recroot, recfile),
                        output_directory + img.split("::")[0] + "/files/documents",
                    )
            except:
                pass
        elif yestoarcs != "n" and (
            recfile.endswith(".zip")
            or recfile.endswith(".rar")
            or recfile.endswith(".7z")
            or recfile.endswith(".tar")
            or recfile.endswith(".gz")
            or recfile.endswith(".arj")
            or recfile.endswith(".jar")
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
                ), " -> {} -> {} archive file '{}' from {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage.replace(",", " &"),
                    recfile,
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                if os.path.exists(output_directory + img.split("::")[0] + "/files/archives/" + recfile):
                    multiple_files(os.path.join(recroot, recfile), output_directory + img.split("::")[0] + "/files/archives/" + recfile + "." + str(increment), increment)
                else:
                    shutil.copy2(
                        os.path.join(recroot, recfile),
                        output_directory + img.split("::")[0] + "/files/archives",
                    )
            except:
                pass
        elif yestoscrs != "n" and (
            recfile.endswith(".ps1") or recfile.endswith(".py") or recfile.endswith(".rpy") or recfile.endswith(".bat") or recfile.endswith(".wbf") or recfile.endswith(".vba") or recfile.endswith(".vb") or recfile.endswith(".vbscript") or recfile.endswith(".js") or recfile.endswith(".c") or recfile.endswith(".o") or recfile.endswith(".cpp") or recfile.endswith(".cc") or recfile.endswith(".pl") or recfile.endswith(".go") or recfile.endswith(".php")
        ):
            try:
                os.stat(output_directory + img.split("::")[0] + "/files/scripts")
            except:
                os.makedirs(output_directory + img.split("::")[0] + "/files/scripts")
            try:
                (entry, prnt,) = "{},{},{},script file '{}'\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    recfile,
                ), " -> {} -> {} script file '{}' from {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage.replace(",", " &"),
                    recfile,
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                if os.path.exists(output_directory + img.split("::")[0] + "/files/scripts/" + recfile):
                    multiple_files(os.path.join(recroot, recfile), output_directory + img.split("::")[0] + "/files/scripts/" + recfile + "." + str(increment), increment)
                else:
                    shutil.copy2(
                        os.path.join(recroot, recfile),
                        output_directory + img.split("::")[0] + "/files/scripts",
                    )
            except:
                pass
        elif yestovmws != "n" and (
            recfile.endswith(".vmware")
            or recfile.endswith(".vmdk")
            or recfile.endswith(".vmx")
            or recfile.endswith(".vdi")
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
                ), " -> {} -> {} virtual file '{}' from {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage.replace(",", " &"),
                    recfile,
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                if os.path.exists(output_directory + img.split("::")[0] + "/files/virtual_machines/" + recfile):
                    multiple_files(os.path.join(recroot, recfile), output_directory + img.split("::")[0] + "/files/virtual_machines/" + recfile + "." + str(increment), increment)
                else:
                    shutil.copy2(
                        os.path.join(recroot, recfile),
                        output_directory + img.split("::")[0] + "/files/virtual_machines",
                    )
            except:
                pass
        elif yestoemls != "n" and (
            recfile.endswith(".ost")
            or recfile.endswith(".pst")
            or recfile.endswith(".eml")
        ):
            try:
                os.stat(
                    output_directory + img.split("::")[0] + "/files/mail"
                )
            except:
                os.makedirs(
                    output_directory + img.split("::")[0] + "/files/mail"
                )
            try:
                (entry, prnt,) = "{},{},{},mail file '{}'\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    stage,
                    recfile,
                ), " -> {} -> {} mail file '{}' from {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage.replace(",", " &"),
                    recfile,
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                if os.path.exists(output_directory + img.split("::")[0] + "/files/mail/" + recfile):
                    multiple_files(os.path.join(recroot, recfile), output_directory + img.split("::")[0] + "/files/mail/" + recfile + "." + str(increment), increment)
                else:
                    shutil.copy2(
                        os.path.join(recroot, recfile),
                        output_directory + img.split("::")[0] + "/files/mail",
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
            os.stat(os.path.join(output_directory, img.split("::")[0]) + "/recovered/" + recroot.split("/")[-1])
        except:
            os.makedirs(
                os.path.join(output_directory, img.split("::")[0]) + "/recovered/" + recroot.split("/")[-1]
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
