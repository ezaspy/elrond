#!/usr/bin/env python3 -tt
import os
import shutil
import time
from datetime import datetime
from zipfile import ZipFile

from rivendell.audit import write_audit_log_entry


def archive_artefacts(verbosity, output_directory):
    stage = "archiving"
    print(
        "\n\n  -> \033[1;36mCommencing Archive Phase...\033[1;m\n  ----------------------------------------"
    )
    for each in os.listdir(output_directory):
        if os.path.exists(output_directory + each + "/artefacts"):
            alist.append(output_directory + each)
    for zeach in alist:
        print("    Archiving artefacts for {}...".format(zeach.split("/")[-1]))
        entry, prnt = "{},{},{},commenced\n".format(
            datetime.now().isoformat(), zeach.split("/")[-1], stage
        ), " -> {} -> {} artefacts for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            zeach.split("/")[-1],
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        print("     Creating archive for '{}'...".format(zeach.split("/")[-1]))
        z = ZipFile(zeach + "/" + zeach.split("/")[-1] + ".zip", "w")
        for ziproot, _, zipfiles in os.walk(zeach):
            for zf in zipfiles:
                name = ziproot + "/" + zf
                if not name.endswith(
                    zeach.split("/")[-1] + "/" + zeach.split("/")[-1] + ".log"
                ) and not name.endswith(
                    zeach.split("/")[-1] + "/" + zeach.split("/")[-1] + ".zip"
                ):
                    z.write(name)
        print("  -> Completed Archiving Phase for '{}'".format(zeach.split("/")[-1]))
        entry, prnt = "{},{},{},completed\n".format(
            datetime.now().isoformat(), zeach.split("/")[-1], stage
        ), " -> {} -> archiving completed for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            zeach.split("/")[-1],
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        print(
            "  ----------------------------------------\n  -> Completed Archiving Phase.\n"
        )
        time.sleep(1)
        alist.clear()


def delete_artefacts(verbosity, output_directory):
    stage = "deleting"
    print(
        "\n\n  -> \033[1;36mCommencing Deletion Phase...\033[1;m\n  ----------------------------------------"
    )
    for each in os.listdir(output_directory):
        if os.path.exists(output_directory + each + "/artefacts"):
            alist.append(output_directory + each)
    for deach in alist:
        print("    Deleting artefacts for {}...".format(deach.split("/")[-1]))
        entry, prnt = "{},{},{},commenced\n".format(
            datetime.now().isoformat(), deach.split("/")[-1], stage
        ), " -> {} -> {} artefacts for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            deach.split("/")[-1],
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        print("     Deleting files for '{}'...".format(deach.split("/")[-1]))
        for droot, ddir, dfile in os.walk(deach):
            for eachdir in ddir:
                name = droot + "/" + eachdir
                if not name.endswith(deach):
                    shutil.rmtree(droot + "/" + eachdir)
            for eachfile in dfile:
                name = droot + "/" + eachfile
                if not name.endswith(
                    deach.split("/")[-1] + "/" + deach.split("/")[-1] + ".log"
                ) and not name.endswith(
                    deach.split("/")[-1] + "/" + deach.split("/")[-1] + ".zip"
                ):
                    os.remove(droot + "/" + eachfile)
        print("  -> Completed Deletion Phase for {}".format(deach.split("/")[-1]))
        entry, prnt = "{},{},{},completed\n".format(
            datetime.now().isoformat(), deach.split("/")[-1], stage
        ), " -> {} -> deletion completed for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            deach.split("/")[-1],
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        print(
            "  ----------------------------------------\n  -> Completed Deletion Phase.\n"
        )
        time.sleep(1)
        alist.clear()


alist = []
