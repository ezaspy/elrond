#!/usr/bin/env python3 -tt
import os
import subprocess
import time
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def carve_files(output_directory, verbosity, d, artefact_directory, img, vssimage):
    print(
        "\n       \033[1;33mCarving files from unallocated space for {}...\033[1;m".format(
            vssimage
        )
    )
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
    for eachdir in os.listdir(artefact_directory + "/carved"):
        for eachfile in os.listdir(artefact_directory + "/carved/" + eachdir):
            print("     Successfully carved '{}' from {}".format(eachfile, vssimage))
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
            time.sleep(0.5)

    entry, prnt = "{},{},{},completed\n".format(
        datetime.now().isoformat(), vssimage.replace("'", ""), "carving"
    ), " -> {} -> {} artefacts from {}".format(
        datetime.now().isoformat().replace("T", " "),
        "carved",
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    print(
        "       \033[1;33mCarved all available files, from {}\n\033[1;m".format(
            vssimage
        )
    )
