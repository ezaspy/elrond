#!/usr/bin/env python3 -tt
import subprocess
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def extract_usn(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
):
    entry, prnt = "{},{},{},'{}' usn journal\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        artefact.split("/")[-1].split("_")[-1],
    ), " -> {} -> {} '{}' for {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        artefact.split("/")[-1].split("_")[-1],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    # python usn.py --csv -f usnjournal -o usn.csv
    """print(
        "python3",
        "/opt/elrond/elrond/tools/USN-Journal-Parser/usn.py",
        "--csv",
        "-f",
        artefact,
        "-o",
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + artefact.split("/")[-1]
        + ".csv",
    )"""
    subprocess.Popen(
        [
            "python3",
            "/opt/elrond/elrond/tools/USN-Journal-Parser/usn.py",
            "--csv",
            "-f",
            artefact,
            "-o",
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + artefact.split("/")[-1]
            + ".csv",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
