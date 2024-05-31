#!/usr/bin/env python3 -tt
import os
import re
import subprocess
import time
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def run_clamscan(verbosity, output_directory, loc, img, collectfiles):
    if collectfiles:
        all_or_collected = input(
            "      Run ClamAV against all files or just those collected for '{}'?\n      [A]ll  [C]ollected\t[A]ll ".format(
                img.split("::")[0]
            )
        )
    else:
        all_or_collected = "A"
    if all_or_collected != "A":
        clam_dir = output_directory + img.split("::")[0] + "/files"
    else:
        clam_dir = loc
    print(
        "      Scanning '{}' ({}/) with ClamAV, please stand by...".format(
            img.split("::")[0], clam_dir
        )
    )
    if not os.path.exists(output_directory + img.split("::")[0] + "/analysis"):
        os.mkdir(output_directory + img.split("::")[0] + "/analysis")
    if not os.path.exists(output_directory + img.split("::")[0] + "/analysis/ClamAV"):
        os.mkdir(output_directory + img.split("::")[0] + "/analysis/ClamAV")
    clam_results = subprocess.Popen(
        [
            "clamscan",
            "-raio",
            "--gen-json",
            "--leave-temps",
            "--tempdir={}/analysis/ClamAV".format(
                os.path.join(output_directory, img.split("::")[0])
            ),
            "--no-summary",
            "--log={}/analysis/ClamAVScan.log".format(
                os.path.join(output_directory, img.split("::")[0])
            ),
            clam_dir,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()[0]
    with open(
        "{}/analysis/ClamAVScan.log".format(
            os.path.join(output_directory, img.split("::")[0])
        )
    ) as clam_results:
        for count, _ in enumerate(clam_results):
            pass
        if count > 0:
            message = "{} instances of malware identified on "
        else:
            message = "No evidence of malware identified on "
    print("       {}'{}'".format(message, img.split("::")[0]))
    (
        entry,
        prnt,
    ) = (
        "{},{},clamAV,{}malware found\n".format(
            datetime.now().isoformat(),
            img.split("::")[0],
            message.split("malware ")[0].lower(),
        ),
    ), " -> {} -> ClamAV identified {}malware on '{}'".format(
        datetime.now().isoformat().replace("T", " "),
        message.split("malware ")[0].lower(),
        img.split("::")[0],
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
