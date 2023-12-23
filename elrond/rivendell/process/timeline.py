import os
import re
import shutil
import subprocess
import time
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def convert_plaso_timeline(verbosity, output_directory, stage, img):
    lineno = 0
    with open(
        output_directory + img.split("::")[0] + "/artefacts/plaso_timeline.csv",
        "a",
    ) as plasocsv:
        plasocsv.write(
            "LastWriteTime,timestamp_desc,logsource,source_long,message,parser,display_name,tag,Message,Artefact\n"
        )
        with open("./plaso_timeline.csvtmp", "r") as plasotmp:
            for eachline in plasotmp:
                if lineno != 0:
                    (
                        LastWriteTime,
                        timestamp_desc__logsource__source_long,
                        Message,
                        parser,
                        Artefact,
                        tag,
                    ) = re.findall(
                        r"^([^,]+),([^,]+,[^,]+,[^,]+),([^,]+),([^,]+),([^,]+),([^,]+)",
                        eachline,
                    )[
                        0
                    ]
                    if (
                        LastWriteTime != "0000-00-00T00:00:00"
                    ):  # removing all entries without timestamp to reduce size
                        plasocsv.write(
                            "{},{},{},{},{},{},{},{}\n".format(
                                LastWriteTime,
                                timestamp_desc__logsource__source_long,
                                Message,
                                parser,
                                Artefact,
                                tag,
                                Message.lower().replace("\\\\", "/").replace("\\", "/"),
                                Artefact.lower()
                                .replace("\\\\", "/")
                                .replace("\\", "/"),
                            )
                        )
                lineno += 1
    entry, prnt = "{},{},{},{}\n".format(
        datetime.now().isoformat(),
        img.split("::")[0],
        stage,
        img.split("::")[0],
    ), " -> {} -> {} '{}'".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        img.split("::")[0],
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)


def create_plaso_timeline(verbosity, output_directory, stage, img, d, timelineimage):
    print("\n    Creating timeline for {}...".format(timelineimage))
    entry, prnt = "{},{},{},commenced\n".format(
        datetime.now().isoformat(), timelineimage, stage
    ), " -> {} -> creating timeline for '{}'".format(
        datetime.now().isoformat().replace("T", " "), timelineimage
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    for image_directory in os.listdir(d):
        if os.path.exists(os.path.join(d, image_directory, img.split("::")[0])):
            timelineimagepath = os.path.join(d, image_directory, img.split("::")[0])
    print(
        "     Entering plaso to create timeline for '{}', please stand by...".format(
            timelineimage
        )
    )
    time.sleep(2)
    if os.path.exists(".plaso"):
        shutil.rmtree("./.plaso")
    os.mkdir(".plaso")
    os.chdir("./.plaso")
    subprocess.Popen(
        [
            "psteal.py",
            "--source",
            timelineimagepath,
            "-o",
            "dynamic",
            "-w",
            "./plaso_timeline.csvtmp",
        ]
    ).communicate()[
        0
    ]  # https://plaso.readthedocs.io/en/latest/sources/user/Creating-a-timeline.html
    os.chdir("..")
    convert_plaso_timeline(verbosity, output_directory, stage, img)
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    shutil.rmtree("./.plaso")
