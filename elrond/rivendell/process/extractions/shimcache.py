import os
import re
import subprocess
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def extract_shimcache(verbosity, vssimage, output_directory, img, vssartefact, stage):
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vssartefact
        + ".shimcache.csv",
        "a",
    ):
        entry, prnt = "{},{},{},'ShimCache'\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
        ), " -> {} -> {} ShimCache for {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        subprocess.Popen(
            [
                "/usr/local/bin/ShimCacheParser.py",
                "-i",
                output_directory
                + img.split("::")[0]
                + "/artefacts/raw"
                + vssartefact
                + ".SYSTEM",
                "-o",
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vssartefact
                + ".shimcache.csv",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vssartefact
        + ".shimcache.csv",
        "r",
    ) as shimread:
        for shimline in shimread:
            winproc = str(
                re.findall(r"[^\,]+\,[^\,]+(\,[^\,]+).*", shimline)[0]
            ).lower()
            tempshimline = re.sub(
                r"([^\,]+\,[^\,]+)(\,[^\,]+)(.*)",
                r"\1\2\3_-_-_-_-_-_",
                shimline,
            )
            newshimline = tempshimline.replace("_-_-_-_-_-_", winproc)
            with open(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vssartefact
                + "shimcache.csv",
                "a",
            ) as shimwrite:
                shimwrite.write(
                    newshimline.replace("Last Modified", "LastWriteTime")
                    .replace(",path", ",WinProcess")
                    .replace("\\", "/")
                )
    try:
        os.remove(
            output_directory
            + img.split("::")[0]
            + "/artefacts/raw"
            + vssartefact
            + ".SYSTEM"
        )
        os.remove(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + ".shimcache.csv"
        )
    except:
        pass
