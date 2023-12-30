import os
import re
import subprocess
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def extract_shimcache(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage
):
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
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
                + vss_path_insert
                + ".SYSTEM",
                "-o",
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + ".shimcache.csv",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
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
                + vss_path_insert
                + "shimcache.csv",
                "a",
            ) as shimwrite:
                shimwrite.write(
                    newshimline.replace("Last Modified", "LastWriteTime")
                    .replace(",path", ",Process")
                    .replace("\\", "/")
                )
    try:
        os.remove(
            output_directory
            + img.split("::")[0]
            + "/artefacts/raw"
            + vss_path_insert
            + ".SYSTEM"
        )
        os.remove(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + ".shimcache.csv"
        )
    except:
        pass
