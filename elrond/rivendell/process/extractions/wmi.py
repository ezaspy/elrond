import subprocess
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def extract_wmi(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
    wmijsonlist,
):
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "wmi/"
        + artefact.split("/")[-1]
        + ".json",
        "a",
    ) as wmijson:
        entry, prnt = "{},{},{},'{}' wmi evidence\n".format(
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
        # experiencing error: event_header_chunk = ChunkParser.parse(chunks[0].payload)
        subprocess.Popen(
            [
                "python3",
                "/opt/elrond/elrond/tools/etl-parser/bin/etl2xml",
                "-i",
                artefact,
                "-o",
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "wmi/."
                + artefact.split("/")[-1]
                + ".xml",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        wmijsonlist.clear()
        jsonlist.clear()
