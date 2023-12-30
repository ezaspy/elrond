import os
import re
import subprocess
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def extract_wbem(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
):
    entry, prnt = "{},{},{},'{}' wbem evidence\n".format(
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
    subprocess.Popen(  # CCM_RUA_Finder
        [
            "python2.7",
            "/opt/elrond/elrond/tools/WMI_Forensics/CCM_RUA_Finder.py",
            "-i",
            artefact,
            "-o",
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "wbem/."
            + artefact.split("/")[-1]
            + ".tsv",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    if os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "wbem/."
        + artefact.split("/")[-1]
        + ".tsv"
    ):
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "wbem/."
            + artefact.split("/")[-1]
            + ".tsv"
        ) as wbem_tsv:
            with open(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "wbem/"
                + artefact.split("/")[-1]
                + "-CCM_RUA.csv",
                "a",
            ) as wbem_csv:
                for tab_line in wbem_tsv:
                    wbem_csv.write(tab_line.replace(",", "‚").replace("\t", ","))
                    # wbem_csv.write("{}\n".format(tab_line.replace(",", "‚").replace("\t", ","))) # during testing, there were no lines so unsure if a newline is provided automatically or not
        os.remove(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "wbem/."
            + artefact.split("/")[-1]
            + ".tsv"
        )
    try:
        pywmipf = subprocess.Popen(  # PyWMIPersistenceFinder
            [
                "python2.7",
                "/opt/elrond/elrond/tools/WMI_Forensics/PyWMIPersistenceFinder.py",
                artefact,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()[0]
        persistence_pairs = (
            str(pywmipf)[8:-3]
            .split("Enumerating Filters and Consumers...\\n\\n    ")[1]
            .split("\\n\\n\\n    Thanks for using PyWMIPersistenceFinder")[0]
            .replace(":\\n\\n        ", "::")
            .replace("\\n                ", " ")
            .replace("\\n            ", "||")
            .replace("Filter: \\n\\t\\t", "")
            .replace("\\n\\t\\t", "||")
            .replace(":  ", "::")
            .replace(": ", "::")
            .replace("Bindings::", "\nBindings::")
            .replace("\\\\n", "")
            .replace("\\n", "")
        )
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "wbem/"
            + artefact.split("/")[-1]
            + "-Persistence.csv",
            "a",
        ) as wbemcsv:
            elements = []
            headers = (
                str(re.findall(r"([^:\|]+)::", persistence_pairs))[2:-2]
                .strip("\\n")
                .replace("', '", ",")
            )
            elements.append(
                str(re.findall(r"::([^:\|]+)", persistence_pairs))[2:-2].replace(
                    "', '", ","
                )
            )
            wbemcsv.write("{}\n".format(headers))
            for element in elements:
                wbemcsv.write("{}\n".format(element))
            # need to add additional field such as timestamp, host
    except:
        pass
