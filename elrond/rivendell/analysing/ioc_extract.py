#!/usr/bin/env python3 -tt
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def extract_iocs(
    iocfiletimes,
    output_directory,
    verbosity,
    img,
    stage,
    iocfile,
    eachioc,
    ioctype,
    lineno,
    line,
    resolve,
):
    with open(
        output_directory + img.split("::")[0] + "/analysis/IOCs.csv", "a"
    ) as ioccsv:
        if verbosity != "":
            print(
                "       '{}' of type {} found on line {} extracted from '{}' for '{}'".format(
                    eachioc.split("@")[-1],
                    ioctype.replace("_", " "),
                    str(lineno),
                    iocfile.split(": ")[0].split("/")[-1],
                    img.split("::")[0],
                )
            )
        else:
            pass
        ioccsv.write(
            "{},{},{},{},{},{},{}\n".format(
                iocfiletimes,
                iocfile.split(": ")[0].replace(",", "%2C").strip(),
                eachioc.split("@")[-1],
                ioctype,
                str(lineno),
                line.replace(",", "%2C").strip(),
                resolve,
            )
        )
    (entry, prnt,) = "{},{},{},IOC '{}' ({}) extracted from '{}'".format(
        datetime.now().isoformat(),
        img.split("::")[0],
        stage,
        eachioc.split("@")[-1],
        ioctype,
        iocfile.split(": ")[0],
    ), " -> {} -> IOC '{}' ({}) extracted from '{}' on line {} for '{}'".format(
        datetime.now().isoformat().replace("T", " "),
        eachioc.split("@")[-1],
        ioctype,
        iocfile.split(": ")[0],
        str(lineno),
        img.split("::")[0],
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
