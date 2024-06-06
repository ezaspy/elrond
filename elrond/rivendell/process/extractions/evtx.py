import json
import re
import subprocess
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def extract_evtx(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
    evtjsonlist,
):
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "evt/"
        + artefact.split("/")[-1]
        + ".json",
        "a",
    ) as evtjson:
        entry, prnt = "{},{},{},'{}' event log\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
            artefact.split("/")[-1],
        ), " -> {} -> {} {} for {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            artefact.split("/")[-1],
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        evtout = str(
            subprocess.Popen(
                [
                    "/usr/local/bin/evtx_dump.py",
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/raw"
                    + vss_path_insert
                    + "evt/"
                    + artefact.split("/")[-1],
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
        )[3:-9]
        for event in evtout.split("\\r\\n"):
            if (
                event
                != '<?xml version="1.1" encoding="utf-8" standalone="yes" ?>\\n\\n<Events>\\n</Events>'
            ):
                for evtrow in event.split("\\n"):
                    for eachkv in re.findall(
                        r"(?:\ (?P<k1>(?!Name)[^\=]+)\=\"(?P<v1>[^\"]+)\"|\<(?P<k2>[^\>\/\=\ ]+)(?:\ \D+\=\"\"\>|\=\"|\>)(?P<v2>[^\"\>]+)(?:\"\>)?\<\/[^\>]+\>|\<Data\ Name\=\"(?P<k3>[^\"]+)\"\>(?P<v3>[^\<]+)\<\/Data\>)",
                        evtrow,
                    ):
                        kv = list(filter(None, eachkv))
                        if len(kv) > 0:
                            jsondict[kv[0]] = kv[1]
                if len(jsondict) > 0:
                    jsonlist.append(json.dumps(jsondict))
        for eachjson in jsonlist:
            try:
                eachjson = str(eachjson).replace('""', '"-"')
                if '"RegistryKey"' in eachjson:
                    insert = ', "Registry{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"RegistryKey(\"\: \"[^\"]+\")",
                                    eachjson,
                                )[0]
                            ).lower()
                        )
                        .replace(" ", "_")
                        .replace('":_"', '": "')
                    )
                    evtjsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                else:
                    evtjsonlist.append(json.dumps(eachjson))
            except:
                pass
        if len(evtjsonlist) > 0:
            evtjson.write(
                re.sub(
                    r"\d+\s(Public Primary Certification Authority)\s-\s\w\d",
                    r"\1",
                    str(evtjsonlist)
                    .replace(
                        "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\",
                        "/",
                    )
                    .replace("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\", "/")
                    .replace("\\\\\\\\\\\\\\\\", "/")
                    .replace("\\\\\\\\", "/")
                    .replace("\\\\", "/")
                    .replace("\\", "/")
                    .replace('/"', '"')
                    .replace(
                        "                                                                ",
                        " ",
                    )
                    .replace("                                ", " ")
                    .replace("                ", " ")
                    .replace("        ", " ")
                    .replace("    ", " ")
                    .replace("  ", " ")
                    .replace("  ", "")
                    .replace('" ', '"')
                    .replace(' "', '"')
                    .replace("//'", "'")
                    .replace('":"', '": "')
                    .replace('","', '", "')
                    .replace('"}"\', \'"{"', '"}, {"')
                    .replace('[\'"{"', '[{"')
                    .replace('"}"\']', '"}]')
                    .replace('/"', "/")
                    .replace('/, "', '/", "')
                    .replace('/}, {"', '/"}, {"')
                    .replace("/}]", '/"}]')
                    .replace("ProcessName", "Process"),
                )
            )
        evtjsonlist.clear()
        jsonlist.clear()
