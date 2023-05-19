#!/usr/bin/env python3 -tt
import json
import os
import shutil
import subprocess
from datetime import datetime
from io import StringIO

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry

def ingest_elastic_data(
    verbosity,
    output_directory,
    case,
    stage,
    allimgs,
    postpath,
):
    imgs_to_ingest = []
    for _, img in allimgs.items():
        if img not in str(imgs_to_ingest):
            imgs_to_ingest.append(img)
        else:
            pass
    subprocess.Popen(
        [
            "curl",
            "-X",
            "PUT",
            "\"localhost:9200/{}?pretty\"".format(case)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()[0]
    for img in imgs_to_ingest:
        if "vss" in img.split("::")[1]:
            vssimage, vsstext = "'" + img.split("::")[0] + "' (" + img.split("::")[
                1
            ].split("_")[1].replace(
                "vss", "volume shadow copy #"
            ) + ")", " from " + img.split(
                "::"
            )[
                1
            ].split(
                "_"
            )[
                1
            ].replace(
                "vss", "volume shadow copy #"
            )
        else:
            vssimage, vsstext = "'" + img.split("::")[0] + "'", ""
        print()
        print("     Ingesting artefacts into elasticsearch for {}...".format(vssimage))
        entry, prnt = "{},{}{},{},ingesting\n".format(
            datetime.now().isoformat(), img.split("::")[0], vsstext, stage
        ), " -> {} -> ingesting artfacts into {} for {}{}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            vssimage,
            vsstext,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        for _, _, atftfiles in os.walk(
            os.path.realpath(
                output_directory + img.split("::")[0] + "/artefacts/cooked/"
            )
        ):
            for atftfile in atftfiles:
                if atftfile.endswith(".json"):
                    with open(atftfile) as read_json:
                        json_content = read_json.read()
                    in_json = StringIO(json_content)
                    results = [json.dumps(record) for record in json.load(in_json)]
                    ndjsonfile = atftfile[0:-5] + ".ndjson"
                    with open(ndjsonfile, "w") as write_json:
                        for result in results:
                            write_json.write("{\"index\": ")
                            write_json.write("{\"_index\": \"")
                            write_json.write("{}\"".format("casetest"))
                            write_json.write("}")
                            write_json.write("}\n")
                            write_json.write("{}\n".format(result))
                    shutil.copy2(ndjsonfile, ".")
                    subprocess.Popen(
                        [
                            "curl",
                            "-s",
                            "-H",
                            "\"Content-Type:",
                            "application/x-ndjson\"",
                            "-XPOST",
                            "localhost:9200/product/default/_bulk?pretty",
                            "--data-binary",
                            "@{}".format()
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[0]
                    os.remove(ndjsonfile.split("/")[-1])
                else:
                    pass
                print()