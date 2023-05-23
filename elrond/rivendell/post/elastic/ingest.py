#!/usr/bin/env python3 -tt
import csv
import json
import os
import re
import shlex
import subprocess
import time
from datetime import datetime
from io import StringIO

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry


def ingest_elastic_ndjson(case, ndjsonfile):
    ingest_data_command = shlex.split(
        'curl -s -H "Content-Type: application/x-ndjson" -XPOST localhost:9200/{}/default/_bulk?pretty --data-binary @"{}"'.format(
            case.lower(), ndjsonfile
        )
    )
    ingested_data = subprocess.Popen(
        ingest_data_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()[0]
    if (
        "Unexpected character" in str(ingested_data)
        or 'failed" : 1' in str(ingested_data)
        or "request body is required" in str(ingested_data)
    ):
        print(
            "       Could not ingest\t'{}'\t\t- perhaps the json did not format correctly?".format(
                ndjsonfile.split("/")[-1]
            )
        )
    else:
        pass


def ingest_elastic_data(
    verbosity,
    output_directory,
    case,
    stage,
    allimgs,
):
    imgs_to_ingest = []
    for _, img in allimgs.items():
        if img not in str(imgs_to_ingest):
            imgs_to_ingest.append(img)
        else:
            pass
    """for data, index_name in index_mapping.items():  # consider making individual indexes for each log source type - to ensure the correct timestamp is mapped for that log source - _index should be casetest-<usb/evtx/registry/log/etc.>
        if atftroot.split("/")[-1] == "cooked":
            index = atftfile.split(".")[0]
        else:
            index = atftroot.split("/")[-1]
        print(atftroot.split("/")[-1])
        print(atftfile)
        print(data, index_name)
        print(index)"""
    # creating index based on case name in elasticsearch
    make_index = shlex.split(
        'curl -X PUT "localhost:9200/{}?pretty"'.format(case.lower())
    )
    subprocess.Popen(
        make_index, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).communicate()[0]
    # increasing field limitations in elasticsearch
    increase_index_limit = shlex.split(
        'curl -X PUT  -H "Content-Type: application/x-ndjson" localhost:9200/{}/_settings?pretty -d \'{{"index.mapping.total_fields.limit": 10000}}\''.format(
            case.lower()
        )
    )
    subprocess.Popen(
        increase_index_limit, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).communicate()[0]
    # creating index pattern to ensure data is mapped correctly in Kibana
    make_index_pattern = shlex.split(
        'curl -X POST "localhost:5601/api/saved_objects/index-pattern/{}" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d \'{{"attributes": {{"title": "{}*"}}}}\''.format(
            case.lower(), case.lower()
        )
    )
    subprocess.Popen(
        make_index_pattern, stdout=subprocess.PIPE, stderr=subprocess.PIPE
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
        for atftroot, _, atftfiles in os.walk(
            os.path.realpath(
                output_directory + img.split("::")[0] + "/artefacts/cooked/"
            )
        ):
            for (
                atftfile
            ) in (
                atftfiles
            ):  # spliting the large csv files into smaller chunks for easing ingestion
                if os.path.getsize(
                    os.path.join(atftroot, atftfile)
                ) > 52427769 and atftfile.endswith(".csv"):
                    subprocess.Popen(
                        [
                            "split",
                            "-C",
                            "20m",
                            "--numeric-suffixes",
                            os.path.join(atftroot, atftfile),
                            "{}-split".format(os.path.join(atftroot, atftfile[0:-4])),
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[0]
        time.sleep(0.5)
        for atftroot, _, atftfiles in os.walk(
            os.path.realpath(
                output_directory + img.split("::")[0] + "/artefacts/cooked/"
            )
        ):
            for (
                atftfile
            ) in atftfiles:  # renaming the split files with the .csv extension
                if "-split" in atftfile:
                    os.rename(
                        os.path.join(atftroot, atftfile),
                        os.path.join(atftroot, atftfile + ".csv"),
                    )
                else:
                    pass
        time.sleep(0.5)
        for atftroot, _, atftfiles in os.walk(
            os.path.realpath(
                output_directory + img.split("::")[0] + "/artefacts/cooked/"
            )
        ):
            for atftfile in atftfiles:  # converting csv files to ndjson
                if (
                    os.path.getsize(os.path.join(atftroot, atftfile)) > 0
                    and atftfile.endswith(".csv")
                    and os.path.getsize(os.path.join(atftroot, atftfile)) < 52427770
                ):
                    if atftfile.endswith(".csv"):
                        with open(
                            os.path.join(atftroot, atftfile), encoding="utf-8"
                        ) as read_csv:
                            csv_results = csv.DictReader(read_csv)
                            with open(
                                os.path.join(atftroot, atftfile)[0:-4] + ".ndjson",
                                "a",
                                encoding="utf-8",
                            ) as write_json:
                                for result in csv_results:
                                    data = (
                                        str(result)[2:]
                                        .replace("': '", '": "')
                                        .replace("', '", '", "')
                                        .replace("'}", '"}')
                                        .replace("': None", '": None')
                                        .replace("\": None, '", '": None, "')
                                        .replace("': \"", '": "')
                                        .replace("\", '", '", "')
                                        .replace('"-": "-", ', "")
                                        .replace('"": "", ', "")
                                    )
                                    """if "+index.dat" in atftfile:
                                        malformed_indexdat_data = re.findall(
                                            r"\"Domain\": \"(.*)\"url\"", data
                                        )
                                        print(malformed_indexdat_data)
                                        time.sleep(10)
                                    else:
                                        pass"""
                                    write_json.write(
                                        '{{"index": {{"_index": "{}"}}}}\n{{"hostname": "{}", "artefact": "{}", "{}\n\n'.format(
                                            case.lower(),
                                            img.split("::")[0],
                                            atftfile,
                                            data,
                                        )
                                    )
                            ingest_elastic_ndjson(
                                case.lower(),
                                os.path.join(atftroot, atftfile)[0:-4] + ".ndjson",
                            )
                    else:
                        pass
                else:
                    pass
        time.sleep(0.5)
        for atftroot, _, atftfiles in os.walk(
            os.path.realpath(
                output_directory + img.split("::")[0] + "/artefacts/cooked/"
            )
        ):
            for atftfile in atftfiles:  # converting json files to ndjson
                if os.path.getsize(
                    os.path.join(atftroot, atftfile)
                ) > 0 and atftfile.endswith(".json"):
                    if atftfile.endswith(".json"):
                        with open(os.path.join(atftroot, atftfile)) as read_json:
                            json_content = read_json.read()
                        in_json = StringIO(json_content)
                        results = [json.dumps(record) for record in json.load(in_json)]
                        with open(
                            os.path.join(atftroot, atftfile)[0:-5] + ".ndjson", "w"
                        ) as write_json:
                            for result in results:
                                if result != "{}":
                                    write_json.write(
                                        '{{"index": {{"_index": "{}"}}}}\n{{"hostname": "{}", "artefact": "{}", {}\n\n'.format(
                                            case.lower(),
                                            img.split("::")[0],
                                            atftfile,
                                            result[1:],
                                        )
                                    )
                                else:
                                    pass
                        ingest_elastic_ndjson(
                            case.lower(),
                            os.path.join(atftroot, atftfile)[0:-5] + ".ndjson",
                        )
                    else:
                        pass
                else:
                    pass
        time.sleep(0.5)
        print_done(verbosity)
        print("     elasticsearch ingestion completed for {}".format(vssimage))
        entry, prnt = "{},{},{},completed\n".format(
            datetime.now().isoformat(), vssimage, stage
        ), " -> {} -> indexed artfacts into {} for {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
