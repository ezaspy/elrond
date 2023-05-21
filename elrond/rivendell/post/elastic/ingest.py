#!/usr/bin/env python3 -tt
import csv
import json
import os
import shlex
import subprocess
from datetime import datetime
from io import StringIO

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry

def ingest_elastic_data(
    verbosity,
    output_directory,
    case,
    allimgs,
):
    imgs_to_ingest = []
    for _, img in allimgs.items():
        if img not in str(imgs_to_ingest):
            imgs_to_ingest.append(img)
        else:
            pass
    # need to make individual indexes for each log source type - to ensure the correct timestamp is mapped for that log source - _index should be casetest-<usb/evtx/registry/log/etc.>
    make_index = shlex.split('curl -X PUT "localhost:9200/{}?pretty"'.format(case))
    subprocess.Popen(make_index, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
    make_index_pattern = shlex.split('curl -X POST "localhost:5601/api/saved_objects/index-pattern/{}" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d \'{{"attributes": {{"title": "{}*"}}}}\''.format(case, case))
    subprocess.Popen(make_index_pattern, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
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
        entry, prnt = "{},{}{},elastic,ingesting\n".format(
            datetime.now().isoformat(), img.split("::")[0], vsstext
        ), " -> {} -> ingesting artfacts into elastic for {}{}".format(
            datetime.now().isoformat().replace("T", " "),
            vssimage,
            vsstext,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        for atftroot, _, atftfiles in os.walk(
            os.path.realpath(
                output_directory + img.split("::")[0] + "/artefacts/cooked/"
            )
        ):
            for atftfile in atftfiles:
                if os.path.getsize(os.path.join(atftroot, atftfile)) > 0 and (atftfile.endswith(".csv") or atftfile.endswith(".json")):
                    """if atftfile.endswith(".csv"):
                        csvtojson = {}
                        with open(os.path.join(atftroot, atftfile), encoding='utf-8') as read_csv:
                            csv_reader = csv.DictReader(read_csv)
                            for rows in csv_reader:
                                print(rows)
                                import time
                                time.sleep(20)
                                key = rows['Serial Number']
                                csvtojson[key] = rows
                            with open(os.path.join(atftroot, atftfile)[0:-4] + ".json", 'w', encoding='utf-8') as write_json:
                                write_json.write(json.dumps(csvtojson))"""
                    if atftfile.endswith(".json"):
                        with open(os.path.join(atftroot, atftfile)) as read_json:
                            json_content = read_json.read()
                        in_json = StringIO(json_content)
                        results = [json.dumps(record) for record in json.load(in_json)]
                        ndjsonfile = os.path.join(atftroot, atftfile)[0:-5] + ".ndjson"
                        with open(ndjsonfile, "w") as write_json:
                            for result in results:
                                write_json.write('{{"index": {{"_index": "{}"}}}}\n{{"hostname": "{}", "artefact": "{}", {}\n\n'.format(case, img.split("::")[0], atftfile, result[1:]))
                        ingest_data_command = shlex.split('curl -s -H "Content-Type: application/x-ndjson" -XPOST localhost:9200/{}/default/_bulk?pretty --data-binary @{}'.format(case, ndjsonfile))
                        ingested_data = subprocess.Popen(ingest_data_command,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()[0]
                        if 'failed" : 1' in str(ingested_data) or "request body is required" in str(ingested_data):
                            print(ndjsonfile.split("/")[-1])
                            import time
                            time.sleep(20)
                    else:
                        pass
                else:
                    pass
        print_done(verbosity)
        print("     elasticsearch ingestion completed for {}".format(vssimage))
        entry, prnt = "{},{},elastic,completed\n".format(
            datetime.now().isoformat(), vssimage
        ), " -> {} -> indexed artfacts into elastic for {}".format(
            datetime.now().isoformat().replace("T", " "),
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
