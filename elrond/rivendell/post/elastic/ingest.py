#!/usr/bin/env python3 -tt
import csv
import json
import os
import re
import shlex
import shutil
import subprocess
import time
from datetime import datetime
from io import StringIO

from rivendell.audit import write_audit_log_entry


def split_large_csv_files(root_dir):
    for atftroot, _, atftfiles in os.walk(root_dir):
        for (
            atftfile
        ) in (
            atftfiles
        ):  # spliting the large csv files into smaller chunks for easing ingestion
            if os.path.exists(os.path.join(atftroot, atftfile)):
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
    time.sleep(0.2)


def prepare_csv_to_ndjson(root_dir):
    for atftroot, _, atftfiles in os.walk(root_dir):
        for atftfile in atftfiles:  # renaming the split files with the .csv extension
            if "-split" in atftfile:
                os.rename(
                    os.path.join(atftroot, atftfile),
                    os.path.join(atftroot, atftfile + ".csv"),
                )
    for atftroot, _, atftfiles in os.walk(root_dir):
        for atftfile in atftfiles:  # adding header to split csv files
            if (
                "-split" in atftfile
                and "journal_mft" in atftfile
                and atftfile.endswith(".csv")
                and "00" not in atftfile
            ):
                with open(
                    os.path.join(atftroot, ".adding_header_" + atftfile),
                    "a",
                ) as adding_header:
                    adding_header.write(
                        "record,state,active,record_type,seq_number,parent_file_record,parent_file_record_seq,std_info_creation_date,std_info_modification_date,std_info_access_date,std_info_entry_date,object_id,birth_volume_id,birth_object_id,birth_domain_id,std_info,attribute_list,has_filename,has_object_id,volume_name,volume_info,data,index_root,index_allocation,bitmap,reparse_point,ea_information,ea,property_set,logged_utility_stream,log/notes,stf_fn_shift,usec_zero,ads,possible_copy,possible_volume_move,Filename,fn_info_creation_date,fn_info_modification_date,fn_info_access_date,fn_info_entry_date,LastWriteTime\n"
                    )
                    with open(os.path.join(atftroot, atftfile)) as read_split_file:
                        for eachcsvrow in read_split_file:
                            adding_header.write(eachcsvrow)
                os.remove(os.path.join(atftroot, atftfile))
    for atftroot, _, atftfiles in os.walk(root_dir):
        for atftfile in atftfiles:  # renaming the split files, with headers
            if (
                "-split" in atftfile
                and ".adding_header_" in atftfile
                and "journal_mft" in atftfile
                and atftfile.endswith(".csv")
            ):
                os.rename(
                    os.path.join(atftroot, atftfile),
                    os.path.join(atftroot, atftfile.split(".adding_header_")[-1]),
                )
    time.sleep(0.2)


def convert_csv_to_ndjson(output_directory, case, img, root_dir):
    for atftroot, _, atftfiles in os.walk(root_dir):
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
                        # try/catch with file-reading error
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
                                if "+index.dat" in atftfile:
                                    malformed_indexdat_data = re.findall(
                                        r"(.*\"Domain\": \")([\S\s]+)(\"url\".*)",
                                        data,
                                    )
                                    reformed_data = (
                                        malformed_indexdat_data[0][1]
                                        .replace("(", "%28")
                                        .replace(")", "%29")
                                        .replace("{", "%7B")
                                        .replace("}", "%7D")
                                        .replace('"', "%22")
                                    )
                                    reformed_data = re.sub(
                                        r'(Description": "[^"]+)(\}$)',
                                        r'\1"\2',
                                        reformed_data,
                                    )
                                    if reformed_data.endswith("%22, "):
                                        reformed_data = reformed_data.replace(
                                            "%22, ", '", '
                                        )
                                    reformed_data.replace("\" ', ", '"').replace(
                                        "\\\\\\", "\\\\"
                                    )
                                    data = "{}{}{}".format(
                                        malformed_indexdat_data[0][0],
                                        reformed_data.replace("\\\\\\", "\\\\").replace(
                                            "\\\\\\", "\\\\"
                                        ),
                                        malformed_indexdat_data[0][2],
                                    )
                                # inserting timestamp now() as no timestamp exists
                                if (
                                    "_index" not in data
                                    and "LastWrite" not in data
                                    and "@timestamp" not in data
                                ):
                                    time_insert = '", "@timestamp": "{}'.format(
                                        datetime.now().isoformat().replace("T", " ")
                                    )
                                else:
                                    time_insert = ""
                                data = '{{"index": {{"_index": "{}"}}}}\n{{"hostname": "{}", "artefact": "{}{}", "{}\n\n'.format(
                                    case.lower(),
                                    img.split("::")[0],
                                    atftfile,
                                    time_insert,
                                    data.replace("SystemTime", "@timestamp")
                                    .replace("LastWriteTime", "@timestamp")
                                    .replace("LastWrite Time", "@timestamp")
                                    .replace('"LastWrite": "', '"@timestamp": "')
                                    .replace(
                                        '"@timestamp": "@timestamp ',
                                        '"@timestamp": "',
                                    ),
                                )
                                data = re.sub(r'(": )(None)([,:\}])', r'\1"\2"\3', data)
                                data = data.replace("', None: ['", '", "None": ["')
                                data = re.sub(r'(": \["[^\']+)\'(\])', r'\1"\2', data)
                                converted_timestamp = convert_timestamps(data)
                                write_json.write(
                                    re.sub(
                                        r'([^\{\[ ])"([^:,\}])',
                                        r"\1%22\2",
                                        re.sub(
                                            r'([^:,] )"([^:,])',
                                            r"\1%22\2",
                                            converted_timestamp,
                                        ),
                                    )
                                )
                        prepare_elastic_ndjson(
                            output_directory,
                            img,
                            case.lower(),
                            os.path.join(atftroot, atftfile)[0:-4] + ".ndjson",
                        )
    time.sleep(0.2)


def convert_json_to_ndjson(output_directory, case, img, root_dir):
    for atftroot, _, atftfiles in os.walk(root_dir):
        for atftfile in atftfiles:  # converting json files to ndjson
            if os.path.getsize(
                os.path.join(atftroot, atftfile)
            ) > 0 and atftfile.endswith(".json"):
                try:
                    with open(os.path.join(atftroot, atftfile)) as read_json:
                        json_content = read_json.read()
                    in_json = StringIO(json_content)
                    results = [json.dumps(record) for record in json.load(in_json)]
                    with open(
                        os.path.join(atftroot, atftfile)[0:-5] + ".ndjson", "w"
                    ) as write_json:
                        for result in results:
                            if result != "{}":
                                data = '{{"index": {{"_index": "{}"}}}}\n{{"hostname": "{}", "artefact": "{}", {}\n\n'.format(
                                    case.lower(),
                                    img.split("::")[0],
                                    atftfile,
                                    result[1:]
                                    .replace("SystemTime", "@timestamp")
                                    .replace("LastWriteTime", "@timestamp")
                                    .replace("LastWrite Time", "@timestamp")
                                    .replace('"LastWrite": "', '"@timestamp": "')
                                    .replace(
                                        '"@timestamp": "@timestamp ',
                                        '"@timestamp": "',
                                    ),
                                )
                                data = re.sub(r'(": )(None)([,:\}])', r'\1"\2"\3', data)
                                converted_timestamp = convert_timestamps(data)
                                write_json.write(converted_timestamp)
                    prepare_elastic_ndjson(
                        output_directory,
                        img,
                        case.lower(),
                        os.path.join(atftroot, atftfile)[0:-5] + ".ndjson",
                    )
                except:
                    print(
                        "       Could not ingest\t'{}'\t- perhaps the json did not format correctly?".format(
                            atftfile
                        )
                    )
    time.sleep(0.2)


def convert_timestamps(data):
    # yyyy/MM/dd HH:mm:ss.SSS
    converted_timestamp_formats = re.sub(
        r"(@timestamp\": \"\d{4})/(\d{2})/(\d{2}) (\d{2}:\d{2}:\d{2}\.\d{3}[^\d])",
        r"\1-\2-\3 \4 000",
        data,
    )
    # yyyy-MM-dd HH:mm:ssZ/yyyy-MM-dd HH:mm:ss
    converted_timestamp_formats = re.sub(
        r"(@timestamp\": \"\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})Z?",
        r"\1 \2\.000000",
        converted_timestamp_formats,
    )
    # MM/dd/yy HH:mm:ss
    converted_timestamp_formats = re.sub(
        r"(@timestamp\": \"\d{2})/(\d{2})/(\d{2}) (\d{2}:\d{2}:\d{2})",
        r"\1-\2-\3 \4\.000000",
        converted_timestamp_formats,
    )
    # evtx files and $I30
    return (
        converted_timestamp_formats.replace(" 000", "000")
        .replace("000000.", ".")
        .replace("\\.000000", ".000000")
        .replace("\\..", ".")
    )


def ingest_elastic_ndjson(case, ndjsonfile):
    ingest_data_command = shlex.split(
        'curl -s -H "Content-Type: application/x-ndjson" -XPOST localhost:9200/{}/_doc/_bulk?pretty --data-binary @"{}"'.format(
            case.lower(), ndjsonfile
        )
    )
    ingested_data = subprocess.Popen(
        ingest_data_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()[0]
    if "Unexpected character" in str(ingested_data) or 'failed" : 1' in str(
        ingested_data
    ):
        print(
            "       Could not ingest\t'{}'\t- perhaps the json did not format correctly?".format(
                ndjsonfile.split("/")[-1]
            )
        )


def prepare_elastic_ndjson(output_directory, img, case, source_location):
    if not os.path.exists(
        os.path.join(output_directory + img.split("::")[0] + "/elastic/")
    ):
        os.makedirs(os.path.join(output_directory + img.split("::")[0] + "/elastic/"))
        os.makedirs(
            os.path.join(output_directory + img.split("::")[0] + "/elastic/documents/")
        )
    if "/vss" in source_location:
        vss_path_insert = "/vss{}".format(
            source_location.split("/vss")[1].split("/")[0]
        )
        if not os.path.exists(
            os.path.join(
                output_directory
                + img.split("::")[0]
                + "/elastic/documents{}".format(vss_path_insert)
            )
        ):
            os.makedirs(
                os.path.join(
                    output_directory
                    + img.split("::")[0]
                    + "/elastic/documents{}".format(vss_path_insert)
                )
            )
    else:
        vss_path_insert = ""
    ndjsonfile = os.path.join(
        output_directory + img.split("::")[0] + "/elastic/documents{}/{}"
    ).format(vss_path_insert, source_location.split("/")[-1])
    shutil.move(source_location, ndjsonfile)
    try:
        ingest_elastic_ndjson(case, ndjsonfile)
    except:
        print(
            "       Could not ingest\t'{}'\t- perhaps the json did not format correctly?".format(
                ndjsonfile.split("/")[-1]
            )
        )


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
        if not os.path.exists(output_directory + img.split("::")[0] + "/elastic/"):
            os.makedirs(
                os.path.join(output_directory + img.split("::")[0] + "/elastic")
            )
            os.makedirs(
                os.path.join(
                    output_directory + img.split("::")[0] + "/elastic/documents/"
                )
            )
    # creating index based on case name in elasticsearch
    make_index = shlex.split(
        'curl -X PUT "localhost:9200/{}?pretty" -H "Content-Type: application/json" -d\'{{"mappings": {{"properties": {{"@timestamp": {{"type": "date", "format": "YYYY-MM-DD HH:mm:ss.SSSSSS"}}}}}}}}\''.format(
            case.lower()
        )
    )  # yyyy/MM/dd HH:mm:ss.SSS||MM/dd/yy HH:mm:ss||yyyy-MM-dd HH:mm:ss.SSSSSS||yyyy-MM-dd HH:mm:ssZ||yyyy-MM-dd HH:mm:ss||epoch_millis
    subprocess.Popen(
        make_index,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()[0]
    # increasing field limitations in elasticsearch
    increase_index_limit = shlex.split(
        'curl -X PUT  -H "Content-Type: application/x-ndjson" localhost:9200/{}/_settings?pretty -d \'{{"index.mapping.total_fields.limit": 1000000}}\''.format(
            case.lower()
        )
    )
    subprocess.Popen(
        increase_index_limit, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).communicate()[0]
    # creating index pattern to ensure data is mapped correctly in Kibana
    make_index_pattern = shlex.split(
        'curl -X POST "localhost:5601/api/saved_objects/index-pattern/{}" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d \'{{"attributes":{{"fieldAttrs":"{{}}","title":"{}*","timeFieldName":"@timestamp","fields":"[]","typeMeta":"{{}}","runtimeFieldMap":"{{}}"}}}}\''.format(
            case.lower(), case.lower()
        )
    )
    subprocess.Popen(
        make_index_pattern, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).communicate()[0]
    time.sleep(0.2)
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
        directories_with_data = [
            os.path.realpath(os.path.join(output_directory, img.split("::")[0])),
            os.path.realpath(
                os.path.join(output_directory, img.split("::")[0], "/artefacts/cooked/")
            ),
        ]
        if os.path.exists(
            os.path.join(output_directory, img.split("::")[0], "/artefacts/cooked/")
        ):
            for sub_dir in os.listdir(
                os.path.realpath(
                    output_directory + img.split("::")[0] + "/artefacts/cooked/"
                )
            ):
                if "vss" in sub_dir:
                    directories_with_data.append(
                        os.path.realpath(
                            os.path.join(
                                output_directory
                                + img.split("::")[0]
                                + "/artefacts/cooked",
                                sub_dir,
                            )
                        )
                    )
        for each_dir in directories_with_data:
            if os.path.exists(each_dir):
                split_large_csv_files(each_dir)
                prepare_csv_to_ndjson(each_dir)
                convert_csv_to_ndjson(output_directory, case, img, each_dir)
                convert_json_to_ndjson(output_directory, case, img, each_dir)

        print("     elasticsearch ingestion completed for {}".format(vssimage))
        entry, prnt = "{},{},{},completed\n".format(
            datetime.now().isoformat(), vssimage, stage
        ), " -> {} -> ingested artfacts into {} for {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
