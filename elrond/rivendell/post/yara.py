#!/usr/bin/env python3 -tt
import os
import re
import subprocess
import time
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def validate_yara(verbosity, output_directory, img, yara_file, binary_dir):
    yara_valid = str(
        subprocess.run(
            [
                "yara",
                yara_file,
                "-r",
                "/opt/elrond/elrond/tools/scripts",
                "-s",
                "-w",
                "-p",
                "32",
            ],
            capture_output=True,
            encoding="UTF-8",
        )
    )
    print()
    if "error" in yara_valid:
        input(
            "    '{}' error: {}\n    It is advisable to review the syntax of the yara file. Continue? Y/n [Y] ".format(
                yara_file.split("/")[-1], yara_valid.split(": error: ")[-1][0:-4]
            )
        )
        validate_yara(verbosity, output_directory, img, yara_file, binary_dir)
    else:
        invoke_yara(verbosity, output_directory, img, yara_file, binary_dir)


def invoke_yara(verbosity, output_directory, img, yara_file, binary_dir):
    print(
        "      Invoking '{}' against '{}', please stand by...".format(
            yara_file.split("/")[-1], img.split("::")[0]
        )
    )
    yara_results = re.sub(
        r"\\n([^\:\$\ ]+\ )",
        r"±§§±\1",
        str(
            subprocess.Popen(
                [
                    "yara",
                    yara_file,
                    "-r",
                    "/" + binary_dir.strip("/"),
                    "-s",
                    "-w",
                    "-p",
                    "32",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()[0]
        )[2:-3],
    )
    if len(yara_results) > 0:
        if not os.path.exists(output_directory + img.split("::")[0] + "/analysis"):
            os.mkdir(output_directory + img.split("::")[0] + "/analysis")
        with open(
            output_directory + img.split("::")[0] + "/analysis/yara.csv", "w"
        ) as yara_out_file:
            yara_out_file.write(
                "yara_rule,yara_file,file,path,memory_address,signature_name,result\n"
            )
        for each_yara_result in yara_results.split("±§§±"):
            sub_results = []
            for each_sub_result in each_yara_result.split("\\n")[1:]:
                sub_results.append(each_sub_result.split(":$")[1])
            sub_results = list(set(sub_results))
            for sub_result in sub_results:
                (
                    entry,
                    prnt,
                ) = "{},{},yara,rule '{}' (${}) matched '{}' in '{}'\n".format(
                    datetime.now().isoformat(),
                    img.split("::")[0],
                    each_yara_result.split("\\n")[0].split(" ")[0],
                    sub_result.split(": ")[0],
                    sub_result.split(": ")[1],
                    str(each_yara_result.split("\\n")[0].split(" ")[1:])[2:-2].replace(
                        "', '", " "
                    ),
                ), " -> {} -> condition '${}' matched '{}' in '{}' from '{}'".format(
                    datetime.now().isoformat().replace("T", " "),
                    sub_result.split(": ")[0],
                    sub_result.split(": ")[1],
                    str(each_yara_result.split("\\n")[0].split(" ")[1:])[2:-2]
                    .replace("', '", " ")
                    .split("/")[-1],
                    img.split("::")[0],
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
            for each_yara_match in each_yara_result.split("\\n")[1:]:
                write_result = (
                    each_yara_result.split("\\n")[0].split(" ")[0]
                    + ","
                    + yara_file
                    + ","
                    + each_yara_result.split("\\n")[0].split(" ")[1].split("/")[-1]
                    + ","
                    + "/".join(
                        each_yara_result.split("\\n")[0].split(" ")[1].split("/")[:-1]
                    )
                    + ","
                    + each_yara_match.split(":")[0]
                    + ","
                    + each_yara_match.split(":")[1]
                    + ","
                    + each_yara_match.split(":")[2].strip()
                )
                with open(
                    output_directory + img.split("::")[0] + "/artefacts/yara.csv",
                    "a",
                ) as yara_out_file:
                    yara_out_file.write(write_result)
                time.sleep(0.2)

        print("       Done.")
    else:
        print(
            "       No evidence found based on '{}'.".format(yara_file.split("/")[-1])
        )
    time.sleep(2)


def run_yara_signatures(
    verbosity, output_directory, img, loc, collectfiles, yara_files
):
    if collectfiles:
        all_or_collected = input(
            "      Run Yara signatures against all files or just those collected for '{}'?\n      [A]ll  [C]ollected\t[A]ll ".format(
                img.split("::")[0]
            )
        )
    else:
        all_or_collected = "A"
    if all_or_collected != "A":
        binary_dir = output_directory + img.split("::")[0] + "/files"
    else:
        binary_dir = loc
    for yara_file in yara_files:
        validate_yara(verbosity, output_directory, img, yara_file, binary_dir)
