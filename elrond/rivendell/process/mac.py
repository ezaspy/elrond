#!/usr/bin/env python3 -tt
import json
import os
import plistlib
import re
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.process.extractions.plist import (
    format_plist_extractions,
)


def repair_malformed_plist(plist_out):
    plist_out = re.sub(r"'(: \d+, )'", r'"\1"', plist_out)
    plist_out = re.sub(r"'(: )((?:True|False))(, )'", r'"\1"\2"\3"', plist_out)
    plist_out = plist_out.replace('[\\"', '["').replace('\\"]', '"]')
    plist_out = plist_out.replace('": "[{"', '": [{"').replace('"}]", "', '"}], "')
    plist_out = plist_out.replace('": "[\'', '": ["').replace('\']", "', '"], "')
    plist_out = re.sub(r"'(: \d+\}\])\"(, \")", r'"\1\2', plist_out)
    plist_out = (
        plist_out.replace(']"}]', '"]}]')
        .replace('""]}]', '"]}]')
        .replace('": "[\'', '": ["')
        .replace('\']", "', '"], "')
        .replace('": [">', '": ["')
        .replace('": "}, \'', '": {{}}, "')
        .replace("': [", '": [')
        .replace("]'}]\"}}]", "]}]}}]")
        .replace("': ['", '": ["')
        .replace('\']", "', '"], "')
        .replace("'}, '", '"}, "')
        .replace("': {'", '": {"')
        .replace("'}, {'", '"}, {"')
        .replace('": "[\'', '": ["')
        .replace("'}}, {'", "'}}, {'")
        .replace('": "[', '": ["')
        .replace('": [""', '": ["')
        .replace('\']"}], "', '"]}], "')
        .replace("']\"}}", '"]}}')
        .replace('": ["]", "', '": [], "')
        .replace('": ["]"}', '": []}')
    )
    plist_out = re.sub(r"': (-?\d+)\}, '", r'": "\1"}, "', plist_out)
    plist_out = re.sub(r"(\": \[\{\"[^']+)'(: )(b')", r'\1"\2"\3', plist_out)
    plist_out = re.sub(r'\'(: \d+\}\])"(\})', r'"\1\2', plist_out)
    plist_out = plist_out.replace('": [", "', '": ["')
    plist_out = re.sub(r'(\w+)(\])"([\}\]]{1,2})', r'\1"\2\3', plist_out)
    plist_out = plist_out.replace('\']"}, "', '"]}, "')
    plist_out = re.sub(r"(\w+)'(], \")", r'\1"\2', plist_out)
    plist_out = re.sub(r"(\w+)(: )(\[')", r'\1"\2"\3', plist_out)
    plist_out = plist_out.replace('[\\"', '["').replace('\\"]', '"]')
    plist_out = re.sub(r"(\w+)(\])(, \"\w+)", r"\1'\2\"\3", plist_out)
    plist_out = plist_out.re.sub(r'(\w+)\'\}\]"\}, \{"', r'\1"}]}, {"', plist_out)
    plist_out = re.sub(
        r'(": "[^"]+", "[^\']+)\'(: )([^,]+)(, )\'([^"]+": ")',
        r'\1"\2"\3"\4"\5',
        plist_out,
    )
    plist_out = re.sub(r'(\w+)\'(\}\])"(\})', r'\1"\2\3', plist_out)
    plist_out = re.sub(
        r"(\d+\])'(\}\])\"(\})",
        r"\1\2\3",
    )
    plist_out = re.sub(r'(w+)\'(\])"(\})', r'\1"\2\3', plist_out)
    plist_out = plist_out.replace("', {'", '", {"')
    plist_out = re.sub(r"'(: \d+}, {)'", r'"\1"', plist_out)
    return plist_out


def process_plist(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "plists/"
        + artefact.split("/")[-1]
        + ".json"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "plists"
            )
        except:
            pass
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "plists/"
            + artefact.split("/")[-1]
            + ".json",
            "a",
        ) as plistjson:
            try:
                with open(artefact, "rb") as plist:
                    plistdata = plistlib.load(plist)
                if verbosity != "":
                    print(
                        "     Processing '{}' plist for {}...".format(
                            artefact.split("/")[-1].split("+")[-1],
                            vssimage,
                        )
                    )
                entry, prnt = "{},{},{},'{}' plist file\n".format(
                    datetime.now().isoformat(),
                    vssimage.replace("'", ""),
                    stage,
                    artefact.split("/")[-1].split("+")[-1],
                ), " -> {} -> {} plist file '{}' from {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage,
                    artefact.split("/")[-1].split("+")[-1],
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                pliststr = format_plist_extractions(plistdata)
                if (
                    '"Program"' in pliststr
                    and '"ProgramArguments"' in pliststr
                    and '"Label"' in pliststr
                ):
                    insert = ', "Process{}, "CommandLine{}, "Plist{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"Program(\"\: \"[^\"]+\")",
                                    pliststr,
                                )[0]
                            ).lower()
                        ),
                        str(
                            str(
                                str(
                                    re.findall(
                                        r"ProgramArguments(\"\: \"\[[^\]]+\])",
                                        pliststr,
                                    )[0]
                                ).lower()
                            )
                        )
                        .replace('"', "")
                        .replace(",", ""),
                        str(
                            str(
                                re.findall(r"Label(\"\: \"[^\"]+\")", pliststr)[0]
                            ).lower()
                        ),
                    )
                    plistout = str(pliststr[0:-1] + insert + "}")
                elif '"Program"' in pliststr and '"ProgramArguments"' in pliststr:
                    insert = ', "Process{}", "CommandLine{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"Program(\"\: \"[^\"]+\")",
                                    pliststr,
                                )[0]
                            ).lower()
                        ),
                        str(
                            str(
                                str(
                                    re.findall(
                                        r"ProgramArguments(\"\: \"\[[^\]]+\])",
                                        pliststr,
                                    )[0]
                                ).lower()
                            )
                        )
                        .replace('"', "")
                        .replace(",", ""),
                    )
                    plistout = str(pliststr[0:-1] + insert + "}")
                elif '"Program"' in pliststr and '"Label"' in pliststr:
                    insert = ', "Process{}", "Plist{}'.format(
                        str(
                            str(
                                re.findall(
                                    r"Program(\"\: \"[^\"]+\")",
                                    pliststr,
                                )[0]
                            ).lower()
                        ),
                        str(
                            str(
                                re.findall(r"Label(\"\: \"[^\"]+\")", pliststr)[0]
                            ).lower()
                        ),
                    )
                    plistout = str(pliststr[0:-1] + insert + "}")
                elif '"ProgramArguments"' in pliststr and '"Label"' in pliststr:
                    insert = ', "CommandLine{}, "Plist{}'.format(
                        str(
                            str(
                                str(
                                    re.findall(
                                        r"ProgramArguments(\"\: \"\[[^\]]+\])",
                                        pliststr,
                                    )[0]
                                ).lower()
                            )
                        )
                        .replace('"', "")
                        .replace(",", ""),
                        str(
                            str(
                                re.findall(r"Label(\"\: \"[^\"]+\")", pliststr)[0]
                            ).lower()
                        ),
                    )
                    plistout = str(pliststr[0:-1] + insert + "}")
                elif '"Program"' in pliststr:
                    insert = ', "Process{}"'.format(
                        str(
                            str(
                                re.findall(
                                    r"Program(\"\: \"[^\"]+\")",
                                    pliststr,
                                )[0]
                            ).lower()
                        )
                    )
                    plistout = str(pliststr[0:-1] + insert + "}")
                elif '"ProgramArguments"' in pliststr:
                    insert = ', "Command{}'.format(
                        str(
                            str(
                                str(
                                    re.findall(
                                        r"ProgramArguments(\"\: \"\[[^\]]+\])",
                                        pliststr,
                                    )[0]
                                ).lower()
                            )
                        )
                        .replace('"', "")
                        .replace(",", "")
                    )
                    plistout = str(pliststr[0:-1] + insert + "}")
                elif '"Label"' in pliststr:
                    insert = ', "Plist{}'.format(
                        str(
                            str(
                                re.findall(r"Label(\"\: \"[^\"]+\")", pliststr)[0]
                            ).lower()
                        )
                    )
                    plistout = str(pliststr[0:-1] + insert + "}")
                else:
                    plistout = pliststr
                plist_out = (
                    plistout.replace("', '", '", "')
                    .replace("': '", '": "')
                    .replace('": "[{\'', '": "[{"')
                    .replace('\'}]", "', '"}]", "')
                )
                plist_out = repair_malformed_plist(plist_out)
                plistjson.write("[{}]".format(plist_out))

            except:
                pass
