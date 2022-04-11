#!/usr/bin/env python3 -tt
import json
import os
import plistlib
import re
from datetime import datetime

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry
from rivendell.processing.extractions.plist import (
    format_plist_extractions,
)


def process_plist(
    verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vssartefact
        + "plists/"
        + artefact.split("/")[-1]
        + ".json"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vssartefact
                + "plists"
            )
        except:
            pass
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + "plists/"
            + artefact.split("/")[-1]
            + ".json",
            "a",
        ) as plistjson:
            with open(artefact, "rb") as plist:
                plistdata = plistlib.load(plist)
            if verbosity != "":
                print(
                    "     Processing '{}' plist for {}...".format(
                        artefact.split("/")[-1].split("+")[-1],
                        vssimage,
                    )
                )
            else:
                pass
            entry, prnt = "{},{},{},'{}' plist file\n".format(
                datetime.now().isoformat(),
                vssimage.replace("'", ""),
                stage,
                artefact.split("/")[-1].split("+")[-1],
            ), " -> {} -> {} plist file '{}' for {}".format(
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
                insert = ', "nixProcess{}, "nixCommandLine{}, "Plist{}'.format(
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
                        str(re.findall(r"Label(\"\: \"[^\"]+\")", pliststr)[0]).lower()
                    ),
                )
                plistout = str(pliststr[0:-1] + insert + "}")
            elif '"Program"' in pliststr and '"ProgramArguments"' in pliststr:
                insert = ', "nixProcess{}", "nixCommandLine{}'.format(
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
                insert = ', "nixProcess{}", "Plist{}'.format(
                    str(
                        str(
                            re.findall(
                                r"Program(\"\: \"[^\"]+\")",
                                pliststr,
                            )[0]
                        ).lower()
                    ),
                    str(
                        str(re.findall(r"Label(\"\: \"[^\"]+\")", pliststr)[0]).lower()
                    ),
                )
                plistout = str(pliststr[0:-1] + insert + "}")
            elif '"ProgramArguments"' in pliststr and '"Label"' in pliststr:
                insert = ', "nixCommandLine{}, "Plist{}'.format(
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
                        str(re.findall(r"Label(\"\: \"[^\"]+\")", pliststr)[0]).lower()
                    ),
                )
                plistout = str(pliststr[0:-1] + insert + "}")
            elif '"Program"' in pliststr:
                insert = ', "nixProcess{}"'.format(
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
                insert = ', "nixCommand{}'.format(
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
                    str(str(re.findall(r"Label(\"\: \"[^\"]+\")", pliststr)[0]).lower())
                )
                plistout = str(pliststr[0:-1] + insert + "}")
            else:
                plistout = pliststr
            plistout = pliststr
            plistjson.write(plistout)
            print_done(verbosity)
    else:
        pass
