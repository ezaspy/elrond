import json
import re
import sqlite3
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def extract_clipboard(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
    clipjsonlist,
):
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "clipboard/"
        + artefact.split("/")[-1]
        + ".json",
        "a",
    ) as clipboardjson:
        entry, prnt = "{},{},{},'{}' ({}) clipboard evidence\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
            artefact.split("/")[-1].split("_")[-1],
            artefact.split("/")[-1].split("+")[0],
        ), " -> {} -> {} '{}' ({}) for {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            artefact.split("/")[-1].split("_")[-1],
            artefact.split("/")[-1].split("+")[0],
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        cursor_items = (
            sqlite3.connect(artefact)
            .cursor()
            .execute(
                "SELECT SmartLookup.AppId, SmartLookup.PackageIdHash, SmartLookup.AppActivityId, SmartLookup.ActivityType, SmartLookup.ActivityStatus, SmartLookup.ParentActivityId, SmartLookup.LastModifiedTime, SmartLookup.ExpirationTime, SmartLookup.Payload, SmartLookup.Priority, SmartLookup.IsLocalOnly, SmartLookup.PlatformDeviceId, SmartLookup.CreatedInCloud, SmartLookup.StartTime, SmartLookup.EndTime, SmartLookup.LastModifiedOnClient, SmartLookup.UserActionState, SmartLookup.ClipboardPayload, SmartLookup.IsRead, SmartLookup.ETag FROM SmartLookup;"
            )
        )
        clipitems = cursor_items.fetchall()
        if len(clipitems) > 0:
            jsondict["AppId"] = str(clipitems[0][0])
            jsondict["PackageIdHash"] = clipitems[0][1]
            jsondict["AppActivityId"] = clipitems[0][2]
            jsondict["ActivityType"] = clipitems[0][3]  # important
            jsondict["ActivityStatus"] = clipitems[0][4]
            jsondict["ParentActivityId"] = "0x" + str(clipitems[0][5])[2:-1]
            jsondict["LastModifiedTime"] = clipitems[0][6]
            jsondict["ExpirationTime"] = clipitems[0][7]  # important
            jsondict["Payload"] = str(clipitems[0][8])[2:-1]  # important
            jsondict["Priority"] = clipitems[0][9]
            jsondict["IsLocalOnly"] = clipitems[0][10]
            jsondict["PlatformDeviceId"] = clipitems[0][11]
            jsondict["CreatedInCloud"] = clipitems[0][12]
            jsondict["StartTime"] = clipitems[0][13]  # important
            jsondict["EndTime"] = clipitems[0][14]
            jsondict["LastModifiedOnClient"] = clipitems[0][15]
            jsondict["ClipboardPayload"] = clipitems[0][16]  # important
            jsondict["UserActionState"] = clipitems[0][17]
            jsondict["IsRead"] = clipitems[0][18]
            jsondict["ETag"] = clipitems[0][19]
        if len(jsondict) > 0:
            clipjsonlist.append(json.dumps(jsondict))
        if len(clipjsonlist) > 0:
            clipjson = re.sub(
                r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                r"\1'\2",
                re.sub(
                    r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                    r"\1'\2",
                    re.sub(
                        r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                        r"\1'\2",
                        re.sub(
                            r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                            r"\1'\2",
                            re.sub(
                                r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                r"\1'\2",
                                re.sub(
                                    r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                    r"\1'\2",
                                    re.sub(
                                        r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                        r"\1'\2",
                                        re.sub(
                                            r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                            r"\1'\2",
                                            re.sub(
                                                r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                r"\1'\2",
                                                re.sub(
                                                    r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                    r"\1'\2",
                                                    re.sub(
                                                        r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                        r"\1'\2",
                                                        re.sub(
                                                            r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                            r"\1'\2",
                                                            re.sub(
                                                                r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                r"\1'\2",
                                                                re.sub(
                                                                    r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                    r"\1'\2",
                                                                    re.sub(
                                                                        r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                        r"\1'\2",
                                                                        re.sub(
                                                                            r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                            r"\1'\2",
                                                                            re.sub(
                                                                                r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                r"\1'\2",
                                                                                re.sub(
                                                                                    r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                    r"\1'\2",
                                                                                    re.sub(
                                                                                        r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                        r"\1'\2",
                                                                                        re.sub(
                                                                                            r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                            r"\1'\2",
                                                                                            re.sub(
                                                                                                r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                r"\1'\2",
                                                                                                re.sub(
                                                                                                    r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                    r"\1'\2",
                                                                                                    re.sub(
                                                                                                        r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                        r"\1'\2",
                                                                                                        re.sub(
                                                                                                            r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                            r"\1'\2",
                                                                                                            re.sub(
                                                                                                                r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                                r"\1'\2",
                                                                                                                re.sub(
                                                                                                                    r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                                    r"\1'\2",
                                                                                                                    re.sub(
                                                                                                                        r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                                        r"\1'\2",
                                                                                                                        re.sub(
                                                                                                                            r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                                            r"\1'\2",
                                                                                                                            re.sub(
                                                                                                                                r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                                                r"\1'\2",
                                                                                                                                re.sub(
                                                                                                                                    r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                                                    r"\1'\2",
                                                                                                                                    re.sub(
                                                                                                                                        r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                                                        r"\1'\2",
                                                                                                                                        re.sub(
                                                                                                                                            r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                                                            r"\1'\2",
                                                                                                                                            re.sub(
                                                                                                                                                r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                                                                r"\1'\2",
                                                                                                                                                re.sub(
                                                                                                                                                    r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                                                                    r"\1'\2",
                                                                                                                                                    re.sub(
                                                                                                                                                        r"(\"\[\{'[^\"]+)\"([^\]]+\]\")",
                                                                                                                                                        r"\1'\2",
                                                                                                                                                        str(
                                                                                                                                                            clipjsonlist
                                                                                                                                                        )
                                                                                                                                                        .replace(
                                                                                                                                                            ', \\\\"',
                                                                                                                                                            ', "',
                                                                                                                                                        )
                                                                                                                                                        .replace(
                                                                                                                                                            '\\\\"',
                                                                                                                                                            '"',
                                                                                                                                                        )
                                                                                                                                                        .replace(
                                                                                                                                                            "['{",
                                                                                                                                                            "[{",
                                                                                                                                                        )
                                                                                                                                                        .replace(
                                                                                                                                                            "}']",
                                                                                                                                                            "}]",
                                                                                                                                                        )
                                                                                                                                                        .replace(
                                                                                                                                                            "\\\\x",
                                                                                                                                                            "",
                                                                                                                                                        )
                                                                                                                                                        .replace(
                                                                                                                                                            '": "[{"',
                                                                                                                                                            '": "[{\'',
                                                                                                                                                        ),
                                                                                                                                                        #
                                                                                                                                                    ),
                                                                                                                                                ),
                                                                                                                                            ),
                                                                                                                                        ),
                                                                                                                                    ),
                                                                                                                                ),
                                                                                                                            ),
                                                                                                                        ),
                                                                                                                    ),
                                                                                                                ),
                                                                                                            ),
                                                                                                        ),
                                                                                                    ),
                                                                                                ),
                                                                                            ),
                                                                                        ),
                                                                                    ),
                                                                                ),
                                                                            ),
                                                                        ),
                                                                    ),
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
            clipjson = re.sub(
                r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                r"\1'\2",
                re.sub(
                    r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                    r"\1'\2",
                    re.sub(
                        r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                        r"\1'\2",
                        re.sub(
                            r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                            r"\1'\2",
                            re.sub(
                                r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                r"\1'\2",
                                re.sub(
                                    r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                    r"\1'\2",
                                    re.sub(
                                        r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                        r"\1'\2",
                                        re.sub(
                                            r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                            r"\1'\2",
                                            re.sub(
                                                r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                r"\1'\2",
                                                re.sub(
                                                    r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                    r"\1'\2",
                                                    re.sub(
                                                        r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                        r"\1'\2",
                                                        re.sub(
                                                            r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                            r"\1'\2",
                                                            re.sub(
                                                                r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                r"\1'\2",
                                                                re.sub(
                                                                    r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                    r"\1'\2",
                                                                    re.sub(
                                                                        r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                        r"\1'\2",
                                                                        re.sub(
                                                                            r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                            r"\1'\2",
                                                                            re.sub(
                                                                                r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                r"\1'\2",
                                                                                re.sub(
                                                                                    r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                    r"\1'\2",
                                                                                    re.sub(
                                                                                        r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                        r"\1'\2",
                                                                                        re.sub(
                                                                                            r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                            r"\1'\2",
                                                                                            re.sub(
                                                                                                r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                r"\1'\2",
                                                                                                re.sub(
                                                                                                    r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                    r"\1'\2",
                                                                                                    re.sub(
                                                                                                        r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                        r"\1'\2",
                                                                                                        re.sub(
                                                                                                            r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                            r"\1'\2",
                                                                                                            re.sub(
                                                                                                                r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                                r"\1'\2",
                                                                                                                re.sub(
                                                                                                                    r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                                    r"\1'\2",
                                                                                                                    re.sub(
                                                                                                                        r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                                        r"\1'\2",
                                                                                                                        re.sub(
                                                                                                                            r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                                            r"\1'\2",
                                                                                                                            re.sub(
                                                                                                                                r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                                                r"\1'\2",
                                                                                                                                re.sub(
                                                                                                                                    r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                                                    r"\1'\2",
                                                                                                                                    re.sub(
                                                                                                                                        r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                                                        r"\1'\2",
                                                                                                                                        re.sub(
                                                                                                                                            r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                                                            r"\1'\2",
                                                                                                                                            re.sub(
                                                                                                                                                r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                                                                r"\1'\2",
                                                                                                                                                re.sub(
                                                                                                                                                    r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                                                                    r"\1'\2",
                                                                                                                                                    re.sub(
                                                                                                                                                        r"(\"\{\"[^\"]+)\"([^ \}]+\")",
                                                                                                                                                        r"\1'\2",
                                                                                                                                                        clipjson,
                                                                                                                                                    ),
                                                                                                                                                ),
                                                                                                                                            ),
                                                                                                                                        ),
                                                                                                                                    ),
                                                                                                                                ),
                                                                                                                            ),
                                                                                                                        ),
                                                                                                                    ),
                                                                                                                ),
                                                                                                            ),
                                                                                                        ),
                                                                                                    ),
                                                                                                ),
                                                                                            ),
                                                                                        ),
                                                                                    ),
                                                                                ),
                                                                            ),
                                                                        ),
                                                                    ),
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
            clipjson = re.sub(
                r"(\{'[^\"]+)\"([^ ]+\")",
                r"\1'\2",
                re.sub(
                    r"(\{'[^\"]+)\"([^ ]+\")",
                    r"\1'\2",
                    re.sub(
                        r"(\{'[^\"]+)\"([^ ]+\")",
                        r"\1'\2",
                        re.sub(
                            r"(\{'[^\"]+)\"([^ ]+\")",
                            r"\1'\2",
                            re.sub(
                                r"(\{'[^\"]+)\"([^ ]+\")",
                                r"\1'\2",
                                re.sub(
                                    r"(\{'[^\"]+)\"([^ ]+\")",
                                    r"\1'\2",
                                    re.sub(
                                        r"(\{'[^\"]+)\"([^ ]+\")",
                                        r"\1'\2",
                                        re.sub(
                                            r"(\{'[^\"]+)\"([^ ]+\")",
                                            r"\1'\2",
                                            re.sub(
                                                r"(\{'[^\"]+)\"([^ ]+\")",
                                                r"\1'\2",
                                                re.sub(
                                                    r"(\{'[^\"]+)\"([^ ]+\")",
                                                    r"\1'\2",
                                                    re.sub(
                                                        r"(\{'[^\"]+)\"([^ ]+\")",
                                                        r"\1'\2",
                                                        re.sub(
                                                            r"(\{'[^\"]+)\"([^ ]+\")",
                                                            r"\1'\2",
                                                            re.sub(
                                                                r"(\{'[^\"]+)\"([^ ]+\")",
                                                                r"\1'\2",
                                                                re.sub(
                                                                    r"(\{'[^\"]+)\"([^ ]+\")",
                                                                    r"\1'\2",
                                                                    re.sub(
                                                                        r"(\{'[^\"]+)\"([^ ]+\")",
                                                                        r"\1'\2",
                                                                        re.sub(
                                                                            r"(\{'[^\"]+)\"([^ ]+\")",
                                                                            r"\1'\2",
                                                                            re.sub(
                                                                                r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                r"\1'\2",
                                                                                re.sub(
                                                                                    r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                    r"\1'\2",
                                                                                    re.sub(
                                                                                        r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                        r"\1'\2",
                                                                                        re.sub(
                                                                                            r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                            r"\1'\2",
                                                                                            re.sub(
                                                                                                r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                r"\1'\2",
                                                                                                re.sub(
                                                                                                    r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                    r"\1'\2",
                                                                                                    re.sub(
                                                                                                        r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                        r"\1'\2",
                                                                                                        re.sub(
                                                                                                            r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                            r"\1'\2",
                                                                                                            re.sub(
                                                                                                                r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                                r"\1'\2",
                                                                                                                re.sub(
                                                                                                                    r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                                    r"\1'\2",
                                                                                                                    re.sub(
                                                                                                                        r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                                        r"\1'\2",
                                                                                                                        re.sub(
                                                                                                                            r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                                            r"\1'\2",
                                                                                                                            re.sub(
                                                                                                                                r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                                                r"\1'\2",
                                                                                                                                re.sub(
                                                                                                                                    r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                                                    r"\1'\2",
                                                                                                                                    re.sub(
                                                                                                                                        r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                                                        r"\1'\2",
                                                                                                                                        re.sub(
                                                                                                                                            r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                                                            r"\1'\2",
                                                                                                                                            re.sub(
                                                                                                                                                r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                                                                r"\1'\2",
                                                                                                                                                re.sub(
                                                                                                                                                    r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                                                                    r"\1'\2",
                                                                                                                                                    re.sub(
                                                                                                                                                        r"(\{'[^\"]+)\"([^ ]+\")",
                                                                                                                                                        r"\1'\2",
                                                                                                                                                        clipjson,
                                                                                                                                                    ),
                                                                                                                                                ),
                                                                                                                                            ),
                                                                                                                                        ),
                                                                                                                                    ),
                                                                                                                                ),
                                                                                                                            ),
                                                                                                                        ),
                                                                                                                    ),
                                                                                                                ),
                                                                                                            ),
                                                                                                        ),
                                                                                                    ),
                                                                                                ),
                                                                                            ),
                                                                                        ),
                                                                                    ),
                                                                                ),
                                                                            ),
                                                                        ),
                                                                    ),
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
            clipjson = re.sub(
                r"(\"\{'[^\"]+)\"([^\}]+\")",
                r"\1'\2",
                re.sub(
                    r"(\"\{'[^\"]+)\"([^\}]+\")",
                    r"\1'\2",
                    re.sub(
                        r"(\"\{'[^\"]+)\"([^\}]+\")",
                        r"\1'\2",
                        re.sub(
                            r"(\"\{'[^\"]+)\"([^\}]+\")",
                            r"\1'\2",
                            re.sub(
                                r"(\"\{'[^\"]+)\"([^\}]+\")",
                                r"\1'\2",
                                re.sub(
                                    r"(\"\{'[^\"]+)\"([^\}]+\")",
                                    r"\1'\2",
                                    re.sub(
                                        r"(\"\{'[^\"]+)\"([^\}]+\")",
                                        r"\1'\2",
                                        re.sub(
                                            r"(\"\{'[^\"]+)\"([^\}]+\")",
                                            r"\1'\2",
                                            re.sub(
                                                r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                r"\1'\2",
                                                re.sub(
                                                    r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                    r"\1'\2",
                                                    re.sub(
                                                        r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                        r"\1'\2",
                                                        re.sub(
                                                            r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                            r"\1'\2",
                                                            re.sub(
                                                                r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                r"\1'\2",
                                                                re.sub(
                                                                    r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                    r"\1'\2",
                                                                    re.sub(
                                                                        r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                        r"\1'\2",
                                                                        re.sub(
                                                                            r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                            r"\1'\2",
                                                                            re.sub(
                                                                                r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                r"\1'\2",
                                                                                re.sub(
                                                                                    r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                    r"\1'\2",
                                                                                    re.sub(
                                                                                        r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                        r"\1'\2",
                                                                                        re.sub(
                                                                                            r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                            r"\1'\2",
                                                                                            re.sub(
                                                                                                r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                r"\1'\2",
                                                                                                re.sub(
                                                                                                    r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                    r"\1'\2",
                                                                                                    re.sub(
                                                                                                        r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                        r"\1'\2",
                                                                                                        re.sub(
                                                                                                            r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                            r"\1'\2",
                                                                                                            re.sub(
                                                                                                                r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                                r"\1'\2",
                                                                                                                re.sub(
                                                                                                                    r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                                    r"\1'\2",
                                                                                                                    re.sub(
                                                                                                                        r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                                        r"\1'\2",
                                                                                                                        re.sub(
                                                                                                                            r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                                            r"\1'\2",
                                                                                                                            re.sub(
                                                                                                                                r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                                                r"\1'\2",
                                                                                                                                re.sub(
                                                                                                                                    r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                                                    r"\1'\2",
                                                                                                                                    re.sub(
                                                                                                                                        r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                                                        r"\1'\2",
                                                                                                                                        re.sub(
                                                                                                                                            r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                                                            r"\1'\2",
                                                                                                                                            re.sub(
                                                                                                                                                r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                                                                r"\1'\2",
                                                                                                                                                re.sub(
                                                                                                                                                    r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                                                                    r"\1'\2",
                                                                                                                                                    re.sub(
                                                                                                                                                        r"(\"\{'[^\"]+)\"([^\}]+\")",
                                                                                                                                                        r"\1'\2",
                                                                                                                                                        clipjson,
                                                                                                                                                    ),
                                                                                                                                                ),
                                                                                                                                            ),
                                                                                                                                        ),
                                                                                                                                    ),
                                                                                                                                ),
                                                                                                                            ),
                                                                                                                        ),
                                                                                                                    ),
                                                                                                                ),
                                                                                                            ),
                                                                                                        ),
                                                                                                    ),
                                                                                                ),
                                                                                            ),
                                                                                        ),
                                                                                    ),
                                                                                ),
                                                                            ),
                                                                        ),
                                                                    ),
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
            clipjson = (
                str(clipjson).replace('": "{"', '": "{\'').replace('"}", "', '\'}", "')
            )
            clipjson = re.sub(
                r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                r"\1'\2",
                re.sub(
                    r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                    r"\1'\2",
                    re.sub(
                        r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                        r"\1'\2",
                        re.sub(
                            r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                            r"\1'\2",
                            re.sub(
                                r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                r"\1'\2",
                                re.sub(
                                    r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                    r"\1'\2",
                                    re.sub(
                                        r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                        r"\1'\2",
                                        re.sub(
                                            r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                            r"\1'\2",
                                            re.sub(
                                                r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                r"\1'\2",
                                                re.sub(
                                                    r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                    r"\1'\2",
                                                    re.sub(
                                                        r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                        r"\1'\2",
                                                        re.sub(
                                                            r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                            r"\1'\2",
                                                            re.sub(
                                                                r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                r"\1'\2",
                                                                re.sub(
                                                                    r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                    r"\1'\2",
                                                                    re.sub(
                                                                        r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                        r"\1'\2",
                                                                        re.sub(
                                                                            r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                            r"\1'\2",
                                                                            re.sub(
                                                                                r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                r"\1'\2",
                                                                                re.sub(
                                                                                    r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                    r"\1'\2",
                                                                                    re.sub(
                                                                                        r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                        r"\1'\2",
                                                                                        re.sub(
                                                                                            r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                            r"\1'\2",
                                                                                            re.sub(
                                                                                                r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                r"\1'\2",
                                                                                                re.sub(
                                                                                                    r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                    r"\1'\2",
                                                                                                    re.sub(
                                                                                                        r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                        r"\1'\2",
                                                                                                        re.sub(
                                                                                                            r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                            r"\1'\2",
                                                                                                            re.sub(
                                                                                                                r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                                r"\1'\2",
                                                                                                                re.sub(
                                                                                                                    r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                                    r"\1'\2",
                                                                                                                    re.sub(
                                                                                                                        r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                                        r"\1'\2",
                                                                                                                        re.sub(
                                                                                                                            r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                                            r"\1'\2",
                                                                                                                            re.sub(
                                                                                                                                r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                                                r"\1'\2",
                                                                                                                                re.sub(
                                                                                                                                    r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                                                    r"\1'\2",
                                                                                                                                    re.sub(
                                                                                                                                        r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                                                        r"\1'\2",
                                                                                                                                        re.sub(
                                                                                                                                            r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                                                            r"\1'\2",
                                                                                                                                            re.sub(
                                                                                                                                                r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                                                                r"\1'\2",
                                                                                                                                                re.sub(
                                                                                                                                                    r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                                                                    r"\1'\2",
                                                                                                                                                    re.sub(
                                                                                                                                                        r"(\"\{'[^\"]+)\"([^\}]+\}\")",
                                                                                                                                                        r"\1'\2",
                                                                                                                                                        clipjson,
                                                                                                                                                    ),
                                                                                                                                                ),
                                                                                                                                            ),
                                                                                                                                        ),
                                                                                                                                    ),
                                                                                                                                ),
                                                                                                                            ),
                                                                                                                        ),
                                                                                                                    ),
                                                                                                                ),
                                                                                                            ),
                                                                                                        ),
                                                                                                    ),
                                                                                                ),
                                                                                            ),
                                                                                        ),
                                                                                    ),
                                                                                ),
                                                                            ),
                                                                        ),
                                                                    ),
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
            clipjson = str(clipjson).replace('": "0x\\\\', '": "0x')
            clipjson = re.sub(
                r'(": "0x[^"]+)\\\\([^"]+", ")',
                r"\1\2",
                re.sub(
                    r'(": "0x[^"]+)\\\\([^"]+", ")',
                    r"\1\2",
                    re.sub(
                        r'(": "0x[^"]+)\\\\([^"]+", ")',
                        r"\1\2",
                        re.sub(
                            r'(": "0x[^"]+)\\\\([^"]+", ")',
                            r"\1\2",
                            re.sub(
                                r'(": "0x[^"]+)\\\\([^"]+", ")',
                                r"\1\2",
                                re.sub(
                                    r'(": "0x[^"]+)\\\\([^"]+", ")',
                                    r"\1\2",
                                    re.sub(
                                        r'(": "0x[^"]+)\\\\([^"]+", ")',
                                        r"\1\2",
                                        re.sub(
                                            r'(": "0x[^"]+)\\\\([^"]+", ")',
                                            r"\1\2",
                                            re.sub(
                                                r'(": "0x[^"]+)\\\\([^"]+", ")',
                                                r"\1\2",
                                                re.sub(
                                                    r'(": "0x[^"]+)\\\\([^"]+", ")',
                                                    r"\1\2",
                                                    re.sub(
                                                        r'(": "0x[^"]+)\\\\([^"]+", ")',
                                                        r"\1\2",
                                                        re.sub(
                                                            r'(": "0x[^"]+)\\\\([^"]+", ")',
                                                            r"\1\2",
                                                            re.sub(
                                                                r'(": "0x[^"]+)\\\\([^"]+", ")',
                                                                r"\1\2",
                                                                re.sub(
                                                                    r'(": "0x[^"]+)\\\\([^"]+", ")',
                                                                    r"\1\2",
                                                                    re.sub(
                                                                        r'(": "0x[^"]+)\\\\([^"]+", ")',
                                                                        r"\1\2",
                                                                        re.sub(
                                                                            r'(": "0x[^"]+)\\\\([^"]+", ")',
                                                                            r"\1\2",
                                                                            re.sub(
                                                                                r'(": "0x[^"]+)\\\\([^"]+", ")',
                                                                                r"\1\2",
                                                                                re.sub(
                                                                                    r'(": "0x[^"]+)\\\\([^"]+", ")',
                                                                                    r"\1\2",
                                                                                    re.sub(
                                                                                        r'(": "0x[^"]+)\\\\([^"]+", ")',
                                                                                        r"\1\2",
                                                                                        re.sub(
                                                                                            r'(": "0x[^"]+)\\\\([^"]+", ")',
                                                                                            r"\1\2",
                                                                                            clipjson,
                                                                                        ),
                                                                                    ),
                                                                                ),
                                                                            ),
                                                                        ),
                                                                    ),
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
            clipboardjson.write(
                clipjson.replace("\\\\\\\\\\\\\\\\\\\\", "\\\\")
                .replace("\\\\\\\\\\\\\\\\\\", "\\\\")
                .replace("\\\\\\\\\\\\\\\\", "\\\\")
                .replace("\\\\\\\\\\\\\\", "\\\\")
                .replace("\\\\\\\\\\\\", "\\\\")
                .replace("\\\\\\\\\\", "\\\\")
                .replace("\\\\\\\\", "\\\\")
                .replace("\\\\\\", "\\\\")
            )
        clipjsonlist.clear()
        jsonlist.clear()
