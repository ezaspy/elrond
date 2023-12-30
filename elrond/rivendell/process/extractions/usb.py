#!/usr/bin/env python3 -tt
import json
import re


def extract_usb(
    output_directory,
    img,
    vss_path_insert,
    jsondict,
    jsonlist,
    setupdata,
):
    for session in setupdata.split("[Boot Session: ")[0][21:-14].split("     "):
        for eachkv in re.findall(r"^(?P<k>[^\=]+)\ \=\ (?P<v>[\S]+)", session):
            kv = list(eachkv)
            if len(kv) > 0:
                jsondict[kv[0]] = kv[1]
    if len(jsondict) > 0:
        jsonlist.append(json.dumps(jsondict))
        jsondict.clear()
    for session in setupdata.split("[Boot Session: ")[1:]:
        for section in session.split(">>>  ["):
            jsondict["BootDateStart"], jsondict["BootTimeStart"] = (
                session[0:10],
                session[11:23],
            )
            if len(section) > 26:
                (
                    jsondict["Artefact"],
                    jsondict["Status"],
                    jsondict["StartDate"],
                    jsondict["StartTime"],
                ) = (
                    section.split(">>>  ")[0][0:-2],
                    section.split("<<<  ")[-1].split(": ")[1][0:-4],
                    section.split(">>>  ")[1].split("<<<  ")[0][14:24],
                    section.split(">>>  ")[1].split("<<<  ")[0][25:37],
                )
                try:
                    (
                        jsondict["SectionEndDate"],
                        jsondict["SectionEndTime"],
                    ) = (
                        section.split(">>>  ")[1].split("<<<  ")[1][12:][0:10],
                        section.split(">>>  ")[1].split("<<<  ")[1][12:][11:23],
                    )
                except:
                    pass
                for eachinfo in (
                    section.split(">>>  ")[1].split("<<<  ")[0][38:].split("\n")
                ):
                    for eachkv in re.findall(
                        r"^\ +(?P<ActionInstruction>[A-Za-z]+)\:\ +(?P<ActionObject>[\S\ ]+)",
                        eachinfo.replace("!", "")
                        .replace("__", "_")
                        .replace("__", "_")
                        .strip("."),
                    ):
                        kv = list(eachkv)
                        if len(kv) > 0:
                            (
                                jsondict["ActionObject"],
                                jsondict["ActionInstruction"],
                            ) = (kv[1], kv[0])
                    for eachkv in re.findall(
                        r"\ (?P<ActionTime>\d{2}\:\d{2}\:\d{2}\.\d{3})",
                        eachinfo.replace("__", "_").replace("__", "_").strip("."),
                    ):
                        jsondict["ActionTime"] = eachkv
                    if len(jsondict) > 8:
                        jsonlist.append(json.dumps(jsondict))
                        jsondict.clear()
    if len(jsonlist) > 0:
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "usb.log.json",
            "a",
        ) as usbjson:
            usbout = (
                str(jsonlist)
                .replace("'{", "{")
                .replace("}'", "}")
                .replace("'[", "[")
                .replace("]'", "]")
                .replace("\\\\n", "")
                .replace("\\\\", "\\")
            )
            usbjson.write("[{")
            for eachinfo in usbout.split("}, {"):
                usbsd, usbst = re.findall(
                    r"\"StartDate\"\:\ \"([^\"]+)", eachinfo
                ), re.findall(r"\"StartTime\"\:\ \"([^\"]+)", eachinfo)
                if len(usbsd) == 1 and len(usbst) == 1:
                    usb_json = str(
                        re.sub(
                            r"([^,:] )\"",
                            r"\1",
                            str(
                                re.sub(
                                    r"\"( )",
                                    r"\1",
                                    "}, {"
                                    + str(
                                        re.sub(
                                            r"(, \"StartTime\": \"[^\"]+\")",
                                            r"\1, \"LastWriteTime\": "
                                            + '"'
                                            + usbsd[0]
                                            + " "
                                            + usbst[0]
                                            + '"',
                                            eachinfo,
                                        )
                                    ).replace('\\"', '"'),
                                )
                            ),
                        )
                    ).replace(' , "', '" , "')
                    usb_json = re.sub(
                        r"([^\\]\\)([^\\])",
                        r"\1\\\2",
                        usb_json.replace('": ""', '": "')
                        .replace('"", "', '", "')
                        .replace('="', "="),
                    )
                    usbjson.write(usb_json)
