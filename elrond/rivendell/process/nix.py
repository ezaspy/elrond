#!/usr/bin/env python3 -tt
import json
import os
import re
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.process.extractions.mail import (
    extract_email_artefacts,
)


def repair_malformed_service(service_json):
    def repair_malformed_service_iteration(service_json):
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        service_json = re.sub(r"(\\'[^']+)\"([^']+')", r"\1'\2", service_json)
        return service_json

    service_json = repair_malformed_service_iteration(service_json)
    service_json = (
        service_json.replace("\\'", '"')
        .replace("', '", "")
        .replace("n\\\\\", '", '", "')
        .replace("'", "'")
        .replace("n', \\\"    ", "")
    )
    service_json = re.sub(r'(", "[^"]+"),( "[^"]+"): "[^"]+"', r"\1:\2", service_json)
    service_json = re.sub(r'([^:,] )"([^\\]+\\")', r"\1'\2", service_json)
    service_json = (
        service_json.replace('n", \\"    ', "")
        .replace('\'n\\\\", "', '\'", "')
        .replace('\\\\\\\\n\\\\", "', '", "')
    )
    service_json = re.sub(r'", "([^"]+)\\\\\\\\n", \\"', r".  \1.  ", service_json)
    service_json = re.sub(r'(", ")\\\\\\\\n", \\"[^"]+", "', r"\1", service_json)
    service_json = service_json.replace('n", \\"', ".  ")
    service_json = re.sub(r'n\\\\", "[^"]+("\})', r"\1", service_json)
    service_json = (
        service_json.replace('n\\\\", \\\\"', ".  ")
        .replace('n\\\\", "', '", "')
        .replace("[Unit]\\\\\\\\.  ", "")
    )
    service_json = re.sub(r"(\{\"[^\"]+)': '([^\"]+\", \")", r'\1": "\2', service_json)
    service_json = service_json.replace("\\\\\"': '", "\\\"': '").replace(
        'n", \\\\"        ', ""
    )
    service_json = service_json.replace("n\\', \\\\\"", ".  ")
    service_json = re.sub(r"(\w+)\\'(\w+)", r"\1`\2", service_json)
    service_json = re.sub(r"n\\\\\", \\'[^\"]+(\"\}\])$", r"\1", service_json)
    service_json = re.sub(r"n\\\", \\'(\w+)", r".  \1", service_json)
    service_json = re.sub(r"(\w+)\\\\\\\\n\\', \\\\\"(\w+)", r"\1\.  \2", service_json)
    service_json = re.sub(r"(\w+)\\\\\\\\n\\\\\", \'(\w+)", r"\1\.  \2", service_json)
    service_json = re.sub(r"(\w+)n\\', \\\\\"(\w+)", r"\1.  \2", service_json)
    service_json = re.sub(r"\"\[Unit\]\\\\\\\\n\\', \\\\\"", r'"', service_json)
    service_json = re.sub(r'"\\\\", \\\'"', r'", "', service_json)
    service_json = re.sub(
        r'(\w+)", "\\\\\\\\n\\\', \\\\"(\w+)', r'\1", "\2', service_json
    )
    service_json = re.sub(r'(": None)([,\}])', r'\1"\2', service_json)
    return service_json


def process_bash_history(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    if verbosity != "":
        print(
            "     Processing 'bash_history' ({}) for {}...".format(
                artefact.split("/")[-1].split("+")[0], vssimage
            )
        )
    entry, prnt = "{},{},{},bash_history ({}) file\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        artefact.split("/")[-1].split("+")[0],
    ), " -> {} -> {} bash_history ({}) file from {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        artefact.split("/")[-1].split("+")[0],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + artefact.split("/")[-1].split("+")[0]
        + "+bash_history.csv"
    ):
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + artefact.split("/")[-1].split("+")[0]
            + "+bash_history.csv",
            "a",
        ) as bashcsv:
            bashcsv.write("Command\n")
    with open(artefact) as bashcontent:
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + artefact.split("/")[-1].split("+")[0]
            + "+bash_history.csv",
            "a",
        ) as bashcsv:
            for bashline in bashcontent:
                bashcsv.write(bashline)


def process_email(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
):
    mailjsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "mail"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "mail"
            )
        except:
            pass
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "mail/"
        + artefact.split("/")[-2]
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "mail/"
                + artefact.split("/")[-2]
            )
        except:
            pass
    if verbosity != "":
        print(
            "     Processing Mail artefact '{}' ({}) for {}...".format(
                artefact.split("/")[-1],
                artefact.split("/")[-2],
                vssimage,
            )
        )
    entry, prnt = "{},{},{},'{}' ({}) Mail artefact\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        artefact.split("/")[-1],
        artefact.split("/")[-2],
    ), " -> {} -> {} Mail artefact '{}' ({}) from {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        artefact.split("/")[-1],
        artefact.split("/")[-2],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "mail/"
        + artefact.split("/")[-2]
        + "/"
        + artefact.split("/")[-1]
        + ".json",
        "a",
    ) as emlxjson:
        try:
            with open(
                output_directory
                + img.split("::")[0]
                + "/artefacts/raw"
                + vss_path_insert
                + "mail/emails/"
                + artefact.split("/")[-2]
                + "/"
                + artefact.split("/")[-1],
                "r",
                encoding="utf-8",
            ) as mailemlx:
                emlxchain = str(mailemlx.readlines())
        except:
            with open(
                output_directory
                + img.split("::")[0]
                + "/artefacts/raw"
                + vss_path_insert
                + "mail/emails/"
                + artefact.split("/")[-2]
                + "/"
                + artefact.split("/")[-1],
                "r",
                encoding="ISO-8859-1",
            ) as mailemlx:
                emlxchain = str(mailemlx.readlines())
        ThreadNo, allLinks = 1, []
        try:
            boundaryPattern = re.compile(r"boundary\=\"([^\"]+)", re.IGNORECASE)
            boundary = re.findall(boundaryPattern, emlxchain)[0]
        except:
            boundary = ""
        try:
            ReceivedTime = re.findall(
                r"(?P<ReceivedTime>[A-Z][a-z]{2}\,\ \d+\ [A-Z][a-z]{2}\ \d+(?:\\n\'\,\ \')?\ \d+\:\d+\:\d+[^\\]+)",
                emlxchain,
            )[0]
            jsondict["ReceivedTime"] = ReceivedTime
        except:
            pass
        try:
            ReceivedByPattern = re.compile(
                r"'Received\:\ by\ (?P<ReceivedBy>[A-Fa-f\d\.\:]+)[^\;]+\;(?:\ |\\n(?:[\'\,\ ]+)?)",
                re.IGNORECASE,
            )
            ReceivedBy = re.findall(ReceivedByPattern, emlxchain)[0]
            jsondict["ReceivedBy"] = ReceivedBy
        except:
            pass
        try:
            ReturnPathPattern = re.compile(
                r"'Return\-Path\:\ (?P<ReturnPath>[^\\]+)\\n",
                re.IGNORECASE,
            )
            ReturnPath = re.findall(ReturnPathPattern, emlxchain)[0]
            jsondict["ReturnPath"] = ReturnPath
        except:
            pass
        try:
            ReceivedFromPattern = re.compile(
                r"'Received\:\ from\ (?P<ReceivedFrom>[^\\]+)",
                re.IGNORECASE,
            )
            ReceivedFrom = re.findall(ReceivedFromPattern, emlxchain)[0]
            jsondict["ReceivedFrom"] = ReceivedFrom
        except:
            pass
        try:
            ReceivedFromIP = re.findall(
                r"((?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[A-Fa-f\d]+\:[A-Fa-f\d]+\:[A-Fa-f\d]+\:[A-Fa-f\d]+\:[A-Fa-f\d]+\:[A-Fa-f\d]+\:[A-Fa-f\d]+\:[A-Fa-f\d]+))",
                ReceivedFrom,
            )[0]
            jsondict["ReceivedFromIP"] = ReceivedFromIP
        except:
            pass
        try:
            FromPattern = re.compile(r"From\:\ ([^\\]+)", re.IGNORECASE)
            From = re.findall(FromPattern, emlxchain)[0]
            jsondict["From"] = From
        except:
            pass
        try:
            ToPattern = re.compile(r"To\:\ ([^\\]+)", re.IGNORECASE)
            To = re.findall(ToPattern, emlxchain)[0]
            jsondict["To"] = To
        except:
            pass
        try:
            SubjectPattern = re.compile(r"Subject\:\ ([^\\]+)", re.IGNORECASE)
            Subject = re.findall(SubjectPattern, emlxchain)[0]
            jsondict["Subject"] = Subject
        except:
            pass
        try:
            LastWriteTimePattern = re.compile(r"Date\:\ ([^\\]+)", re.IGNORECASE)
            LastWriteTime = re.findall(LastWriteTimePattern, emlxchain)[0]
            jsondict["LastWriteTime"] = LastWriteTime
        except:
            pass
        try:
            MessageIDPattern = re.compile(r"Message\-ID\:\ ([^\\]+)", re.IGNORECASE)
            MessageID = re.findall(MessageIDPattern, emlxchain)[0]
            jsondict["MessageID"] = MessageID
        except:
            pass
        try:
            MIMEVersionPattern = re.compile(r"MIME\-Version\:\ ([^\\]+)", re.IGNORECASE)
            MIMEVersion = re.findall(MIMEVersionPattern, emlxchain)[0]
            jsondict["MIMEVersion"] = MIMEVersion
        except:
            pass
        jsondict["Mailbox"], jsondict["ThreadNo"] = (
            artefact.split("/")[-2],
            ThreadNo,
        )
        if boundary != "":
            for eachmesg in emlxchain.split(boundary)[2:-1]:
                jsondict["Boundary"] = boundary
                extract_email_artefacts(
                    eachmesg[6::],
                    jsondict,
                    mailjsonlist,
                    ThreadNo,
                    allLinks,
                )
        else:
            extract_email_artefacts(
                emlxchain,
                jsondict,
                mailjsonlist,
                ThreadNo,
                allLinks,
            )
        if len(mailjsonlist) > 0:
            emlxjson.write(
                str(mailjsonlist)
                .replace('\\\\"', "")
                .replace("\\\\\\\\n", "\\n")
                .replace("\"}', '{\"", '"}, {"')
                .replace("['{", "[{")
                .replace("}']", "}]")
                .replace("\\' >", "")
            )
        mailjsonlist.clear()


def process_group(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    if verbosity != "":
        print("     Processing 'group' file for {}...".format(vssimage))
    entry, prnt = "{},{},{},group file\n".format(
        datetime.now().isoformat(), vssimage.replace("'", ""), stage
    ), " -> {} -> {} group file from {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "group.csv"
    ):
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "group.csv",
            "a",
        ) as groupcsv:
            groupcsv.write("group_name,password,groupID,group_list\n")
    with open(artefact) as groupcontent:
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "group.csv",
            "a",
        ) as groupcsv:
            for groupline in groupcontent:
                if ":*:" or ":x:" in groupline:
                    groupcsv.write(groupline.replace(":", ","))


def process_logs(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
):
    logjsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "logs/"
        + artefact.split("/")[-1]
        + ".json"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "logs"
            )
        except:
            pass
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "logs/"
            + artefact.split("/")[-1]
            + ".json",
            "a",
        ) as logjson:
            if (
                "auth" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "boot" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "corecaptured"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "dpkg" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "fsck_apfs"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "fsck_hfs" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "hfs_convert"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "install" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "kern" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "LKDC-setup"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "syslog" in artefact.split("/")[-1].split("+")[-1]
                or "system" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "vmware-vmsvc"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "vmware-vmsvc-root"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                or "vmware-vmtoolsd-root"
                in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
            ):
                if verbosity != "":
                    print(
                        "     Processing '{}' for {}...".format(
                            artefact.split("/")[-1].split("+")[-1],
                            vssimage,
                        )
                    )
                entry, prnt = "{},{},{},'{}' file\n".format(
                    datetime.now().isoformat(),
                    vssimage.replace("'", ""),
                    stage,
                    artefact.split("/")[-1].split("+")[-1],
                ), " -> {} -> {} file '{}' from {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage,
                    artefact.split("/")[-1].split("+")[-1],
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                if (
                    "auth" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                    or "syslog" in artefact.split("/")[-1].split("+")[-1]
                ):
                    with open(artefact) as logfile:
                        for eachinfo in logfile:
                            for eachkv in re.findall(
                                r"(?P<LastWriteTime>[A-Z][a-z]{2}\s+\d+\s+\d+\:\d+\:\d+)\s+(?P<Device>[^\ ]+)\s+(?:(?P<Profile>[^\ ]+)\:\s+)?(?P<Account>[^\ ]+)\s?\:\s+(?P<Message>.*)",
                                eachinfo,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 4:
                                    (
                                        jsondict["LastWriteTime"],
                                        jsondict["Device"],
                                        jsondict["Profile"],
                                        jsondict["Account"],
                                        jsondict["Message"],
                                    ) = (
                                        kv[0],
                                        kv[1],
                                        kv[2],
                                        kv[3],
                                        kv[4],
                                    )
                                elif len(kv) > 3:
                                    (
                                        jsondict["LastWriteTime"],
                                        jsondict["Device"],
                                        jsondict["Account"],
                                        jsondict["Message"],
                                    ) = (kv[0], kv[1], kv[2], kv[3])
                                jsonlist.append(json.dumps(jsondict))
                            jsondict.clear()
                elif "kern" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]:
                    with open(artefact) as logfile:
                        for eachinfo in logfile:
                            for eachkv in re.findall(
                                r"(?P<LastWriteTime>[A-Z][a-z]{2}\s+\d+\s+\d+\:\d+\:\d+)\s+(?P<Device>[^\ ]+)\s+(?P<Service>[^\[]+)(?:\[(?P<PID>\d+)\]\:\s+\<(?P<LogLevel>[^\>]+)\>)?\s+\[\s?\d+\.\d+\]\s+(?P<Message>.*)",
                                eachinfo,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 5:
                                    (
                                        jsondict["LastWriteTime"],
                                        jsondict["Device"],
                                        jsondict["Service"],
                                        jsondict["PID"],
                                        jsondict["LogLevel"],
                                        jsondict["Message"],
                                    ) = (
                                        kv[0],
                                        kv[1],
                                        kv[2],
                                        kv[3],
                                        kv[4],
                                        kv[5],
                                    )
                                elif len(kv) > 4:
                                    (
                                        jsondict["LastWriteTime"],
                                        jsondict["Device"],
                                        jsondict["Service"],
                                        jsondict["LogLevel"],
                                        jsondict["Message"],
                                    ) = (
                                        kv[0],
                                        kv[1],
                                        kv[2],
                                        kv[3],
                                        kv[4],
                                    )
                                jsonlist.append(json.dumps(jsondict))
                        jsondict.clear()
                elif (
                    "corecaptured"
                    in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                ):
                    with open(artefact) as logfile:
                        for eachinfo in logfile:
                            for eachkv in re.findall(
                                r"(?P<LastWriteTime>[A-Za-z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2})\s(?P<Service>\w+)\:\:(?P<Message>.*)",
                                eachinfo,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    (
                                        jsondict["LastWriteTime"],
                                        jsondict["Service"],
                                        jsondict["Message"],
                                    ) = (kv[0], kv[1], kv[2])
                                jsonlist.append(json.dumps(jsondict))
                        jsondict.clear()
                elif (
                    "vmware-vmsvc"
                    in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                    or "vmware-vmsvc-root"
                    in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                    or "vmware-vmtoolsd-root"
                    in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                ):
                    with open(artefact) as logfile:
                        for eachinfo in logfile:
                            for eachkv in re.findall(
                                r"\[(?P<LastWriteTime>[^\]]+)\]\s+\[\s*(?P<Action>[^\]]+)\]\s+\[(?P<Service>[^\]]+)\]\s*(?P<Message>.*)",
                                eachinfo,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    (
                                        jsondict["LastWriteTime"],
                                        jsondict["Service"],
                                        jsondict["Message"],
                                    ) = (kv[0], kv[1], kv[2])
                                jsonlist.append(json.dumps(jsondict))
                        jsondict.clear()
                elif (
                    "LKDC-setup"
                    in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                ):
                    with open(artefact) as logfile:
                        for eachinfo in str(logfile.readlines()).split(
                            "...creating certificate..."
                        )[1:]:
                            for eachkv in re.findall(
                                r"\s*(?P<k>\w[^\'\:]+\w)\s+\:\s+(?P<v>[^\']+)\\n",
                                eachinfo.split("', 'Extension struct")[0],
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    jsondict[kv[0].replace(" ", "")] = (
                                        kv[1].strip("\\n").strip()
                                    )
                            for info in eachinfo.split("', 'Extension struct")[1:]:
                                for extinfo in info.split("\\n', '"):
                                    for extkv in re.findall(
                                        r"\s*(?P<k>\w[^\'\:]+\w)\s+\:\s+(?P<v>[^\']+)",
                                        extinfo,
                                    ):
                                        ekv = list(extkv)
                                        if len(ekv) > 0:
                                            jsondict[ekv[0].replace(" ", "")] = (
                                                ekv[1].strip("\\n").strip()
                                            )
                                jsonlist.append(json.dumps(jsondict))
                        jsondict.clear()
                elif (
                    "fsck_apfs"
                    in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                    or "fsck_hfs"
                    in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                ):
                    with open(artefact) as logfile:
                        for eachinfo in str(logfile.readlines()).split(
                            ", '\\n', '\\n', "
                        ):
                            for eachkv in re.findall(
                                r"(?P<Disk>[\w\/]+)\:\s+(?P<Service>\w+)\sstarted\sat\s(?P<LastWriteTime>[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s\d{4})(?P<Message>[\S\s]+)\1\:\s+\2\s+completed\sat\s(?P<LastWriteTimeEnd>[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s\d{4})",
                                eachinfo,
                            ):
                                kv = list(eachkv)
                                if len(kv) > 0:
                                    (
                                        jsondict["Service"],
                                        jsondict["Disk"],
                                        jsondict["LastWriteTime"],
                                        jsondict["LastWriteTimeEnd"],
                                        jsondict["Message"],
                                    ) = (
                                        kv[1],
                                        kv[0],
                                        kv[2],
                                        kv[4],
                                        str(kv[3])[6:-6],
                                    )
                                jsonlist.append(json.dumps(jsondict))
                        jsondict.clear()
                elif (
                    "hfs_convert"
                    in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                ):
                    with open(artefact) as logfile:
                        logdata = str(logfile.readlines())
                    for eachinfo in str(
                        re.sub(
                            r"(\'\,\s|\[)\'([A-Z][a-z]{2})\s",
                            r"||||\2\ ",
                            logdata,
                        )
                    ).split("||||")[1:]:
                        for info in str(
                            re.sub(
                                r"(\d{2}\:\d{2}\:\d{2}\ \d{4}\:)\ ",
                                r"\1:::",
                                eachinfo.replace("['", "")
                                .replace("']", "")
                                .replace("  ", "")
                                .replace("\\ ", " ")
                                .replace("', '", ""),
                            )
                        ).split("::::")[1:]:
                            for everyinfo in info.split("\\n"):
                                if len(everyinfo.strip()) > 0:
                                    (
                                        jsondict["LastWriteTime"],
                                        jsondict["Message"],
                                    ) = (
                                        str(
                                            re.sub(
                                                r"^([A-Z][a-z]{2}\ [A-Z][a-z]{2})(\d+)(\ \d{2}\:\d{2}\:\d{2}\ \d{4})",
                                                r"\1 \2\3",
                                                str(
                                                    re.sub(
                                                        r"(\d{2}\:\d{2}\:\d{2}\ \d{4}\:)\ ",
                                                        r"\1:::",
                                                        eachinfo.replace("['", "")
                                                        .replace("']", "")
                                                        .replace("  ", "")
                                                        .replace(
                                                            "\\ ",
                                                            " ",
                                                        )
                                                        .replace(
                                                            "', '",
                                                            "",
                                                        ),
                                                    )
                                                ).split("::::")[0],
                                            )
                                        ),
                                        everyinfo.strip(),
                                    )
                                jsonlist.append(json.dumps(jsondict))
                    jsondict.clear()
                elif (
                    "install" in artefact.split("/")[-1].split("+")[-1].split(".log")[0]
                ):
                    with open(artefact) as logfile:
                        logdata = str(logfile.readlines())
                    for eachinfo in str(
                        re.sub(
                            r"(\d{4}\-\d{2}\-\d{2}\s\d{2}\:\d{2}\:\d{2})",
                            r"||||\1",
                            logdata,
                        )
                    ).split("||||"):
                        for eachkv in re.findall(
                            r"^(?P<LastWriteTime>\d{4}\-\d{2}\-\d{2}\s\d{2}\:\d{2}\:\d{2}\-\d{2})\s(?P<Device>[^\s]+)\s(?P<Service>[^\[]+)\[(?P<PID>\d+)\]\:\s(?P<Message>.*)",
                            str(
                                eachinfo.strip("', '")
                                .replace("  ", "")
                                .replace("', '", "")
                                .replace('", "', "")
                                .replace("\\n", "")
                                .replace("\\t", "")
                                .replace("\\", "")
                                .replace("'/", "'")
                                .replace("', \"", "")
                            ),
                        ):
                            if len(eachkv) > 4:
                                (
                                    jsondict["LastWriteTime"],
                                    jsondict["Device"],
                                    jsondict["Service"],
                                    jsondict["PID"],
                                    jsondict["Message"],
                                ) = (
                                    eachkv[0],
                                    eachkv[1],
                                    eachkv[2],
                                    eachkv[3],
                                    eachkv[4].replace("\\", ""),
                                )
                            jsonlist.append(json.dumps(jsondict))
                    jsondict.clear()
                for eachjson in jsonlist:
                    eachjson = str(eachjson).replace('""', '"-"')
                    if '"CommonName"' in eachjson:
                        insert = ', "Log{}'.format(
                            str(
                                str(
                                    re.findall(
                                        r"CommonName(\"\: \"[^\"]+\")",
                                        eachjson,
                                    )[0]
                                ).lower()
                            )
                            .replace(" ", "_")
                            .replace('":_"', '": "')
                        )
                        logjsonlist.append(json.dumps(eachjson[0:-1] + insert + "}"))
                    else:
                        logjsonlist.append(json.dumps(eachjson))
                if len(logjsonlist) > 0:
                    log_json = (
                        str(logjsonlist)
                        .replace('\\\\"', '"')
                        .replace('"{"', '{"')
                        .replace('"}"', '}"')
                        .replace("'{\"", '{"')
                        .replace("\"}'", '"}')
                        .replace("'\"{", '{"')
                        .replace("}\"'", '"}')
                        .replace('"', "'")
                        .replace("': '", '": "')
                        .replace("', '", '", "')
                        .replace("{'", '{"')
                        .replace("'}", '"}')
                        .replace("\\\\\\\\", "\\")
                        .replace("\\\\", "\\")
                        .replace("\\n", "")
                        .replace("\\'", "'")
                        .replace("\\", "\\\\")
                    )
                    log_json = re.sub(r'\\\\"(\}\} "\}, \{")', r"'\1", log_json)
                    logjson.write(log_json)
                logjsonlist.clear()
                jsonlist.clear()


def process_service(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
    jsondict,
    jsonlist,
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "services/"
        + artefact.split("/")[-1]
        + ".json"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "services"
            )
        except:
            pass
        if verbosity != "":
            print(
                "     Processing '{}' service for {}...".format(
                    artefact.split("/")[-1], vssimage
                )
            )
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "services/"
            + artefact.split("/")[-1]
            + ".json",
            "a",
        ) as servicejson:
            entry, prnt = "{},{},{},'{}' service file\n".format(
                datetime.now().isoformat(),
                vssimage.replace("'", ""),
                stage,
                artefact.split("/")[-1].split("+")[-1],
            ), " -> {} -> {} service file '{}' from {}".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                artefact.split("/")[-1].split("+")[-1],
                vssimage,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            with open(artefact) as service:
                servicedata = str(service.readlines())
                for eachinfo in servicedata.split("\\n', '"):
                    if "=" in eachinfo:
                        jsondict[
                            str(eachinfo.split("=")[0])
                            .strip()
                            .replace("Service", "Command")
                            .replace("BusName", "Command")
                            .replace("ExecStart", "Command")
                            .replace("Description", "Process")
                        ] = (
                            str(eachinfo.split("=")[1])
                            .strip()
                            .replace("\\", "")
                            .replace("n']", "")
                        )
                jsonlist.append(json.dumps(jsondict))
            jsondict.clear()
            if len(jsonlist) > 0:
                service_json = re.sub(
                    r"(\w)\\'(\w)",
                    r"\1'\2",
                    str(jsonlist)
                    .replace("'{", "{")
                    .replace("}'", "}")
                    .replace("# ", "")
                    .replace("#", "")
                    .replace("n', \\\"", ".  ")
                    .replace("n\\\", '", ".  ")
                    .replace("n', \\\"", "")
                    .replace("[Unit]\\\\n', \\\"", ""),
                )
                service_json = repair_malformed_service(service_json)
                servicejson.write(service_json)
