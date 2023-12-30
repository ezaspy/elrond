#!/usr/bin/env python3 -tt
import os
import re
import sqlite3
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def process_browser_index(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "browsers"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "browsers"
            )
        except:
            pass
    for indexuser in os.listdir(
        output_directory
        + img.split("::")[0]
        + "/artefacts/raw"
        + vss_path_insert
        + "browsers"
    ):
        if os.path.exists(
            output_directory
            + img.split("::")[0]
            + "/artefacts/raw"
            + vss_path_insert
            + "browsers/"
            + indexuser
            + "/ie/History.IE5/index.dat"
        ):
            if verbosity != "":
                print(
                    "     Processing Internet Explorer artefact '{}' ({}) for {}...".format(
                        artefact.split("/")[-1], indexuser, vssimage
                    )
                )
            (
                entry,
                prnt,
            ) = "{},{},{},({}) '{}' browser artefact\n".format(
                datetime.now().isoformat(),
                vssimage.replace("'", ""),
                stage,
                artefact.split("/")[-1],
                indexuser,
            ), " -> {} -> {} browser artefact '{}' ({}) from {}".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                artefact.split("/")[-1],
                indexuser,
                vssimage,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            if not os.path.exists(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "browsers/ie"
            ):
                os.makedirs(
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/cooked"
                    + vss_path_insert
                    + "browsers/ie"
                )
            if not os.path.exists(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "browsers/ie/"
                + indexuser
                + "+"
                + artefact.split("/")[-1]
                + ".csv"
            ):
                with open(
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/cooked"
                    + vss_path_insert
                    + "browsers/ie/"
                    + indexuser
                    + "+"
                    + artefact.split("/")[-1]
                    + ".csv",
                    "w",
                ) as indexout:
                    indexout.write("Profile,Protocol,Domain,url,Description\n")
            with open(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "browsers/ie/"
                + indexuser
                + "+"
                + artefact.split("/")[-1]
                + ".csv",
                "a",
            ) as indexout:
                with open(artefact, encoding="ISO-8859-1") as indexdat:
                    indexdata = indexdat.read()
                for eachindex in str(
                    re.sub(
                        r"[^A-Za-z\d\_\-\ \.\,\;\:\"\'\/\?\!\<\>\@\(\)\[\]\{\}\&\=\+\*\%\#\^\~\`\\\|\$\£\€]",
                        r",",
                        indexdata,
                    )
                ).split("Visited:")[1:]:
                    indexentry = (
                        str(
                            re.sub(
                                r"<\|>\S\S<\|>[^A-Za-z\d\-]",
                                r"<|>",
                                str(
                                    str(
                                        eachindex.split("@")[0]
                                        + "<|>"
                                        + eachindex.split("@")[1]
                                        .split("URL")[0]
                                        .split("@")[0]
                                        .replace("\\", "/")
                                    )
                                    .strip()
                                    .strip(",")
                                )
                                .replace(",,,,,,,,,,,,,,,,", "")
                                .replace(",,", "<|>")
                                .replace(",,", "<|>")
                                .replace(",,", "<|>")
                                .replace("<|><|>", "<|>")
                                .replace("<|><|>", "<|>")
                                .replace("<|><|>", "<|>"),
                            )
                        )
                        + "<|>-<|>-"
                    )
                    profile, protocol, site = (
                        indexentry.split("<|>")[0].lower(),
                        indexentry.split("<|>")[1].split(":")[0],
                        str(indexentry.split("<|>")[1].split(":")[1:])
                        .replace("///", "")
                        .replace("//", "")
                        .replace("['", "")
                        .replace("', '", ":")
                        .strip("']")
                        .strip(";")
                        .split(",")[0],
                    )
                    details = (
                        str(
                            re.sub(
                                r"(\S),(\S)",
                                r"\1\2",
                                str(
                                    re.sub(
                                        r"(\S),(\S)",
                                        r"\1\2",
                                        indexentry.split("<|>")[2],
                                    )
                                ).strip(","),
                            )
                        )
                        .replace(", ,", " ")
                        .strip(",")
                    )
                    description = re.sub(
                        r"\w\-\ \.",
                        r"",
                        str(
                            re.sub(
                                r"(\S),(\S)",
                                r"\1\2",
                                str(
                                    re.sub(
                                        r"(\S),(\S)",
                                        r"\1\2",
                                        indexentry.split("<|>")[3],
                                    )
                                ).strip(","),
                            )
                        ).replace(", ,", " "),
                    ).strip(",")
                    if ":" not in details:
                        description, details = str(
                            re.sub(
                                r"(\S),(\S)",
                                r"\1\2",
                                str(
                                    re.sub(
                                        r"(\S),(\S)",
                                        r"\1\2",
                                        indexentry.split("<|>")[2],
                                    )
                                ).strip(","),
                            )
                        ).replace(", ,", " ").strip(","), str(
                            re.sub(
                                r"(\S),(\S)",
                                r"\1\2",
                                str(
                                    re.sub(
                                        r"(\S),(\S)",
                                        r"\1\2",
                                        indexentry.split("<|>")[3],
                                    )
                                ).strip(","),
                            )
                        ).replace(
                            ", ,", " "
                        ).strip(
                            ","
                        )
                    if len(details) < 5:
                        details = "-"
                    if len(description) < 5:
                        description = "-"
                    if description.endswith(", "):
                        description = description[0:-2]
                    if "/" in site:
                        details = site
                        site = (
                            details.replace("https://", "")
                            .replace("http://", "")
                            .split("/")[0]
                        )
                    index_dat_row = "{},{},{},{},{}\n".format(
                        profile,
                        protocol,
                        site,
                        details,
                        description,
                    )
                    indexout.write("{}".format(index_dat_row))


def format_browser_entries(artefact, browsertype, eachentry):
    if artefact.endswith("/Edge/History") or artefact.endswith("/chrome/History"):
        bwsrtime = eachentry[1:-1].split(",")[-1]
    elif artefact.endswith("places.sqlite"):
        if str(eachentry)[1:-1].split(",")[-1] != "None":
            bwsrtime = str(
                datetime.fromtimestamp(float(str(eachentry)[1:-1].split(",")[-1][:-6]))
            )
        else:
            bwsrtime = "0"
    elif "safari" in artefact and artefact.endswith("History.db"):
        bwsrtime = str(
            datetime.fromtimestamp(
                float(int(str(eachentry).split(",")[-1].split(".")[0]) + 978307200)
            )
        )
    if browsertype == "history" and (
        "', '" in str(eachentry)
        or '", "' in str(eachentry)
        or "', \"" in str(eachentry)
        or "\", '" in str(eachentry)
    ):
        bwsrstart, bwsrmid, bwsrend = re.findall(
            r"(§[^\,]+)', '([^\']*)([\S\s]+)",
            str(eachentry)
            .replace(' "', " '")
            .replace('",', "',")
            .replace(",", "%2C")
            .replace("%2C ", ", ")
            .replace("'", "§")
            .replace(", §", ", '")
            .replace("§,", "',"),
        )[0]
        entry = "{},{},{}".format(
            bwsrstart[1:],
            bwsrmid.replace("§", "'").replace(",", "%2C"),
            bwsrend[:-1],
        )
    else:
        entry = str(eachentry)[1:-1]
    return entry, bwsrtime


def process_browser(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "browsers"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "browsers"
            )
        except:
            pass
    if verbosity != "":
        if "Edge" in artefact:
            print(
                "     Processing Edge browser artefact '{}' ({}) for {}...".format(
                    artefact.split("/")[-1],
                    artefact.split("/")[-3],
                    vssimage,
                )
            )
        elif "chrome" in artefact:
            print(
                "     Processing Google Chrome artefact '{}' ({}) for {}...".format(
                    artefact.split("/")[-1],
                    artefact.split("/")[-3],
                    vssimage,
                )
            )
        elif "safari" in artefact:
            print(
                "     Processing Safari artefact '{}' ({}) for {}...".format(
                    artefact.split("/")[-1],
                    artefact.split("/")[-3],
                    vssimage,
                )
            )
        elif "firefox" in artefact:
            print(
                "     Processing Firefox artefact '{}' ({}) for {}...".format(
                    artefact.split("/")[-1],
                    artefact.split("/")[-3],
                    vssimage,
                )
            )
    (
        entry,
        prnt,
    ) = "{},{},{},'{}' ({}) {} browser artefact\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        artefact.split("/")[-1],
        artefact.split("/")[-3],
        artefact.split("/")[-2],
    ), " -> {} -> {} {} browser artefact '{}' ({}) from {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        artefact.split("/")[-2],
        artefact.split("/")[-1],
        artefact.split("/")[-3],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "browsers/"
        + artefact.split("/raw/")[1].split("/")[2]
    ):
        os.makedirs(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "browsers/"
            + artefact.split("/raw/")[1].split("/")[2]
        )
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "browsers/"
        + artefact.split("/raw/")[1].split("/")[2]
        + "/"
        + artefact.split("/raw/")[1].split("/")[1]
        + "+"
        + artefact.split("/")[-1]
        + ".csv"
    ):
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "browsers/"
            + artefact.split("/raw/")[1].split("/")[2]
            + "/"
            + artefact.split("/raw/")[1].split("/")[1]
            + "+"
            + artefact.split("/")[-1]
            + ".csv",
            "w",
        ) as bwsr:
            bwsr.write("url,title,visit_count,from_visit,visit_date,LastWriteTime\n")
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "browsers/"
        + artefact.split("/raw/")[1].split("/")[2]
        + "/"
        + artefact.split("/raw/")[1].split("/")[1]
        + "+"
        + artefact.split("/")[-1]
        + "_downloads.csv"
    ):
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "browsers/"
            + artefact.split("/raw/")[1].split("/")[2]
            + "/"
            + artefact.split("/raw/")[1].split("/")[1]
            + "+"
            + artefact.split("/")[-1]
            + "_downloads.csv",
            "w",
        ) as downloads:
            downloads.write(
                "url,downloaded_file,received_bytes,total_bytes,start_time,end_time,LastWriteTime\n"
            )
    if artefact.endswith("/Edge/History") or artefact.endswith("/chrome/History"):
        cursor_items = (
            sqlite3.connect(artefact)
            .cursor()
            .execute(
                "SELECT urls.id, urls.url, urls.title, urls.visit_count, datetime(urls.last_visit_time / 1000000 + (strftime('%s', '1601-01-01')), 'unixepoch', 'localtime') FROM urls;"
            )
        )
        cursor_visit = (
            sqlite3.connect(artefact)
            .cursor()
            .execute("SELECT visits.id, visits.from_visit FROM visits;")
        )
        bwsritems, bwsrvisit, bwsrentries = (
            cursor_items.fetchall(),
            cursor_visit.fetchall(),
            [],
        )
        for eachitem in bwsritems:
            for eachvisit in bwsrvisit:
                if eachitem[0] == eachvisit[0]:
                    bwsrentries.append(
                        "[{},{},{},{},{}]".format(
                            str(eachitem[1]).replace(",", "%2C"),
                            str(eachitem[2]).replace(",", "%2C"),
                            eachitem[3],
                            eachvisit[1],
                            eachitem[4],
                        )
                    )
        bwsrhist = bwsrentries
        try:
            cursor_downloads = (
                sqlite3.connect(artefact)
                .cursor()
                .execute(
                    "SELECT downloads.url, downloads.full_path, downloads.start_time, downloads.end_time, downloads.received_bytes, downloads.total_bytes FROM downloads;"
                )
            )
            bwsrdownloads, bwsrdownloadentries = cursor_downloads.fetchall(), []
            for eachdownload in bwsrdownloads:
                bwsrdownloadentries.append(
                    "[{},{},{},{},{},{}]".format(
                        eachdownload[0],
                        eachdownload[1].replace("\\", "/"),
                        eachdownload[2],
                        eachdownload[3],
                        eachdownload[4],
                        eachdownload[5],
                    )
                )
            bwsrdwnlds = bwsrdownloadentries
        except:
            bwsrdwnlds = ""
    elif artefact.endswith("places.sqlite"):
        cursor_items = (
            sqlite3.connect(artefact)
            .cursor()
            .execute(
                "SELECT moz_places.id, moz_places.url, moz_places.title, moz_places.visit_count, moz_places.last_visit_date FROM moz_places;"
            )
        )
        cursor_visit = (
            sqlite3.connect(artefact)
            .cursor()
            .execute(
                "SELECT moz_historyvisits.id, moz_historyvisits.from_visit FROM moz_historyvisits;"
            )
        )
        bwsritems, bwsrvisit, bwsrentries = (
            cursor_items.fetchall(),
            cursor_visit.fetchall(),
            [],
        )
        for eachitem in bwsritems:
            for eachvisit in bwsrvisit:
                if eachitem[0] == eachvisit[0]:
                    bwsrentries.append(
                        "[{},{},{},{},{}]".format(
                            str(eachitem[1]).replace(",", "%2C"),
                            str(eachitem[2]).replace(",", "%2C"),
                            eachitem[3],
                            eachvisit[1],
                            eachitem[4],
                        )
                    )
        bwsrhist = bwsrentries
        try:
            cursor_downloads = (
                sqlite3.connect(artefact)
                .cursor()
                .execute(
                    "SELECT moz_annos.place_id, moz_annos.content, moz_annos.type, moz_annos.dateAdded, moz_annos.lastModified FROM moz_annos;"
                )
            )
            bwsrdownloads, bwsrdownloadentries = cursor_downloads.fetchall(), []
            for eachdownload in bwsrdownloads:
                if eachitem[0] == eachdownload[0]:
                    bwsrdownloadentries.append(
                        "[{},{},{},{},{}]".format(
                            str(eachitem[1]).replace(",", "%2C"),
                            eachdownload[1],
                            eachdownload[2],
                            eachdownload[3],
                            eachdownload[4],
                        )
                    )
            bwsrdwnlds = bwsrdownloadentries
        except:
            bwsrdwnlds = ""
    elif "safari" in artefact and artefact.endswith(
        "History.db"
    ):  # for macOS downloads are collected from Downloads.plist
        cursor_items, cursor_visit = sqlite3.connect(artefact).cursor().execute(
            "SELECT history_items.id, history_items.url, history_items.visit_count FROM history_items;"
        ), sqlite3.connect(artefact).cursor().execute(
            "SELECT history_visits.history_item, history_visits.title, history_visits.origin, history_visits.visit_time FROM history_visits;"
        )
        bwsritems, bwsrvisit, bwsrentries = (
            cursor_items.fetchall(),
            cursor_visit.fetchall(),
            [],
        )
        for eachitem in bwsritems:
            for eachvisit in bwsrvisit:
                if eachitem[0] == eachvisit[0]:
                    bwsrentries.append(
                        "[{},{},{},{},{}]".format(
                            str(eachitem[1]).replace(",", "%2C"),
                            str(eachvisit[1]).replace(",", "%2C"),
                            eachitem[2],
                            eachvisit[2],
                            eachvisit[3],
                        )
                    )
        bwsrhist = bwsrentries
        bwsrdwnlds = ""
    for eachentry in bwsrhist:
        hist, histtime = format_browser_entries(artefact, "history", eachentry)
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "browsers/"
            + artefact.split("/raw/")[1].split("/")[2]
            + "/"
            + artefact.split("/raw/")[1].split("/")[1]
            + "+"
            + artefact.split("/")[-1]
            + ".csv",
            "a",
        ) as bwsr:
            bwsr.write(
                hist.replace("''", "-")
                .replace(", ", ",")
                .replace(",',", ",")
                .replace("Site", "url")
                + ","
                + histtime
                + "\n"
            )
    if bwsrdwnlds != "":
        for eachentry in bwsrdwnlds:
            download, downloadtime = format_browser_entries(
                artefact, "downloads", eachentry
            )
            with open(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "browsers/"
                + artefact.split("/raw/")[1].split("/")[2]
                + "/"
                + artefact.split("/raw/")[1].split("/")[1]
                + "+"
                + artefact.split("/")[-1]
                + "_downloads.csv",
                "a",
            ) as downloads:
                downloads.write(
                    download.replace("''", "-")
                    .replace(", ", ",")
                    .replace(",',", ",")
                    .replace("Site", "url")
                    + ","
                    + downloadtime
                    + "\n"
                )
