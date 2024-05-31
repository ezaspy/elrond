#!/usr/bin/env python3 -tt
import os
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def ingest_splunk_data(
    verbosity,
    output_directory,
    case,
    stage,
    allimgs,
    postpath,
):
    imgs_to_index = []
    for _, img in allimgs.items():
        if img not in str(imgs_to_index):
            imgs_to_index.append(img)
    for img in imgs_to_index:
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
        print("     Indexing artefacts into Splunk for {}...".format(vssimage))
        entry, prnt = "{},{}{},{},indexing\n".format(
            datetime.now().isoformat(), img.split("::")[0], vsstext, stage
        ), " -> {} -> indexing artfacts into {} for {}{}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            vssimage,
            vsstext,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        with open(
            "/" + postpath + "splunk/etc/apps/elrond/default/inputs.conf", "a"
        ) as inputsconf:
            if not os.path.exists(
                "/" + postpath + "splunk/etc/apps/elrond/default/inputs.conf"
            ):
                inputsconf.write("\n")
            if not img.split("::")[-1].startswith("memory"):
                for atftfile in os.listdir(
                    os.path.realpath(output_directory + img.split("::")[0])
                ):
                    if atftfile.endswith(".audit"):
                        inputsconf.write(
                            "[monitor://{}]\ndisabled = false\nhost = {}\nsourcetype = elrondCSV\nindex = {}\n\n".format(
                                os.path.realpath(output_directory + img.split("::")[0])
                                + "/"
                                + atftfile,
                                img.split("::")[0],
                                case,
                            )
                        )
                for atftroot, atftdirs, atftfiles in os.walk(
                    os.path.realpath(
                        output_directory + img.split("::")[0] + "/artefacts/cooked/"
                    )
                ):
                    for atftfile in atftfiles:
                        if os.path.isfile(os.path.join(atftroot, atftfile)):
                            if str(img.split("::")[-1])[1:].startswith("indows"):
                                if atftfile.endswith(
                                    "shimcache.csv"
                                ) or atftfile.endswith("jumplists.csv"):
                                    sourcetype = "elrondCSV_noTime"
                                elif (
                                    atftfile.endswith("mft.csv")
                                    or atftfile.endswith("usn.csv")
                                    or atftfile.endswith("sqlite.csv")
                                ):
                                    sourcetype = "elrondCSV"
                                elif (
                                    (
                                        atftfile.endswith(".json")
                                        and "windows." not in atftfile
                                        and "memory_" not in atftfile
                                        and "/memory/" not in atftroot
                                    )
                                    and "registry" not in atftroot
                                    and "evt" not in atftroot
                                ):
                                    sourcetype = "elrondJSON"
                                else:
                                    sourcetype = ""
                            elif str(img.split("::")[-1])[1:].startswith("ac"):
                                if (
                                    (
                                        atftfile.endswith(".json")
                                        and "macos." not in atftfile
                                        and "memory_" not in atftfile
                                        and "/memory/" not in atftroot
                                    )
                                    and "logs" not in atftroot
                                    and "plists" not in atftroot
                                ):
                                    sourcetype = "elrondJSON"
                                elif atftfile.endswith("History.db.csv"):
                                    sourcetype = "elrondCSV"
                                else:
                                    sourcetype = ""
                            elif str(img.split("::")[-1])[1:].startswith("inux"):
                                if (
                                    (
                                        atftfile.endswith(".json")
                                        and "linux." not in atftfile
                                        and "memory_" not in atftfile
                                        and "/memory/" not in atftroot
                                    )
                                    and "logs" not in atftroot
                                    and "services" not in atftroot
                                ):
                                    sourcetype = "elrondJSON_noTime"
                                elif atftfile.endswith("sqlite.csv"):
                                    sourcetype = "elrondCSV"
                                else:
                                    sourcetype = ""
                            else:
                                sourcetype = ""
                            if sourcetype != "":
                                inputsconf.write(
                                    "[monitor://{}]\ndisabled = false\nhost = {}\nsourcetype = {}\nindex = {}\n\n".format(
                                        os.path.join(atftroot, atftfile),
                                        img.split("::")[0],
                                        sourcetype,
                                        case,
                                    )
                                )
                    for atftdir in atftdirs:
                        if os.path.isdir(os.path.join(atftroot, atftdir)):
                            if str(img.split("::")[-1])[1:].startswith("indows"):
                                if len(
                                    os.listdir(os.path.join(atftroot, atftdir))
                                ) > 0 and (atftdir == "registry" or atftdir == "evt"):
                                    inputsconf.write(
                                        "[monitor://{}/*.json]\ndisabled = false\ncrcSalt = <SOURCE>\nhost = {}\nsourcetype = elrondJSON\nindex = {}\n\n".format(
                                            os.path.join(atftroot, atftdir),
                                            str(img.split("::")[0]),
                                            case,
                                        )
                                    )
                                elif len(
                                    os.listdir(os.path.join(atftroot, atftdir))
                                ) > 0 and (atftdir == "IE"):
                                    inputsconf.write(
                                        "[monitor://{}/*.csv]\ndisabled = false\ncrcSalt = <SOURCE>\nhost = {}\nsourcetype = elrondCSV_noTime\nindex = {}\n\n".format(
                                            os.path.join(atftroot, atftdir),
                                            str(img.split("::")[0]),
                                            case,
                                        )
                                    )
                                elif len(
                                    os.listdir(os.path.join(atftroot, atftdir))
                                ) > 0 and (atftdir == "chrome"):
                                    inputsconf.write(
                                        "[monitor://{}/*.csv]\ndisabled = false\ncrcSalt = <SOURCE>\nhost = {}\nsourcetype = elrondCSV\nindex = {}\n\n".format(
                                            os.path.join(atftroot, atftdir),
                                            str(img.split("::")[0]),
                                            case,
                                        )
                                    )
                            if str(img.split("::")[-1])[1:].startswith("ac"):
                                if len(
                                    os.listdir(os.path.join(atftroot, atftdir))
                                ) > 0 and (atftdir == "logs" or atftdir == "plists"):
                                    inputsconf.write(
                                        "[monitor://{}/*.json]\ndisabled = false\ncrcSalt = <SOURCE>\nhost = {}\nsourcetype = elrondJSON\nindex = {}\n\n".format(
                                            os.path.join(atftroot, atftdir),
                                            str(img.split("::")[0]),
                                            case,
                                        )
                                    )
                            if str(img.split("::")[-1])[1:].startswith("inux"):
                                if len(
                                    os.listdir(os.path.join(atftroot, atftdir))
                                ) > 0 and (atftdir == "logs" or atftdir == "services"):
                                    inputsconf.write(
                                        "[monitor://{}/*.json]\ndisabled = false\ncrcSalt = <SOURCE>\nhost = {}\nsourcetype = elrondJSON\nindex = {}\n\n".format(
                                            os.path.join(atftroot, atftdir),
                                            str(img.split("::")[0]),
                                            case,
                                        )
                                    )
                if os.path.isdir(
                    os.path.realpath(output_directory + img.split("::")[0])
                    + "/artefacts/cooked/memory/"
                ):
                    inputsconf.write(
                        "[monitor://{}/artefacts/cooked/memory/*.json]\ndisabled = false\ncrcSalt = <SOURCE>\nhost = {}\nsourcetype = elrondJSON\nindex = {}\n\n".format(
                            os.path.realpath(output_directory + img.split("::")[0]),
                            img.split("::")[0],
                            case,
                        )
                    )
                    if os.path.exists(
                        str(os.path.realpath(output_directory + img.split("::")[0]))
                        + "/artefacts/cooked/memory/timeliner.csv"
                    ):
                        inputsconf.write(
                            "[monitor://{}/artefacts/cooked/memory/timeliner.csv]\ndisabled = false\nhost = {}\nsourcetype = elrondCSV\nindex = {}\n\n".format(
                                os.path.realpath(output_directory + img.split("::")[0]),
                                img.split("::")[0],
                                case,
                            )
                        )
                    if os.path.exists(
                        str(os.path.realpath(output_directory + img.split("::")[0]))
                        + "/artefacts/cooked/memory/iehistory"
                    ):
                        inputsconf.write(
                            "[monitor://{}/artefacts/cooked/memory/iehistory]\ndisabled = false\nhost = {}\nsourcetype = elrond_\nindex = {}\n\n".format(
                                os.path.realpath(output_directory + img.split("::")[0]),
                                img.split("::")[0],
                                case,
                            )
                        )
                for atftroot, atftdirs, atftfiles in os.walk(
                    os.path.realpath(
                        output_directory + img.split("::")[0] + "/analysis/"
                    )
                ):
                    for atftfile in atftfiles:
                        if img.split("::")[0] in atftroot and os.path.isfile(
                            os.path.join(atftroot, atftfile)
                        ):
                            if (
                                atftfile.endswith("analysis.csv")
                                or atftfile.endswith("iocs.csv")
                                or atftfile.endswith("keyword_matches.csv")
                                or atftfile.endswith("yara.csv")
                            ):
                                inputsconf.write(
                                    "[monitor://{}/*.csv]\ndisabled = false\ncrcSalt = <SOURCE>\nhost = {}\nsourcetype = elrondCSV\nindex = {}\n\n".format(
                                        atftroot,
                                        str(img.split("::")[0]),
                                        case,
                                    )
                                )
                for timeroot, _, timefiles in os.walk(
                    os.path.realpath(
                        output_directory + img.split("::")[0] + "/artefacts/"
                    )
                ):
                    for timefile in timefiles:
                        if img.split("::")[0] in timeroot and os.path.isfile(
                            os.path.join(timeroot, timefile)
                        ):
                            if timefile.endswith("plaso_timeline.csv"):
                                inputsconf.write(
                                    "[monitor://{}]\ndisabled = false\nhost = {}\nsourcetype = elrondCSV\nindex = {}\n\n".format(
                                        os.path.join(timeroot, timefile),
                                        str(img.split("::")[0]),
                                        case,
                                    )
                                )
            elif img.split("::")[-1].startswith("memory") and ".json" in str(
                os.listdir(os.path.realpath(output_directory + img.split("::")[0]))
            ):
                inputsconf.write(
                    "[monitor://{}/*.json]\ndisabled = false\ncrcSalt = <SOURCE>\nhost = {}\nsourcetype = elrondJSON\nindex = {}\n\n".format(
                        os.path.realpath(output_directory + img.split("::")[0]),
                        img.split("::")[0],
                        case,
                    )
                )
                if os.path.exists(
                    str(os.path.realpath(output_directory + img.split("::")[0]))
                    + "/timeliner.csv"
                ):
                    inputsconf.write(
                        "[monitor://{}/timeliner.csv]\ndisabled = false\nhost = {}\nsourcetype = elrondCSV\nindex = {}\n\n".format(
                            os.path.realpath(output_directory + img.split("::")[0]),
                            img.split("::")[0],
                            case,
                        )
                    )
                if os.path.exists(
                    str(os.path.realpath(output_directory + img.split("::")[0]))
                    + "/iehistory"
                ):
                    inputsconf.write(
                        "[monitor://{}/iehistory]\ndisabled = false\nhost = {}\nsourcetype = elrond_\nindex = {}\n\n".format(
                            os.path.realpath(output_directory + img.split("::")[0]),
                            img.split("::")[0],
                            case,
                        )
                    )
        with open(
            "/" + postpath + "splunk/etc/apps/elrond/default/tags.conf", "a"
        ) as tagsconf:
            if (
                img.split("::")[0].endswith(".E01")
                or img.split("::")[0].endswith(".e01")
                or img.split("::")[0].endswith(".VMDK.raw")
                or img.split("::")[0].endswith(".vmdk.raw")
                or img.split("::")[0].endswith(".dd.raw")
            ):
                imgtype = "\ndisk = enabled"
            else:
                imgtype = "\nmemory = enabled"
            if "Windows" in img.split("::")[1]:
                imgtype = imgtype + "\nWindows = enabled\n\n"
            elif "mac" in img.split("::")[1] or "Mac" in img.split("::")[1]:
                imgtype = imgtype + "\nmacOS = enabled\n\n"
            elif "Linux" in img.split("::")[1]:
                imgtype = imgtype + "\nLinux = enabled\n\n"
            tagsconf.write("[host={}]{}".format(img.split("::")[0], imgtype))
        output_directory = os.path.dirname(output_directory) + "/"
        if os.path.exists(
            "/" + postpath + "splunk/etc/apps/elrond/default/tags.conf.orig.pre41"
        ):
            os.remove("/" + postpath + "splunk/etc/apps/elrond/default/tags.conf")
            os.rename(
                r"/" + postpath + "splunk/etc/apps/elrond/default/tags.conf.orig.pre41",
                r"/" + postpath + "splunk/etc/apps/elrond/default/tags.conf",
            )

        print("     Splunk indexing completed for {}".format(vssimage))
        entry, prnt = "{},{},{},completed\n".format(
            datetime.now().isoformat(), vssimage, stage
        ), " -> {} -> indexed artfacts into {} for {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
