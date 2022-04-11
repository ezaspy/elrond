#!/usr/bin/env python3 -tt
import os
import time
from datetime import datetime

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry


import sys


def search_keywords(
    verbosity, output_directory, img, keywords, kwsfilelist, vssimage, vsstext
):
    if not os.path.exists(output_directory + img.split("::")[0] + "/analysis/"):
        os.mkdir(output_directory + img.split("::")[0] + "/analysis/")
        with open(
            output_directory + img.split("::")[0] + "/analysis/KeywordMatches.csv",
            "a",
        ) as kwmatchesfile:
            kwmatchesfile.write("elrond_host,Keyword,Filename,LineNumber,LineEntry\n")
    else:
        pass
    with open(keywords[0], "r") as keywordsfile:
        for eachkeyword in keywordsfile:
            if verbosity != "":
                print("     Searching for keyword '{}'...".format(eachkeyword.strip()))
            else:
                pass
            for kwfile in kwsfilelist:
                with open(kwfile, "r") as kwsfile:
                    kwlno = 0
                    try:
                        for eachline in kwsfile:
                            if eachkeyword.lower().strip() in eachline.lower().strip():
                                (
                                    entry,
                                    prnt,
                                ) = "{},{},keyword {} identified on line {},{}\n".format(
                                    datetime.now().isoformat(),
                                    vssimage,
                                    eachkeyword.strip(),
                                    kwlno,
                                    kwfile.split("/")[-1],
                                ), " -> {} -> identified keyword '{}' on line {} in '{}' for {}{}".format(
                                    datetime.now().isoformat().replace("T", " "),
                                    eachkeyword.strip(),
                                    kwlno,
                                    kwfile.split("/")[-1],
                                    vssimage,
                                    vsstext,
                                )
                                write_audit_log_entry(
                                    verbosity, output_directory, entry, prnt
                                )
                                with open(
                                    output_directory
                                    + img.split("::")[0]
                                    + "/analysis/KeywordMatches.csv",
                                    "a",
                                ) as kwmatchesfile:
                                    kwmatchesfile.write(
                                        vssimage.strip("'")
                                        + ","
                                        + eachkeyword.strip()
                                        + ","
                                        + kwfile
                                        + ","
                                        + str(kwlno)
                                        + ","
                                        + eachline.strip()
                                        + "\n"
                                    )
                            else:
                                pass
                            kwlno += 1
                    except:
                        pass
            print_done(verbosity)


def build_keyword_list(mnt):
    kwsfilelist = []
    for kwsr, _, kwsf in os.walk(mnt):
        for kwsfile in kwsf:
            try:
                if (
                    os.stat(os.path.join(kwsr, kwsfile)).st_size > 0
                    and os.stat(os.path.join(kwsr, kwsfile)).st_size < 100000000
                    and not os.path.islink(os.path.join(kwsr, kwsfile))  # 100MB
                ):
                    with open(os.path.join(kwsr, kwsfile), "r") as filetest:
                        filetest.readline()
                        kwsfilelist.append(os.path.join(kwsr, kwsfile))
                else:
                    pass
            except:
                pass
    return kwsfilelist


def prepare_keywords(verbosity, output_directory, imgs, keywords, stage):
    if stage == "mounting":
        print(
            "\n\n  -> \033[1;36mCommencing Keyword Searching Phase...\033[1;m\n  ----------------------------------------"
        )
        time.sleep(1)
        for each in imgs:
            img, mnt = [each, imgs[each]]
            stage = "keyword searching"
            if "vss" in img.split("::")[1]:
                vssimage, vsstext = (
                    "'"
                    + img.split("::")[0]
                    + "' ("
                    + img.split("::")[1]
                    .split("_")[1]
                    .replace("vss", "volume shadow copy #")
                    + ")",
                    " ("
                    + img.split("::")[1]
                    .split("_")[1]
                    .replace("vss", "volume shadow copy #")
                    + ")",
                )
            else:
                vssimage, vsstext = "'" + img.split("::")[0] + "'", ""
            print("    Conducting Keyword Searching for {}...".format(vssimage))
            entry, prnt = "{},{},{},commenced\n".format(
                datetime.now().isoformat(), vssimage.replace("'", ""), stage
            ), " -> {} -> {} commenced for '{}'{}".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                img.split("::")[0],
                vsstext,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            print(
                "     Assessing readable files in {} before searching for keywords...".format(
                    vssimage
                )
            )
            kwsfilelist = build_keyword_list(mnt)
            print_done(verbosity)
            search_keywords(
                verbosity,
                output_directory,
                img,
                keywords,
                kwsfilelist,
                vssimage,
                vsstext,
            )
            print("  -> Completed Keyword Searching Phase for {}".format(vssimage))
            entry, prnt = "{},{},{},completed\n".format(
                datetime.now().isoformat(),
                vssimage.replace("'", ""),
                "keyword searching",
            ), " -> {} -> keyword searching completed for {}".format(
                datetime.now().isoformat().replace("T", " "), vssimage
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            print()
        print(
            "  ----------------------------------------\n  -> Completed Keyword Searching Phase.\n"
        )
        time.sleep(1)
    else:
        for each in imgs:
            if os.path.exists(
                os.path.join(output_directory, each.split("::")[0], "artefacts")
            ):
                mnt = os.path.join(output_directory, each.split("::")[0], "artefacts")
                kwsfilelist = build_keyword_list(mnt)
                search_keywords(
                    verbosity,
                    output_directory,
                    each.split("::")[0],
                    keywords,
                    kwsfilelist,
                    each.split("::")[0],
                    "",
                )
            else:
                pass
            if os.path.exists(
                os.path.join(output_directory, each.split("::")[0], "files")
            ):  # for office documents and archives - extract and then build keyword search list
                mnt = os.path.join(output_directory, each.split("::")[0], "files")
                kwsfilelist = build_keyword_list(mnt)
                search_keywords(
                    verbosity,
                    output_directory,
                    each.split("::")[0],
                    keywords,
                    kwsfilelist,
                    each.split("::")[0],
                    "",
                )
            else:
                pass
