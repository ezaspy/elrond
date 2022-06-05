#!/usr/bin/env python3 -tt
import os
import time
from datetime import datetime

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry


def search_keywords(
    verbosity, output_directory, img, keywords, keywords_target_list, vssimage, insert
):
    if not os.path.exists(output_directory + img.split("::")[0] + "/analysis/"):
        os.mkdir(output_directory + img.split("::")[0] + "/analysis/")
        with open(
            output_directory + img.split("::")[0] + "/analysis/KeywordMatches.csv",
            "a",
        ) as keyword_matches_results_file:
            keyword_matches_results_file.write(
                "hostname,Keyword,Filename,line_number,line_entry\n"
            )
    else:
        pass
    with open(keywords[0], "r") as keywords_source_file:
        for eachkeyword in keywords_source_file:
            if verbosity != "":
                print(
                    "     Searching for keyword '{}' from {}...".format(
                        eachkeyword.strip(), insert
                    )
                )
            else:
                pass
            for keywords_target_file in keywords_target_list:
                with open(keywords_target_file, "r") as keyword_search_fileile:
                    keyword_line_number = 1
                    try:
                        for eachline in keyword_search_fileile:
                            if eachkeyword.lower().strip() in eachline.lower().strip():
                                (
                                    entry,
                                    prnt,
                                ) = "{},{},keyword identified,{} (line {}) found in {}\n".format(
                                    datetime.now().isoformat(),
                                    vssimage,
                                    eachkeyword.strip(),
                                    keyword_line_number,
                                    keywords_target_file.split("/")[-1],
                                ), " -> {} -> identified keyword '{}' on line {} in '{}' for {}".format(
                                    datetime.now().isoformat().replace("T", " "),
                                    eachkeyword.strip(),
                                    keyword_line_number,
                                    keywords_target_file.split("/")[-1],
                                    vssimage,
                                )
                                write_audit_log_entry(
                                    verbosity, output_directory, entry, prnt
                                )
                                with open(
                                    output_directory
                                    + img.split("::")[0]
                                    + "/analysis/KeywordMatches.csv",
                                    "a",
                                ) as keyword_matches_results_file:
                                    keyword_matches_results_file.write(
                                        vssimage.strip("'")
                                        + ","
                                        + eachkeyword.strip()
                                        + ","
                                        + keywords_target_file
                                        + ","
                                        + str(keyword_line_number)
                                        + ","
                                        + eachline.strip()
                                        + "\n"
                                    )
                            else:
                                pass
                            keyword_line_number += 1
                    except:
                        pass
                with open(
                    keywords_target_file, "r", encoding="ISO-8859-1"
                ) as keyword_search_fileile:
                    keyword_line_number = 0
                    try:
                        for eachline in keyword_search_fileile:
                            if eachkeyword.lower().strip() in eachline.lower().strip():
                                (
                                    entry,
                                    prnt,
                                ) = "{},{},keyword identified,{} (line {}) found in {}\n".format(
                                    datetime.now().isoformat(),
                                    vssimage,
                                    eachkeyword.strip(),
                                    keyword_line_number,
                                    keywords_target_file.split("/")[-1],
                                ), " -> {} -> identified keyword '{}' on line {} in '{}' for {}".format(
                                    datetime.now().isoformat().replace("T", " "),
                                    eachkeyword.strip(),
                                    keyword_line_number,
                                    keywords_target_file.split("/")[-1],
                                    vssimage,
                                )
                                write_audit_log_entry(
                                    verbosity, output_directory, entry, prnt
                                )
                                with open(
                                    output_directory
                                    + img.split("::")[0]
                                    + "/analysis/KeywordMatches.csv",
                                    "a",
                                ) as keyword_matches_results_file:
                                    keyword_matches_results_file.write(
                                        vssimage.strip("'")
                                        + ","
                                        + eachkeyword.strip()
                                        + ","
                                        + keywords_target_file
                                        + ","
                                        + str(keyword_line_number)
                                        + ","
                                        + eachline.strip()
                                        + "\n"
                                    )
                            else:
                                pass
                            keyword_line_number += 1
                    except:
                        pass
            print_done(verbosity)


def build_keyword_list(mnt):
    keywords_target_list = []
    for keyword_search_root, _, keyword_search_file in os.walk(mnt):
        for keyword_search_fileile in keyword_search_file:
            try:
                if (
                    os.stat(
                        os.path.join(keyword_search_root, keyword_search_fileile)
                    ).st_size
                    > 0
                    and os.stat(
                        os.path.join(keyword_search_root, keyword_search_fileile)
                    ).st_size
                    < 100000000
                    and not os.path.islink(
                        os.path.join(keyword_search_root, keyword_search_fileile)
                    )  # 100MB
                ):
                    with open(
                        os.path.join(keyword_search_root, keyword_search_fileile), "r"
                    ) as filetest:
                        filetest.readline()
                        keywords_target_list.append(
                            os.path.join(keyword_search_root, keyword_search_fileile)
                        )
                else:
                    pass
            except:
                pass
            try:
                if (
                    os.stat(
                        os.path.join(keyword_search_root, keyword_search_fileile)
                    ).st_size
                    > 0
                    and os.stat(
                        os.path.join(keyword_search_root, keyword_search_fileile)
                    ).st_size
                    < 100000000
                    and not os.path.islink(
                        os.path.join(keyword_search_root, keyword_search_fileile)
                    )  # 100MB
                ):
                    with open(
                        os.path.join(keyword_search_root, keyword_search_fileile),
                        "r",
                        encoding="ISO-8859-1",
                    ) as filetest:
                        filetest.readline()
                        keywords_target_list.append(
                            os.path.join(keyword_search_root, keyword_search_fileile)
                        )
                else:
                    pass
            except:
                pass
    return keywords_target_list


def prepare_keywords(verbosity, output_directory, auto, imgs, flags, keywords, stage):
    if stage == "mounting":
        if not auto:
            yes_kw = input(
                "  Do you wish to conduct Keyword Searching for '{}'? Y/n [Y] ".format(
                    img.split("::")[0]
                )
            )
        else:
            pass
        if auto or yes_kw != "n":
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
                keywords_target_list = build_keyword_list(mnt)
                print_done(verbosity)
                search_keywords(
                    verbosity,
                    output_directory,
                    img,
                    keywords,
                    keywords_target_list,
                    vssimage,
                    vssimage,
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
            pass
    else:
        for each in imgs:
            if os.path.exists(
                os.path.join(output_directory, each.split("::")[0], "artefacts")
            ):
                mnt = os.path.join(output_directory, each.split("::")[0], "artefacts")
                keywords_target_list = build_keyword_list(mnt)
                search_keywords(
                    verbosity,
                    output_directory,
                    each.split("::")[0],
                    keywords,
                    keywords_target_list,
                    each.split("::")[0],
                    "'collected artefacts'",
                )
            else:
                pass
            if os.path.exists(
                os.path.join(output_directory, each.split("::")[0], "files")
            ):  # for office documents and archives - extract and then build keyword search list
                mnt = os.path.join(output_directory, each.split("::")[0], "files")
                keywords_target_list = build_keyword_list(mnt)
                search_keywords(
                    verbosity,
                    output_directory,
                    each.split("::")[0],
                    keywords,
                    keywords_target_list,
                    each.split("::")[0],
                    "'collected files'",
                )
            else:
                pass
    if "keyword searching" not in str(flags):
        flags.append("03keyword searching")
    else:
        pass
