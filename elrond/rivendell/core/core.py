import os
import shutil
import sys
import time
from datetime import datetime

from rivendell.analysis.analysis import analyse_artefacts
from rivendell.analysis.keywords import prepare_keywords
from rivendell.audit import write_audit_log_entry
from rivendell.collect.collect import collect_artefacts
from rivendell.collect.reorganise import reorganise_artefacts
from rivendell.process.select import select_pre_process_artefacts
from rivendell.process.timeline import create_plaso_timeline


def collect_process_keyword_analysis_timeline(
    auto,
    collect,
    process,
    analysis,
    extractiocs,
    timeline,
    vss,
    collectfiles,
    nsrl,
    keywords,
    volatility,
    metacollected,
    superquick,
    quick,
    reorganise,
    symlinks,
    userprofiles,
    verbose,
    d,
    cwd,
    sha256,
    flags,
    system_artefacts,
    output_directory,
    verbosity,
    f,
    allimgs,
    imgs,
    path,
    volchoice,
    vssmem,
    memtimeline,
    stage,
):
    if (collect and len(imgs) != 0) or reorganise:
        if collect:
            collect_artefacts(
                auto,
                vss,
                collectfiles,
                nsrl,
                keywords,
                volatility,
                metacollected,
                superquick,
                quick,
                symlinks,
                userprofiles,
                verbose,
                d,
                cwd,
                sha256,
                flags,
                system_artefacts,
                output_directory,
                verbosity,
                f,
                imgs,
                path,
                volchoice,
                vssmem,
                memtimeline,
                stage,
            )
        else:
            imgs = reorganise_artefacts(
                output_directory, verbosity, d, allimgs, flags, auto, volatility
            )
        for eachdir in os.listdir(output_directory):
            if (
                os.path.isdir(os.path.join(output_directory, eachdir))
                and eachdir != ".DS_Store"
            ):
                if len(os.listdir(os.path.join(output_directory, eachdir))) == 0:
                    os.rmdir(os.path.join(output_directory, eachdir))
        if process:
            select_pre_process_artefacts(
                output_directory,
                verbosity,
                d,
                flags,
                stage,
                cwd,
                imgs,
                f,
                path,
                vssmem,
                volatility,
                volchoice,
                vss,
                memtimeline,
                collectfiles,
            )
        if os.path.exists("/opt/elrond/elrond/tools/.profiles"):
            os.remove("/opt/elrond/elrond/tools/.profiles")
    if keywords:
        if not os.path.exists(keywords[0]):
            continue_with_kw = input(
                "\n    {} is an invalid path because it does not exist. Continue? Y/n [Y] \n".format(
                    keywords[0]
                )
            )
            if continue_with_kw == "n":
                sys.exit()
        else:
            print(
                "\n\n  -> \033[1;36mCommencing Keyword Searching phase for proccessed artefacts...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            prepare_keywords(
                verbosity,
                output_directory,
                auto,
                imgs,
                flags,
                keywords,
                "keyword searching",
            )
            print(
                "  ----------------------------------------\n  -> Completed Keyword Searching phase for proccessed artefacts.\n"
            )
            time.sleep(1)
    if analysis or extractiocs:
        alysdirs = []
        for eachdir in os.listdir(output_directory):
            if os.path.exists(output_directory + eachdir + "/artefacts"):
                alysdirs.append(output_directory + eachdir + "/artefacts")
        if len(alysdirs) > 0:
            print(
                "\n\n  -> \033[1;36mCommencing Analysis Phase...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            for mnt, img in imgs.items():
                if "vss" in img.split("::")[1]:
                    vssimage = (
                        "'"
                        + img.split("::")[0]
                        + "' ("
                        + img.split("::")[1]
                        .split("_")[1]
                        .replace("vss", "volume shadow copy #")
                        + ")"
                    )
                else:
                    vssimage = "'" + img.split("::")[0] + "'"
                analyse_artefacts(
                    verbosity,
                    output_directory,
                    img,
                    mnt,
                    analysis,
                    extractiocs,
                    vssimage,
                )
        else:
            print(
                "  -> Analysis could not be conducted as there are no artefacts processed (-P), please try again.\n"
            )
        flags.append("04analysis")
        print(
            "  ----------------------------------------\n  -> Completed Analysis Phase.\n"
        )
        time.sleep(1)
    if timeline:
        stage, timelineimages = "timeline", []
        print(
            "\n\n  -> \033[1;36mCommencing Timeline Phase...\033[1;m\n  ----------------------------------------"
        )
        time.sleep(1)
        for img in imgs:  # Identifying images for timelining
            if not img.split("::")[1].endswith("memory"):
                timelineimages.append(img.split("::")[0])
        if len(timelineimages) > 0:
            for each in os.listdir(output_directory):
                if each + "/" == output_directory or each == img.split("::")[0]:
                    if not os.path.exists(
                        output_directory + img.split("::")[0] + "/artefacts/"
                    ):
                        os.makedirs(
                            output_directory + img.split("::")[0] + "/artefacts/"
                        )
            for timelineimage in timelineimages:
                timelineexist = input(
                    "   Does a timeline already exist for '{}'? Y/n [n] ".format(
                        timelineimage
                    )
                )
                if timelineexist != "Y":
                    create_plaso_timeline(
                        verbosity, output_directory, stage, img, d, timelineimage
                    )
                else:

                    def doTimelineFile(timelinepath):
                        if not os.path.exists(timelinepath):
                            timelinepath = input(
                                "    '{}' does not exist and/or is an invalid csv file.\n     Please provide a valid file path: ".format(
                                    timelinepath
                                )
                            )
                            doTimelineFile(timelinepath)
                        return timelinepath

                    timelinepath = input(
                        "    Please provide the full file path of the timeline: "
                    )
                    timelinefile = doTimelineFile(timelinepath)
                    if os.path.exists(".plaso"):
                        shutil.rmtree("./.plaso")
                    with open(timelinefile) as tlf:
                        firstline = tlf.readline()
                    if "Message" not in firstline and "Artefact" not in firstline:
                        os.mkdir(".plaso")
                        shutil.copy2(timelinefile, "./.plaso/plaso_timeline.csvtmp")
                        create_plaso_timeline()
                    else:
                        shutil.copy2(
                            timelinefile,
                            output_directory
                            + timelineimage
                            + "/artefacts/plaso_timeline.csv",
                        )
                print(" -> Completed Timeline Phase for '{}'.".format(timelineimage))
                entry, prnt = "{},{},{},{}\n".format(
                    datetime.now().isoformat(), timelineimage, stage, timelineimage
                ), " -> {} -> {} completed for '{}'".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage,
                    timelineimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                print()
            flags.append("05timelining")
            print(
                "  ----------------------------------------\n  -> Completed Timelining Phase.\n"
            )
            time.sleep(1)
