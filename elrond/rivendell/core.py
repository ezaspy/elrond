import os
import shutil
import sys
import time
from datetime import datetime

from rivendell.analysing.analysis import analyse_artefacts
from rivendell.analysing.keywords import prepare_keywords
from rivendell.audit import write_audit_log_entry
from rivendell.collecting.collect import collect_artefacts
from rivendell.collecting.reorganise import reorganise_artefacts
from rivendell.processing.process import identify_pre_process_artefacts
from rivendell.processing.timeline import create_plaso_timeline


def collect_process_kw_analysis_timelining(
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
    hashcollected,
    superquick,
    quick,
    recover,
    carving,
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
):
    if collect:
        collect_artefacts(
            vss,
            collectfiles,
            nsrl,
            keywords,
            volatility,
            hashcollected,
            superquick,
            quick,
            recover,
            carving,
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
        reorganise_artefacts()
    if process:
        identify_pre_process_artefacts(
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
        )
    else:
        pass
    if keywords:
        if not os.path.exists(keywords[0]):
            print(
                "\n    {} is an invalid path because it does not exist. Please try again.\n".format(
                    keywords[0]
                )
            )
            sys.exit()
        else:
            print(
                "\n\n  -> \033[1;36mCommencing Keyword Searching phase for proccessed artefacts...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            prepare_keywords(
                verbosity, output_directory, imgs, keywords, "keyword searching"
            )
            if "keyword searching" not in str(flags):
                flags.append("3keyword searching")
            else:
                pass
            print(
                "  ----------------------------------------\n  -> Completed Keyword Searching phase for proccessed artefacts.\n"
            )
            time.sleep(1)
    else:
        pass
    if analysis or extractiocs:
        alysdirs = []
        for eachdir in os.listdir(output_directory):
            if os.path.exists(output_directory + eachdir + "/artefacts"):
                alysdirs.append(output_directory + eachdir + "/artefacts")
            else:
                pass
        if len(alysdirs) > 0:
            print(
                "\n\n  -> \033[1;36mCommencing Analysis Phase...\033[1;m\n  ----------------------------------------"
            )
            time.sleep(1)
            for img, mnt in imgs.items():
                analyse_artefacts(
                    verbosity,
                    output_directory,
                    img,
                    mnt,
                    analysis,
                    extractiocs,
                    img,
                )
        else:
            print(
                "  -> Analysis could not be conducted as there are no artefacts processed (-P), please try again.\n"
            )
        flags.append("4analysis")
        print(
            "  ----------------------------------------\n  -> Completed Analysis Phase.\n"
        )
        time.sleep(1)
    else:
        pass
    if timeline:
        stage, timelineimages = "timeline", []
        print(
            "\n\n  -> \033[1;36mCommencing Timeline Phase...\033[1;m\n  ----------------------------------------"
        )
        time.sleep(1)
        for img in imgs:  # Identifying images for timelining
            if not img.split("::")[1].endswith("memory"):
                timelineimages.append(img.split("::")[0])
            else:
                pass
        if len(timelineimages) > 0:
            for each in os.listdir(output_directory):
                if each + "/" == output_directory or each == img.split("::")[0]:
                    if not os.path.exists(
                        output_directory + img.split("::")[0] + "/artefacts/"
                    ):
                        os.makedirs(
                            output_directory + img.split("::")[0] + "/artefacts/"
                        )
                    else:
                        pass
                else:
                    pass
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
                        else:
                            pass
                        return timelinepath

                    timelinepath = input(
                        "    Please provide the full file path of the timeline: "
                    )
                    timelinefile = doTimelineFile(timelinepath)
                    if os.path.exists(".plaso"):
                        shutil.rmtree("./.plaso")
                    else:
                        pass
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
            flags.append("5timelining")
            print(
                "  ----------------------------------------\n  -> Completed Timelining Phase.\n"
            )
            time.sleep(1)
        else:
            pass
    else:
        pass
