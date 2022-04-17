#!/usr/bin/env python3 -tt
import os
import re
import subprocess
from datetime import datetime

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry
from rivendell.processing.memory import process_memory
from rivendell.processing.extractions.evtx import extract_evtx
from rivendell.processing.extractions.registry.system import extract_registry_system
from rivendell.processing.extractions.registry.users import extract_registry_users
from rivendell.processing.extractions.shimcache import extract_shimcache
from rivendell.processing.extractions.usb import extract_usb


def process_mft(
    verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
):
    if verbosity != "":
        print("     Processing '$MFT' for {}...".format(vssimage))
    else:
        pass
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vssartefact
        + "..MFT.csv",
        "a",
    ) as mftcsv:
        entry, prnt = "{},{},{},'$MFT'\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
        ), " -> {} -> {} '$MFT' for {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        try:
            mftout = subprocess.Popen(
                [
                    "analyzeMFT.py",
                    "-a",
                    "-f",
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/raw"
                    + vssartefact
                    + "$MFT",
                    "-o",
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/cooked"
                    + vssartefact
                    + "..MFT.csv",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
            mftcsv.write(str(mftout.communicate()[0]))
            print_done(verbosity)
        except:
            pass
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + ".MFT.csv",
            "a",
        ) as mftwrite:
            with open(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vssartefact
                + "..MFT.csv"
            ) as mftread:
                for eachinfo in mftread:
                    mftentries, mftcounter = (
                        list(
                            str(
                                re.sub(
                                    r"^([^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,\")([^\"]*)(\"\,[^\,]*\,[^\,]*\,\")([^\"]*)(\"\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,\")([^\"]*)(\"\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,\")([^\"]*)(\"\,[^\,]*\,[^\,]*\,[^\,]*\,[^\,]*\,\")([^\"]*)(\")([\S\s]*)",
                                    r"\1\2\3\4\5\6\7\8\9\10\11\12,\"\2\",\"\6\",\"\8\",\"\10\",\"\4\"",
                                    re.sub(
                                        r"([^\"])\,([^\"])",
                                        r"\1\2",
                                        eachinfo.strip(),
                                    ),
                                )
                            )
                            .replace(
                                '"Record Number","Good","Active","Record type","Sequence Number","Parent File Rec. #","Parent File Rec. Seq. #","Filename #1","Std Info Creation date","Std Info Modification date","Std Info Access date","Std Info Entry date","FN Info Creation date","FN Info Modification date","FN Info Access date","FN Info Entry date","Object ID","Birth Volume ID","Birth Object ID","Birth Domain ID","Filename #2","FN Info Creation date","FN Info Modify date","FN Info Access date","FN Info Entry date","Filename #3","FN Info Creation date","FN Info Modify date","FN Info Access date","FN Info Entry date","Filename #4","FN Info Creation date","FN Info Modify date","FN Info Access date","FN Info Entry date","Standard Information","Attribute List","Filename","Object ID","Volume Name","Volume Info","Data","Index Root","Index Allocation","Bitmap","Reparse Point","EA Information","EA","Property Set","Logged Utility Stream","Log/Notes","STF FN Shift","uSec Zero","ADS","Possible Copy","Possible Volume Move",\\"Filename #1\\",\\"Filename #2\\",\\"Filename #3\\",\\"Filename #4\\",\\"Std Info Access date\\"',
                                '"Record_Number","Good","Active","Record_type","Sequence_Number","Parent_File_Rec","Parent_File_Rec_Seq","Filename_1","Std_Info_Creation_date","Std_Info_Modification_date","Std_Info_Access_date","Std_Info_Entry_date","FN_Info_Creation_date1","FN_Info_Modification_date1","FN_Info_Access_date1","FN_Info_Entry_date1","Object_ID","Birth_Volume_ID","Birth_Object_ID","Birth_Domain_ID","Filename_2","FN_Info_Creation_date2","FN_Info_Modify_date2","FN_Info_Access_date2","FN_Info_Entry_date2","Filename_3","FN_Info_Creation_date3","FN_Info_Modify_date3","FN_Info_Access_date3","FN_Info_Entry_date3","Filename_4","FN_Info_Creation_date4","FN_Info_Modify_date4","FN_Info_Access_date4","FN_Info_Entry_date4","Standard_Information","Attribute_List","Filename","Object_ID","Volume_Name","Volume_Info","Data","Index_Root","Index_Allocation","Bitmap","Reparse_Point","EA_Information","EA","Property_Set","Logged_Utility_Stream","Log/Notes","STF_FN_Shift","uSec_Zero","ADS","Possible_Copy","Possible_Volume_Move","Filename1","Filename2","Filename3","Filename4","LastWriteTime"',
                            )
                            .split(",")
                        ),
                        0,
                    )
                    for mftentry in mftentries:
                        mftwrite.write(
                            str(mftentry.replace("\\", "").lower())
                            .replace('""', '"-"')
                            .replace(",,", ",-,")
                            .replace("filename", "Filename")
                            .replace("lastwritetime", "LastWriteTime")[1:-1]
                        )
                        if mftcounter <= 60:
                            mftwrite.write(",")
                        else:
                            pass
                        mftcounter += 1
                    mftwrite.write("\n")
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vssartefact
        + "MFT.csv",
        "a",
    ) as mftwrite:
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + ".MFT.csv"
        ) as mftread:
            for eachentry in mftread:
                mftwrite.write(eachentry.strip().strip(",") + "\n")
    if os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vssartefact
        + "..MFT.csv"
    ):
        os.remove(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + "..MFT.csv"
        )
        os.remove(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + ".MFT.csv"
        )
    else:
        pass
    print_done(verbosity)


def process_usb(
    verbosity,
    vssimage,
    output_directory,
    img,
    vssartefact,
    stage,
    artefact,
    jsondict,
    jsonlist,
):
    if verbosity != "":
        print("     Processing 'setupapi.dev.log' for {}...".format(vssimage))
    else:
        pass
    entry, prnt = "{},{},{},'setupapi.dev.log'\n".format(
        datetime.now().isoformat(), vssimage.replace("'", ""), stage
    ), " -> {} -> {} 'setupapi.dev.log' for {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    with open(artefact, encoding="ISO-8859-1") as setupapi:
        setupdata = setupapi.read()
    extract_usb(
        output_directory,
        img,
        vssartefact,
        jsondict,
        jsonlist,
        setupdata,
    )
    print_done(verbosity)


def process_shimcache(verbosity, vssimage, output_directory, img, vssartefact, stage):
    if verbosity != "":
        print("     Processing shimcache for {}...".format(vssimage))
    else:
        pass
    extract_shimcache(verbosity, vssimage, output_directory, img, vssartefact, stage)
    print_done(verbosity)


def process_registry_system(
    verbosity,
    vssimage,
    output_directory,
    img,
    vssartefact,
    stage,
    artefact,
    jsondict,
    jsonlist,
    cwd,
):
    regjsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vssartefact
        + "registry/"
        + artefact.split("/")[-1]
        + ".json"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vssartefact
                + "registry"
            )
        except:
            pass
        if verbosity != "":
            print(
                "     Processing '{}' registry hive for {}...".format(
                    artefact.split("/")[-1], vssimage
                )
            )
        else:
            pass
        entry, prnt = "{},{},{},'{}' registry hive\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
            artefact.split("/")[-1],
        ), " -> {} -> {} registry hive '{}' for {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            artefact.split("/")[-1],
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        extract_registry_system(
            output_directory,
            img,
            vssartefact,
            artefact,
            jsondict,
            jsonlist,
            cwd,
            regjsonlist,
        )
        print_done(verbosity)
    else:
        pass


def process_registry_user(
    verbosity,
    vssimage,
    output_directory,
    img,
    vssartefact,
    stage,
    artefact,
    jsondict,
    jsonlist,
    cwd,
):
    regusr, regart = artefact.split("/")[-1].split("+")
    regjsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vssartefact
        + "/registry/"
        + regusr
        + "+"
        + regart
        + ".json"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vssartefact
                + "/registry"
            )
        except:
            pass
        if verbosity != "":
            print(
                "     Processing '{}' {} registry hive for {}...".format(
                    regusr, regart, vssimage
                )
            )
        else:
            pass
        entry, prnt = "{},{},{},'{}' ({}) registry hive\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
            regart,
            regusr,
        ), " -> {} -> {} '{}' {} registry hive for {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            regusr,
            regart,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        extract_registry_users(
            output_directory,
            img,
            vssartefact,
            artefact,
            jsondict,
            jsonlist,
            cwd,
            regjsonlist,
            regusr,
            regart,
        )
        print_done(verbosity)
    else:
        pass


def process_evtx(
    verbosity,
    vssimage,
    output_directory,
    img,
    vssartefact,
    stage,
    artefact,
    jsondict,
    jsonlist,
):
    evtjsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vssartefact
        + "evt/"
        + artefact.split("/")[-1]
        + ".json"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vssartefact
                + "evt"
            )
        except:
            pass
        if verbosity != "":
            print(
                "     Processing '{}' event log for {}...".format(
                    artefact.split("/")[-1], vssimage
                )
            )
        else:
            pass
        extract_evtx(
            verbosity,
            vssimage,
            output_directory,
            img,
            vssartefact,
            stage,
            artefact,
            jsondict,
            jsonlist,
            evtjsonlist,
        )
    else:
        pass


def process_jumplists(
    verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vssartefact
        + "jumplists.csv"
    ):
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + "jumplists.csv",
            "a",
        ) as jumplistcsv:
            jumplistcsv.write("Device,Account,JumplistID,JumplistType\n")
    else:
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + "jumplists.csv",
            "a",
        ) as jumplistcsv:
            if os.path.exists(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vssartefact
                + "jumplists.csv"
            ):
                if verbosity != "":
                    print(
                        "     Processing Jumplist file '{}' ({}) for {}...".format(
                            artefact.split("+")[1],
                            artefact.split("/")[-1].split("+")[0],
                            vssimage,
                        )
                    )
                else:
                    pass
                (entry, prnt,) = "{},{},{},'{}' ({}) jumplist file\n".format(
                    datetime.now().isoformat(),
                    vssimage.replace("'", ""),
                    stage,
                    artefact.split("+")[1],
                    artefact.split("/")[-1].split("+")[0],
                ), " -> {} -> {} jumplist file '{}' ({}) for {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage,
                    artefact.split("+")[1],
                    artefact.split("/")[-1].split("+")[0],
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
                jumplistcsv.write(
                    img.split("::")[0]
                    + ","
                    + artefact.split("/")[-1].split("+")[0]
                    + ","
                    + artefact.split("+")[1].split(".")[0]
                    + ","
                    + artefact.split("+")[1].split(".")[1]
                    + "\n"
                )
                print_done(verbosity)
            else:
                pass


def process_outlook(
    verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
):
    if verbosity != "":
        print(
            "     Processing Outlook file '{}' ({}) for {}...".format(
                artefact.split("/")[-1],
                artefact.split("/")[-2],
                vssimage,
            )
        )
    else:
        pass
    (entry, prnt,) = "{},{},{},'{}' ({}) outlook file\n".format(
        datetime.now().isoformat(),
        vssimage.replace("'", ""),
        stage,
        artefact.split("/")[-1],
        artefact.split("/")[-2],
    ), " -> {} -> {} outlook file '{}' ({}) for {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        artefact.split("/")[-1],
        artefact.split("/")[-2],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    if not os.path.exists(os.path.join(artefact.split(".pst")[0])):
        subprocess.Popen(
            [
                "sudo",
                "readpst",
                artefact,
                "-D",
                "-S",
                "-o",
                "/".join(os.path.join(artefact.split(".pst")[0]).split("/")[:-1]),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
    else:
        pass
    print_done(verbosity)


def process_hiberfil(
    d,
    verbosity,
    vssimage,
    output_directory,
    img,
    vssartefact,
    stage,
    artefact,
    volatility,
    volchoice,
    vss,
    vssmem,
    memtimeline,
):
    if volatility:
        if not os.path.exists(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + "memory"
        ):
            if verbosity != "":
                print(
                    "     Processing '{}' for {}...".format(
                        artefact.split("/")[-1], vssimage
                    )
                )
            else:
                pass
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vssartefact
                + "memory"
            )
            profile, vssmem = process_memory(
                output_directory,
                verbosity,
                d,
                stage,
                img,
                artefact,
                volchoice,
                vss,
                vssmem,
                memtimeline,
            )
        else:
            pass
    else:
        pass
    return profile, vssmem


def process_pagefile(
    verbosity, vssimage, output_directory, img, vssartefact, stage, artefact
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vssartefact
        + "memory"
    ):
        if verbosity != "":
            print(
                "     Processing '{}' for {}...".format(
                    artefact.split("/")[-1], vssimage
                )
            )
        else:
            pass
        os.makedirs(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + "memory"
        )
        entry, prnt = "{},{},extracting strings,'{}'\n".format(
            datetime.now().isoformat(),
            vssimage,
            artefact.split("/")[-1],
        ), " -> {} -> extracting strings from '{}' for {}".format(
            datetime.now().isoformat().replace("T", " "),
            artefact.split("/")[-1],
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        subprocess.Popen(
            [
                "strings",
                artefact,
                ">>",
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vssartefact
                + "memory/"
                + artefact.split("/")[-1]
                + ".strings",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()[0]
        (entry, prnt,) = "{},{},extraction of strings complete,'{}'\n".format(
            datetime.now().isoformat(),
            vssimage,
            artefact.split("/")[-1],
        ), " -> {} -> extraction of strings from '{}' completed for {}".format(
            datetime.now().isoformat().replace("T", " "),
            artefact.split("/")[-1],
            vssimage,
        )
        print_done(verbosity)
    else:
        pass


# sudo readpst -o -D -j 4 -r -u -w -m
# pip install libpff-python
#  import pypff
#  pst = pypff.file()
#  pst.open("MyPst.pst")
#  pst.close()

# https://stackoverflow.com/questions/69905319/how-to-parse-read-outlook-pst-files-with-python
