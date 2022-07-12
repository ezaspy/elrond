#!/usr/bin/env python3 -tt
import os
import re
import subprocess
from datetime import datetime

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry
from rivendell.process.memory import process_memory
from rivendell.process.extractions.evtx import extract_evtx
from rivendell.process.extractions.registry.system import extract_registry_system
from rivendell.process.extractions.registry.users import extract_registry_users
from rivendell.process.extractions.shimcache import extract_shimcache
from rivendell.process.extractions.usb import extract_usb


def process_mft(verbosity, vssimage, output_directory, img, vssartefact, stage):
    if verbosity != "":
        print("     Processing '$MFT' for {}...".format(vssimage))
    else:
        pass
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vssartefact
        + "..journal_mft.csv",
        "a",
    ) as mftcsv:
        entry, prnt = "{},{},{},'$MFT'\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
        ), " -> {} -> {} '$MFT' from {}".format(
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
                    + "..journal_mft.csv",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
            mftcsv.write(str(mftout.communicate()[0]))
        except:
            pass
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + ".journal_mft.csv",
            "a",
        ) as mftwrite:
            mftwrite.write(
                "record,state,active,record_type,seq_number,parent_file_record,parent_file_record_seq,std_info_creation_date,std_info_modification_date,std_info_access_date,std_info_entry_date,object_id,birth_volume_id,birth_object_id,birth_domain_id,std_info,attribute_list,has_filename,has_object_id,volume_name,volume_info,data,index_root,index_allocation,bitmap,reparse_point,ea_information,ea,property_set,logged_utility_stream,log/notes,stf_fn_shift,usec_zero,ads,possible_copy,possible_volume_move,Filename,fn_info_creation_date,fn_info_modification_date,fn_info_access_date,fn_info_entry_date,LastWriteTime\n"
            )
            with open(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vssartefact
                + "..journal_mft.csv"
            ) as mftread:
                for eachinfo in mftread:
                    try:
                        mftentries = (
                            list(
                                str(
                                    re.sub(
                                        r"([^\"])\,([^\"])",
                                        r"\1\2",
                                        eachinfo.strip(),
                                    ),
                                ).split(",")
                            ),
                        )
                        mftrow_information = (
                            mftentries[0][0].strip('"').strip(",")
                            + ","
                            + mftentries[0][1].strip('"').strip(",")
                            + ","
                            + mftentries[0][2].strip('"').strip(",")
                            + ","
                            + mftentries[0][3].strip('"').strip(",")
                            + ","
                            + mftentries[0][4].strip('"').strip(",")
                            + ","
                            + mftentries[0][5].strip('"').strip(",")
                            + ","
                            + mftentries[0][6].strip('"').strip(",")
                            + ","
                            + mftentries[0][8].strip('"').strip(",")
                            + ","
                            + mftentries[0][9].strip('"').strip(",")
                            + ","
                            + mftentries[0][10].strip('"').strip(",")
                            + ","
                            + mftentries[0][11].strip('"').strip(",")
                            + ","
                            + mftentries[0][16].strip('"').strip(",")
                            + ","
                            + mftentries[0][17].strip('"').strip(",")
                            + ","
                            + mftentries[0][18].strip('"').strip(",")
                            + ","
                            + mftentries[0][19].strip('"').strip(",")
                            + ","
                            + mftentries[0][35].strip('"').strip(",")
                            + ","
                            + mftentries[0][36].strip('"').strip(",")
                            + ","
                            + mftentries[0][37].strip('"').strip(",")
                            + ","
                            + mftentries[0][38].strip('"').strip(",")
                            + ","
                            + mftentries[0][39].strip('"').strip(",")
                            + ","
                            + mftentries[0][40].strip('"').strip(",")
                            + ","
                            + mftentries[0][41].strip('"').strip(",")
                            + ","
                            + mftentries[0][42].strip('"').strip(",")
                            + ","
                            + mftentries[0][43].strip('"').strip(",")
                            + ","
                            + mftentries[0][44].strip('"').strip(",")
                            + ","
                            + mftentries[0][45].strip('"').strip(",")
                            + ","
                            + mftentries[0][46].strip('"').strip(",")
                            + ","
                            + mftentries[0][47].strip('"').strip(",")
                            + ","
                            + mftentries[0][48].strip('"').strip(",")
                            + ","
                            + mftentries[0][49].strip('"').strip(",")
                            + ","
                            + mftentries[0][50].strip('"').strip(",")
                            + ","
                            + mftentries[0][51].strip('"').strip(",")
                            + ","
                            + mftentries[0][52].strip('"').strip(",")
                            + ","
                            + mftentries[0][53].strip('"').strip(",")
                            + ","
                            + mftentries[0][54].strip('"').strip(",")
                            + ","
                            + mftentries[0][55].strip('"').strip(",")
                        )
                        mftrow = (
                            mftrow_information
                            + ","
                            + mftentries[0][7].strip('"').strip(",")
                            + ","
                            + mftentries[0][12].strip('"').strip(",")
                            + ","
                            + mftentries[0][13].strip('"').strip(",")
                            + ","
                            + mftentries[0][14].strip('"').strip(",")
                            + ","
                            + mftentries[0][15].strip('"').strip(",")
                            + ","
                            + mftentries[0][13].strip('"').strip(",")
                        )
                        if len(mftentries[0][20].strip('"').strip(",")) > 0:
                            mftrow = (
                                "\n"
                                + mftrow_information
                                + ","
                                + mftentries[0][20].strip('"').strip(",")
                                + ","
                                + mftentries[0][21].strip('"').strip(",")
                                + ","
                                + mftentries[0][22].strip('"').strip(",")
                                + ","
                                + mftentries[0][23].strip('"').strip(",")
                                + ","
                                + mftentries[0][24].strip('"').strip(",")
                                + ","
                                + mftentries[0][22].strip('"').strip(",")
                            )
                        else:
                            pass
                        if len(mftentries[0][25].strip('"').strip(",")) > 0:
                            mftrow = (
                                "\n"
                                + mftrow_information
                                + ","
                                + mftentries[0][25].strip('"').strip(",")
                                + ","
                                + mftentries[0][26].strip('"').strip(",")
                                + ","
                                + mftentries[0][27].strip('"').strip(",")
                                + ","
                                + mftentries[0][28].strip('"').strip(",")
                                + ","
                                + mftentries[0][29].strip('"').strip(",")
                                + ","
                                + mftentries[0][27].strip('"').strip(",")
                            )
                        else:
                            pass
                        if len(mftentries[0][30].strip('"').strip(",")) > 0:
                            mftrow = (
                                "\n"
                                + mftrow_information
                                + ","
                                + mftentries[0][30].strip('"').strip(",")
                                + ","
                                + mftentries[0][31].strip('"').strip(",")
                                + ","
                                + mftentries[0][32].strip('"').strip(",")
                                + ","
                                + mftentries[0][33].strip('"').strip(",")
                                + ","
                                + mftentries[0][34].strip('"').strip(",")
                                + ","
                                + mftentries[0][32].strip('"').strip(",")
                            )
                        else:
                            pass
                        if (
                            "record number,good,active,record type,sequence number,parent file rec"
                            not in mftrow.lower()
                            and "NoFNRecord,NoFNRecord,NoFNRecord,NoFNRecord,NoFNRecord,NoFNRecord"
                            not in mftrow
                        ):
                            mftwrite.write(mftrow + "\n")
                    except:
                        pass
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vssartefact
        + "journal_mft.csv",
        "a",
    ) as mftwrite:
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + ".journal_mft.csv"
        ) as mftread:
            for eachentry in mftread:
                if len(eachentry.strip()) > 0:
                    mftwrite.write(
                        eachentry.strip().strip(",").replace(",,", ",-,") + "\n"
                    )
                else:
                    pass
    if os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vssartefact
        + "..journal_mft.csv"
    ):
        os.remove(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + "..journal_mft.csv"
        )
        os.remove(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vssartefact
            + ".journal_mft.csv"
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
    ), " -> {} -> {} 'setupapi.dev.log' from {}".format(
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
        ), " -> {} -> {} registry hive '{}' from {}".format(
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
        ), " -> {} -> {} '{}' {} registry hive from {}".format(
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
                ), " -> {} -> {} jumplist file '{}' ({}) from {}".format(
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
    ), " -> {} -> {} outlook file '{}' ({}) from {}".format(
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
    volchoice,
    vss,
    vssmem,
    memtimeline,
):
    if verbosity != "":
        print(
            "     Processing '{}' for {}...".format(artefact.split("/")[-1], vssimage)
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
    return profile, vssmem


def process_pagefile(verbosity, vssimage, output_directory, img, vssartefact, artefact):
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
        ), " -> {} -> extracting strings from '{}' from {}".format(
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
        ), " -> {} -> extraction of strings from '{}' completed from {}".format(
            datetime.now().isoformat().replace("T", " "),
            artefact.split("/")[-1],
            vssimage,
        )
        print_done(verbosity)
    else:
        pass
