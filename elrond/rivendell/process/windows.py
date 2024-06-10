#!/usr/bin/env python3 -tt
import os
import subprocess
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.memory.memory import process_memory
from rivendell.process.extractions.clipboard import extract_clipboard
from rivendell.process.extractions.evtx import extract_evtx
from rivendell.process.extractions.mft import extract_mft
from rivendell.process.extractions.registry.profile import extract_registry_profile
from rivendell.process.extractions.registry.system import extract_registry_system
from rivendell.process.extractions.shimcache import extract_shimcache
from rivendell.process.extractions.usb import extract_usb
from rivendell.process.extractions.usn import extract_usn
from rivendell.process.extractions.wbem import extract_wbem
from rivendell.process.extractions.wmi import extract_wmi


def process_mft(
    verbosity, vssimage, output_directory, img, artefact, vss_path_insert, stage
):
    if verbosity != "":
        print(
            "     Processing '{}' for {}...".format(artefact.split("/")[-1], vssimage)
        )
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "..journal_mft.csv",
        "a",
    ) as mftcsv:
        try:
            entry, prnt = "{},{},{},'{}'\n".format(
                datetime.now().isoformat(),
                vssimage.replace("'", ""),
                stage,
                vss_path_insert,
            ), " -> {} -> {} '{}' from {}".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                artefact.split("/")[-1],
                vssimage,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            mftout = subprocess.Popen(
                [
                    "analyzeMFT.py",
                    "-a",
                    "-f",
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/raw"
                    + vss_path_insert
                    + "$MFT",
                    "-o",
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/cooked"
                    + vss_path_insert
                    + "..journal_mft.csv",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
            mftcsv.write(str(mftout[0]))
        except:
            pass
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + ".journal_mft.csv",
            "a",
        ) as mftwrite:
            if not os.path.exists(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "journal_mft.csv"
            ):
                mftwrite.write(
                    "record,state,active,record_type,seq_number,parent_file_record,parent_file_record_seq,std_info_creation_date,std_info_modification_date,std_info_access_date,std_info_entry_date,object_id,birth_volume_id,birth_object_id,birth_domain_id,std_info,attribute_list,has_filename,has_object_id,volume_name,volume_info,data,index_root,index_allocation,bitmap,reparse_point,ea_information,ea,property_set,logged_utility_stream,log/notes,stf_fn_shift,usec_zero,ads,possible_copy,possible_volume_move,Filename,fn_info_creation_date,fn_info_modification_date,fn_info_access_date,fn_info_entry_date,LastWriteTime\n"
                )
            extract_mft(
                output_directory,
                img,
                vss_path_insert,
                mftwrite,
            )
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "journal_mft.csv",
        "a",
    ) as mftwrite:
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + ".journal_mft.csv"
        ) as mftread:
            for eachentry in mftread:
                if len(eachentry.strip()) > 0:
                    mftwrite.write(
                        eachentry.strip().strip(",").replace(",,", ",-,") + "\n"
                    )
    if os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "..journal_mft.csv"
    ):
        os.remove(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "..journal_mft.csv"
        )
        os.remove(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + ".journal_mft.csv"
        )


def process_usn(
    verbosity, vssimage, output_directory, img, artefact, vss_path_insert, stage
):
    if verbosity != "":
        print(
            "     Processing '{}' for {}...".format(artefact.split("/")[-1], vssimage)
        )
    extract_usn(verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact)


def process_usb(
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
    if verbosity != "":
        print(
            "     Processing '{}' for {}...".format(artefact.split("/")[-1], vssimage)
        )
    entry, prnt = "{},{},{},'{}'\n".format(
        datetime.now().isoformat(), vssimage.replace("'", ""), stage, vss_path_insert
    ), " -> {} -> {} '{}' from {}".format(
        datetime.now().isoformat().replace("T", " "),
        stage,
        artefact.split("/")[-1],
        vssimage,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    with open(artefact, encoding="ISO-8859-1") as setupapi:
        setupdata = setupapi.read()
    extract_usb(
        output_directory,
        img,
        vss_path_insert,
        jsondict,
        jsonlist,
        setupdata,
    )


def process_shimcache(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage
):
    if verbosity != "":
        print("     Processing shimcache for {}...".format(vssimage))
    extract_shimcache(
        verbosity, vssimage, output_directory, img, vss_path_insert, stage
    )


def process_registry_system(
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
    regjsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "registry/"
        + artefact.split("/")[-1]
        + ".json"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
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
            vss_path_insert,
            artefact,
            jsondict,
            jsonlist,
            regjsonlist,
        )


def process_registry_profile(
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
    regusr, regart = artefact.split("/")[-1].split("+")
    regjsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
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
                + vss_path_insert
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
        extract_registry_profile(
            output_directory,
            img,
            vss_path_insert,
            artefact,
            jsondict,
            jsonlist,
            regjsonlist,
            regusr,
            regart,
        )


def process_evtx(
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
    evtjsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "evt/"
        + artefact.split("/")[-1]
        + ".json"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
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
        extract_evtx(
            verbosity,
            vssimage,
            output_directory,
            img,
            vss_path_insert,
            stage,
            artefact,
            jsondict,
            jsonlist,
            evtjsonlist,
        )


def process_clipboard(
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
    clipjsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "clipboard/"
        + artefact.split("/")[-1]
        + ".json"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "clipboard"
            )
        except:
            pass
        if verbosity != "":
            print(
                "     Processing '{}' ({}) clipboard evidence for {}...".format(
                    artefact.split("/")[-1].split("_")[-1],
                    artefact.split("/")[-1].split("+")[0],
                    vssimage,
                )
            )
        extract_clipboard(
            verbosity,
            vssimage,
            output_directory,
            img,
            vss_path_insert,
            stage,
            artefact,
            jsondict,
            jsonlist,
            clipjsonlist,
        )


def process_prefetch(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    mount_location,
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "prefetch"
    ):
        os.makedirs(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "prefetch"
        )
        if verbosity != "":
            print("     Processing prefetch files for {}...".format(vssimage))
        entry, prnt = "{},{},{},prefetch files\n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
        ), " -> {} -> {} prefetch files for {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        try:
            subprocess.Popen(
                [
                    "log2timeline.py",
                    "--parsers",
                    "prefetch",
                    "{}/Windows/Prefetch/".format(mount_location),
                    "--storage_file",
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/cooked"
                    + vss_path_insert
                    + "prefetch/prefetch.plaso",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
            subprocess.Popen(
                [
                    "psteal.py",
                    "--source",
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/cooked"
                    + vss_path_insert
                    + "prefetch/prefetch.plaso",
                    "-o",
                    "dynamic",
                    "-w",
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/cooked"
                    + vss_path_insert
                    + "prefetch/prefetch.csv",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
        except:
            subprocess.Popen(
                [
                    "/opt/plaso/plaso/scripts/log2timeline.py",
                    "--parsers",
                    "prefetch",
                    "{}/Windows/Prefetch/".format(mount_location),
                    "--storage_file",
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/cooked"
                    + vss_path_insert
                    + "prefetch/prefetch.plaso",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
            subprocess.Popen(
                [
                    "/opt/plaso/plaso/scripts/psteal.py",
                    "--source",
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/cooked"
                    + vss_path_insert
                    + "prefetch/prefetch.plaso",
                    "-o",
                    "dynamic",
                    "-w",
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/cooked"
                    + vss_path_insert
                    + "prefetch/prefetch.csv",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
        if os.path.exists(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "prefetch/prefetch.plaso"
        ):
            os.remove(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "prefetch/prefetch.plaso"
            )


def process_wmi(
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
    wmijsonlist = []
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "wmi/"
        + artefact.split("/")[-1]
        + ".json"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "wmi"
            )
        except:
            pass
        if verbosity != "":
            print(
                "     Processing WMI '{}' for {}...".format(
                    artefact.split("/")[-1].split("_")[-1],
                    vssimage,
                )
            )
        extract_wmi(
            verbosity,
            vssimage,
            output_directory,
            img,
            vss_path_insert,
            stage,
            artefact,
            jsondict,
            jsonlist,
            wmijsonlist,
        )


def process_wbem(
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
    stage,
    artefact,
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "wbem/"
        + artefact.split("/")[-1]
        + ".json"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "wbem"
            )
        except:
            pass
        if verbosity != "":
            print(
                "     Processing WBEM '{}' for {}...".format(
                    artefact.split("/")[-1].split("_")[-1],
                    vssimage,
                )
            )
        extract_wbem(
            verbosity,
            vssimage,
            output_directory,
            img,
            vss_path_insert,
            stage,
            artefact,
        )


def process_sru(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    cooked_xlsx = output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert + "sru/" + artefact.split("/")[-1] + ".xlsx"
    if not os.path.exists(
        cooked_xlsx
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "sru"
            )
        except:
            pass
        if verbosity != "":
            print(
                "     Processing System Resource Utilisation database '{}' for {}...".format(
                    artefact.split("/")[-1].split("_")[-1],
                    vssimage,
                )
            )
        entry, prnt = "{},{},{},'{}' system resource utilisation database \n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
            artefact.split("/")[-1].split("_")[-1],
        ), " -> {} -> {} '{}' for {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            artefact.split("/")[-1].split("_")[-1],
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        # creating srum_dump2.py with respective artefact input and output values
        with open("/opt/elrond/elrond/tools/srum_dump/srum_dump.py") as srumdumpfile:
            srumdump = srumdumpfile.read()
        srumdump = srumdump.replace('<SRUDB.dat>', artefact).replace('<SRUM_DUMP_OUTPUT.xlsx>', cooked_xlsx)
        with open("/opt/elrond/elrond/tools/srum_dump/.srum_dump.py", "w") as srumdumpfile:
            srumdumpfile.write(srumdump)
        subprocess.Popen(
            [
                "python3",
                "/opt/elrond/elrond/tools/srum_dump/.srum_dump.py",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        os.remove("/opt/elrond/elrond/tools/srum_dump/.srum_dump.py")
        # cooked_csv = output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert + "sru/" + artefact.split("/")[-1] + ".csv"
        # cooked_json = output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert + "sru/" + artefact.split("/")[-1] + ".json"
        # read from "/opt/elrond/elrond/tools/srum-dump/SRUM_TEMPLATE2.XLSX" using pandas to then convert into csv/json


def process_ual(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "ual/"
        + artefact.split("/")[-1]
        + ".csv"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
                + "ual"
            )
        except:
            pass
        if verbosity != "":
            print(
                "     Processing User Access Log '{}' for {}...".format(
                    artefact.split("/")[-1].split("_")[-1],
                    vssimage,
                )
            )
        entry, prnt = "{},{},{},'{}' user access log \n".format(
            datetime.now().isoformat(),
            vssimage.replace("'", ""),
            stage,
            artefact.split("/")[-1].split("_")[-1],
        ), " -> {} -> {} '{}' for {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            artefact.split("/")[-1].split("_")[-1],
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        try:
            kstrike_list = str(
                subprocess.Popen(
                    [
                        "python3",
                        "/opt/elrond/elrond/tools/KStrike/KStrike.py",
                        artefact,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[0]
            )[2:-4].split("\\r\\n")
            if len(kstrike_list) > 0:
                with open(
                    output_directory
                    + img.split("::")[0]
                    + "/artefacts/cooked"
                    + vss_path_insert
                    + "ual/"
                    + artefact.split("/")[-1]
                    + ".csv",
                    "a",
                ) as ual_csv:
                    ual_csv.write(
                        "{},LastWriteTime\n".format(
                            kstrike_list[0][0:-4].replace(",", "").replace("||", ","),
                        )
                    )
                    for ual_entry in kstrike_list[1:]:
                        ual_csv.write(
                            "{},{}\n".format(
                                ual_entry[0:-4].replace(",", "").replace("||", ","),
                                ual_entry.split("||")[4],
                            )
                        )
        except KeyError as error:
            entry, prnt = "{},{},{},'{}' user access log [{}]\n".format(
                error,
                datetime.now().isoformat(),
                vssimage.replace("'", ""),
                stage,
                artefact.split("/")[-1].split("_")[-1],
            ), " -> {} -> {} '{}' experienced {} for {}".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                artefact.split("/")[-1].split("_")[-1],
                error,
                vssimage,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)


def process_jumplists(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "jumplists.csv"
    ):
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "jumplists.csv",
            "a",
        ) as jumplistcsv:
            jumplistcsv.write("Device,Account,JumplistID,JumplistType\n")
    else:
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "jumplists.csv",
            "a",
        ) as jumplistcsv:
            if os.path.exists(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
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
                (
                    entry,
                    prnt,
                ) = "{},{},{},'{}' ({}) jumplist file\n".format(
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


def process_outlook(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    if verbosity != "":
        print(
            "     Processing Outlook file '{}' ({}) for {}...".format(
                artefact.split("/")[-1],
                artefact.split("/")[-2],
                vssimage,
            )
        )
    (
        entry,
        prnt,
    ) = "{},{},{},'{}' ({}) outlook file\n".format(
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


def process_hiberfil(
    d,
    verbosity,
    vssimage,
    output_directory,
    img,
    vss_path_insert,
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
    os.makedirs(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
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


def process_pagefile(
    verbosity, vssimage, output_directory, img, vss_path_insert, artefact
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "memory"
    ):
        if verbosity != "":
            print(
                "     Processing '{}' for {}...".format(
                    artefact.split("/")[-1], vssimage
                )
            )
        os.makedirs(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
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
                + vss_path_insert
                + "memory/"
                + artefact.split("/")[-1]
                + ".strings",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()[0]
        (
            entry,
            prnt,
        ) = "{},{},extraction of strings complete,'{}'\n".format(
            datetime.now().isoformat(),
            vssimage,
            artefact.split("/")[-1],
        ), " -> {} -> extraction of strings from '{}' completed from {}".format(
            datetime.now().isoformat().replace("T", " "),
            artefact.split("/")[-1],
            vssimage,
        )
