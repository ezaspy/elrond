#!/usr/bin/env python3 -tt
import os
import time
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.meta import extract_metadata
from rivendell.process.memory import process_memory


def identify_disk_image(verbosity, output_directory, disk_image, mount_location):
    def print_identification(verbosity, output_directory, disk_image, osplatform):
        print("   Identified platform of '{}' for '{}'.".format(osplatform, disk_image))
        entry, prnt = "{},{},identified platform,{}\n".format(
            datetime.now().isoformat(),
            disk_image,
            osplatform,
        ), " -> {} -> identified platform of '{}' for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            osplatform,
            disk_image,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)

    if not mount_location.endswith("/"):
        mount_location = mount_location + "/"
    else:
        pass
    if len(os.listdir(mount_location)) > 0:
        if "Users" in str(os.listdir(mount_location)) and "MFTMirr" in str(
            os.listdir(mount_location)
        ):
            if "MSOCache" in str(os.listdir(mount_location)):
                print_identification(
                    verbosity, output_directory, disk_image, "Windows7"
                )
                disk_image = disk_image + "::Windows7"
            else:
                print_identification(
                    verbosity, output_directory, disk_image, "Windows10"
                )
                disk_image = disk_image + "::Windows10"
        elif "root" in str(os.listdir(mount_location)) and "media" in str(
            os.listdir(mount_location)
        ):
            print_identification(verbosity, output_directory, disk_image, "Linux")
            disk_image = disk_image + "::Linux"
        elif os.path.exists(mount_location + "root"):
            if "Applications" in str(os.listdir(mount_location + "root")):
                print_identification(verbosity, output_directory, disk_image, "macOS")
                disk_image = disk_image + "::macOS"
            else:
                pass
        else:
            pass
    else:
        pass
    return disk_image


def identify_memory_image(
    verbosity,
    output_directory,
    flags,
    auto,
    superquick,
    quick,
    hashcollected,
    cwd,
    sha256,
    nsrl,
    f,
    ot,
    d,
    path,
    volchoice,
    vss,
    vssmem,
    memtimeline,
):
    if not auto:
        wtm = input("  Do you wish to process '{}'? Y/n [Y] ".format(f))
    else:
        wtm = "y"
    if wtm != "n":
        if not superquick and not quick and not hashcollected:
            extract_metadata(
                verbosity,
                output_directory,
                f,
                path,
                "metadata",
                sha256,
                nsrl,
            )
        else:
            pass
        entry, prnt = (
            "LastWriteTime,elrond_host,elrond_stage,elrond_log_entry\n",
            " -> {} -> created audit log file for '{}'".format(
                datetime.now().isoformat().replace("T", " "), f
            ),
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        if volchoice == "2.6":
            symbolprofile, vssmem = process_memory(
                output_directory,
                verbosity,
                d,
                "process",
                f,
                path,
                "2.6",
                vss,
                vssmem,
                memtimeline,
            )
        elif volchoice == "3":
            symbolprofile, vssmem = process_memory(
                output_directory,
                verbosity,
                d,
                "process",
                f,
                path,
                "3",
                vss,
                vssmem,
                memtimeline,
            )
        else:
            symbolprofile, vssmem = process_memory(
                output_directory,
                verbosity,
                d,
                "process",
                f,
                path,
                "2.6",
                vss,
                vssmem,
                memtimeline,
            )
            symbolprofile, vssmem = process_memory(
                output_directory,
                verbosity,
                d,
                "process",
                f,
                path,
                "3",
                vss,
                vssmem,
                memtimeline,
            )
        if "Win" in symbolprofile or "win" in symbolprofile:
            memoryplatform = "Windows memory"
        elif (
            "macOS" == symbolprofile
            or "Mac" in symbolprofile
            or "11." in symbolprofile
            or "10." in symbolprofile
        ):
            memoryplatform = "macOS memory"
        else:
            memoryplatform = "Linux memory"
        ot[
            f
            + "::"
            + memoryplatform.replace(" ", "_").split("_")[1]
            + "_"
            + memoryplatform.replace(" ", "_").split("_")[0]
        ] = d
        if "02processing" not in str(flags):
            flags.append("02processing")
        else:
            pass
        os.chdir(cwd)
    else:
        print("    OK. '{}' will not be processed.\n".format(f))
    return ot


def identify_gandalf_host(output_directory, verbosity, host_info_file):
    time.sleep(2)
    with open(host_info_file) as host_info:
        gandalf_host, osplatform = host_info.readline().strip().split("::")
    print("   Identified platform of '{}' for '{}'.".format(osplatform, gandalf_host))
    (entry, prnt,) = "{},{},identified platform,{}\n".format(
        datetime.now().isoformat(),
        gandalf_host,
        osplatform,
    ), " -> {} -> identified platform of '{}' for '{}'".format(
        datetime.now().isoformat().replace("T", " "),
        osplatform,
        gandalf_host,
    )
    write_audit_log_entry(verbosity, output_directory, entry, prnt)
    return gandalf_host, osplatform
