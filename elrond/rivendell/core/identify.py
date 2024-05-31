#!/usr/bin/env python3 -tt
import os
import time
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.meta import extract_metadata
from rivendell.memory.memory import process_memory


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


def identify_disk_image(verbosity, output_directory, disk_image, mount_location):
    if not mount_location.endswith("/"):
        mount_location = mount_location + "/"
    if len(os.listdir(mount_location)) > 0:
        if (
            "MFTMirr" in str(os.listdir(mount_location))
            or ("Bitmap" in str(os.listdir(mount_location)))
            or ("LogFile" in str(os.listdir(mount_location)))
            or ("Boot" in str(os.listdir(mount_location)))
            or ("Windows" in str(os.listdir(mount_location)))
        ):
            if "MSOCache" in str(os.listdir(mount_location)):
                windows_os = "Windows7"
            elif "Windows" in str(os.listdir(mount_location)) or "Boot" in str(
                os.listdir(mount_location)
            ):
                if (
                    "BrowserCore" in str(os.listdir(mount_location + "Windows/"))
                    or "Containers" in str(os.listdir(mount_location + "Windows/"))
                    or "IdentityCRL" in str(os.listdir(mount_location + "Windows/"))
                ):
                    windows_os = "Windows Server 2022"
                elif (
                    "DsfrAdmin" in str(os.listdir(mount_location + "Windows/"))
                    and "WaaS" in str(os.listdir(mount_location + "Windows/"))
                    and "WMSysPr9.prx" in str(os.listdir(mount_location + "Windows/"))
                ):
                    windows_os = "Windows Server 2019"
                elif "InfusedApps" in str(os.listdir(mount_location + "Windows/")):
                    windows_os = "Windows Server 2016"
                elif "ToastData" in str(os.listdir(mount_location + "Windows/")):
                    windows_os = "Windows Server 2012R2"
                else:
                    windows_os = "Windows Server"
            else:
                windows_os = "Windows10"
            """
            else:
                windows_os = "Windows11"
            """
            print_identification(verbosity, output_directory, disk_image, windows_os)
            disk_image = disk_image + "::" + windows_os
        elif "root" in str(os.listdir(mount_location)) and "media" in str(
            os.listdir(mount_location)
        ):
            print_identification(verbosity, output_directory, disk_image, "Linux")
            disk_image = disk_image + "::Linux"
        elif os.path.exists(mount_location + "root"):
            if "Applications" in str(os.listdir(mount_location + "root")):
                print_identification(verbosity, output_directory, disk_image, "macOS")
                disk_image = disk_image + "::macOS"
    return disk_image


def identify_memory_image(
    verbosity,
    output_directory,
    flags,
    auto,
    superquick,
    quick,
    metacollected,
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
        if not superquick and not quick and not metacollected:
            extract_metadata(
                verbosity,
                output_directory,
                f,
                path,
                "metadata",
                sha256,
                nsrl,
            )
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
        ot[d] = "{}::{}_{}".format(
            f,
            memoryplatform.replace(" ", "_").split("_")[1],
            memoryplatform.replace(" ", "_").split("_")[0],
        )
        if "02processing" not in str(flags):
            flags.append("02processing")
        os.chdir(cwd)
    else:
        print("    OK. '{}' will not be processed.\n".format(f))
    return ot


def identify_gandalf_host(output_directory, verbosity, host_info_file):
    time.sleep(2)
    with open(host_info_file) as host_info:
        gandalf_host, osplatform = host_info.readline().strip().split("::")
    print_identification(verbosity, output_directory, gandalf_host, osplatform)
    return gandalf_host, osplatform
