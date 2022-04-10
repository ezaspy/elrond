#!/usr/bin/env python3 -tt
import os
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.meta import collect_metadata
from rivendell.processing.memory import process_memory


def identify_disk_image(allimgs, ot):
    for i, m in allimgs.items():
        if "vss" not in i and os.path.isdir(m):
            if not m.endswith("/"):
                m = m + "/"
            else:
                pass
            if len(os.listdir(m)) > 0:
                if "Users" in str(os.listdir(m)) and "MFTMirr" in str(os.listdir(m)):
                    if "MSOCache" in str(os.listdir(m)):
                        ot[i + "::Windows7"] = m
                    else:
                        ot[i + "::Windows10"] = m
                elif "root" in str(os.listdir(m)) and "media" in str(os.listdir(m)):
                    ot[i + "::Linux"] = m
                elif os.path.exists(m + "root"):
                    if "Applications" in str(os.listdir(m + "root")):
                        ot[i + "::macOS"] = m + "root"
                    else:
                        pass
                else:
                    pass
            else:
                pass
        else:
            pass


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
            collect_metadata(
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
        print("   Identifying '{}', please stand by...".format(f))
        (entry, prnt,) = "{},{},identifying memory platform,{}\n".format(
            datetime.now().isoformat(), f, f
        ), " -> {} -> identifying memory platform for '{}'".format(
            datetime.now().isoformat().replace("T", " "), f
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        symbolprofile, vssmem = process_memory(
            output_directory,
            verbosity,
            d,
            "process",
            f,
            path,
            volchoice,
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
        ot[f + "::" + memoryplatform] = d
        print()
        flags.append("2processing")
        os.chdir(cwd)
    else:
        print("    OK. '{}' will not be processed.\n".format(f))
