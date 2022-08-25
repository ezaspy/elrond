#!/usr/bin/env python3 -tt
import os
import shutil
import subprocess
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.mount import obtain_offset


def check_i30directory(i30directory, img):
    if os.path.exists(i30directory) and img.split("::")[0] in str(i30directory):
        i30imagepath = i30directory
    else:
        i30imagepath = ""
    return i30imagepath


def rip_i30(output_directory, img, offset):
    indxripper_result = subprocess.Popen(
        [
            "sudo",
            "python3.9",
            "/opt/elrond/elrond/tools/INDXRipper/INDXRipper.py",
            "-w",
            "csv",
            "-o",
            "{}".format(offset),
            "/mnt/i30_{}/ewf1".format(img.split("::")[0]),
            output_directory
            + "artefacts/"
            + img.split("::")[0]
            + "/"
            + img.split("::")[0]
            + ".csv",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    return indxripper_result


def recover_files(
    output_directory,
    verbosity,
    stage,
    d,
    img,
    vssimage,
):
    if "Windows" in img.split("::")[1] and "memory_" not in img.split("::")[1]:
        try:
            for image_directory in os.listdir(d):
                i30imagepath = check_i30directory(
                    os.path.join(d, image_directory, img.split("::")[0]), img
                )
        except:
            i30imagepath = check_i30directory(os.path.join(d, img.split("::")[0]), img)
        if os.path.exists("/mnt/i30_{}".format(img.split("::")[0])):
            subprocess.Popen(
                ["umount", "/mnt/i30_{}".format(img.split("::")[0])],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
            shutil.rmtree("/mnt/i30_{}".format(img.split("::")[0]))
        else:
            pass
        os.mkdir("/mnt/i30_{}".format(img.split("::")[0]))
        os.chmod("/mnt/i30_{}".format(img.split("::")[0]), 0o0777)
        if img.split("::")[0].endswith(".E01") or img.split("::")[0].endswith(".e01"):
            subprocess.Popen(
                ["ewfmount", i30imagepath, "/mnt/i30_{}".format(img.split("::")[0])],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
            subprocess.Popen(
                ["chmod", "-f", "777", "/mnt/i30_{}".format(img.split("::")[0])]
            ).communicate()
            subprocess.Popen(
                [
                    "chmod",
                    "-f",
                    "777",
                    "/mnt/i30_{}/ewf1".format(img.split("::")[0]),
                ]
            ).communicate()
            indxripper_result = rip_i30(output_directory, img, "0")
            if "invalid volume boot record" in str(indxripper_result[1])[2:-3]:
                offset_values = obtain_offset(
                    "/mnt/i30_{}/ewf1".format(img.split("::")[0])
                )
                for eachoffset in offset_values:
                    indxripper_result = rip_i30(
                        output_directory, img, str(int(eachoffset) * 512)
                    )
                    if "construct.core.StreamError" in str(indxripper_result[1])[2:-3]:
                        entry, prnt = "{},{},recovery,$I30 records (failed)\n".format(
                            datetime.now().isoformat(),
                            vssimage.replace("'", ""),
                        ), " -> {} -> recovery of $I30 records failed from {}".format(
                            datetime.now().isoformat().replace("T", " "),
                            vssimage,
                        )
                        write_audit_log_entry(verbosity, output_directory, entry, prnt)
                    else:
                        pass
            else:
                entry, prnt = "{},{},{},$I30 records\n".format(
                    datetime.now().isoformat(),
                    vssimage.replace("'", ""),
                    stage,
                ), " -> {} -> {} $I30 records from {}".format(
                    datetime.now().isoformat().replace("T", " "),
                    stage,
                    vssimage,
                )
                write_audit_log_entry(verbosity, output_directory, entry, prnt)
        else:
            pass
        subprocess.Popen(
            ["umount", "/mnt/i30_{}".format(img.split("::")[0])],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        shutil.rmtree("/mnt/i30_{}".format(img.split("::")[0]))
    else:
        pass
