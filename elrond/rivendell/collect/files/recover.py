#!/usr/bin/env python3 -tt
import os
import shutil
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def recover_files(
    output_directory,
    verbosity,
    stage,
    img,
    vssimage,
    recovered_file_root,
    recovered_file,
):
    if recovered_file.lower().endswith("$I30"):
        try:
            os.stat(os.path.join(output_directory, img.split("::")[0]) + "/recovered")
        except:
            os.makedirs(
                os.path.join(output_directory, img.split("::")[0]) + "/recovered"
            )
        try:
            os.stat(
                os.path.join(output_directory, img.split("::")[0])
                + "/recovered/"
                + recovered_file_root.split("/")[-1]
            )
        except:
            os.makedirs(
                os.path.join(output_directory, img.split("::")[0])
                + "/recovered/"
                + recovered_file_root.split("/")[-1]
            )
        try:
            shutil.copy2(
                os.path.join(recovered_file_root, recovered_file),
                output_directory + img.split("::")[0] + "/recovered",
            )
            (entry, prnt,) = "{},{},{},virtual file '{}'\n".format(
                datetime.now().isoformat(),
                img.split("::")[0],
                stage,
                recovered_file,
            ), " -> {} -> {} virtual file '{}' for '{}'".format(
                datetime.now().isoformat().replace("T", " "),
                stage.replace(",", " &"),
                recovered_file,
                vssimage,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
        except:
            pass
    else:
        pass
