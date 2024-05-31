#!/usr/bin/env python3 -tt
import os
import shutil
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def multiple_files(source, destination, increment):
    def copy_files(source, destination, increment):
        if os.path.exists(source):
            shutil.copy2(source, destination + "." + str(increment))

    if os.path.exists(destination + "." + str(increment)):
        increment += 1
        multiple_files(source, destination, increment)
    else:
        copy_files(source, destination, increment)
        increment += 1


def compare_include_exclude(
    output_directory,
    verbosity,
    stage,
    img,
    vssimage,
    recpath,
    filetype,
    recovered_file_root,
    recovered_file,
    increment,
    collectfiles,
):
    def successful_copy(
        verbosity, output_directory, img, stage, vssimage, recovered_file, filetype
    ):
        (
            entry,
            prnt,
        ) = "{},{},{},{} '{}'\n".format(
            datetime.now().isoformat(),
            img.split("::")[0],
            stage,
            filetype,
            recovered_file,
        ), " -> {} -> {} {} '{}' from {}".format(
            datetime.now().isoformat().replace("T", " "),
            stage.replace(",", " &"),
            filetype,
            recovered_file,
            vssimage,
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)

    if os.path.exists(
        output_directory + img.split("::")[0] + recpath + recovered_file
    ):  # multiple files with the same name
        if collectfiles != True:
            with open(collectfiles.split(":")[1]) as include_or_exclude_selection_file:
                for inc_ex_line in include_or_exclude_selection_file:
                    if collectfiles.split(":")[0] == "include" and (
                        inc_ex_line.strip() in recovered_file
                    ):
                        multiple_files(
                            os.path.join(recovered_file_root, recovered_file),
                            output_directory
                            + img.split("::")[0]
                            + recpath
                            + recovered_file,
                            increment,
                        )
                        successful_copy(
                            verbosity,
                            output_directory,
                            img,
                            stage,
                            vssimage,
                            recovered_file,
                            filetype,
                        )
                    elif collectfiles.split(":")[0] == "exclude" and (
                        inc_ex_line.strip() not in recovered_file
                    ):
                        multiple_files(
                            os.path.join(recovered_file_root, recovered_file),
                            output_directory
                            + img.split("::")[0]
                            + recpath
                            + recovered_file,
                            increment,
                        )
                        successful_copy(
                            verbosity,
                            output_directory,
                            img,
                            stage,
                            vssimage,
                            recovered_file,
                            filetype,
                        )
        else:
            multiple_files(
                os.path.join(recovered_file_root, recovered_file),
                output_directory + img.split("::")[0] + recpath + recovered_file,
                increment,
            )
    else:  # files with unique name
        if collectfiles != True:
            with open(collectfiles.split(":")[1]) as include_or_exclude_selection_file:
                for inc_ex_line in include_or_exclude_selection_file:
                    if collectfiles.split(":")[0] == "include" and (
                        inc_ex_line.strip() in recovered_file
                    ):
                        if os.path.exists(
                            os.path.join(recovered_file_root, recovered_file)
                        ):
                            shutil.copy2(
                                os.path.join(recovered_file_root, recovered_file),
                                output_directory + img.split("::")[0] + recpath,
                            )
                            successful_copy(
                                verbosity,
                                output_directory,
                                img,
                                stage,
                                vssimage,
                                recovered_file,
                                filetype,
                            )
                        else:
                            copy_success = False
                    elif collectfiles.split(":")[0] == "exclude" and (
                        inc_ex_line.strip() not in recovered_file
                    ):
                        if os.path.exists(
                            os.path.join(recovered_file_root, recovered_file)
                        ):
                            shutil.copy2(
                                os.path.join(recovered_file_root, recovered_file),
                                output_directory + img.split("::")[0] + recpath,
                            )
                            successful_copy(
                                verbosity,
                                output_directory,
                                img,
                                stage,
                                vssimage,
                                recovered_file,
                                filetype,
                            )
                        else:
                            copy_success = False
                    else:
                        copy_success = False
        else:
            if os.path.exists(os.path.join(recovered_file_root, recovered_file)):
                shutil.copy2(
                    os.path.join(recovered_file_root, recovered_file),
                    output_directory + img.split("::")[0] + recpath,
                )
                successful_copy(
                    verbosity,
                    output_directory,
                    img,
                    stage,
                    vssimage,
                    recovered_file,
                    filetype,
                )
            else:
                copy_success = False
