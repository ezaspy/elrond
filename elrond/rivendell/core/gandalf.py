import getpass
import os
import shutil
import subprocess
import sys
from datetime import datetime
from zipfile import ZipFile

from rivendell.audit import write_audit_log_entry
from rivendell.core.identify import identify_gandalf_host
from rivendell.core.identify import identify_memory_image


def assess_gandalf(
    auto,
    gandalf,
    vss,
    nsrl,
    volatility,
    metacollected,
    superquick,
    quick,
    ot,
    d,
    cwd,
    sha256,
    flags,
    output_directory,
    verbosity,
    allimgs,
    imgs,
    volchoice,
    vssmem,
    memtimeline,
):
    def extract7z(output_directory, verbosity, groot, gfile, pw_7z, iteration):
        out_7z = str(
            subprocess.Popen(
                [
                    "7z",
                    "x",
                    os.path.join(groot, gfile),
                    "-o" + os.path.join(output_directory, groot.split("/")[-1]),
                    "-p{}".format(pw_7z),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
        )
        if "Wrong password" in out_7z:
            if iteration == "First":
                pw_7z = getpass.getpass(
                    "    Encrypted archive; please provide password: "
                )
            else:
                pw_7z = getpass.getpass("    Incorrect password; please try again: ")
            out_7z = extract7z(output_directory, verbosity, groot, gfile, pw_7z, "1")

    if not d.endswith("/"):
        d = d + "/"
    if not d.endswith("/acquisitions/"):
        print(
            "   Hosts, must be in the 'acquisitions' directory, produced from gandalf's output.\n    For example, '/{}/acquisitions/'\n     Please try again\n\n".format(
                d.strip("/")
            )
        )
        sys.exit()
    for groot, _, gfiles in os.walk(d):
        for gfile in gfiles:
            if gfile.endswith("log.audit"):  # copying gandalf audit file
                gandalf_audit_source = os.path.join(groot, gfile)
                gandalf_audit_destination = os.path.join(
                    output_directory, groot.split("/")[-1]
                )
                if not os.path.exists(gandalf_audit_destination):
                    os.makedirs(gandalf_audit_destination)
                try:
                    shutil.copy2(
                        gandalf_audit_source,
                        os.path.join(gandalf_audit_destination, "gandalf_log.audit"),
                    )
                except:
                    pass
            if os.path.join(groot, gfile).endswith(".zip") or os.path.join(
                groot, gfile
            ).endswith(".7z"):
                source_filepath = os.path.join(output_directory, groot.split("/")[-1])
                if gfile.endswith(".zip"):
                    if not os.path.exists(
                        os.path.join(
                            output_directory,
                            groot.split("/")[-1],
                            gfile.strip(".zip").strip(".7z"),
                        )
                    ):
                        os.makedirs(
                            os.path.join(output_directory, groot.split("/")[-1])
                        )
                        entry, prnt = (
                            "LastWriteTime,elrond_host,elrond_stage,elrond_log_entry\n",
                            " -> {} -> created audit log file for '{}'".format(
                                datetime.now().isoformat().replace("T", " "),
                                gfile.strip(".zip").strip(".7z"),
                            ),
                        )
                        write_audit_log_entry(verbosity, output_directory, entry, prnt)
                        print(
                            "  Extracting and reorganising artefacts for '{}'...".format(
                                gfile.replace(".zip", "").replace(".7z", "")
                            )
                        )
                    with ZipFile(
                        os.path.join(groot, gfile)
                    ) as gandalf_archive:  # unencrypted zip
                        gandalf_archive.extractall(
                            os.path.join(output_directory, groot.split("/")[-1])
                        )
                    for each_artefact in os.listdir(source_filepath):
                        if gandalf:  # make artefact directories
                            artefact_directory = str(each_artefact.split("\\")[0:-1])
                            if "', '" in artefact_directory:
                                artefact_directory = artefact_directory.replace(
                                    "', '", "/"
                                )
                            artefact_path = os.path.join(
                                source_filepath, artefact_directory[2:-2]
                            )
                            if not os.path.exists(artefact_path):
                                os.makedirs(artefact_path)
                        if os.path.isfile(
                            os.path.join(source_filepath, each_artefact)
                        ):  # reorganising artefacts
                            if (
                                len(artefact_path.split("/artefacts")[-1]) == 0
                            ):  # volatile information files
                                try:
                                    shutil.move(
                                        os.path.join(source_filepath, each_artefact),
                                        os.path.join(
                                            output_directory,
                                            groot.split("/")[-1],
                                            "artefacts",
                                            each_artefact.replace("\\", "/").replace(
                                                "artefacts/", ""
                                            ),
                                        ),
                                    )
                                    if each_artefact.endswith("host.info"):
                                        (
                                            gandalf_host,
                                            osplatform,
                                        ) = identify_gandalf_host(
                                            output_directory,
                                            verbosity,
                                            os.path.join(
                                                output_directory,
                                                groot.split("/")[-1],
                                                "artefacts",
                                                each_artefact.replace(
                                                    "\\", "/"
                                                ).replace("artefacts/", ""),
                                            ),
                                        )
                                except:
                                    pass
                            else:  # artefacts in subdirectories
                                if artefact_path.endswith("/raw"):
                                    try:
                                        shutil.move(
                                            os.path.join(
                                                source_filepath, each_artefact
                                            ),
                                            os.path.join(
                                                source_filepath,
                                                "artefacts",
                                                "raw",
                                                each_artefact.split("\\")[-1],
                                            ),
                                        )
                                    except:
                                        pass
                                else:
                                    try:
                                        shutil.move(
                                            os.path.join(
                                                source_filepath, each_artefact
                                            ),
                                            os.path.join(
                                                artefact_path,
                                                each_artefact.split("\\")[-1],
                                            ),
                                        )
                                    except:
                                        pass
                    print(
                        "   Successfully extracted artefacts for '{}'".format(
                            gfile.strip(".zip").strip(".7z")
                        )
                    )
                    print()
                else:
                    entry, prnt = (
                        "LastWriteTime,elrond_host,elrond_stage,elrond_log_entry\n",
                        " -> {} -> created audit log file for '{}'".format(
                            datetime.now().isoformat().replace("T", " "),
                            gfile.strip(".zip").strip(".7z"),
                        ),
                    )
                    write_audit_log_entry(verbosity, output_directory, entry, prnt)
                    print(
                        "  Extracting and reorganising artefacts for '{}'...".format(
                            gfile.replace(".zip", "").replace(".7z", "")
                        )
                    )
                    extract7z(output_directory, verbosity, groot, gfile, "", "First")
                    for each_artefact in os.listdir(
                        os.path.join(source_filepath, "artefacts")
                    ):
                        if each_artefact.endswith("host.info"):
                            gandalf_host, osplatform = identify_gandalf_host(
                                output_directory,
                                verbosity,
                                os.path.join(
                                    source_filepath, "artefacts", each_artefact
                                ),
                            )
                    print(
                        "   Successfully extracted artefacts for '{}'".format(
                            gfile.strip(".zip").strip(".7z")
                        )
                    )
                    print()
                allimgs[gandalf_host + "::" + osplatform] = d
    for file_root, file_dirs, _ in os.walk(output_directory):
        for file_dir in file_dirs:
            file_dir_path = os.path.join(file_root, file_dir)
            if len(os.listdir(file_dir_path)) < 1:
                shutil.rmtree(file_dir_path)
    if volatility:
        for dumpit_root, _, dumpit_files in os.walk(output_directory):
            for memory_file in dumpit_files:
                memory_path = os.path.join(dumpit_root, memory_file)
                if memory_path.endswith(".raw") and "memory" in memory_path:
                    if memory_path.endswith(".raw") and "memory" in memory_path:
                        memory_path_moved = os.path.join(
                            output_directory, memory_file, memory_file
                        )
                        if not os.path.exists(memory_path_moved):
                            os.mkdir(os.path.join(output_directory, memory_file))
                        try:
                            shutil.move(memory_path, memory_path_moved)
                        except:
                            pass
                        if memory_path.endswith(".raw") and "memory" in memory_path:
                            if os.path.exists(memory_path_moved):
                                ot = identify_memory_image(
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
                                    memory_file,
                                    ot,
                                    d,
                                    memory_path_moved,
                                    volchoice,
                                    vss,
                                    vssmem,
                                    memtimeline,
                                )
                                allimgs = {**allimgs, **ot}
            for json_file in dumpit_files:
                json_path = os.path.join(dumpit_root, json_file)
                if json_path.endswith(".json") and "memory" in memory_path:
                    try:
                        shutil.move(memory_path, memory_path_moved)
                    except:
                        pass
    allimgs = {**allimgs, **ot}
