#!/usr/bin/env python3 -tt
import os
import re
import subprocess
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def extract_metadata(
    verbosity, output_directory, img, imgloc, stage, sha256, nsrl
):  # comment - do not meta file multiple times
    for hr, _, hf in os.walk(imgloc):
        for intgfile in hf:
            metaimg, metapath, unknowngoods = (
                img.split("::")[0],
                os.path.join(hr, intgfile),
                {},
            )
            if not os.path.exists(output_directory + metaimg + "/meta.audit"):
                with open(
                    output_directory + metaimg + "/meta.audit", "w"
                ) as metaimglog:
                    metaimglog.write(
                        "Filename,SHA256,NSRL,Entropy,Filesize,LastWriteTime,LastAccessTime,LastInodeChangeTime,Permissions,FileType\n"
                    )
            with open(output_directory + metaimg + "/meta.audit", "a") as metaimglog:
                try:
                    iinfo = os.stat(metapath)
                    isize = iinfo.st_size
                    if (
                        isize > 0
                        and os.path.isfile(metapath)
                        and not os.path.islink(metapath)
                        and (
                            ("Inbox" not in metapath)
                            or ("Inbox" in metapath and "." in metapath.split("/")[-1])
                        )
                    ):
                        if "_vss" in img and "/vss" in metapath:
                            if stage == "processing":
                                metaimage = (
                                    "'"
                                    + img.split("::")[0]
                                    + "' ("
                                    + metapath.split("cooked/")[1][0:4].replace(
                                        "vss", "volume shadow copy #"
                                    )
                                    + ")"
                                )
                            elif stage == "metadata":
                                metaimage = (
                                    "'"
                                    + img.split("::")[0]
                                    + "' ("
                                    + img.split("::")[1]
                                    .split("_")[1]
                                    .replace("vss", "volume shadow copy #")
                                    + ")"
                                )
                        else:
                            metaimage = "'" + img.split("::")[0] + "'"
                        if verbosity != "":
                            print(
                                "     Extracting metadata for '{}' for {}...".format(
                                    metapath.split("/")[-1], metaimage
                                )
                            )
                        metaentry = metapath + ","
                        try:
                            with open(metapath, "rb") as metafile:
                                buffer = metafile.read(262144)
                                while len(buffer) > 0:
                                    sha256.update(buffer)
                                    buffer = metafile.read(262144)
                                metaentry = metaentry + sha256.hexdigest() + ","
                            if nsrl and "/files/" in metapath:
                                entry, prnt = "{},{},{},{}: {}\n".format(
                                    datetime.now().isoformat(),
                                    metaimage.replace("'", ""),
                                    "metadata",
                                    metapath,
                                    metaentry.strip(),
                                ), " -> {} -> calculating SHA256 hash digest for '{}' and comparing against NSRL for {}".format(
                                    datetime.now().isoformat().replace("T", " "),
                                    intgfile,
                                    metaimage,
                                )
                                write_audit_log_entry(
                                    verbosity, output_directory, entry, prnt
                                )
                                with open(
                                    "/opt/elrond/elrond/tools/rds_modernm/NSRLFile.txt"
                                ) as nsrlhashfile:
                                    for i, line in enumerate(nsrlhashfile):
                                        if i != 0:
                                            sha = re.findall(r"\"([^\"]{64})\"", line)
                                            if len(sha) > 0:
                                                if sha256 == sha[0]:
                                                    unknowngoods[sha256] = "Y"
                                                else:
                                                    unknowngoods[sha256] = "N"
                                for _, state in unknowngoods.items():
                                    if state == "Y":
                                        metaentry = metaentry + "Y,"
                                    else:
                                        metaentry = metaentry + "N,"
                            else:
                                entry, prnt = "{},{},{},{} ({})\n".format(
                                    datetime.now().isoformat(),
                                    metaimage.replace("'", ""),
                                    "metadata",
                                    metapath,
                                    sha256.hexdigest(),
                                ), " -> {} -> calculating SHA256 hash digest for '{}' from {}".format(
                                    datetime.now().isoformat().replace("T", " "),
                                    intgfile,
                                    metaimage,
                                )
                                write_audit_log_entry(
                                    verbosity, output_directory, entry, prnt
                                )
                                metaentry = metaentry + "unknown,"
                        except:
                            metaentry = metaentry + "N/A,N/A,"
                        if (
                            "/files/binaries/" in metapath
                            or "/files/documents/" in metapath
                            or "/files/archives/" in metapath
                            or "/files/scripts/" in metapath
                            or "/files/lnk/" in metapath
                            or "/files/web/" in metapath
                            or "/files/mail/" in metapath
                            or "/files/virtual/" in metapath
                            or "{}/user_profiles/".format(img.split("::")[0])
                            in metapath
                        ):  # do not assess entropy or extract metadata from raw or cooked artefacts - only files
                            try:
                                eout = subprocess.Popen(
                                    ["densityscout", "-r", metapath],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                ).communicate()[0]
                                entry, prnt = "{},{},{},{}\n".format(
                                    datetime.now().isoformat(),
                                    metaimage,
                                    "metadata",
                                    str(eout)[88:-5].split("\\n(")[1].split(")")[0],
                                ), " -> {} -> assessing entropy for '{}' from  {}".format(
                                    datetime.now().isoformat().replace("T", " "),
                                    intgfile,
                                    metaimage,
                                )
                                write_audit_log_entry(
                                    verbosity, output_directory, entry, prnt
                                )
                                if str(eout)[2:-1] != "" and "\\n(" in str(eout)[88:-5]:
                                    metaentry = (
                                        metaentry
                                        + str(eout)[88:-5]
                                        .split("\\n(")[1]
                                        .split(")")[0]
                                        + ","
                                    )
                                else:
                                    metaentry = metaentry + "N/A,"
                            except:
                                metaentry = metaentry + "N/A,"
                            try:
                                mout, exifinfo = (
                                    subprocess.Popen(
                                        ["exiftool", metapath],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                    ).communicate()[0],
                                    [],
                                )
                                if str(mout)[2:-3] != "":
                                    mout = (
                                        "File Size"
                                        + str(mout)[2:-3].split("File Size")[1]
                                    )
                                    entry, prnt = "{},{},{},{}\n".format(
                                        datetime.now().isoformat(),
                                        metaimage,
                                        "metadata",
                                        str(exifinfo)
                                        .replace(", ", "||")
                                        .replace("'", "")[1:-1],
                                    ), " -> {} -> extracting exif metadata for '{}' from {}".format(
                                        datetime.now().isoformat().replace("T", " "),
                                        intgfile,
                                        metaimage,
                                    )
                                    write_audit_log_entry(
                                        verbosity, output_directory, entry, prnt
                                    )
                                    for meta in mout.split("\\n"):
                                        exifinfo.append(
                                            meta.replace("   ", "")
                                            .replace("  ", "")
                                            .replace(" : ", ": ")
                                            .replace(": ", ":")
                                        )
                                    metaentry = (
                                        metaentry
                                        + str(
                                            str(exifinfo)
                                            .replace(", ", ",")
                                            .replace("'", "")
                                            .replace("File Size:", "")
                                            .replace("File Modification Date/Time:", "")
                                            .replace("File Access Date/Time:", "")
                                            .replace("File Inode Change Date/Time:", "")
                                            .replace("File Permissions:", "")
                                            .replace("Error:", "")
                                            .replace(" file type", "")[1:-1]
                                        ).lower()
                                    )
                                else:
                                    metaentry = metaentry + "N/A,N/A,N/A,N/A,N/A,N/A"
                            except:
                                metaentry = metaentry + "N/A,N/A,N/A,N/A,N/A,N/A"
                        metaimglog.write(metaentry + "\n")
                except:
                    pass
