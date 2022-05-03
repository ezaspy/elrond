#!/usr/bin/env python3 -tt
import os
import random
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.identify import identify_disk_image


def unmount_images(elrond_mount, ewf_mount):
    def unmount_locations(each):
        subprocess.Popen(
            ["umount", each], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ).communicate()
        time.sleep(0.1)

    def remove_directories(each):
        shutil.rmtree(each)
        time.sleep(0.1)

    for shadowimg in os.listdir("/mnt/shadow_mount/"):
        for everyshadow in os.listdir("/mnt/shadow_mount/" + shadowimg):
            unmount_locations("/mnt/shadow_mount/" + shadowimg + "/" + everyshadow)
        remove_directories("/mnt/shadow_mount/" + shadowimg)
    unmount_locations("/mnt/vss/")
    for eachelrond in elrond_mount:
        if os.path.exists(eachelrond):
            unmount_locations(eachelrond)
            remove_directories(eachelrond)
        else:
            pass
    for eachewf in ewf_mount:
        if os.path.exists(eachewf):
            unmount_locations(eachewf + "/")
            if eachewf != "/mnt/ewf_mount":
                remove_directories(eachewf)
            else:
                pass
        else:
            pass


def mount_images(
    d,
    auto,
    verbosity,
    output_directory,
    path,
    f,
    elrond_mount,
    ewf_mount,
    allimgs,
    imageinfo,
    imgformat,
    vss,
    stage,
    cwd,
    quotes,
    removeimgs,
):
    def apfs_error():
        if (
            input(
                "  apfs-fuse and associated libraries are not installed. This is required for macOS disk images.\n   Continue? Y/n [Y] "
            )
            == "n"
        ):
            print(
                "\n  Please run https://github.com/ezaspy/elrond/elrond/tools/scripts/apfs-fuse.sh and try again.\n\n"
            )
            if os.path.exists("/usr/local/bin/apfs"):
                shutil.rmtree("/usr/local/bin/apfs")
            else:
                pass
            sys.exit()
        else:
            apfs = ""
        return apfs

    def collect_ewfinfo(path, mpath):
        ewfinfo = list(
            re.findall(
                r"ewfinfo[^\\]+\\n\\n.*Acquisition\sdate\:\\t(?P<aquisition_date>[^\\]+)\\n.*Operating\ssystem\sused\:\\t(?P<os_used>[^\\]+)\\n.*Sectors\sper\schunk\:\\t(?P<sector_chunks>[^\\]+)\\n.*Bytes\sper\ssector\:\\t(?P<bps>[^\\]+)\\n\\tNumber\sof\ssectors\:\\t(?P<nos>[^\\]+)\\n\\tMedia\ssize\:\\t\\t(?P<media_size>[^\\]+)\\n",
                str(
                    subprocess.Popen(
                        ["ewfinfo", path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[0]
                ),
            )[0]
        )
        os.chdir(mpath)
        subprocess.Popen(
            ["ewfmount", path, mpath + "/"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()[0]
        rawinfo = list(
            re.findall(
                r"Disk\sidentifier\:\s(?P<rawdiskid>[^\\]+)\\n",
                str(
                    subprocess.Popen(
                        ["fdisk", "-l", "ewf1"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[0]
                )[2:-3],
            )[0]
        )
        print(
            "\n  -> Information for '{}'\n\n   Acquisition date/time:\t{}\n   Operating system:\t\t{}\n   Image size:\t\t\t{}\n   Identifier:\t\t\t{}\n   No. of sectors:\t\t{}\n   Size of sector chunks:\t{}\n   Bytes per sector:\t\t{}\n".format(
                path,
                ewfinfo[0],
                ewfinfo[1],
                ewfinfo[5],
                rawinfo[0],
                ewfinfo[2],
                ewfinfo[3],
                ewfinfo[4],
            )
        )
        os.chdir(cwd)
        conelrond = input(
            "    Typically, the --information flag is used before forensic analysis commences.\n     Do you want to continue with the forensic analysis? Y/n [Y] "
        )
        if conelrond == "n":
            unmount_images(elrond_mount, ewf_mount)
            print("\n\n     " + random.choice(quotes) + "\n\n")
            sys.exit()
        else:
            pass

    def mount_vmdk_image(verbosity, output_directory, mpath, mntpath, f, allimgs):
        apfsexists = str(
            subprocess.Popen(
                [
                    "locate",
                    "apfs",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()[0]
        )
        if not "/usr/local/bin/apfs" in apfsexists:
            apfs = apfs_error()
        else:
            pass
        try:
            apfs = str(
                subprocess.Popen(
                    [
                        "/usr/local/bin/apfs-fuse/build/./apfs-fuse",
                        "-o",
                        "allow_other",
                        mpath,
                        mntpath,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[1]
            )
        except:
            apfs = apfs_error()
        if apfs != "":
            offset_out = re.findall(
                r"\\n[\w\-\.\/]+.(?:raw|dd|img)\d[\ \*]+(?P<offset>\d+)[\w\d\.\ \*]+\s+(?:Linux|Microsoft\ basic\ data|HPFS[\S]+|NTFS[\S]+|exFAT[\S]+)",
                str(
                    subprocess.Popen(
                        ["fdisk", "-l", mpath],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[0]
                )[2:-3],
            )
            if len(offset_out) > 0:
                if (
                    str(
                        subprocess.Popen(
                            [
                                "mount",
                                "-t",
                                "ext4",
                                "-o",
                                "ro,norecovery,loop,offset="
                                + str(int(offset_out[0]) * 512),
                                mpath,
                                mntpath,
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()[1]
                    )
                    == "b''"
                ):
                    disk_image = identify_disk_image(
                        verbosity, output_directory, f, mntpath
                    )
                    allimgs[disk_image] = mntpath
                    print("   Mounted '{}' successfully at '{}'".format(f, mntpath))
                elif (
                    str(
                        subprocess.Popen(
                            [
                                "mount",
                                "-t",
                                "ntfs",
                                "-o",
                                "ro,loop,show_sys_files,streams_interface=windows,offset="
                                + str(int(offset_out[0]) * 512),
                                mpath,
                                mntpath,
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()[1]
                    )
                    == "b''"
                ):
                    disk_image = identify_disk_image(
                        verbosity, output_directory, f, mntpath
                    )
                    allimgs[disk_image] = mntpath
                    print("   Mounted '{}' successfully at '{}'".format(f, mntpath))
                else:
                    print(
                        "   An error occured when mounting '{}'.\n    Perhaps this is a macOS-based image and requires apfs-fuse? Visit https://github.com/ezaspy/apfs-fuse and try again.\n   If this does not work, the disk may not be supported and/or may be corrupt? Feel free to raise an issue via https://github.com/ezaspy/elrond/issues".format(
                            f
                        )
                    )
                    if os.path.exists(
                        os.path.join(output_directory, mpath.split("/")[-1])
                    ):
                        os.remove(
                            os.path.join(output_directory, mpath.split("/")[-1])
                            + "/"
                            + mpath.split("/")[-1]
                            + ".log"
                        )
                        os.rmdir(os.path.join(output_directory, mpath.split("/")[-1]))
                    else:
                        pass
                    if input("    Continue? Y/n [n] ") != "Y":
                        print("\n  OK. Exiting.\n\n")
                        sys.exit()
                    else:
                        pass
            else:
                disk_image = identify_disk_image(
                    verbosity, output_directory, f, mntpath
                )
                allimgs[disk_image] = mntpath
                print("   Mounted '{}' successfully at '{}'".format(f, mntpath))
        else:
            pass

    if not os.path.exists(elrond_mount[0]):
        try:
            os.makedirs(elrond_mount[0])
        except:
            print(
                "\n    An error occured creating the '{}' directory for '{}'.\n    This scipt needs to be run as 'root' please try again...\n\n".format(
                    elrond_mount[0], f.split("::")[0]
                )
            )
            sys.exit()
    else:
        pass
    if len(os.listdir(elrond_mount[0])) != 0:
        elrond_mount.pop(0)
        mount_images(
            d,
            auto,
            verbosity,
            output_directory,
            path,
            f,
            elrond_mount,
            ewf_mount,
            allimgs,
            imageinfo,
            imgformat,
            vss,
            stage,
            cwd,
            quotes,
            removeimgs,
        )
    else:
        if "EWF" in imgformat or "Expert Witness" in imgformat:
            if not os.path.exists(ewf_mount[0]):
                try:
                    os.makedirs(ewf_mount[0])
                except:
                    print(
                        "\n    An error occured creating the '{}' directory for '{}'.\n    This scipt needs to be run as 'root', please try again...\n\n".format(
                            ewf_mount[0], f.split("::")[0]
                        )
                    )
                    sys.exit()
            else:
                pass
            if len(os.listdir(ewf_mount[0])) != 0:
                ewf_mount.pop(0)
                mount_images(
                    d,
                    auto,
                    verbosity,
                    output_directory,
                    path,
                    f,
                    elrond_mount,
                    ewf_mount,
                    allimgs,
                    imageinfo,
                    imgformat,
                    vss,
                    stage,
                    cwd,
                    quotes,
                    removeimgs,
                )
            else:
                pass
            mntpath, mpath, _ = (
                elrond_mount[0],
                ewf_mount[0],
                subprocess.Popen(
                    ["ewfmount", path, ewf_mount[0]],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[1],
            )
            if imageinfo:
                try:
                    collect_ewfinfo(path, mpath)
                except:
                    print(
                        "  -> Information for '{}' could not be obtained".format(path)
                    )
                elrond_mount.pop(0)
                ewf_mount.pop(0)
            else:
                pass
            mounterr = str(
                subprocess.Popen(
                    [
                        "mount",
                        "-o",
                        "ro,loop,show_sys_files,streams_interface=windows",
                        mpath + "/ewf1",
                        mntpath,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[1]
            )
            if mounterr == "b''":
                disk_image = identify_disk_image(
                    verbosity, output_directory, f, mntpath
                )
                allimgs[disk_image] = mntpath
                print("   Mounted '{}' successfully at '{}'".format(f, mntpath))
                allimgs[f] = mntpath
                if vss:
                    if verbosity != "":
                        print(
                            "    Attempting to mount Volume Shadow Copies for '{}'...".format(
                                f
                            )
                        )
                    else:
                        pass
                    subprocess.Popen(
                        ["vshadowmount", mpath + "/ewf1", "/mnt/vss/"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()
                    time.sleep(0.5)
                    if os.path.exists("/mnt/shadow_mount/" + f.split("::")[0] + "/"):
                        for current in os.listdir(
                            "/mnt/shadow_mount/" + f.split("::")[0] + "/"
                        ):
                            subprocess.Popen(
                                [
                                    "umount",
                                    "/mnt/shadow_mount/"
                                    + f.split("::")[0]
                                    + "/"
                                    + current,
                                ],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            ).communicate()
                            time.sleep(0.1)
                            shutil.rmtree(
                                "/mnt/shadow_mount/" + f.split("::")[0] + "/" + current
                            )
                            shutil.rmtree("/mnt/shadow_mount/" + f.split("::")[0] + "/")
                    else:
                        pass
                    if not os.path.exists(
                        "/mnt/shadow_mount/" + f.split("::")[0] + "/"
                    ):
                        os.mkdir("/mnt/shadow_mount/" + f.split("::")[0] + "/")
                        for i in os.listdir("/mnt/vss/"):
                            os.mkdir("/mnt/shadow_mount/" + f.split("::")[0] + "/" + i)
                            try:
                                subprocess.Popen(
                                    [
                                        "mount",
                                        "-o",
                                        "ro,loop,show_sys_files,streams_interface=windows",
                                        "/mnt/vss/" + i,
                                        "/mnt/shadow_mount/"
                                        + f.split("::")[0]
                                        + "/"
                                        + i,
                                    ],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                ).communicate()
                                time.sleep(0.1)
                            except:
                                pass
                    else:
                        pass
                    if verbosity != "":
                        print(
                            "    All valid Volume Shadow Copies for '{}' have been successfully mounted.".format(
                                f
                            )
                        )
                    else:
                        pass
                    os.chdir(cwd)
                else:
                    pass
            elif (
                "unknown filesystem type 'apfs'" in mounterr
                or "wrong fs type" in mounterr
            ):
                try:
                    apfs = str(
                        subprocess.Popen(
                            [
                                "/usr/local/bin/apfs-fuse/build/./apfs-fuse",
                                "-o",
                                "allow_other",
                                mpath + "/ewf1",
                                mntpath,
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()[1]
                    )
                    if apfs == "b''":
                        if verbosity != "":
                            disk_image = identify_disk_image(
                                verbosity, output_directory, f, mntpath
                            )
                            allimgs[disk_image] = mntpath
                            print(
                                "   Mounted '{}' successfully at '{}'".format(
                                    f, mntpath
                                )
                            )
                        else:
                            pass
                    elif "mountpoint is not empty" in apfs:
                        pass
                    else:
                        if (
                            input(
                                "  apfs-fuse and associated libraries are not installed. This is required for macOS disk images.\n   Continue? Y/n [Y] "
                            )
                            == "n"
                        ):
                            print(
                                "\n  Please visit https://github.com/ezaspy/apfs-fuse and try again.\n\n"
                            )
                            if os.path.exists("/usr/local/bin/apfs"):
                                shutil.rmtree("/usr/local/bin/apfs")
                            else:
                                pass
                            sys.exit()
                        else:
                            apfs = ""
                except:
                    apfs = apfs_error()
            elif "is already mounted." in mounterr:
                pass
            else:
                print(
                    "\n    '{}' is not a supported image type and could not be mounted.\n  ----------------------------------------".format(
                        f
                    )
                )
                if verbosity != "":
                    print(
                        "    elrond only supports the following disk images:\n     -> Windows 10/7 (E01/VMDK)\n     -> macOS        (E01/VMDK)\n     -> Linux        (dd/VMDK)\n  ----------------------------------------\n    If you believe your image is supported but it still is not mounting, it may be corrupt or not be the image you think it is.\n    However, if you do have any issues, please raise them https://github.com/ezaspy/elrond/issues"
                    )
                    continueafterinvalid = input(
                        "      Do you wish to continue? Y/n [Y] "
                    )
                    if continueafterinvalid == "n":
                        print("       OK. Exiting.\n")
                        sys.exit()
                    else:
                        pass
                else:
                    pass
                removeimgs.append(f)
        elif ("VMware" in imgformat and " disk image" in imgformat) or (
            "DOS/MBR boot sector" in imgformat
            and f.endswith(".raw")
            or f.endswith(".dd")
            or f.endswith(".img")
        ):

            def doVMDKConvert(mpath):
                subprocess.Popen(
                    ["qemu-img", "convert", "-O", "raw", mpath, mpath + ".raw"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()

            if d.startswith("/"):
                mntpath, mpath, err = (
                    elrond_mount[0],
                    "/" + d.strip("/") + "/" + f.strip("/"),
                    "b''",
                )
            else:
                mntpath, mpath, err = (
                    elrond_mount[0],
                    d.strip("/") + "/" + f.strip("/"),
                    "b''",
                )
            if "DOS/MBR boot sector" in imgformat and f.endswith(".dd"):
                mount_vmdk_image(
                    verbosity, output_directory, mpath, mntpath, f, allimgs
                )
            elif "DOS/MBR boot sector" in imgformat and f.endswith(".raw"):
                if auto != True:
                    vmdkow = input(
                        "  '{}' has already been converted, do you wish to overwrite this file? Y/n [Y] ".format(
                            mpath.split("/")[-1]
                        )
                    )
                else:
                    vmdkow = "n"
                if vmdkow != "n":
                    if os.path.exists(mpath + ".raw"):
                        os.remove(mpath + ".raw")
                    elif os.path.exists(mpath):
                        os.remove(mpath)
                    else:
                        pass
                    doVMDKConvert(mpath)
                else:
                    pass
                mount_vmdk_image(
                    verbosity, output_directory, mpath, mntpath, f, allimgs
                )
            else:
                if not os.path.exists(mpath + ".raw"):
                    print(
                        "  '{}' needs to be converted before it can be mounted, please stand by...".format(
                            mpath.split("/")[-1]
                        )
                    )
                    doVMDKConvert(mpath)
                else:
                    convertVMDK = input(
                        "  It looks like '{}'.raw already exists. Did you want to replace it? Y/n [Y] ".format(
                            mpath.split("/")[-1]
                        )
                    )
                    if convertVMDK != "n":
                        os.remove(mpath)
                        doVMDKConvert(mpath)
                    else:
                        pass
                mount_vmdk_image(
                    verbosity, output_directory, mpath + ".raw", mntpath, f, allimgs
                )
        else:
            print(
                "\n    '{}' may not be a valid image type.\n    Remember, this scipt needs to be run as 'root' and only accepts E01, VMDK & memory images.\n    If you believe you have a supported image type, it may be corrupted? Feel free to raise an issue via https://github.com/ezaspy/elrond/issues\n    Please try again...\n  ----------------------------------------\n\n".format(
                    path
                )
            )
            entry, prnt = "{},{},{},{}\n".format(
                datetime.now().isoformat(), f, stage, mpath
            ), " -> {} -> {} '{}' failed".format(
                datetime.now().isoformat().replace("T", " "), stage, mpath
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
    return allimgs
