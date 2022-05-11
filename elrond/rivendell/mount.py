#!/usr/bin/env python3 -tt
import os
import random
import re
import shutil
import subprocess
import sys
import time

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
    disk_file,
    elrond_mount,
    ewf_mount,
    allimgs,
    imageinfo,
    imgformat,
    vss,
    stage,
    cwd,
    quotes,
):
    def collect_ewfinfo(path, intermediate_mount):
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
        os.chdir(intermediate_mount)
        subprocess.Popen(
            ["ewfmount", path, intermediate_mount + "/"],
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

    def obtain_offset(intermediate_mount):
        offset_value = re.findall(
            r"\\n[\w\-\.\/]+(?:(?:ewf1p2)|\.(?:raw|dd|img)\d)[\ \*]+(?P<offset>\d+)[\w\d\.\ \*]+\s+(?:Linux|Microsoft\ basic\ data|HPFS|NTFS|exFAT)[\S]+",
            str(
                subprocess.Popen(
                    ["fdisk", "-l", intermediate_mount],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[0]
            )[2:-3],
        )
        return offset_value

    def mount_vmdk_image(
        verbosity,
        output_directory,
        intermediate_mount,
        destination_mount,
        disk_file,
        allimgs,
    ):
        try:
            apfs = str(
                subprocess.Popen(
                    [
                        "/usr/local/bin/apfs-fuse/build/./apfs-fuse",
                        "-o",
                        "allow_other",
                        intermediate_mount,
                        destination_mount,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[1]
            )
        except:
            if (
                input(
                    "  apfs-fuse and associated libraries are not installed. This is required for macOS disk images.\n   Continue? Y/n [Y] "
                )
                == "n"
            ):
                if os.path.exists("/usr/local/bin/apfs"):
                    shutil.rmtree("/usr/local/bin/apfs")
                else:
                    pass
                sys.exit()
            else:
                apfs = ""
        if apfs != "":
            offset_value = obtain_offset(intermediate_mount)
            if len(offset_value) > 0:
                if (
                    str(
                        subprocess.Popen(
                            [
                                "mount",
                                "-t",
                                "ext4",
                                "-o",
                                "ro,norecovery,loop,offset="
                                + str(int(offset_value[0]) * 512),
                                intermediate_mount,
                                destination_mount,
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()[1]
                    )
                    == "b''"
                ):
                    disk_image = identify_disk_image(
                        verbosity, output_directory, disk_file, destination_mount
                    )
                    allimgs[disk_image] = destination_mount
                    print(
                        "   Mounted '{}' successfully at '{}'".format(
                            disk_file, destination_mount
                        )
                    )
                elif (
                    str(
                        subprocess.Popen(
                            [
                                "mount",
                                "-t",
                                "ntfs",
                                "-o",
                                "ro,loop,show_sys_files,streams_interface=windows,offset="
                                + str(int(offset_value[0]) * 512),
                                intermediate_mount,
                                destination_mount,
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()[1]
                    )
                    == "b''"
                ):
                    disk_image = identify_disk_image(
                        verbosity, output_directory, disk_file, destination_mount
                    )
                    allimgs[disk_image] = destination_mount
                    print(
                        "   Mounted '{}' successfully at '{}'".format(
                            disk_file, destination_mount
                        )
                    )
                else:
                    print(
                        "   An error occured when mounting '{}'.\n    Perhaps this is a macOS-based image and requires apfs-fuse? Visit https://github.com/ezaspy/apfs-fuse and try again.\n   If this does not work, the disk may not be supported and/or may be corrupt? Feel free to raise an issue via https://github.com/ezaspy/elrond/issues".format(
                            disk_file
                        )
                    )
                    if os.path.exists(
                        os.path.join(
                            output_directory, intermediate_mount.split("/")[-1]
                        )
                    ):
                        os.remove(
                            os.path.join(
                                output_directory, intermediate_mount.split("/")[-1]
                            )
                            + "/"
                            + intermediate_mount.split("/")[-1]
                            + ".log"
                        )
                        os.rmdir(
                            os.path.join(
                                output_directory, intermediate_mount.split("/")[-1]
                            )
                        )
                    else:
                        pass
                    if input("    Continue? Y/n [n] ") != "Y":
                        print("\n  OK. Exiting.\n\n")
                        sys.exit()
                    else:
                        pass
            else:
                disk_image = identify_disk_image(
                    verbosity, output_directory, disk_file, destination_mount
                )
                allimgs[disk_image] = destination_mount
                print(
                    "   Mounted '{}' successfully at '{}'".format(
                        disk_file, destination_mount
                    )
                )
        else:
            pass

    if not os.path.exists(elrond_mount[0]):
        try:
            os.makedirs(elrond_mount[0])
        except:
            print(
                "\n    An error occured creating the '{}' directory for '{}'.\n    This scipt needs to be run as 'root' please try again...\n\n".format(
                    elrond_mount[0], disk_file.split("::")[0]
                )
            )
            sys.exit()
    else:
        pass
    if len(os.listdir(elrond_mount[0])) != 0:
        elrond_mount.pop(0)
        allimgs = mount_images(
            d,
            auto,
            verbosity,
            output_directory,
            path,
            disk_file,
            elrond_mount,
            ewf_mount,
            allimgs,
            imageinfo,
            imgformat,
            vss,
            stage,
            cwd,
            quotes,
        )
    else:
        if "EWF" in imgformat or "Expert Witness" in imgformat:
            if not os.path.exists(ewf_mount[0]):
                try:
                    os.makedirs(ewf_mount[0])
                except:
                    print(
                        "\n    An error occured creating the '{}' directory for '{}'.\n    This scipt needs to be run as 'root', please try again...\n\n".format(
                            ewf_mount[0], disk_file.split("::")[0]
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
                    disk_file,
                    elrond_mount,
                    ewf_mount,
                    allimgs,
                    imageinfo,
                    imgformat,
                    vss,
                    stage,
                    cwd,
                    quotes,
                )
            else:
                pass
            destination_mount, intermediate_mount, _ = (
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
                    collect_ewfinfo(path, intermediate_mount)
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
                        intermediate_mount + "/ewf1",
                        destination_mount,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[1]
            )
            if mounterr == "b''":
                disk_image = identify_disk_image(
                    verbosity, output_directory, disk_file, destination_mount
                )
                allimgs[disk_image] = destination_mount
                print(
                    "   Mounted '{}' successfully at '{}'".format(
                        disk_file, destination_mount
                    )
                )
                if vss:
                    if verbosity != "":
                        print(
                            "    Attempting to mount Volume Shadow Copies for '{}'...".format(
                                disk_file
                            )
                        )
                    else:
                        pass
                    subprocess.Popen(
                        ["vshadowmount", intermediate_mount + "/ewf1", "/mnt/vss/"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()
                    time.sleep(0.5)
                    if os.path.exists(
                        "/mnt/shadow_mount/" + disk_file.split("::")[0] + "/"
                    ):
                        for current in os.listdir(
                            "/mnt/shadow_mount/" + disk_file.split("::")[0] + "/"
                        ):
                            subprocess.Popen(
                                [
                                    "umount",
                                    "/mnt/shadow_mount/"
                                    + disk_file.split("::")[0]
                                    + "/"
                                    + current,
                                ],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            ).communicate()
                            time.sleep(0.1)
                            shutil.rmtree(
                                "/mnt/shadow_mount/"
                                + disk_file.split("::")[0]
                                + "/"
                                + current
                            )
                            shutil.rmtree(
                                "/mnt/shadow_mount/" + disk_file.split("::")[0] + "/"
                            )
                    else:
                        pass
                    if not os.path.exists(
                        "/mnt/shadow_mount/" + disk_file.split("::")[0] + "/"
                    ):
                        os.mkdir("/mnt/shadow_mount/" + disk_file.split("::")[0] + "/")
                        for i in os.listdir("/mnt/vss/"):
                            os.mkdir(
                                "/mnt/shadow_mount/"
                                + disk_file.split("::")[0]
                                + "/"
                                + i
                            )
                            try:
                                subprocess.Popen(
                                    [
                                        "mount",
                                        "-o",
                                        "ro,loop,show_sys_files,streams_interface=windows",
                                        "/mnt/vss/" + i,
                                        "/mnt/shadow_mount/"
                                        + disk_file.split("::")[0]
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
                                disk_file
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

                def successfull_mount(
                    verbosity, output_directory, disk_file, destination_mount, allimgs
                ):
                    if verbosity != "":
                        disk_image = identify_disk_image(
                            verbosity, output_directory, disk_file, destination_mount
                        )
                        allimgs[disk_image] = destination_mount
                        print(
                            "   Mounted '{}' successfully at '{}'".format(
                                disk_file, destination_mount
                            )
                        )
                    else:
                        pass

                if "unknown filesystem type 'apfs'" in mounterr:
                    try:
                        attempt_to_mount = str(
                            subprocess.Popen(
                                [
                                    "/usr/local/bin/apfs-fuse/build/./apfs-fuse",
                                    "-o",
                                    "allow_other",
                                    intermediate_mount + "/ewf1",
                                    destination_mount,
                                ],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            ).communicate()[1]
                        )
                        if attempt_to_mount == "b''":
                            successfull_mount(
                                verbosity,
                                output_directory,
                                disk_file,
                                destination_mount,
                                allimgs,
                            )
                        elif "mountpoint is not empty" in attempt_to_mount:
                            pass
                        else:
                            pass
                    except:
                        pass
                if "wrong fs type" in mounterr:
                    offset_value = obtain_offset(intermediate_mount + "/ewf1")
                    attempt_to_mount = str(
                        subprocess.Popen(
                            [
                                "mount",
                                "-o",
                                "ro,loop,show_sys_files,streams_interface=windows,offset="
                                + str(int(offset_value[0]) * 512),
                                intermediate_mount + "/ewf1",
                                destination_mount,
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()[1]
                    )
                    if attempt_to_mount == "b''":
                        successfull_mount(
                            verbosity,
                            output_directory,
                            disk_file,
                            destination_mount,
                            allimgs,
                        )
                    elif "mountpoint is not empty" in attempt_to_mount:
                        pass
                    else:
                        pass
            elif "is already mounted." in mounterr:
                pass
            else:
                pass
        elif ("VMware" in imgformat and " disk image" in imgformat) or (
            "DOS/MBR boot sector" in imgformat
            and disk_file.endswith(".raw")
            or disk_file.endswith(".dd")
            or disk_file.endswith(".img")
        ):

            def doVMDKConvert(intermediate_mount):
                subprocess.Popen(
                    [
                        "qemu-img",
                        "convert",
                        "-O",
                        "raw",
                        intermediate_mount,
                        intermediate_mount + ".raw",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()

            if d.startswith("/"):
                destination_mount, intermediate_mount, = (
                    elrond_mount[0],
                    "/" + d.strip("/") + "/" + disk_file.strip("/"),
                )
            else:
                destination_mount, intermediate_mount, = (
                    elrond_mount[0],
                    d.strip("/") + "/" + disk_file.strip("/"),
                )
            if "DOS/MBR boot sector" in imgformat and disk_file.endswith(".dd"):
                mount_vmdk_image(
                    verbosity,
                    output_directory,
                    intermediate_mount,
                    destination_mount,
                    disk_file,
                    allimgs,
                )
            elif "DOS/MBR boot sector" in imgformat and disk_file.endswith(".raw"):
                if auto != True:
                    vmdkow = input(
                        "  '{}' has already been converted, do you wish to overwrite this file? Y/n [Y] ".format(
                            intermediate_mount.split("/")[-1]
                        )
                    )
                else:
                    vmdkow = "n"
                if vmdkow != "n":
                    if os.path.exists(intermediate_mount + ".raw"):
                        os.remove(intermediate_mount + ".raw")
                    elif os.path.exists(intermediate_mount):
                        os.remove(intermediate_mount)
                    else:
                        pass
                    doVMDKConvert(intermediate_mount)
                else:
                    pass
                mount_vmdk_image(
                    verbosity,
                    output_directory,
                    intermediate_mount,
                    destination_mount,
                    disk_file,
                    allimgs,
                )
            else:
                if not os.path.exists(intermediate_mount + ".raw"):
                    print(
                        "  '{}' needs to be converted before it can be mounted, please stand by...".format(
                            intermediate_mount.split("/")[-1]
                        )
                    )
                    doVMDKConvert(intermediate_mount)
                else:
                    convertVMDK = input(
                        "  It looks like '{}'.raw already exists. Did you want to replace it? Y/n [Y] ".format(
                            intermediate_mount.split("/")[-1]
                        )
                    )
                    if convertVMDK != "n":
                        os.remove(intermediate_mount)
                        doVMDKConvert(intermediate_mount)
                    else:
                        pass
                mount_vmdk_image(
                    verbosity,
                    output_directory,
                    intermediate_mount + ".raw",
                    destination_mount,
                    disk_file,
                    allimgs,
                )
        else:
            pass
    return allimgs
