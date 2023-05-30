#!/usr/bin/env python3 -tt
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime

from rivendell.audit import write_audit_log_entry
from rivendell.core.identify import identify_disk_image


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
    for eachimg in os.listdir("/mnt/vss/"):
        for eachvss in os.listdir("/mnt/vss/" + eachimg):
            if os.path.exists("/mnt/vss/" + eachimg + "/" + eachvss):
                unmount_locations("/mnt/vss/" + eachimg + "/" + eachvss)
            else:
                pass
        if os.path.exists("/mnt/vss/" + eachimg):
            unmount_locations("/mnt/vss/" + eachimg)
            remove_directories("/mnt/vss/" + eachimg)
        else:
            pass
    for devnbd in range(1, 15):
        if os.path.exists("/dev/nbd" + str(devnbd)):
            unmount_locations("/dev/nbd" + str(devnbd))
            subprocess.Popen(
                [
                    "qemu-nbd",
                    "--disconnect",
                    "/dev/nbd" + str(devnbd),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
        else:
            pass
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


def collect_ewfinfo(elrond_mount, ewf_mount, path, intermediate_mount, cwd):
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
    mount_ewf(path, intermediate_mount + "/")
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
        sys.exit()
    else:
        pass


def obtain_offset(
    intermediate_mount,
):
    offset_values = re.findall(
        r"\\n[\w\-\.\/]+(?:(?:(?:ewf1|nbd\d)p\d+)|\.(?:raw|dd|img)\d)[\ \*]+(?P<offset>\d+)[\w\d\.\ \*]+\s+(?:NTFS|Microsoft\ basic\ data|HPFS|Linux|exFAT)",
        str(
            subprocess.Popen(
                ["fdisk", "-l", intermediate_mount],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()[0]
        )[2:-3],
    )
    return offset_values


def mounted_image(allimgs, disk_image, destination_mount, disk_file, index):
    if index == "0":
        partition = ""
    elif index == 0:
        partition = " (zeroth partition)"
    elif index == 1:
        partition = " (first partition)"
    elif index == 2:
        partition = " (second partition)"
    elif index == 3:
        partition = " (third partition)"
    elif index == 4:
        partition = " (forth partition)"
    elif index == 5:
        partition = " (fifth partition)"
    elif index == 6:
        partition = " (sixth partition)"
    elif index == 7:
        partition = " (seventh partition)"
    elif index == 8:
        partition = " (eighth partition)"
    elif index == 9:
        partition = " (ninth partition)"
    if "::Windows" in disk_image or "::macOS" in disk_image or "::Linux" in disk_image:
        allimgs[destination_mount] = disk_image
        print(
            "   Mounted '{}'{} successfully at '{}'".format(
                disk_file, partition, destination_mount
            )
        )
    else:
        print("   '{}'{} could not be mounted.".format(disk_image, partition))
    return partition


def mount_vmdk_image(
    verbosity,
    output_directory,
    intermediate_mount,
    destination_mount,
    disk_file,
    path,
    allimgs,
    partitions,
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
        if disk_file.endswith(".vmdk"):
            subprocess.Popen(
                [
                    "modprobe",
                    "nbd",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
            for devnbd in range(1, 15):  # check for first empty /dev/ndbX location
                validfile = str(
                    subprocess.Popen(
                        ["fdisk", "-l", "/dev/nbd" + str(devnbd)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()
                )
                if "Inappropriate ioctl for device" in validfile:
                    intermediate_mount = "/dev/nbd" + str(devnbd)
                    break
                else:
                    pass
            subprocess.Popen(
                [
                    "qemu-nbd",
                    "-r",
                    "-c",
                    intermediate_mount,
                    path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
        else:
            pass
        offset_values = obtain_offset(intermediate_mount)
        if len(offset_values) > 0:
            for offset_value in offset_values:
                if (
                    str(
                        subprocess.Popen(
                            [
                                "mount",
                                "-t",
                                "ext4",
                                "-o",
                                "ro,norecovery,loop,offset="
                                + str(int(offset_value) * 512),
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
                    partition = mounted_image(
                        allimgs, disk_image, destination_mount, disk_file, "0"
                    )
                    partitions.append(
                        "{}||{}".format(
                            partition[2:-1]
                            .replace("partition", "")
                            .replace("zeroth", "00zeroth")
                            .replace("first", "01first")
                            .replace("second", "02second")
                            .replace("third", "03third")
                            .replace("forth", "04forth")
                            .replace("fifth", "05fifth")
                            .replace("sixth", "06sixth")
                            .replace("seventh", "07seventh")
                            .replace("eighth", "08eighth")
                            .replace("ninth", "09ninth")
                            .strip(),
                            disk_image,
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
                                + str(int(offset_value) * 512),
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
                    partition = mounted_image(
                        allimgs, disk_image, destination_mount, disk_file, "0"
                    )
                    partitions.append(
                        "{}||{}".format(
                            partition[2:-1]
                            .replace("partition", "")
                            .replace("zeroth", "00zeroth")
                            .replace("first", "01first")
                            .replace("second", "02second")
                            .replace("third", "03third")
                            .replace("forth", "04forth")
                            .replace("fifth", "05fifth")
                            .replace("sixth", "06sixth")
                            .replace("seventh", "07seventh")
                            .replace("eighth", "08eighth")
                            .replace("ninth", "09ninth")
                            .strip(),
                            disk_image,
                        )
                    )
                else:
                    mount_attempt = str(
                        subprocess.Popen(
                            [
                                "mount",
                                "-o",
                                "ro,loop,show_sys_files,streams_interface=windows,offset="
                                + str(int(offset_value) * 512),
                                intermediate_mount,
                                destination_mount,
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()[1]
                    )
                    if mount_attempt == "b''":
                        disk_image = identify_disk_image(
                            verbosity, output_directory, disk_file, destination_mount
                        )
                        partition = mounted_image(
                            allimgs, disk_image, destination_mount, disk_file, "0"
                        )
                        partitions.append(
                            "{}||{}".format(
                                partition[2:-1]
                                .replace("partition", "")
                                .replace("zeroth", "00zeroth")
                                .replace("first", "01first")
                                .replace("second", "02second")
                                .replace("third", "03third")
                                .replace("forth", "04forth")
                                .replace("fifth", "05fifth")
                                .replace("sixth", "06sixth")
                                .replace("seventh", "07seventh")
                                .replace("eighth", "08eighth")
                                .replace("ninth", "09ninth")
                                .strip(),
                                disk_image,
                            )
                        )
                    elif (
                        "overlapping loop device exists" in mount_attempt
                    ):  # mounted the first valid partition, but cannot mount another partition in the same way
                        print("TEST2")
                        nbd_mount = re.findall(
                            r"\\n[\w\-\.\/]+(nbd\dp\d+)|\.(?:raw|dd|img)\d[\ \*]+(?:\d+)[\w\d\.\ \*]+\s+(?:NTFS|Microsoft\ basic\ data|HPFS|Linux|exFAT)",
                            str(
                                subprocess.Popen(
                                    ["fdisk", "-l", intermediate_mount],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                ).communicate()[0]
                            )[2:-3],
                        )
                        nbd_mount.pop(0)
                        for eachnbd in nbd_mount:
                            if len(os.listdir(destination_mount)) > 0:
                                new_destination = int(
                                    re.findall(
                                        r"elrond_mount0?(\d+)", destination_mount
                                    )[0]
                                )
                                new_destination += 1
                                if len(str(new_destination)) == 1:
                                    new_destination = "/mnt/elrond_mount0" + str(
                                        new_destination
                                    )
                                else:
                                    new_destination = "/mnt/elrond_mount" + str(
                                        new_destination
                                    )
                                if not os.path.exists(new_destination):
                                    os.mkdir(new_destination)
                                else:
                                    pass
                                destination_mount = new_destination + "/"
                                subprocess.Popen(
                                    ["mount", "/dev/" + eachnbd, destination_mount],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                ).communicate()[
                                    0
                                ]  # to mount VMDKs - sudo mount /dev/nbd1p2 /mnt/elrond_mount01/
                                disk_image = identify_disk_image(
                                    verbosity,
                                    output_directory,
                                    disk_file,
                                    destination_mount,
                                )
                                partition = mounted_image(
                                    allimgs,
                                    disk_image,
                                    destination_mount,
                                    disk_file,
                                    "0",
                                )
                                partitions.append(
                                    "{}||{}".format(
                                        partition[2:-1]
                                        .replace("partition", "")
                                        .replace("zeroth", "00zeroth")
                                        .replace("first", "01first")
                                        .replace("second", "02second")
                                        .replace("third", "03third")
                                        .replace("forth", "04forth")
                                        .replace("fifth", "05fifth")
                                        .replace("sixth", "06sixth")
                                        .replace("seventh", "07seventh")
                                        .replace("eighth", "08eighth")
                                        .replace("ninth", "09ninth")
                                        .strip(),
                                        disk_image,
                                    )
                                )
                    elif (
                        "unknown filesystem type 'swap'" in mount_attempt
                    ):  # cannot mount swap partition
                        pass
                    else:
                        print(
                            "   An error occured when mounting '{}'.\n    Perhaps this is a macOS-based image and requires apfs-fuse (https://github.com/ezaspy/apfs-fuse)?\n    Alternatively, the disk may not be supported and/or may be corrupt? You can raise an issue via https://github.com/ezaspy/elrond/issues".format(
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
                                + "/log.audit"
                            )
                            os.rmdir(
                                os.path.join(
                                    output_directory, intermediate_mount.split("/")[-1]
                                )
                            )
                        else:
                            pass
        else:
            disk_image = identify_disk_image(
                verbosity, output_directory, disk_file, destination_mount
            )
            partition = mounted_image(
                allimgs, disk_image, destination_mount, disk_file, "0"
            )
            partitions.append(
                "{}||{}".format(
                    partition[2:-1]
                    .replace("partition", "")
                    .replace("zeroth", "00zeroth")
                    .replace("first", "01first")
                    .replace("second", "02second")
                    .replace("third", "03third")
                    .replace("forth", "04forth")
                    .replace("fifth", "05fifth")
                    .replace("sixth", "06sixth")
                    .replace("seventh", "07seventh")
                    .replace("eighth", "08eighth")
                    .replace("ninth", "09ninth")
                    .strip(),
                    disk_image,
                )
            )
    else:
        pass
    return partitions


def mount_ewf(path, intermediate_mount):
    subprocess.Popen(
        ["ewfmount", path, intermediate_mount],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()[1],


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
    partitions,
):
    if not os.path.exists(elrond_mount[0]):
        try:
            os.makedirs(elrond_mount[0])
        except:
            print(
                "\n    An error occured creating the '{}' directory for '{}'.\n    This scipt needs to be run as 'root', please try again...\n\n".format(
                    elrond_mount[0], disk_file.split("::")[0]
                )
            )
            sys.exit()
    else:
        pass
    if len(os.listdir(elrond_mount[0])) != 0:
        elrond_mount.pop(0)
        allimgs, partitions = mount_images(
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
    else:  # mounting images
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
                allimgs, partitions = mount_images(
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
            destination_mount, intermediate_mount = elrond_mount[0], ewf_mount[0]
            mount_ewf(path, intermediate_mount)
            if imageinfo:
                try:
                    collect_ewfinfo(
                        elrond_mount, ewf_mount, path, intermediate_mount, cwd
                    )
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
                partition = mounted_image(
                    allimgs, disk_image, destination_mount, disk_file, "0"
                )
                partitions.append(
                    "{}||{}".format(
                        partition[2:-1]
                        .replace("partition", "")
                        .replace("zeroth", "00zeroth")
                        .replace("first", "01first")
                        .replace("second", "02second")
                        .replace("third", "03third")
                        .replace("forth", "04forth")
                        .replace("fifth", "05fifth")
                        .replace("sixth", "06sixth")
                        .replace("seventh", "07seventh")
                        .replace("eighth", "08eighth")
                        .replace("ninth", "09ninth")
                        .strip(),
                        disk_image,
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
                    os.mkdir("/mnt/vss/" + disk_file.split("::")[0] + "/")
                    subprocess.Popen(
                        [
                            "vshadowmount",
                            intermediate_mount + "/ewf1",
                            "/mnt/vss/" + disk_file.split("::")[0] + "/",
                        ],
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
                        os.mkdir("/mnt/shadow_mount/" + disk_file.split("::")[0] + "/")
                        for i in os.listdir(
                            "/mnt/vss/" + disk_file.split("::")[0] + "/"
                        ):
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
                                        "/mnt/vss/"
                                        + disk_file.split("::")[0]
                                        + "/"
                                        + i,
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
            ):  # mounting images with multiple valid partitions
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
                            if verbosity != "":
                                disk_image = identify_disk_image(
                                    verbosity,
                                    output_directory,
                                    disk_file,
                                    destination_mount,
                                )
                                partition = mounted_image(
                                    allimgs,
                                    disk_image,
                                    destination_mount,
                                    disk_file,
                                    "0",
                                )
                                partitions.append(
                                    "{}||{}".format(
                                        partition[2:-1]
                                        .replace("partition", "")
                                        .replace("zeroth", "00zeroth")
                                        .replace("first", "01first")
                                        .replace("second", "02second")
                                        .replace("third", "03third")
                                        .replace("forth", "04forth")
                                        .replace("fifth", "05fifth")
                                        .replace("sixth", "06sixth")
                                        .replace("seventh", "07seventh")
                                        .replace("eighth", "08eighth")
                                        .replace("ninth", "09ninth")
                                        .strip(),
                                        disk_image,
                                    )
                                )
                            else:
                                pass
                        elif "mountpoint is not empty" in attempt_to_mount:
                            pass
                        else:
                            pass
                    except:
                        pass
                else:  # mounting images with multiple valid partitions
                    offset_values = obtain_offset(intermediate_mount + "/ewf1")
                    if len(offset_values) > 0:
                        for offset_value in offset_values:
                            destination_mount, intermediate_mount = (
                                elrond_mount[0],
                                ewf_mount[0],
                            )
                            if not os.path.exists(intermediate_mount):
                                os.mkdir(intermediate_mount)
                            else:
                                pass
                            mount_ewf(path, intermediate_mount)
                            if not os.path.exists(destination_mount):
                                os.mkdir(destination_mount)
                            else:
                                pass
                            attempt_to_mount = str(
                                subprocess.Popen(
                                    [
                                        "mount",
                                        "-o",
                                        "ro,loop,show_sys_files,streams_interface=windows,offset="
                                        + str(int(offset_value) * 512),
                                        intermediate_mount + "/ewf1",
                                        destination_mount,
                                    ],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                ).communicate()[1]
                            )
                            if len(os.listdir(destination_mount)) > 0:
                                if (
                                    verbosity != ""
                                    and offset_values.index(offset_value) == 0
                                ):
                                    disk_image = identify_disk_image(
                                        verbosity,
                                        output_directory,
                                        disk_file,
                                        destination_mount,
                                    )
                                else:
                                    pass
                                partition = mounted_image(
                                    allimgs,
                                    disk_image,
                                    destination_mount,
                                    disk_file,
                                    offset_values.index(offset_value),
                                )
                                partitions.append(
                                    "{}||{}".format(
                                        partition[2:-1]
                                        .replace("partition", "")
                                        .replace("zeroth", "00zeroth")
                                        .replace("first", "01first")
                                        .replace("second", "02second")
                                        .replace("third", "03third")
                                        .replace("forth", "04forth")
                                        .replace("fifth", "05fifth")
                                        .replace("sixth", "06sixth")
                                        .replace("seventh", "07seventh")
                                        .replace("eighth", "08eighth")
                                        .replace("ninth", "09ninth")
                                        .strip(),
                                        disk_image,
                                    )
                                )
                            else:
                                pass
                            elrond_mount.pop(0)
                            ewf_mount.pop(0)
                    else:
                        pass
            elif "is already mounted." in mounterr:
                pass
            else:
                pass
        elif ("VMware" in imgformat and " disk image" in imgformat) or (
            "DOS/MBR boot sector" in imgformat
            and (
                disk_file.endswith(".vmdk")
                or disk_file.endswith(".raw")
                or disk_file.endswith(".dd")
                or disk_file.endswith(".img")
            )
        ):
            if d.startswith("/"):
                (
                    destination_mount,
                    intermediate_mount,
                ) = (
                    elrond_mount[0],
                    "/" + d.strip("/") + "/" + disk_file.strip("/"),
                )
            else:
                (
                    destination_mount,
                    intermediate_mount,
                ) = (
                    elrond_mount[0],
                    d.strip("/") + "/" + disk_file.strip("/"),
                )
            if "DOS/MBR boot sector" in imgformat and disk_file.endswith(".dd"):
                partitions = mount_vmdk_image(
                    verbosity,
                    output_directory,
                    intermediate_mount,
                    destination_mount,
                    disk_file,
                    path,
                    allimgs,
                )
            elif "DOS/MBR boot sector" in imgformat and disk_file.endswith(
                ".raw"
            ):  # vmdk file has already been converted (not using elrond)
                if auto != True:
                    vmdkow = input(
                        "    '{}' has already been converted, do you wish to overwrite this file? Y/n [Y] ".format(
                            intermediate_mount.split("/")[-1]
                        )
                    )
                else:
                    vmdkow = "n"
                if vmdkow != "n" or "Invalid partition table" in imgformat:
                    if "Invalid partition table" in imgformat:
                        print(
                            "    It looks like '{}' is corrupt; it will be removed and will need to be re-converted, please try again.".format(
                                intermediate_mount.split("/")[-1]
                            )
                        )
                        # insert Continue? here...
                else:
                    pass
                partitions = mount_vmdk_image(
                    verbosity,
                    output_directory,
                    intermediate_mount,
                    destination_mount,
                    disk_file,
                    path,
                    allimgs,
                )
            else:  # raw vmdk file can be mounted
                partitions = mount_vmdk_image(
                    verbosity,
                    output_directory,
                    intermediate_mount,
                    destination_mount,
                    disk_file,
                    path,
                    allimgs,
                )
        else:
            pass
        entry, prnt = "{},{},{},commenced\n".format(
            datetime.now().isoformat(), disk_file, stage
        ), " -> {} -> mounting '{}'".format(
            datetime.now().isoformat().replace("T", " "), disk_file
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
    return allimgs, partitions
