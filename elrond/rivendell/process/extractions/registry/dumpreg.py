#!/usr/bin/env python3 -tt
import re
import subprocess

from rivendell.process.extractions.registry.profile import use_profile_plugins
from rivendell.process.extractions.registry.system import use_system_plugins


def extract_dumpreg_system(
    artefact,
    jsondict,
    jsonlist,
    regjsonlist,
):
    with open(
        artefact + ".json",
        "a",
    ) as regjson:
        rgrplistj = str(
            str(
                subprocess.Popen(
                    [
                        "rip.pl",
                        "-r",
                        artefact,
                        "-f",
                        artefact.split("/")[-1].split(".")[2].lower(),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[0]
            )[2:-1],
        )
        if type(rgrplistj) == str:
            jsonlist, regjsonlist = use_system_plugins(
                artefact, jsondict, jsonlist, regjsonlist, rgrplistj, [], []
            )
        if len(regjsonlist) > 0:
            regjson.write(
                str(regjsonlist)
                .replace(
                    "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\",
                    "/",
                )
                .replace("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\", "/")
                .replace("\\\\\\\\\\\\\\\\", "/")
                .replace("\\\\\\\\", "/")
                .replace("\\\\", "/")
                .replace("\\", "/")
                .replace('/"', '"')
                .replace(
                    "                                                                ",
                    " ",
                )
                .replace("                                ", " ")
                .replace("                ", " ")
                .replace("        ", " ")
                .replace("    ", " ")
                .replace("  ", " ")
                .replace("  ", "")
                .replace('" ', '"')
                .replace(' "', '"')
                .replace("//'", "'")
                .replace('":"', '": "')
                .replace('","', '", "')
                .replace('"}"\', \'"{"', '"}, {"')
                .replace('[\'"{"', '[{"')
                .replace('"}"\']', '"}]')
            )
        regjsonlist.clear()
        jsonlist.clear()


def extract_dumpreg_profile(
    artefact,
    jsondict,
    jsonlist,
    regjsonlist,
):
    with open(
        artefact + ".json",
        "a",
    ) as regjson:
        rgrplistj = (
            str(
                subprocess.Popen(
                    [
                        "rip.pl",
                        "-r",
                        artefact,
                        "-f",
                        artefact.split("/")[-1]
                        .split(".")[2]
                        .lower()
                        .replace("dat", ""),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[0]
            )[2:-1],
        )
        if type(rgrplistj) == str:
            jsonlist, regjsonlist = use_profile_plugins(
                artefact,
                jsondict,
                jsonlist,
                regjsonlist,
                rgrplistj,
                artefact.split("/")[-1].split(".")[2].lower().replace("dat", ""),
                "UNKNOWN (dumpreg)",
            )
            if len(regjsonlist) > 0:
                regjson.write(
                    str(regjsonlist)
                    .replace(
                        "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\",
                        "/",
                    )
                    .replace("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\", "/")
                    .replace("\\\\\\\\\\\\\\\\", "/")
                    .replace("\\\\\\\\", "/")
                    .replace("\\\\", "/")
                    .replace("\\", "/")
                    .replace('/"', '"')
                    .replace(
                        "                                                                ",
                        " ",
                    )
                    .replace("                                ", " ")
                    .replace("                ", " ")
                    .replace("        ", " ")
                    .replace("    ", " ")
                    .replace("  ", " ")
                    .replace("  ", "")
                    .replace('" ', '"')
                    .replace(' "', '"')
                    .replace("//'", "'")
                    .replace('":"', '": "')
                    .replace('","', '", "')
                    .replace('"}"\', \'"{"', '"}, {"')
                    .replace('[\'"{"', '[{"')
                    .replace('"}"\']', '"}]')
                )
            regjsonlist.clear()
            jsonlist.clear()


def extract_dumpreg_guess(
    artefact,
    jsondict,
    jsonlist,
    regjsonlist,
):
    with open(
        artefact + ".json",
        "a",
    ) as regjson:
        rgrplistguess = str(
            (
                str(
                    subprocess.Popen(
                        [
                            "rip.pl",
                            "-r",
                            artefact,
                            "-g",
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[0]
                )[2:-1],
            )
        )
        hive_guess = re.findall(
            r"(sam|security|software|system|ntuser|usrclass)", rgrplistguess
        )
        if len(hive_guess) > 0:
            guessed_hive = hive_guess[0]
            if (
                guessed_hive == "sam"
                or guessed_hive == "security"
                or guessed_hive == "software"
                or guessed_hive == "system"
                or guessed_hive == "ntuser"
                or guessed_hive == "usrclass"
            ):
                rgrplistj = str(
                    str(
                        subprocess.Popen(
                            [
                                "rip.pl",
                                "-r",
                                artefact,
                                "-f",
                                guessed_hive,
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ).communicate()[0]
                    )[2:-1],
                )
                if type(rgrplistj) == str:
                    if (
                        guessed_hive == "sam"
                        or guessed_hive == "security"
                        or guessed_hive == "software"
                        or guessed_hive == "system"
                    ):
                        jsonlist, regjsonlist = use_system_plugins(
                            artefact,
                            jsondict,
                            jsonlist,
                            regjsonlist,
                            rgrplistj,
                            [],
                            [],
                        )
                    else:
                        jsonlist, regjsonlist = use_profile_plugins(
                            artefact,
                            jsondict,
                            jsonlist,
                            regjsonlist,
                            rgrplistj,
                            guessed_hive.lower(),
                            "UNKNOWN (dumpreg)",
                        )
                else:
                    guessed_hive = ""
                if len(regjsonlist) > 0:
                    regjson.write(
                        str(regjsonlist)
                        .replace(
                            "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\",
                            "/",
                        )
                        .replace("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\", "/")
                        .replace("\\\\\\\\\\\\\\\\", "/")
                        .replace("\\\\\\\\", "/")
                        .replace("\\\\", "/")
                        .replace("\\", "/")
                        .replace('/"', '"')
                        .replace(
                            "                                                                ",
                            " ",
                        )
                        .replace("                                ", " ")
                        .replace("                ", " ")
                        .replace("        ", " ")
                        .replace("    ", " ")
                        .replace("  ", " ")
                        .replace("  ", "")
                        .replace('" ', '"')
                        .replace(' "', '"')
                        .replace("//'", "'")
                        .replace('":"', '": "')
                        .replace('","', '", "')
                        .replace('"}"\', \'"{"', '"}, {"')
                        .replace('[\'"{"', '[{"')
                        .replace('"}"\']', '"}]')
                    )
                else:
                    guessed_hive = ""
                regjsonlist.clear()
                jsonlist.clear()
            else:
                guessed_hive = ""
        else:
            guessed_hive = ""
    return guessed_hive
