#!/usr/bin/env python3 -tt
import re


def extract_mft(
    output_directory,
    img,
    vss_path_insert,
    mftwrite,
):
    with open(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + "..journal_mft.csv"
    ) as mftread:
        for eachinfo in mftread:
            try:
                mftentries = (
                    list(
                        str(
                            re.sub(
                                r"([^\"])\,([^\"])",
                                r"\1\2",
                                eachinfo.strip(),
                            ),
                        ).split(",")
                    ),
                )
                mftrow_information = (
                    mftentries[0][0].strip('"').strip(",")
                    + ","
                    + mftentries[0][1].strip('"').strip(",")
                    + ","
                    + mftentries[0][2].strip('"').strip(",")
                    + ","
                    + mftentries[0][3].strip('"').strip(",")
                    + ","
                    + mftentries[0][4].strip('"').strip(",")
                    + ","
                    + mftentries[0][5].strip('"').strip(",")
                    + ","
                    + mftentries[0][6].strip('"').strip(",")
                    + ","
                    + mftentries[0][8].strip('"').strip(",")
                    + ","
                    + mftentries[0][9].strip('"').strip(",")
                    + ","
                    + mftentries[0][10].strip('"').strip(",")
                    + ","
                    + mftentries[0][11].strip('"').strip(",")
                    + ","
                    + mftentries[0][16].strip('"').strip(",")
                    + ","
                    + mftentries[0][17].strip('"').strip(",")
                    + ","
                    + mftentries[0][18].strip('"').strip(",")
                    + ","
                    + mftentries[0][19].strip('"').strip(",")
                    + ","
                    + mftentries[0][35].strip('"').strip(",")
                    + ","
                    + mftentries[0][36].strip('"').strip(",")
                    + ","
                    + mftentries[0][37].strip('"').strip(",")
                    + ","
                    + mftentries[0][38].strip('"').strip(",")
                    + ","
                    + mftentries[0][39].strip('"').strip(",")
                    + ","
                    + mftentries[0][40].strip('"').strip(",")
                    + ","
                    + mftentries[0][41].strip('"').strip(",")
                    + ","
                    + mftentries[0][42].strip('"').strip(",")
                    + ","
                    + mftentries[0][43].strip('"').strip(",")
                    + ","
                    + mftentries[0][44].strip('"').strip(",")
                    + ","
                    + mftentries[0][45].strip('"').strip(",")
                    + ","
                    + mftentries[0][46].strip('"').strip(",")
                    + ","
                    + mftentries[0][47].strip('"').strip(",")
                    + ","
                    + mftentries[0][48].strip('"').strip(",")
                    + ","
                    + mftentries[0][49].strip('"').strip(",")
                    + ","
                    + mftentries[0][50].strip('"').strip(",")
                    + ","
                    + mftentries[0][51].strip('"').strip(",")
                    + ","
                    + mftentries[0][52].strip('"').strip(",")
                    + ","
                    + mftentries[0][53].strip('"').strip(",")
                    + ","
                    + mftentries[0][54].strip('"').strip(",")
                    + ","
                    + mftentries[0][55].strip('"').strip(",")
                )
                mftrow = (
                    mftrow_information
                    + ","
                    + mftentries[0][7].strip('"').strip(",")
                    + ","
                    + mftentries[0][12].strip('"').strip(",")
                    + ","
                    + mftentries[0][13].strip('"').strip(",")
                    + ","
                    + mftentries[0][14].strip('"').strip(",")
                    + ","
                    + mftentries[0][15].strip('"').strip(",")
                    + ","
                    + mftentries[0][13].strip('"').strip(",")
                )
                if len(mftentries[0][20].strip('"').strip(",")) > 0:
                    mftrow = (
                        "\n"
                        + mftrow_information
                        + ","
                        + mftentries[0][20].strip('"').strip(",")
                        + ","
                        + mftentries[0][21].strip('"').strip(",")
                        + ","
                        + mftentries[0][22].strip('"').strip(",")
                        + ","
                        + mftentries[0][23].strip('"').strip(",")
                        + ","
                        + mftentries[0][24].strip('"').strip(",")
                        + ","
                        + mftentries[0][22].strip('"').strip(",")
                    )
                if len(mftentries[0][25].strip('"').strip(",")) > 0:
                    mftrow = (
                        "\n"
                        + mftrow_information
                        + ","
                        + mftentries[0][25].strip('"').strip(",")
                        + ","
                        + mftentries[0][26].strip('"').strip(",")
                        + ","
                        + mftentries[0][27].strip('"').strip(",")
                        + ","
                        + mftentries[0][28].strip('"').strip(",")
                        + ","
                        + mftentries[0][29].strip('"').strip(",")
                        + ","
                        + mftentries[0][27].strip('"').strip(",")
                    )
                if len(mftentries[0][30].strip('"').strip(",")) > 0:
                    mftrow = (
                        "\n"
                        + mftrow_information
                        + ","
                        + mftentries[0][30].strip('"').strip(",")
                        + ","
                        + mftentries[0][31].strip('"').strip(",")
                        + ","
                        + mftentries[0][32].strip('"').strip(",")
                        + ","
                        + mftentries[0][33].strip('"').strip(",")
                        + ","
                        + mftentries[0][34].strip('"').strip(",")
                        + ","
                        + mftentries[0][32].strip('"').strip(",")
                    )
                if (
                    "record number,good,active,record type,sequence number,parent file rec"
                    not in mftrow.lower()
                    and "NoFNRecord,NoFNRecord,NoFNRecord,NoFNRecord,NoFNRecord,NoFNRecord"
                    not in mftrow
                ):
                    mftwrite.write(mftrow + "\n")
            except:
                pass
