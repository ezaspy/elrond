#!/usr/bin/env python3 -tt
import json
import os
import re
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def process_journal(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    if not os.path.exists(
        output_directory
        + img.split("::")[0]
        + "/artefacts/cooked"
        + vss_path_insert
        + artefact.split("/")[-1]
        + ".json"
    ):
        try:
            os.makedirs(
                output_directory
                + img.split("::")[0]
                + "/artefacts/cooked"
                + vss_path_insert
            )
        except:
            pass
        with open("journalctl.json") as journalctljson:
            journal = journalctljson.readlines()
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + "."
            + artefact.split("/")[-1]
            + ".json",
            "a",
        ) as journaljson:
            for entry in journal:
                journalentry = entry[0:-1].replace('\\n"', '"')
                journalentry = re.sub(r'([^\\])\\("[^\\])', r"\1\2", journalentry)
                journalentry = re.sub(
                    r'("MESSAGE":")([^_]+)"(\)?",")', r"\1\2'\3", journalentry
                )
                journalentry = re.sub(
                    r'("MESSAGE":")([^_]+)"([^"\']+\'\)?",")', r"\1\2'\3", journalentry
                )
                journalentry = re.sub(
                    r'("MESSAGE":")([^_]+)"(, \'[^"\']+\'\)?",")', r"\1\2'\3", journalentry
                )
                journalcount = 0
                while journalcount < 500:
                    journalentry = re.sub(r'("MESSAGE":"[^_]+)"(, )"', r"\1'\2'", journalentry)
                    journalcount += 1
                journalentry = re.sub(
                    r'("MESSAGE":")([^_]+)"([^"\']+\', \')', r"\1\2'\3", journalentry
                )
                journalentry = re.sub(
                    r'("MESSAGE":"[^"]+)"([^"]+)"([^"]+",")', r"\1'\2'\3", journalentry
                )
                journalentry = re.sub(r'("MESSAGE":"[^>]+)"(",")', r"\1'\2", journalentry)
                journalentry = re.sub(
                    r'("MESSAGE":"[^>]+)"([^"\']+\'",")', r"\1'\2", journalentry
                )
                journalcount = 0
                while journalcount < 500:
                    journalentry = re.sub(r'("MESSAGE":"[^>:]+)" ', r"\1' ", journalentry)
                    journalcount += 1
                journalentry = re.sub(r'(\' [^=]+=)"([^"\']+)', r"\1'\2", journalentry)
                journalentry = re.sub(r'([^=:]+=)"([^"\']+)', r"\1'\2", journalentry)
                journalentry = re.sub(r'(\'[^"]+)" ', r"\1' ", journalentry)
                journalentry = re.sub(r'(=\'[^"]+)"(",")', r"\1'\2", journalentry)
                journalentry = re.sub(r'(","MESSAGE":"[^,]+)" ', r"\1 ", journalentry)
                journalentry = re.sub(r'("MESSAGE":"[^"]+ )"([^",]+)"', r"\1'\2'", journalentry)
                journalentry = re.sub(r'("MESSAGE":"[^"]+ )"([^",]+)"', r"\1'\2'", journalentry)
                journalentry = re.sub(r'("MESSAGE":"[^"]+ )"([^",]+)"', r"\1'\2'", journalentry)
                journalentry = re.sub(r'\'([^"\']+)"(\) \()"', r"\1'\2'", journalentry)
                journalentry = re.sub(r'(\'[^\']+\')(,"[^"]+":")', r'\1"\2', journalentry)
                journalentry = re.sub(
                    r'(\'[^\']+\'[^\]]+)"(\][^"]+",")', r"\1'\2", journalentry
                )
                journalentry = re.sub(
                    r'(","[^"]+":")"([^"]+)"(","_)', r"\1'\2'\3", journalentry
                )
                journalentry = re.sub(
                    r'(\'[^\']+\'[^\']+)"(\) \([^\)]+\)"\})', r"\1'\2", journalentry
                )
                journalentry = re.sub(r'([^=]+=\'[^"]+)"("\})', r"\1'\2", journalentry)
                journalentry = re.sub(r'( \' [^\']+\'[^"]+)"\)(","_)', r"\1'\2", journalentry)
                journalentry = re.sub(
                    r'((?:MESSAGE|SYSLOG_RAW)":\[)([^\]]+)(\],"_)', r'\1"\2"\3', journalentry
                )
                journalentry = re.sub(r'("[^\']+)\'(:"")', r'\1"\2', journalentry)
                journalentry = re.sub(r'(":"[^"]+)"([^"]+)"(")', r"\1'\2'\3", journalentry)
                journalentry = re.sub(r'("MESSAGE":"[^"]+)(\},)', r'\1"\2', journalentry)
                journalentry = re.sub(r'("[^\'"]+)\'(:)\'(",")', r'\1"\2"\3', journalentry)
                while journalcount < 500:
                    journalentry = re.sub(
                        r'(","MESSAGE":"[^"]+)"([^\}]+\}",")', r"\1'\2'\3 ", journalentry
                    )
                    journalcount += 1
                journalentry = re.sub(
                    r'(":"[^"]+)"([^"]+)"([^"]+",")', r"\1'\2'\3", journalentry
                )
                journalentry = journalentry.replace("\\'", "'")
                journalentry = journalentry.replace("\\\\'", "'")
                journalentry = journalentry.replace("\\\\\\'", "'")
                journalentry = re.sub(r'("MESSAGE":"[^"\}]+\')(\})', r'\1"\2', journalentry)
                journalentry = re.sub(r'(, [^"\']+: )"([^"]+)"', r"\1'\2'", journalentry)
                journalentry = re.sub(
                    r'(\()"([^"]+)", "([^"]+)"(\))', r"\1'\2', '\3'\4", journalentry
                )
                journalentry = re.sub(r'(\' \'[^"\']+)"("\})', r"\1'\2", journalentry)
                journalentry = re.sub(r'(\' \'[^"\']+\')\'(,")', r'\1"\2', journalentry)
                journalentry = re.sub(r'(":"[^"]+)"([^"]+"\})', r"\1'\2", journalentry)
                journalentry = re.sub(r'(":")"([^"]+)"(",")', r"\1'\2'\3", journalentry)
                journalentry = re.sub(r'(\', \'[^"]+)"("\})', r"\1'\2", journalentry)
                journalentry = re.sub(r'(":"[^"]+\')(,"[^"]+":")', r'\1"\2', journalentry)
                journalentry = re.sub(r'(")"([^"]+)"("\})', r"\1'\2'\3", journalentry)
                journalentry = re.sub(r'(","[^"]+":"[^"]+)"([^"]+",")', r"\1'\2", journalentry)
                journalentry = journalentry.replace(' "--', " '--")
                journalentry = journalentry.replace('" --', "' --")
                journalentry = journalentry.replace('" \\"--', "' '--")
                journaljson.write("{},\n".format(journalentry))
        with open(".journal.json") as journaljson:
            journal = journaljson.read()
            with open("journal.json", "w") as finaljournaljson:
                finaljournaljson.write("[{}\n]".format(journal[0:-3]))
