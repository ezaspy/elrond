#!/usr/bin/env python3 -tt
import os
import re
import shlex
import subprocess
from datetime import datetime

from rivendell.audit import write_audit_log_entry


def tidy_journalentry(entry):
    journalentry = '{{"{}'.format(entry[0:-1].replace('\\n"', '"'))
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
    journalentry = journalentry.replace("\\'", "'")
    journalentry = re.sub(r"([^\\]\\)'", r"\1'", journalentry)
    journalentry = re.sub(r"([^\\]\\)x", r"\1\\x", journalentry)
    journalentry = re.sub(r"( [^=]+=)\\\\\"([^\"']+)(?:'|\")", r"\1'\2'", journalentry)
    journalentry = re.sub(r"([^\\])\\(' [^=]+=)", r"\1\2", journalentry)
    journalentry = re.sub(r"([^\\'\"])\\(\"\},)", r"\1'\2", journalentry)
    journalentry = re.sub(r"(\":\"[^\"]+)\\\\\"([^\"']+)(\")", r"\1'\2'\3", journalentry)
    journalentry = re.sub(r'(")\\\\"([^"]+)', r'\1\2', journalentry)
    journalentry = re.sub(r'\\\\"([^"]+)', r"'\1'", journalentry)
    journalentry = re.sub(r"('[^']+)\\\\(')", r"\1\2", journalentry)
    journalentry = re.sub(r"(')\"([^\}])", r"\1\2", journalentry)
    journalentry = re.sub(r'(\')(,"[^"]+":")', r"\1\2", journalentry)
    journalentry = re.sub(r"([^\\])\\(')", r"\1\2", journalentry)
    journalentry = re.sub(r'(":"[^"]+\')(,")', r'\1"\2', journalentry)
    journalentry = journalentry.strip("\\")
    journalentry = '{}"}},\n'.format(journalentry)
    journalentry = re.sub(r'([^\"])("\}\},)', r'\1"\2', journalentry)
    journalentry = journalentry.replace('":"},\n', '":""},\n')
    journalentry = journalentry.replace('\\\\""},', "'\"},")
    return journalentry


def process_journal(
    verbosity, vssimage, output_directory, img, vss_path_insert, stage, artefact
):
    journal_tmpfile = output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert + ".journalctl.json"
    journal_outfile = output_directory + img.split("::")[0] + "/artefacts/cooked" + vss_path_insert + "journalctl.json"
    if not os.path.exists(
        journal_outfile
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
        journal_command = shlex.split(
            'journalctl -D {} --all --output=json'.format(
                "/".join(artefact.split("/")[0:-1])
            )
        )
        journal_command_output = str(subprocess.Popen(
            journal_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()[0])[2:-3]
        with open(
            output_directory
            + img.split("::")[0]
            + "/artefacts/cooked"
            + vss_path_insert
            + ".journalctl.json",
            "a",
        ) as journaljson:
            if verbosity != "":
                print(
                    "     Processing systemd journals for {}...".format(
                        vssimage,
                    )
                )
            entry, prnt = "{},{},{},systemd journals\n".format(
                datetime.now().isoformat(),
                vssimage.replace("'", ""),
                stage,
            ), " -> {} -> {} systemd journals from {}".format(
                datetime.now().isoformat().replace("T", " "),
                stage,
                vssimage,
            )
            write_audit_log_entry(verbosity, output_directory, entry, prnt)
            journal_command_output = re.sub(r'(:)(\[[^\["]+,\d+\])(\}\\n\{")', r'\1"\2"\3', journal_command_output)
            for entry in journal_command_output[2:-2].split('"}\\n{"'):
                journalentry = tidy_journalentry(entry)
                with open(journal_tmpfile, "a") as journaljson:
                    journaljson.write(journalentry)
        with open(journal_tmpfile) as journaljson:
            journal = journaljson.read()
        with open(journal_outfile, "w") as finaljournaljson:
            finaljournaljson.write("[{}]".format(journal[0:-2]))
        os.remove(journal_tmpfile)
