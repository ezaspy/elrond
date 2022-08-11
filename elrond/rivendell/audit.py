#!/usr/bin/env python3 -tt
def print_done(verbosity):
    if verbosity != "":
        print("      Done.")
    else:
        pass


def write_audit_log_entry(verbosity, output_directory, entry, prnt):
    if "LastWriteTime,elrond_host,elrond_stage,elrond_log_entry\n" in entry:
        writemode = "w"
    else:
        writemode = "a"
    with open(
        output_directory
        + str(str(prnt.split("'")[-2]).split("/")[-1]).split("::")[0]
        + "/log.audit",
        writemode,
    ) as logentry:
        logentry.write(entry.replace("'", ""))
    if prnt != "" and verbosity == "veryverbose":
        print(prnt)
    else:
        pass
