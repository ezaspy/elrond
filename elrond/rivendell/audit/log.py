#!/usr/bin/env python3 -tt
def doLog(verbosity, outdir, entry, prnt):
    if "elrond_time,elrond_host,elrond_stage,elrond_log_entry" in entry:
        writemode = "w"
    else:
        writemode = "a"
    with open(outdir+str(str(prnt.split("'")[-2]).split("/")[-1]).split("::")[0]+"/log.audit", writemode) as logentry:
        logentry.write(entry.replace("'",""))
    if verbosity == "veryverbose_verbose" or verbosity == "veryverbose":
        print(prnt)
    else:
        pass
