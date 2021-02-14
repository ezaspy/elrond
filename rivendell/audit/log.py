#!/usr/bin/env python3 -tt

def doLog(verbosity, outdir, entry, prnt):
    if "Datetime,Host,Stage,Information" in entry:
        writemode = "w"
    else:
        writemode = "a"
    with open(outdir+str(str(prnt.split("'")[-2]).split("/")[-1]).split("::")[0]+"/"+str(str(prnt.split("'")[-2]).split("/")[-1]).split("::")[0]+".log", writemode) as logentry:
        logentry.write(entry)
    if verbosity == "veryverbose_verbose" or verbosity == "veryverbose":
        print(prnt)
    else:
        pass
