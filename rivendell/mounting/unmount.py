#!/usr/bin/env python3 -tt
import os, subprocess, time

def doUnmount():
    def doU(each):
        subprocess.Popen(["umount", each], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        time.sleep(0.1)
    def doRM(each):
        shutil.rmtree(each)
        time.sleep(0.1)
    for shadowimg in os.listdir("/mnt/shadow_mount/"):
        for everyshadow in os.listdir("/mnt/shadow_mount/"+shadowimg):
            doU("/mnt/shadow_mount/"+shadowimg+"/"+everyshadow)
        doRM("/mnt/shadow_mount/"+shadowimg)
    doU("/mnt/vss/")
    for eachimage in elrond_mount:
        if os.path.exists(eachimage):
            doU(eachimage+"/")
            doRM(eachimage)
        else:
            pass
    for eachewf in ewf_mount:
        if os.path.exists(eachewf):
            doU(eachewf+"/")
            if eachewf != "/mnt/ewf_mount":
                doRM(eachewf)
            else:
                pass
        else:
            pass
