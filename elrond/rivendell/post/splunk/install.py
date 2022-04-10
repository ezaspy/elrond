#!/usr/bin/env python3 -tt
import getpass
import os
import re
import subprocess
import time
from datetime import datetime
from collections import OrderedDict
from tarfile import TarFile

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry
from rivendell.post.splunk.apps.geolocate import build_app_geolocate
from rivendell.post.splunk.apps.lookup import build_app_lookup
from rivendell.post.splunk.apps.punchcard import build_app_punchcard
from rivendell.post.splunk.apps.sankey import build_app_sankey
from rivendell.post.splunk.apps.topology import build_app_topology
from rivendell.post.splunk.apps.treemap import build_app_treemap
from rivendell.post.splunk.elrond_app.app import build_app_elrond
from rivendell.post.splunk.ingest import ingest_splunk_data


def create_splunk_index(verbosity, output_directory, case, stage, imgs, postpath):
    indxq = input(
        "    Index {} already exists, would you like to overwrite the existing index or create a new index? [O]verwrite/[n]ew O ".format(
            case
        )
    )
    if indxq != "n":
        splkindx = str(
            subprocess.Popen(
                ["./splunk", "remove", "index", case],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
        )
    else:
        case = input("    Name of new index: ").strip("\n")
    for img in imgs:
        entry, prnt = "{},{},adding {} index {}, {}".format(
            datetime.now().isoformat(),
            stage,
            stage,
            case,
            img.split("::")[0],
        ), " -> {} -> adding {} index {} for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            case,
            img.split("::")[0],
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        splkindx = str(
            subprocess.Popen(
                [
                    "/" + postpath + "splunk/bin/./splunk",
                    "add",
                    "index",
                    case,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()[0]
        )
        if len(splkindx[2:-1]) == 0 or splkindx[2:-3] == 'Index "' + case + '" added.':
            if len(splkindx[2:-1]) == 0:
                print("    Splunk index '{}' already exists...".format(case))
                create_splunk_index(
                    verbosity, output_directory, case, stage, imgs, postpath
                )
            elif splkindx[2:-3] == 'Index "' + case + '" added.':
                print("    Splunk index created for '{}'...".format(case))
            else:
                pass
        else:
            print(
                "    Splunk index creation failed for '{}'.\n    Please try again.".format(
                    case
                )
            )
            create_splunk_index(
                verbosity, output_directory, case, stage, imgs, postpath
            )


def install_splunk_stack(
    verbosity, output_directory, case, stage, imgs, splunkdeb, postpath
):
    def doSplunkPSWD(reqpswd, postpath):
        try:
            vrfypswd = subprocess.Popen(
                [
                    "/" + postpath + "splunk/bin/./splunk",
                    "validate-passwd",
                    reqpswd,
                    "--accept-license",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()[1]
        except:
            print(
                "\n     It looks like you have a corrupt Splunk installation - neither installed or uninstalled.\n     You may have a Splunk process still running from an unclean install. Remove all traces of Splunk and try again.\n"
            )
        if not str(vrfypswd) == "b''":
            reqpswd = getpass.getpass(
                "     -> Password did not meet complexity requirements...\n       * Password must contain at least 8 printable ASCII character(s)\n       Splunk admin password: "
            )
            doSplunkPSWD(reqpswd, postpath)
        else:
            pass

    subprocess.Popen(
        ["dpkg", "-i", splunkdeb],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    subprocess.Popen(
        ["updatedb"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).communicate()
    requser, reqpswd = input("       Splunk admin username: "), getpass.getpass(
        "       * Password must contain at least 8 printable ASCII character(s)\n       Splunk admin password: "
    )
    doSplunkPSWD(reqpswd, postpath)
    pswdhash = subprocess.Popen(
        ["/" + postpath + "splunk/bin/./splunk", "hash-passwd", reqpswd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()[0]
    with open(
        "/" + postpath + "splunk/etc/system/local/user-seed.conf", "w"
    ) as splunkuserfile:
        splunkuserfile.write(
            "[user_info]\nUSERNAME = "
            + requser
            + "\nHASHED_PASSWORD = "
            + str(pswdhash)[2:-3]
        )
    subprocess.Popen(
        [
            "/" + postpath + "splunk/bin/./splunk",
            "start",
            "--accept-license",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    subprocess.Popen(
        ["/" + postpath + "splunk/bin/./splunk", "stop"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    if "already exists" in str(
        subprocess.Popen(
            ["/" + postpath + "splunk/bin/./splunk", "add", "index", case],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()[0]
    ):
        create_splunk_index(verbosity, output_directory, case, stage, imgs, postpath)
    else:
        pass
    print("     Splunk installed successfully.")
    return requser, reqpswd


def configure_splunk_stack(
    verbosity, output_directory, case, imgs, volatility, analysis, timeline
):
    splunkdebpath = (
        "/opt/elrond/elrond/tools/"  # prompt for cutom location if it doesn't exist
    )
    splkproc = subprocess.Popen(
        ["locate", "splunk.version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()[0]
    postpath = "opt/"
    imgs = OrderedDict(sorted(imgs.items(), key=lambda x: x[1]))
    pwd = os.getcwd()
    stage = "splunk"
    apps = {
        "lookup_editor/": "lookup-file-editor_346.tar",
        "network_topology/": "network_topology.tar",
        "punchcard_app/": "punchcard-custom-visualization_140.tar",
        "sankey_diagram_app/": "splunk-sankey-diagram-custom-visualization_150.tar",
        "TA-geolocate/": "geolocation-lookup-for-splunk_114.tar",
        "treemap_app/": "treemap-custom-visualization_140.tar",
    }
    print(
        "\n\n  -> \033[1;36mCommencing Splunk Phase...\033[1;m\n  ----------------------------------------"
    )
    time.sleep(1)
    for eachfile in os.listdir(splunkdebpath):
        if eachfile.startswith(".splunk") and eachfile.endswith(".deb"):
            splunkdeb = splunkdebpath + eachfile
        else:
            pass
    if len(splkproc[2:-3]) != 0:
        postpath = str(
            re.findall(r"\/(.*)splunk\/etc\/splunk.version", str(splkproc)[2:-3])[0]
        )
    else:
        print("     Splunk is not installed, please stand by...")
        splunkuser, splunkpswd = install_splunk_stack(
            verbosity, output_directory, case, stage, imgs, splunkdeb, postpath
        )
    try:
        subprocess.Popen(
            ["/" + postpath + "splunk/bin/./splunk", "stop"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
    except:
        pass
    with open(
        "/" + postpath + "splunk/etc/system/default/limits.conf"
    ) as limitsconfread:
        oldlimitsdata = limitsconfread.read()
    newlimitsdata = str(
        re.sub(r"indexed_kv_limit = \d+", r"indexed_kv_limit = 0", oldlimitsdata)
    )
    with open(
        "/" + postpath + "splunk/etc/system/default/limits.conf", "w"
    ) as limitsconfwrite:
        limitsconfwrite.write(newlimitsdata)
    if not os.path.isdir(
        "/" + postpath + "splunk/etc/apps/elrond/"
    ):  # deploying elrond Splunk app
        build_app_elrond(case, postpath)
        print_done(verbosity)
    else:
        with open(
            "/" + postpath + "splunk/etc/apps/elrond/default/data/ui/nav/default.xml"
        ) as defaultxml:
            defaultxmllines = defaultxml.read()
            hascase = str(defaultxmllines).split(case)
            if len(hascase) < 2:
                extractcase = re.sub(
                    r"([\S\s]+)(\\n\\t<collection label=\"Cases\">)(\\n\\t\\t<view source=\"all\" match=\")([^\\\"]+)(\" />)([\S\s]+)",
                    r"\1\2\3\4\5\3_-_-_-_-_-_\5\6",
                    str(hascase)[2:-2],
                )
                insertcase = extractcase.replace("_-_-_-_-_-_", case).replace(
                    "\\t", "    "
                )
            else:
                insertcase = "-"
        if insertcase != "-":
            if "already exists" in str(
                subprocess.Popen(
                    [
                        "/" + postpath + "splunk/bin/./splunk",
                        "add",
                        "index",
                        case,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()[0]
            ):
                create_splunk_index(
                    verbosity, output_directory, case, stage, imgs, postpath
                )
            else:
                pass
            with open(
                "/"
                + postpath
                + "splunk/etc/apps/elrond/default/data/ui/nav/default.xml",
                "w",
            ) as defaultxml:
                for eachnavline in insertcase.split("\\n"):
                    defaultxml.write(eachnavline + "\n")
            with open(
                "/"
                + postpath
                + "splunk/etc/apps/elrond/default/data/ui/views/"
                + case
                + ".xml",
                "w",
            ) as casexml:
                casexml.write(
                    '<form stylesheet="mitre.css" theme="light">\n  <search id="base">\n    <query>index=* host=* | dedup index host | table index host</query>\n    <earliest>$time_tok.earliest$</earliest>\n    <latest>$time_tok.latest$</latest>\n  </search>\n  <search id="ip">\n    <query>index=$case_tok$ host=$host_tok$ | fields ip count host | search ip!=NULL | mvexpand ip | search ip!=NULL | stats count BY ip host</query>\n    <earliest>$time_tok.earliest$</earliest>\n    <latest>$time_tok.latest$</latest>\n  </search>\n  <label>{}</label>\n  <fieldset submitButton="true" autoRun="false">\n    <input type="checkbox" token="it_tok" searchWhenChanged="true">\n      <label></label>\n      <populatingSearch fieldForLabel="it" fieldForValue="it">| gentimes start=-1 | eval it="Toggle MITRE Information"</populatingSearch>\n      <delimiter> </delimiter>\n      <fieldForLabel>it</fieldForLabel>\n      <fieldForValue>it</fieldForValue>\n    </input>\n    <input type="dropdown" token="case_tok" searchWhenChanged="false">\n      <label>Select a Case:</label>\n      <choice value="*">All</choice>\n      <default>*</default>\n      <initialValue>*</initialValue>\n      <fieldForLabel>index</fieldForLabel>\n      <fieldForValue>index</fieldForValue>\n      <search base="base">\n        <query>| dedup index | sort index</query>\n      </search>\n    </input>\n    <input type="dropdown" token="host_tok" searchWhenChanged="false">\n      <label>Select a Host:</label>\n      <choice value="*">All</choice>\n      <default>*</default>\n      <initialValue>*</initialValue>\n      <fieldForLabel>host</fieldForLabel>\n      <fieldForValue>host</fieldForValue>\n      <search base="base">\n        <query>| dedup host | sort host</query>\n      </search>\n    </input>\n    <input type="time" token="time_tok" searchWhenChanged="false">\n      <label>Select a Time Range:</label>\n      <default>\n        <earliest>-1d@d</earliest>\n        <latest>@d</latest>\n      </default>\n    </input>\n  </fieldset>\n  <row>\n    <panel depends="$it_tok$">\n      <table>\n        <title>Adversarial Tactics, Techniques &amp; Common Knowledge</title>\n        <search>\n          <query>| inputlookup mitre.csv | table name id tactic platform threat_actor description | sort name | rename name AS Name id AS ID tactic AS Tactic platform AS Platform threat_actor AS "Threat Actor" description AS Description</query>\n          <earliest>$earliest$</earliest>\n          <latest>$latest$</latest>\n        </search>\n        <option name="count">10</option>\n        <option name="dataOverlayMode">none</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">false</option>\n      </table>\n    </panel>\n  </row>\n  <row>\n    <panel>\n      <single>\n        <title>Total Number of Events</title>\n        <search>\n          <query>index=$case_tok$ host=$host_tok$ | stats count</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n        </search>\n        <option name="colorBy">value</option>\n        <option name="colorMode">none</option>\n        <option name="drilldown">none</option>\n        <option name="height">188</option>\n        <option name="numberPrecision">0</option>\n        <option name="rangeColors">["0x53a051","0x0877a6","0xf8be34","0xf1813f","0xdc4e41"]</option>\n        <option name="rangeValues">[0,30,70,100]</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="showSparkline">0</option>\n        <option name="showTrendIndicator">0</option>\n        <option name="trellis.enabled">0</option>\n        <option name="trellis.scales.shared">1</option>\n        <option name="trellis.size">medium</option>\n        <option name="trendColorInterpretation">standard</option>\n        <option name="trendDisplayMode">absolute</option>\n        <option name="unitPosition">after</option>\n        <option name="useColors">0</option>\n        <option name="useThousandSeparators">1</option>\n      </single>\n    </panel>\n    <panel>\n      <table>\n        <title>Top 5 Users</title>\n        <search>\n          <query>index=$case_tok$ host=$host_tok$ | `make_userprofile` | stats count BY user_profile | sort 5 -count | table count user_profile | rename user_profile AS "User Profile" count AS Count</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n        </search>\n        <option name="count">5</option>\n        <option name="dataOverlayMode">highlow</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">false</option>\n      </table>\n    </panel>\n  </row>\n  <row>\n    <panel>\n      <input type="checkbox" token="ltgt_tok" searchWhenChanged="true">\n        <label>Select Less/Greater Than:</label>\n        <choice value="&lt;">Less Than</choice>\n        <choice value="&gt;">Greater Than</choice>\n        <default>&gt;</default>\n        <initialValue>&gt;</initialValue>\n        <delimiter> </delimiter>\n      </input>\n      <input type="text" token="count_tok" searchWhenChanged="true">\n        <label>Enter Number of Connections:</label>\n        <default>0</default>\n        <initialValue>0</initialValue>\n      </input>\n      <viz type="network_topology.network_topology">\n        <title>Internal Network Map</title>\n        <search>\n          <query>index=$case_tok$ host=$host_tok$ | stats count BY ip host | where count$ltgt_tok$$count_tok$ | fields ip count host | search ip=10.0.0.0/8 OR ip=172.16.0.0/16 OR ip=192.168.0.0/16 | table ip count host empty1 empty2 | eval count="#"+count | fillnull value=-</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n        </search>\n        <option name="drilldown">none</option>\n        <option name="height">500</option>\n        <option name="network_topology.network_topology.drilldown">false</option>\n        <option name="network_topology.network_topology.link1">link1</option>\n        <option name="network_topology.network_topology.link1Color">#ffc000</option>\n        <option name="network_topology.network_topology.link1Dashed">true</option>\n        <option name="network_topology.network_topology.link1Label">Link 1</option>\n        <option name="network_topology.network_topology.link2">link2</option>\n        <option name="network_topology.network_topology.link2Color">#00b050</option>\n        <option name="network_topology.network_topology.link2Dashed">true</option>\n        <option name="network_topology.network_topology.link2Label">Link 2</option>\n        <option name="network_topology.network_topology.link3">link3</option>\n        <option name="network_topology.network_topology.link3Color">#006d9c</option>\n        <option name="network_topology.network_topology.link3Dashed">true</option>\n        <option name="network_topology.network_topology.link3Label">Link 3</option>\n        <option name="network_topology.network_topology.link4">link4</option>\n        <option name="network_topology.network_topology.link4Color">#7030A0</option>\n        <option name="network_topology.network_topology.link4Dashed">true</option>\n        <option name="network_topology.network_topology.link4Label">Link 4</option>\n        <option name="network_topology.network_topology.link5">link5</option>\n        <option name="network_topology.network_topology.link5Color">#c00000</option>\n        <option name="network_topology.network_topology.link5Dashed">true</option>\n        <option name="network_topology.network_topology.link5Label">Link 5</option>\n        <option name="network_topology.network_topology.unfocusOpacity">1</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="trellis.enabled">0</option>\n        <option name="trellis.scales.shared">1</option>\n        <option name="trellis.size">medium</option>\n      </viz>\n    </panel>\n    <panel>\n      <table>\n        <title>Top 10 Most/Least Visited URLs</title>\n        <search>\n          <query>index=$case_tok$ host=$host_tok$ | stats count AS Count BY url | eval URL=trim(url,"\'") | sort 10 -Count | table Count URL</query>\n          <earliest>$earliest$</earliest>\n          <latest>$latest$</latest>\n        </search>\n        <option name="count">10</option>\n        <option name="dataOverlayMode">highlow</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">false</option>\n      </table>\n      <table>\n        <search>\n          <query>index=$case_tok$ host=$host_tok$ | stats count AS Count BY url | eval URL=trim(url,"\'") | sort 10 Count | table Count URL</query>\n          <earliest>$earliest$</earliest>\n          <latest>$latest$</latest>\n        </search>\n        <option name="count">10</option>\n        <option name="dataOverlayMode">highlow</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n<option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">false</option>\n      </table>\n    </panel>\n  </row>\n  <row>\n    <panel>\n      <table>\n        <title>External Devices Connected via USB</title>\n        <search>\n          <query>index=$case_tok$ host=$host_tok$ `usb_out`</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n        </search>\n        <option name="count">10</option>\n        <option name="dataOverlayMode">none</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">true</option>\n      </table>\n    </panel>\n  </row>\n  <row>\n    <panel>\n      <map>\n        <title>External Network Communications</title>\n        <search base="ip">\n          <query>| search ip!=10.0.0.0/8 ip!=172.16.0.0/16 ip!=192.168.0.0/16 | iplocation ip | geostats count by Country</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n          <sampleRatio>1</sampleRatio>\n        </search>\n        <option name="drilldown">none</option>\n        <option name="height">600</option>\n        <option name="mapping.map.center">(20,10)</option>\n        <option name="mapping.map.zoom">3</option>\n        <option name="mapping.type">marker</option>\n      </map>\n    </panel>\n  </row>\n</form>'.format(
                        case
                    )
                )
        else:
            pass
    ingest_splunk_data(
        verbosity,
        output_directory,
        case,
        stage,
        imgs,
        postpath,
        volatility,
        analysis,
        timeline,
    )
    for appdir, apptar in apps.items():
        if not os.path.isdir("/" + postpath + "splunk/etc/apps/" + appdir):
            os.makedirs("/" + postpath + "splunk/etc/apps/" + appdir)
            with open("." + apptar, "w") as tarout:
                if appdir == "lookup_editor/":
                    apphexdump = build_app_lookup()
                    tarout.write(apphexdump)
                elif appdir == "network_topology/":
                    apphexdump = build_app_topology()
                    tarout.write(apphexdump)
                elif appdir == "punchcard_app/":
                    apphexdump = build_app_punchcard()
                    tarout.write(apphexdump)
                elif appdir == "sankey_diagram_app/":
                    apphexdump = build_app_sankey()
                    tarout.write(apphexdump)
                elif appdir == "TA-geolocate/":
                    apphexdump = build_app_geolocate()
                    tarout.write(apphexdump)
                elif appdir == "treemap_app/":
                    apphexdump = build_app_treemap()
                    tarout.write(apphexdump)
                else:
                    pass
                subprocess.call(["xxd", "-plain", "-revert", "." + apptar, apptar])
                with TarFile(apptar) as tar:
                    tar.extractall("/" + postpath + "splunk/etc/apps/")
                os.remove("." + apptar)
                os.remove(apptar)
                os.chdir("/" + postpath + "splunk/etc/apps/")
                subprocess.Popen(
                    ["chmod", "-R", "755", appdir],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()
                subprocess.Popen(
                    ["chown", "-R", "splunk:splunk", appdir],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()
        else:
            pass
    os.chdir("/" + postpath + "splunk/etc/apps/")
    subprocess.Popen(
        ["chmod", "-R", "755", "elrond/"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    subprocess.Popen(
        ["chown", "-R", "splunk:splunk", "elrond/"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    subprocess.Popen(
        ["/" + postpath + "splunk/bin/./splunk", "start"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    subprocess.Popen(
        ["sudo", "/bin/systemctl", "enable", "splunk.service"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    subprocess.Popen(
        ["/" + postpath + "splunk/bin/./splunk", "restart"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    print()
    print(
        "   Splunk Web is available at:            127.0.0.1:8000"
    )  # adjust if custom location
    os.chdir(pwd)
    return splunkuser, splunkpswd
