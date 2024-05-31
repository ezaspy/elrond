#!/usr/bin/env python3 -tt
import getpass
import os
import re
import subprocess
import time
from datetime import datetime
from collections import OrderedDict
from tarfile import TarFile

from rivendell.audit import write_audit_log_entry
from rivendell.post.splunk.app.app import build_app_elrond
from rivendell.post.splunk.apps.geolocate import build_app_geolocate
from rivendell.post.splunk.apps.lookup import build_app_lookup
from rivendell.post.splunk.apps.punchcard import build_app_punchcard
from rivendell.post.splunk.apps.sankey import build_app_sankey
from rivendell.post.splunk.apps.topology import build_app_topology
from rivendell.post.splunk.apps.treemap import build_app_treemap
from rivendell.post.splunk.ingest import ingest_splunk_data


def splunk_service(splunk_install_path, action):
    subprocess.Popen(
        ["/" + splunk_install_path + "splunk/bin/./splunk", action],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()


def overwrite_splunk_index(
    verbosity, output_directory, case, stage, allimgs, splunk_install_path
):
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
    for _, everyimg in allimgs.items():
        entry, prnt = "{},{},adding {} index {}, {}".format(
            datetime.now().isoformat(),
            stage,
            stage,
            case,
            everyimg.split("::")[0],
        ), " -> {} -> adding {} index {} for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            case,
            everyimg.split("::")[0],
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        splkindx = str(
            subprocess.Popen(
                [
                    "/" + splunk_install_path + "splunk/bin/./splunk",
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
                overwrite_splunk_index(
                    verbosity,
                    output_directory,
                    case,
                    stage,
                    allimgs,
                    splunk_install_path,
                )
            elif splkindx[2:-3] == 'Index "' + case + '" added.':
                print("    Splunk index created for '{}'...".format(case))
        else:
            print(
                "    Splunk index creation failed for '{}'.\n    Please try again.".format(
                    case
                )
            )
            overwrite_splunk_index(
                verbosity, output_directory, case, stage, allimgs, splunk_install_path
            )


def install_splunk_stack(
    verbosity,
    output_directory,
    case,
    stage,
    allimgs,
    splunk_deb_file,
    splunk_install_path,
):
    def verify_splunk_password(request_password, splunk_install_path):
        try:
            vrfypswd = subprocess.Popen(
                [
                    "/" + splunk_install_path + "splunk/bin/./splunk",
                    "validate-passwd",
                    request_password,
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
            request_password = getpass.getpass(
                "     -> Password did not meet complexity requirements...\n       * Password must contain at least 8 printable ASCII characters\n       Splunk admin password: "
            )
            verify_splunk_password(request_password, splunk_install_path)

    subprocess.Popen(
        ["dpkg", "-i", splunk_deb_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    subprocess.Popen(
        ["updatedb"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).communicate()
    requser, request_password = input(
        "       Splunk admin username: "
    ), getpass.getpass(
        "       * Password must contain at least 8 printable ASCII character(s)\n       Splunk admin password: "
    )
    verify_splunk_password(request_password, splunk_install_path)
    pswdhash = subprocess.Popen(
        [
            "/" + splunk_install_path + "splunk/bin/./splunk",
            "hash-passwd",
            request_password,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()[0]
    with open(
        "/" + splunk_install_path + "splunk/etc/system/local/user-seed.conf", "w"
    ) as splunkuserfile:
        splunkuserfile.write(
            "[user_info]\nUSERNAME = "
            + requser
            + "\nHASHED_PASSWORD = "
            + str(pswdhash)[2:-3]
        )
    subprocess.Popen(
        [
            "/" + splunk_install_path + "splunk/bin/./splunk",
            "start",
            "--accept-license",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    splunk_service(splunk_install_path, "stop")
    if "already exists" in str(
        subprocess.Popen(
            ["/" + splunk_install_path + "splunk/bin/./splunk", "add", "index", case],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()[0]
    ):
        overwrite_splunk_index(
            verbosity, output_directory, case, stage, allimgs, splunk_install_path
        )
    print("     Splunk installed successfully.")
    return requser, request_password


def configure_splunk_stack(verbosity, output_directory, case, stage, allimgs):
    def request_splunk_creds():
        splunkuser, splunkpswd = input(
            "      Splunk admin username: "
        ), getpass.getpass("      Splunk admin password: ")
        splunk_service(splunk_install_path, "start")
        testcreds = subprocess.Popen(
            [
                "curl",
                "-u",
                splunkuser.strip() + ":" + splunkpswd.strip(),
                "-k",
                "https://localhost:8089/services/search/jobs",
                "-d",
                "search=search index=* host=*",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        if "Unauthorized" in str(testcreds)[3:-4] and "ERROR" in str(testcreds)[3:-4]:
            print("\n     Invalid credentials. Please try again...")
            splunkuser, splunkpswd = request_splunk_creds()
        splunk_service(splunk_install_path, "stop")
        return splunkuser, splunkpswd

    splunk_install_locations = []
    splunk_locations = subprocess.Popen(
        ["locate", "splunk.version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    for splunk_location in splunk_locations:
        if (
            not str(splunk_location)[2:-3].startswith("/mnt/elrond_mount")
            and str(splunk_location) != "b''"
        ):
            splunk_install_locations.append(str(splunk_location)[2:-3])
    splunk_install_locations = list(set(splunk_install_locations))
    allimgs = OrderedDict(sorted(allimgs.items(), key=lambda x: x[1]))
    splunk_install_path = "opt/"
    pwd = os.getcwd()
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
    if len(splunk_install_locations) > 0:
        if len(splunk_install_locations[0]) != 0:
            pathfound = str(
                re.findall(
                    r"\/(.*)splunk\/etc\/splunk.version",
                    str(splunk_install_locations[0]),
                )[0]
            )
            if pathfound != "":
                splunk_install_path = pathfound
                print("     Splunk installation found, please provide")
                splunkuser, splunkpswd = request_splunk_creds()
    else:
        print("    Splunk is not installed, please stand by...")
        splunkuser, splunkpswd = install_splunk_stack(
            verbosity,
            output_directory,
            case,
            stage,
            allimgs,
            "/opt/elrond/elrond/tools/.splunk.deb",
            splunk_install_path,
        )
        with open(
            "/" + splunk_install_path + "splunk/etc/system/default/limits.conf"
        ) as limitsconfread:
            oldlimitsdata = limitsconfread.read()
        newlimitsdata = re.sub(
            r"max_mem_usage_mb = \d+",
            r"max_mem_usage_mb = 1000",
            str(
                re.sub(
                    r"indexed_kv_limit = \d+", r"indexed_kv_limit = 0", oldlimitsdata
                )
            ),
        )
        with open(
            "/" + splunk_install_path + "splunk/etc/system/local/limits.conf", "w"
        ) as limitsconfwrite:
            limitsconfwrite.write(newlimitsdata)
    if not os.path.isdir(
        "/" + splunk_install_path + "splunk/etc/apps/elrond/"
    ):  # deploying elrond Splunk app
        build_app_elrond(case, splunk_install_path)
    else:
        with open(
            "/"
            + splunk_install_path
            + "splunk/etc/apps/elrond/default/data/ui/nav/default.xml"
        ) as default_nav:
            default_nav_xml = default_nav.read()
            if case not in default_nav_xml:
                insert_new_case = re.sub(
                    r"([\S\s]+<collection label=\"Cases\">)(\n\s+<view source=\"all\" match=\")([^\"]+)(\" />)([\S\s]+)",
                    r"\1\2§±§±§±§\4\2\3\4\5",
                    default_nav_xml,
                )
                insert_new_case = insert_new_case.replace("§±§±§±§", case)
                if "already exists" in str(
                    subprocess.Popen(
                        [
                            "/" + splunk_install_path + "splunk/bin/./splunk",
                            "add",
                            "index",
                            case,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate()[0]
                ):
                    overwrite_splunk_index(
                        verbosity,
                        output_directory,
                        case,
                        stage,
                        allimgs,
                        splunk_install_path,
                    )
                with open(
                    "/"
                    + splunk_install_path
                    + "splunk/etc/apps/elrond/default/data/ui/nav/default.xml",
                    "w",
                ) as new_default_nav:
                    new_default_nav.write(insert_new_case + "\n")
            if not os.path.isfile(
                "/"
                + splunk_install_path
                + "splunk/etc/apps/elrond/default/data/ui/views/"
                + case
                + ".xml"
            ):
                with open(
                    "/"
                    + splunk_install_path
                    + "splunk/etc/apps/elrond/default/data/ui/views/"
                    + case
                    + ".xml",
                    "w",
                ) as casexml:
                    casexml.write(
                        '<form version="1.1" stylesheet="mitre.css" theme="light">\n  <search id="base">\n    <query>index={} host=* | dedup index host | table index host</query>\n    <earliest>$time_tok.earliest$</earliest>\n    <latest>$time_tok.latest$</latest>\n  </search>\n  <search id="browser">\n    <query>index={} host=$host_tok$ | `browser_domain` | stats count AS Count BY domain</query>\n    <earliest>$time_tok.earliest$</earliest>\n    <latest>$time_tok.latest$</latest>\n  </search>\n  <search id="ip">\n    <query>index={} host=$host_tok$ | fields ip count host | search ip!=NULL | mvexpand ip | search ip!=NULL | stats count BY ip host</query>\n    <earliest>$time_tok.earliest$</earliest>\n    <latest>$time_tok.latest$</latest>\n  </search>\n  <label>{}</label>\n  <fieldset submitButton="true" autoRun="false">\n    <input type="checkbox" token="it_tok" searchWhenChanged="true">\n      <label></label>\n      <search>\n        <query><![CDATA[| gentimes start=-1 | eval it="Toggle MITRE Information"]]></query>\n      </search>\n      <fieldForLabel>it</fieldForLabel>\n      <fieldForValue>it</fieldForValue>\n      <delimiter> </delimiter>\n    </input>\n    <input type="dropdown" token="host_tok" searchWhenChanged="false">\n      <label>Select a Host:</label>\n      <choice value="*">All</choice>\n      <default>*</default>\n      <initialValue>*</initialValue>\n      <fieldForLabel>host</fieldForLabel>\n      <fieldForValue>host</fieldForValue>\n      <search base="base">\n        <query>| dedup host | sort host</query>\n      </search>\n    </input>\n    <input type="time" token="time_tok" searchWhenChanged="false">\n      <label>Select a Time Range:</label>\n      <default>\n        <earliest>-1d@d</earliest>\n        <latest>@d</latest>\n      </default>\n    </input>\n  </fieldset>\n  <row>\n    <panel depends="$it_tok$">\n      <table>\n        <title>Adversarial Tactics, Techniques &amp; Common Knowledge</title>\n        <search>\n          <query>| inputlookup mitreall.csv | table name id tactic platform threat_actor description | sort name | rename name AS Name id AS ID tactic AS Tactic platform AS Platform threat_actor AS "Threat Actor" description AS Description</query>\n          <earliest>$earliest$</earliest>\n          <latest>$latest$</latest>\n        </search>\n        <option name="count">10</option>\n        <option name="dataOverlayMode">none</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">false</option>\n      </table>\n    </panel>\n  </row>\n  <row>\n    <panel>\n      <single>\n        <title>Total Number of Events</title>\n        <search>\n          <query>index={} host=$host_tok$ | stats count</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n        </search>\n        <option name="colorBy">value</option>\n        <option name="colorMode">none</option>\n        <option name="drilldown">none</option>\n        <option name="height">188</option>\n        <option name="numberPrecision">0</option>\n        <option name="rangeColors">["0x53a051","0x0877a6","0xf8be34","0xf1813f","0xdc4e41"]</option>\n        <option name="rangeValues">[0,30,70,100]</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="showSparkline">0</option>\n        <option name="showTrendIndicator">0</option>\n        <option name="trellis.enabled">0</option>\n        <option name="trellis.scales.shared">1</option>\n        <option name="trellis.size">medium</option>\n        <option name="trendColorInterpretation">standard</option>\n        <option name="trendDisplayMode">absolute</option>\n        <option name="unitPosition">after</option>\n        <option name="useColors">0</option>\n        <option name="useThousandSeparators">1</option>\n      </single>\n    </panel>\n    <panel>\n      <table>\n        <title>Top 5 Users</title>\n        <search>\n          <query>index={} host=$host_tok$ | `make_userprofile` | stats count BY user_profile | sort 5 -count | table count user_profile | rename user_profile AS "User Profile" count AS Count</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n        </search>\n        <option name="count">5</option>\n        <option name="dataOverlayMode">highlow</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">false</option>\n      </table>\n    </panel>\n  </row>\n  <row>\n    <panel>\n      <chart>\n        <title>Log Activity</title>\n        <search>\n          <query>index={} host=$host_tok$ (logtype=evt OR logtype=log OR logtype=service OR logtype=plist) | timechart count BY logtype useother=0 usenull=0 limit=0</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n        </search>\n        <option name="charting.axisLabelsX.majorLabelStyle.overflowMode">ellipsisNone</option>\n        <option name="charting.axisLabelsX.majorLabelStyle.rotation">0</option>\n        <option name="charting.axisTitleX.text">Time</option>\n        <option name="charting.axisTitleX.visibility">visible</option>\n        <option name="charting.axisTitleY.text">Count</option>\n        <option name="charting.axisTitleY.visibility">visible</option>\n        <option name="charting.axisTitleY2.visibility">visible</option>\n        <option name="charting.axisX.abbreviation">none</option>\n        <option name="charting.axisX.scale">linear</option>\n        <option name="charting.axisY.abbreviation">none</option>\n        <option name="charting.axisY.scale">linear</option>\n        <option name="charting.axisY2.abbreviation">none</option>\n        <option name="charting.axisY2.enabled">0</option>\n        <option name="charting.axisY2.scale">inherit</option>\n        <option name="charting.chart">line</option>\n        <option name="charting.chart.bubbleMaximumSize">50</option>\n        <option name="charting.chart.bubbleMinimumSize">10</option>\n        <option name="charting.chart.bubbleSizeBy">area</option>\n        <option name="charting.chart.nullValueMode">gaps</option>\n        <option name="charting.chart.showDataLabels">none</option>\n        <option name="charting.chart.sliceCollapsingThreshold">0.01</option>\n        <option name="charting.chart.stackMode">default</option>\n        <option name="charting.chart.style">shiny</option>\n        <option name="charting.drilldown">none</option>\n        <option name="charting.layout.splitSeries">0</option>\n        <option name="charting.layout.splitSeries.allowIndependentYRanges">0</option>\n        <option name="charting.legend.labelStyle.overflowMode">ellipsisMiddle</option>\n        <option name="charting.legend.mode">standard</option>\n        <option name="charting.legend.placement">bottom</option>\n        <option name="charting.lineWidth">2</option>\n        <option name="trellis.enabled">0</option>\n        <option name="trellis.scales.shared">1</option>\n        <option name="trellis.size">medium</option>\n      </chart>\n    </panel>\n  </row>\n  <row>\n    <panel>\n      <table>\n        <title>External Devices Connected via USB</title>\n        <search>\n          <query>index={} host=$host_tok$ | search `usb_out`</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n        </search>\n        <option name="count">20</option>\n        <option name="dataOverlayMode">none</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">true</option>\n      </table>\n    </panel>\n  </row>\n  <row>\n    <panel>\n      <input type="checkbox" token="ltgt_tok" searchWhenChanged="true">\n        <label>Select Less/Greater Than:</label>\n        <choice value="&lt;">Less Than</choice>\n        <choice value="&gt;">Greater Than</choice>\n        <default>&gt;</default>\n        <initialValue>&gt;</initialValue>\n        <delimiter> </delimiter>\n      </input>\n      <input type="text" token="count_tok" searchWhenChanged="true">\n        <label>Enter Number of Connections:</label>\n        <default>0</default>\n        <initialValue>0</initialValue>\n      </input>\n      <viz type="network_topology.network_topology">\n        <title>Internal (IANA Private-Use Networks) Network Map</title>\n        <search>\n          <query>index={} host=$host_tok$ | stats count BY ip host | where count$ltgt_tok$$count_tok$ | fields ip count host | search ip=10.0.0.0/8 OR ip=172.16.0.0/16 OR ip=192.168.0.0/16 | table ip count host empty1 empty2 | eval count="#"+count | fillnull value=-</query>\n          <earliest>$time_tok.earliest$</earliest>\n          <latest>$time_tok.latest$</latest>\n        </search>\n        <option name="drilldown">none</option>\n        <option name="height">500</option>\n        <option name="network_topology.network_topology.drilldown">false</option>\n        <option name="network_topology.network_topology.link1">link1</option>\n        <option name="network_topology.network_topology.link1Color">#ffc000</option>\n        <option name="network_topology.network_topology.link1Dashed">true</option>\n        <option name="network_topology.network_topology.link1Label">Link 1</option>\n        <option name="network_topology.network_topology.link2">link2</option>\n        <option name="network_topology.network_topology.link2Color">#00b050</option>\n        <option name="network_topology.network_topology.link2Dashed">true</option>\n        <option name="network_topology.network_topology.link2Label">Link 2</option>\n        <option name="network_topology.network_topology.link3">link3</option>\n        <option name="network_topology.network_topology.link3Color">#006d9c</option>\n        <option name="network_topology.network_topology.link3Dashed">true</option>\n        <option name="network_topology.network_topology.link3Label">Link 3</option>\n        <option name="network_topology.network_topology.link4">link4</option>\n        <option name="network_topology.network_topology.link4Color">#7030A0</option>\n        <option name="network_topology.network_topology.link4Dashed">true</option>\n        <option name="network_topology.network_topology.link4Label">Link 4</option>\n        <option name="network_topology.network_topology.link5">link5</option>\n        <option name="network_topology.network_topology.link5Color">#c00000</option>\n        <option name="network_topology.network_topology.link5Dashed">true</option>\n        <option name="network_topology.network_topology.link5Label">Link 5</option>\n        <option name="network_topology.network_topology.unfocusOpacity">1</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="trellis.enabled">0</option>\n        <option name="trellis.scales.shared">1</option>\n        <option name="trellis.size">medium</option>\n      </viz>\n    </panel>\n    <panel>\n      <table>\n        <title>Top 10 Most/Least Visited URLs</title>\n        <search base="browser">\n          <query>| sort 10 -Count | table Count domain | rename domain AS Domain</query>\n        </search>\n        <option name="count">10</option>\n        <option name="dataOverlayMode">highlow</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">false</option>\n      </table>\n      <table>\n        <search base="browser">\n          <query>| sort 10 Count | table Count domain | rename domain AS Domain</query>\n        </search>\n        <option name="count">10</option>\n        <option name="dataOverlayMode">highlow</option>\n        <option name="drilldown">none</option>\n        <option name="percentagesRow">false</option>\n        <option name="refresh.display">progressbar</option>\n        <option name="rowNumbers">false</option>\n        <option name="totalsRow">false</option>\n        <option name="wrap">false</option>\n      </table>\n    </panel>\n  </row>\n  <row>\n    <panel>\n      <map>\n        <title>External Network Communications</title>\n        <search base="ip">\n          <query>| search ip!=10.0.0.0/8 ip!=172.16.0.0/16 ip!=192.168.0.0/16 | iplocation ip | geostats count by Country</query>\n        </search>\n        <option name="drilldown">none</option>\n        <option name="height">600</option>\n        <option name="mapping.map.center">(20,10)</option>\n        <option name="mapping.map.zoom">3</option>\n        <option name="mapping.type">marker</option>\n      </map>\n    </panel>\n  </row>\n</form>'.format(
                            case,
                            case,
                            case,
                            case,
                            case,
                            case,
                            case,
                            case,
                            case,
                            case,
                        )
                    )
    ingest_splunk_data(
        verbosity,
        output_directory,
        case,
        stage,
        allimgs,
        splunk_install_path,
    )
    for appdir, apptar in apps.items():
        if not os.path.isdir("/" + splunk_install_path + "splunk/etc/apps/" + appdir):
            os.makedirs("/" + splunk_install_path + "splunk/etc/apps/" + appdir)
            with open("." + apptar, "w") as tarout:
                if appdir == "TA-geolocate/":
                    apphexdump = build_app_geolocate()
                    tarout.write(apphexdump)
                elif appdir == "lookup_editor/":
                    apphexdump = build_app_lookup()
                    tarout.write(apphexdump)
                elif appdir == "punchcard_app/":
                    apphexdump = build_app_punchcard()
                    tarout.write(apphexdump)
                elif appdir == "sankey_diagram_app/":
                    apphexdump = build_app_sankey()
                    tarout.write(apphexdump)
                elif appdir == "network_topology/":
                    apphexdump = build_app_topology()
                    tarout.write(apphexdump)
                elif appdir == "treemap_app/":
                    apphexdump = build_app_treemap()
                    tarout.write(apphexdump)
                subprocess.call(["xxd", "-plain", "-revert", "." + apptar, apptar])
                tar = TarFile.open(apptar, "r:gz")
                tar.extractall("/" + splunk_install_path + "splunk/etc/apps/")
                tar.close()
                os.remove("." + apptar)
                os.remove(apptar)
                os.chdir("/" + splunk_install_path + "splunk/etc/apps/")
                subprocess.Popen(
                    ["chmod", "-R", "644", appdir],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()
                subprocess.Popen(
                    ["chown", "-R", "splunk:splunk", appdir],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate()
    os.chdir("/" + splunk_install_path + "splunk/etc/apps/")
    for root, dirs, files in os.walk(
        "/" + splunk_install_path + "splunk/etc/apps/elrond/"
    ):
        for eachdir in dirs:
            subprocess.Popen(
                ["chmod", "755", os.path.join(root, eachdir)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
        for eachfile in files:
            subprocess.Popen(
                ["chmod", "644", os.path.join(root, eachfile)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
    subprocess.Popen(
        ["chmod", "755", "elrond/"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    subprocess.Popen(
        ["chown", "-R", "splunk:splunk", "elrond/"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    subprocess.Popen(
        ["sudo", "/bin/systemctl", "enable", "splunk.service"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    splunk_service(splunk_install_path, "start")
    os.chdir(pwd)
    return splunkuser, splunkpswd
