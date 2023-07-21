#!/usr/bin/env python3 -tt
import os
import re
import subprocess
import time
from datetime import datetime

from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry
from rivendell.post.mitre.nav_attack import create_attack_navigator

# from rivendell.post.mitre.nav_json import create_attack_navigator_json


def configure_navigator(
    verbosity, output_directory, stage, case, splunk, elastic, usercred, pswdcred
):
    print(
        "    Mapping available artefacts to MITRE ATT&CK® navigator, please stand by..."
    )
    if splunk:
        apiout = subprocess.Popen(
            [
                "curl",
                "-u",
                "{}:{}".format(usercred.strip(), pswdcred.strip()),
                "-k",
                "https://localhost:8089/services/search/jobs",
                "-d",
                "search=search index={} host=* mitre_technique!=- | stats count BY mitre_technique | fields - count".format(
                    case
                ),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        time.sleep(30)
        jobid = re.findall(r"<sid>(?P<sid>[^<]+)</sid>", str(apiout[0]))
        searchout, foundtechniques = (
            subprocess.Popen(
                [
                    "curl",
                    "-u",
                    "{}:{}".format(usercred.strip(), pswdcred.strip()),
                    "-k",
                    "https://localhost:8089/services/search/jobs/{}/results/".format(
                        jobid[0]
                    ),
                    "--get",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate(),
            [],
        )
        for everytechnique in str(searchout[0])[2:-4].split("\\n"):
            if "<value><text>" in everytechnique:
                if everytechnique[19:28].endswith(".000"):
                    foundtechniques.append(everytechnique[19:24])
                else:
                    foundtechniques.append(everytechnique[19:28])
                    foundtechniques.append(everytechnique[19:24])
            else:
                pass
    elif elastic:
        print()
    else:
        pass
    subtechniques, maintechniques, nav_list = (
        sorted(list(set(foundtechniques))),
        [],
        [],
    )
    if len(subtechniques) > 0:
        print(
            "     Evidence of {} MITRE ATT&CK® techniques identified.".format(
                str(len(subtechniques))
            )
        )
        for eachsub in subtechniques:
            if "." in eachsub:
                maintechniques.append(eachsub[:-4])
            else:
                pass
            maintechniques.append(eachsub)
        alltechniques = sorted(list(set(maintechniques)))
        for eachtechnique in alltechniques:
            navlist = create_attack_navigator(nav_list, eachtechnique)
        os.rename(
            "/opt/attack-navigator/enterprise-attack.json",
            "/opt/attack-navigator/nav-app/src/assets/enterprise-attack.json",
        )
        with open(
            "/opt/attack-navigator/nav-app/src/assets/.{}.json".format(case),
            "w",
        ) as attacktmp:
            attacktmp.write(
                '{\n    "name": "layer",\n    "versions": {\n        "attack": "13",\n        "navigator": "4.8.2",\n        "layer": "4.4"\n    },\n    "domain": "enterprise-attack",\n    "description": "",\n    "filters": {\n        "platforms": [\n            "Linux",\n            "macOS",\n            "Windows",\n            "Containers"\n        ]\n    },\n    "sorting": 0,\n    "layout": {\n        "layout": "side",\n        "aggregateFunction": "average",\n        "showID": false,\n        "showName": true,\n        "showAggregateScores": false,\n        "countUnscored": false\n    },\n    "hideDisabled": false,\n    "techniques": [\n        '
            )
            for eachentry in str(navlist[:-1])[2:-2].split("\\n        ', '"):
                attacktmp.write(eachentry.replace("\\n", "\n"))
            attacktmp.write(navlist[-1][:-10])
            attacktmp.write(
                '\n    ],\n    "gradient": ±§±\n        "colors": [\n            "#ff6666ff",\n            "#ffe766ff",\n            "#8ec843ff"\n        ],\n        "minValue": 0,\n        "maxValue": 100\n    §±§,\n    "legendItems": [\n        ±§±\n            '.replace(
                    "±§±", "{"
                ).replace(
                    "§±§", "}"
                )
            )
            attacktmp.write('"label": "{}"'.format(case))
            attacktmp.write(
                ',\n            "color": "#00acb4"\n        §±§,\n        ±§±\n            "label": "Undetectable/Out-of-Scope",\n            "color": "#969696"\n        §±§\n    ],\n    "metadata": [],\n    "showTacticRowBackground": false,\n    "tacticRowBackground": "#dddddd",\n    "selectTechniquesAcrossTactics": true,\n    "selectSubtechniquesWithParent": false\n}'.replace(
                    "±§±", "{"
                ).replace(
                    "§±§", "}"
                )
            )
        with open(
            "/opt/attack-navigator/nav-app/src/assets/.{}.json".format(case),
            "r",
        ) as attacktmp:
            jsoncontent = attacktmp.readlines()
        with open(
            "/opt/attack-navigator/nav-app/src/assets/{}.json".format(case),
            "w",
        ) as attackjson:
            attackjson.write(
                str(jsoncontent)[2:-2]
                .replace("', '", "")
                .replace("\\n", "\n")
                .replace("            {", "        {")
                .replace("},{", "},\n        {")
            )
        os.remove("/opt/attack-navigator/nav-app/src/assets/.{}.json".format(case))
        with open(
            "/opt/attack-navigator/nav-app/src/assets/config.json",
            "w",
        ) as configjson: # https://github.com/mitre-attack/attack-navigator/issues/319
            config_json_content = '±§±\n    "versions": [\n        ±§±\n            "name": "ATT&CK v9", \n            "domains": [\n                ±§±   \n                    "name": "Enterprise", \n                    "data": ["assets/enterprise-attack.json"]\n                §±§\n            ]\n        §±§\n    ],\n\n    "custom_context_menu_items": [\n\n    ],\n\n    "default_layers": ±§±\n        "enabled": true,\n        "urls": ["assets/{}.json"]\n    §±§,\n\n    "comment_color": "yellow",\n\n    "banner": "",\n\n    "features": [\n        ±§±"name": "leave_site_dialog", "enabled": true, "description": "Disable to remove the dialog prompt when leaving site."§±§,\n        ±§±"name": "tabs", "enabled": true, "description": "Disable to remove the ability to open new tabs."§±§,\n        ±§±"name": "selecting_techniques", "enabled": true, "description": "Disable to remove the ability to select techniques."§±§,\n        ±§±"name": "header", "enabled": true, "description": "Disable to remove the header containing \'MITRE ATT&CK Navigator\' and the link to the help page. The help page can still be accessed from the new tab menu."§±§,\n        ±§±"name": "subtechniques", "enabled": true, "description": "Disable to remove all sub-technique features from the interface."§±§,\n        ±§±"name": "selection_controls", "enabled": true, "description": "Disable to to disable all subfeatures", "subfeatures": [\n            ±§±"name": "search", "enabled": true, "description": "Disable to remove the technique search panel from the interface."§±§,\n            ±§±"name": "multiselect", "enabled": true, "description": "Disable to remove the multiselect panel from interface."§±§,\n            ±§±"name": "deselect_all", "enabled": true, "description": "Disable to remove the deselect all button from the interface."§±§\n        ]§±§,\n        ±§±"name": "layer_controls", "enabled": true, "description": "Disable to disable all subfeatures", "subfeatures": [\n            ±§±"name": "layer_info", "enabled": true, "description": "Disable to remove the layer info (name, description and metadata) panel from the interface. Note that the layer can still be renamed in the tab."§±§,\n            ±§±"name": "download_layer", "enabled": true, "description": "Disable to remove the button to download the layer."§±§,\n            ±§±"name": "export_render", "enabled": true, "description": "Disable to remove the button to render the current layer."§±§,\n            ±§±"name": "export_excel", "enabled": true, "description": "Disable to remove the button to export the current layer to MS Excel (.xlsx) format."§±§,\n            ±§±"name": "filters", "enabled": true, "description": "Disable to remove the filters panel from interface."§±§,\n            ±§±"name": "sorting", "enabled": true, "description": "Disable to remove the sorting button from the interface."§±§,\n            ±§±"name": "color_setup", "enabled": true, "description": "Disable to remove the color setup panel from interface, containing customization controls for scoring gradient and tactic row color."§±§,\n            ±§±"name": "toggle_hide_disabled", "enabled": true, "description": "Disable to remove the hide disabled techniques button from the interface."§±§,\n            ±§±"name": "layout_controls", "enabled": true, "description": "Disable to remove the ability to change the current matrix layout."§±§,\n            ±§±"name": "legend", "enabled": true, "description": "Disable to remove the legend panel from the interface."§±§\n        ]§±§,\n        ±§±"name": "technique_controls", "enabled": true, "description": "Disable to disable all subfeatures", "subfeatures": [\n            ±§±"name": "disable_techniques", "enabled": true, "description": "Disable to remove the ability to disable techniques."§±§,\n            ±§±"name": "manual_color", "enabled": true, "description": "Disable to remove the ability to assign manual colors to techniques."§±§,\n            ±§±"name": "scoring", "enabled": true, "description": "Disable to remove the ability to score techniques."§±§,\n            ±§±"name": "comments", "enabled": true, "description": "Disable to remove the ability to add comments to techniques."§±§,\n            ±§±"name": "clear_annotations", "enabled": true, "description": "Disable to remove the button to clear all annotations on the selected techniques."§±§\n        ]§±§\n    ]\n§±§'.format(
                case
            )
            configjson.write(
                config_json_content.replace("±§±", "{").replace("§±§", "}")
            )
        print("TEST")
        with open("/opt/attack-navigator/nav-app/src/index.html", "w") as indexhtml:
            indexhtml.write(
                '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <title>ATT&amp;CK&reg; Navigator</title>\n  <base href=".">\n\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <link rel="icon" type="image/x-icon" href="favicon.ico">\n<link rel="stylesheet" href="styles.css"></head>\n<body>\n  <app-root></app-root>\n<script src="runtime-es2018.js" type="module"></script><script src="runtime-es5.js" nomodule defer></script><script src="polyfills-es5.js" nomodule defer></script><script src="polyfills-es2018.js" type="module"></script><script src="scripts.js" defer></script><script src="vendor-es2018.js" type="module"></script><script src="vendor-es5.js" nomodule defer></script><script src="main-es2018.js" type="module"></script><script src="main-es5.js" nomodule defer></script></body>\n</html>\n'
            )
        navresults = "-"
        subprocess.Popen(
            [
                "sudo", "chmod", "-R", "755", "/opt/attack-navigator/nav-app/src/assets/",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate(),
        subprocess.Popen(
            [
                "sudo", "chown", "-R", "sansforensics:sansforensics", "/opt/attack-navigator/nav-app/src/assets/",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate(),
        print_done(verbosity)
        print("     ATT&CK Navigator built for '{}'".format(case))
    else:
        print("     No evidence of MITRE ATT&CK® techniques could be identified.")
        navresults = ""
    return navresults
