#!/usr/bin/env python3 -tt
import os
import re
import subprocess
import shlex
import time

from rivendell.post.mitre.nav_attack import create_attack_navigator


def configure_navigator(verbosity, case, splunk, elastic, usercred, pswdcred):
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
    elif elastic:
        print()
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
            maintechniques.append(eachsub)
        alltechniques = sorted(list(set(maintechniques)))
        # if case .json file exists - read it, extract the section of techniques and insert into updates file
        for eachtechnique in alltechniques:
            navlist = create_attack_navigator(nav_list, eachtechnique)
        # creating attack-navigator interim.<case>.json
        with open(
            "/opt/attack-navigator/nav-app/src/assets/.{}.json".format(case),
            "w",
        ) as attacktmp:
            attacktmp.write('{}\n    "name": "{}"'.format("{", case))
            attacktmp.write(
                ',\n    "versions": {}\n        "attack": "13",\n        "navigator": "4.8.2",\n        "{}'.format(
                    "{", case
                )
            )
            attacktmp.write(
                '": "4.4"\n    §±§,\n    "domain": "enterprise-attack",\n    "description": "",\n    "filters": ±§±\n        "platforms": [\n            "Linux",\n            "macOS",\n            "Windows",\n            "Containers"\n        ]\n    §±§,\n    "sorting": 0,\n    "layout": ±§±\n        "layout": "side",\n        "aggregateFunction": "average",\n        "showID": false,\n        "showName": true,\n        "showAggregateScores": false,\n        "countUnscored": false\n    §±§,\n    "hideDisabled": false,\n    "techniques": [\n        '.replace(
                    "±§±", "{"
                ).replace(
                    "§±§", "}"
                )
            )
            for eachentry in str(navlist[:-1])[2:-2].split("\\n        ', '"):
                attacktmp.write(eachentry.replace("\\n", "\n"))
            attacktmp.write(navlist[-1][:-10])
            attacktmp.write(
                '\n    ],\n    "gradient": ±§±\n        "colors": [\n            "#ff6666ff",\n            "#ffe766ff",\n            "#8ec843ff"\n        ],\n        "minValue": 0,\n        "maxValue": 100\n    §±§,\n    "legendItems": [\n        ±§±\n            "label": "Evidence of",\n            "color": "#00acb4"\n        §±§\n    ],\n    "metadata": [],\n    "showTacticRowBackground": false,\n    "tacticRowBackground": "#dddddd",\n    "selectTechniquesAcrossTactics": true,\n    "selectSubtechniquesWithParent": false\n§±§'.replace(
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
        # creating attack-navigator <case>.json
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
        # creating attack-navigator config.json
        with open(
            "/opt/attack-navigator/nav-app/src/assets/config.json",
            "w",
        ) as configjson:
            config_json_content = '±§±\n    "versions": [\n        ±§±\n            "name": "ATT&CK v13",\n            "version": "13",\n            "domains": [\n                ±§±\n                    "name": "Enterprise",\n                    "identifier": "enterprise-attack",\n                    "data": [\n                        "assets/enterprise-attack.json"\n                    ]\n                §±§\n            ]\n        §±§\n    ],\n    "custom_context_menu_items": [],\n    "default_layers": ±§±\n        "enabled": true,\n        "urls": [\n            "assets/{}.json"\n        ]\n    §±§,\n    "comment_color": "yellow",\n    "banner": "",\n    "features": [\n        ±§±\n            "name": "leave_site_dialog",\n            "enabled": true,\n            "description": "Disable to remove the dialog prompt when leaving site."\n        §±§,\n        ±§±\n            "name": "tabs",\n            "enabled": true,\n            "description": "Disable to remove the ability to open new tabs."\n        §±§,\n        ±§±\n            "name": "selecting_techniques",\n            "enabled": true,\n            "description": "Disable to remove the ability to select techniques."\n        §±§,\n        ±§±\n            "name": "header",\n            "enabled": true,\n            "description": "Disable to remove the header containing \'MITRE ATT&CK Navigator\' and the link to the help page. The help page can still be accessed from the new tab menu."\n        §±§,\n        ±§±\n            "name": "subtechniques",\n            "enabled": true,\n            "description": "Disable to remove all sub-technique features from the interface."\n        §±§,\n        ±§±\n            "name": "selection_controls",\n            "enabled": true,\n            "description": "Disable to to disable all subfeatures",\n            "subfeatures": [\n                ±§±\n                    "name": "search",\n                    "enabled": true,\n                    "description": "Disable to remove the technique search panel from the interface."\n                §±§,\n                ±§±\n                    "name": "multiselect",\n                    "enabled": true,\n                    "description": "Disable to remove the multiselect panel from interface."\n                §±§,\n                ±§±\n                    "name": "deselect_all",\n                    "enabled": true,\n                    "description": "Disable to remove the deselect all button from the interface."\n                §±§\n            ]\n        §±§,\n        ±§±\n            "name": "layer_controls",\n            "enabled": true,\n            "description": "Disable to disable all subfeatures",\n            "subfeatures": [\n                ±§±\n                    "name": "layer_info",\n                    "enabled": true,\n                    "description": "Disable to remove the layer info (name, description and metadata) panel from the interface. Note that the layer can still be renamed in the tab."\n                §±§,\n                ±§±\n                    "name": "download_layer",\n                    "enabled": true,\n                    "description": "Disable to remove the button to download the layer."\n                §±§,\n                ±§±\n                    "name": "export_render",\n                    "enabled": true,\n                    "description": "Disable to remove the button to render the current layer."\n                §±§,\n                ±§±\n                    "name": "export_excel",\n                    "enabled": true,\n                    "description": "Disable to remove the button to export the current layer to MS Excel (.xlsx) format."\n                §±§,\n                ±§±\n                    "name": "filters",\n                    "enabled": true,\n                    "description": "Disable to remove the filters panel from interface."\n                §±§,\n                ±§±\n                    "name": "sorting",\n                    "enabled": true,\n                    "description": "Disable to remove the sorting button from the interface."\n                §±§,\n                ±§±\n                    "name": "color_setup",\n                    "enabled": true,\n                    "description": "Disable to remove the color setup panel from interface, containing customization controls for scoring gradient and tactic row color."\n                §±§,\n                ±§±\n                    "name": "toggle_hide_disabled",\n                    "enabled": true,\n                    "description": "Disable to remove the hide disabled techniques button from the interface."\n                §±§,\n                ±§±\n                    "name": "layout_controls",\n                    "enabled": true,\n                    "description": "Disable to remove the ability to change the current matrix layout."\n                §±§,\n                ±§±\n                    "name": "legend",\n                    "enabled": true,\n                    "description": "Disable to remove the legend panel from the interface."\n                §±§\n            ]\n        §±§,\n        ±§±\n            "name": "technique_controls",\n            "enabled": true,\n            "description": "Disable to disable all subfeatures",\n            "subfeatures": [\n                ±§±\n                    "name": "background_color",\n                    "enabled": true,\n                    "description": "Disable to remove the background color effect on manually assigned colors."\n                §±§,\n                ±§±\n                    "name": "non_aggregate_score_color",\n                    "enabled": true,\n                    "description": "Disable to remove the color effect on non-aggregate scores."\n                §±§,\n                ±§±\n                    "name": "aggregate_score_color",\n                    "enabled": true,\n                    "description": "Disable to remove the color effect on aggregate scores."\n                §±§,\n                ±§±\n                    "name": "disable_techniques",\n                    "enabled": true,\n                    "description": "Disable to remove the ability to disable techniques."\n                §±§,\n                ±§±\n                    "name": "manual_color",\n                    "enabled": true,\n                    "description": "Disable to remove the ability to assign manual colors to techniques."\n                §±§,\n                ±§±\n                    "name": "scoring",\n                    "enabled": true,\n                    "description": "Disable to remove the ability to score techniques."\n                §±§,\n                ±§±\n                    "name": "comments",\n                    "enabled": true,\n                    "description": "Disable to remove the ability to add comments to techniques."\n                §±§,\n                ±§±\n                    "name": "clear_annotations",\n                    "enabled": true,\n                    "description": "Disable to remove the button to clear all annotations on the selected techniques."\n                §±§\n            ]\n        §±§\n    ]\n§±§'.format(
                case
            )
            configjson.write(
                config_json_content.replace("±§±", "{").replace("§±§", "}")
            )
        with open("/opt/attack-navigator/nav-app/src/index.html", "w") as indexhtml:
            indexhtml.write(
                '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <title>ATT&amp;CK&reg; Navigator</title>\n  <base href=".">\n\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <link rel="icon" type="image/x-icon" href="favicon.ico">\n<link rel="stylesheet" href="styles.css"></head>\n<body>\n  <app-root></app-root>\n<script src="runtime-es2018.js" type="module"></script><script src="runtime-es5.js" nomodule defer></script><script src="polyfills-es5.js" nomodule defer></script><script src="polyfills-es2018.js" type="module"></script><script src="scripts.js" defer></script><script src="vendor-es2018.js" type="module"></script><script src="vendor-es5.js" nomodule defer></script><script src="main-es2018.js" type="module"></script><script src="main-es5.js" nomodule defer></script></body>\n</html>\n'
            )
        navresults = "-"
        subprocess.Popen(
            [
                "sudo",
                "chmod",
                "-R",
                "755",
                "/opt/attack-navigator/nav-app/src/assets/",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate(),
        user = shlex.join(['USER=$(echo', '$USERNAME)'])
        subprocess.Popen(
            [
                user,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate(),
        subprocess.Popen(
            [
                "sudo",
                "chown",
                "-R",
                "'$USERPROFILE':'$USERPROFILE'",
                "/opt/attack-navigator/nav-app/src/assets/",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate(),

        os.chdir("/opt/attack-navigator/nav-app")
        subprocess.Popen(
            [
                "sudo",
                "pm2",
                "stop",
                "--name=attack-navigator",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        subprocess.Popen(
            [
                "sudo",
                "pm2",
                "delete",
                "--name=attack-navigator",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        subprocess.Popen(
            [
                "sudo",
                "pm2",
                "start",
                "--time",
                "--name=attack-navigator",
                "ng",
                "--",
                "serve",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        os.chdir("/opt/elrond/elrond")
        print("     ATT&CK Navigator built for '{}'".format(case))
    else:
        print("     No evidence of MITRE ATT&CK® techniques could be identified.")
        navresults = ""
    return navresults
