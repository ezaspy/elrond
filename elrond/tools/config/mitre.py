#!/usr/bin/env python3 -tt
import os
import pandas
import re
import requests
import sys


# ensure transforms.py is updated with the correct pairings - this will dicate how the html and xml pages are created

def append_threat_actors(related_threat_actors, csv_row):
    with open(
        "/opt/elrond/elrond/tools/attack-navigator/.enterprise-attack-v15.1-procedures.csv",
    ) as techniquecsv:
        procedures_file_content = str(techniquecsv.readlines())
        procedures_contents = re.sub(
            r"((?:C|G|S)\d{4},[^,]+,(?:campaign|intrusion-set|tool|malware)\-\-[A-Za-z\d\-]{36},(?:campaign|group|software))",
            r"\n\1",
            procedures_file_content,
        )
    tid = csv_row.split("||")[0]
    technique_regex = (
        r"((?:C|G|S)\d{4}),([^,]+),(?:campaign|intrusion-set|tool|malware)\-\-[A-Za-z\d\-]{36},(?:campaign|group|software),[^,]+,"
        + re.escape(tid)
    )
    associated_procedures = re.findall(
        technique_regex, procedures_contents, re.IGNORECASE
    )
    if len(associated_procedures) > 0:
        for associated_procedure in associated_procedures:
            associated_procedure_pair = "{} ({})".format(
                associated_procedure[1], associated_procedure[0]
            )
            related_threat_actors.append(associated_procedure_pair)
    related_threat_actors = sorted(list(set(related_threat_actors)))
    if len(related_threat_actors) > 0:
        related_threat_actors = str(related_threat_actors)[2:-2].replace("', '", "; ")
    else:
        related_threat_actors = ""
    return related_threat_actors


def extract_indicators(
    description,
):
    def extract_port_indicators(description):
        port_identifiers = re.findall(
            r"(?:(?:[Pp]orts?(?: of)? |and |& |or |, |e\.g\.? |tcp: ?|udp: ?)|(?:\())(\d{2,})(?: |/|\. |,|\<)",
            description,
        )
        port_identifiers = list(
            filter(
                lambda port: "365" != port,
                list(filter(lambda port: "10" != port, port_identifiers)),
            )
        )  # remove string from list
        port_identifiers = list(filter(None, list(set(port_identifiers))))
        return port_identifiers

    def extract_evt_indicators(description):
        evt_identifiers = re.findall(
            r"(?:(?:Event ?|E)I[Dd]( ==)? ?\"?(\d{1,5}))", description
        )
        if len(evt_identifiers) > 0:
            evt_identifiers = list(filter(None, list(set(evt_identifiers))))
        return evt_identifiers

    def extract_reg_indicators(
        description,
    ):
        description = re.sub(
            r"\(Citation[^\)]+\)",
            r"",
            re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", description),
        )
        description = (
            description.replace('""', '"')
            .replace(". . ", ". ")
            .replace(".. ", ". ")
            .replace("\\\\\\'", "'")
            .replace("\\\\'", "'")
            .replace("\\'", "'")
            .strip(",")
            .strip('"')
            .strip(",")
            .strip('"')
        )
        reg_identifiers = re.findall(
            r"([Hh][Kk](?:[Ll][Mm]|[Cc][Uu]|[Ee][Yy])[^\{\}\|\"'!$<>`]+)",
            description.lower()
            .replace("hkey_local_machine", "hklm")
            .replace("hkey_current_user", "hkcu")
            .replace("[hklm]", "hklm")
            .replace("[hkcu]", "hkcu")
            .replace("hklm]", "hklm")
            .replace("hkcu]", "hkcu")
            .replace("“", '"')
            .replace("”", '"')
            .replace("\\\\\\\\\\\\\\\\", "\\\\\\\\")
            .replace("\\\\\\\\\\\\\\\\", "\\")
            .replace("\\\\\\\\\\\\", "\\")
            .replace("\\\\\\\\", "\\")
            .replace("£\\\    £", "\\\   ")
            .replace('""', '"')
            .replace("  ", " ")
            .replace("[.]", ".")
            .replace("[:]", ":")
            .replace("&#42;", "*")
            .replace("&lbrace;", "{")
            .replace("&rbrace;", "}")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("[username]", "%username%")
            .replace("\\]\\", "]\\")
            .replace('""', '"')
            .replace('""', '"')
            .replace("\\\\", "\\")
            .strip("\\")
            .strip(),
        )
        registry_identifiers = list(filter(None, list(set(reg_identifiers))))
        return registry_identifiers

    def extract_cmd_indicators(description):
        cmd_identifiers = re.findall(
            r"(?:(?:<code> ?([^\{\}!<>`]{3,}) ?<\/code>)|(?:` ?([^\{\}!<>`]{3,}) ?`))",
            description,
        )
        all_identifiers = list(set(cmd_identifiers))
        valid_identifiers = []
        for identifier_set in all_identifiers:
            for each_identifier in identifier_set:
                if (
                    len(each_identifier) > 0
                    and "](https://attack.mitre.org/" not in each_identifier
                    and "example" not in each_identifier.lower()
                    and "citation" not in each_identifier.lower()
                    and " and " not in each_identifier.lower()
                    and " or " not in each_identifier.lower()
                    and not each_identifier.startswith(")")
                    and not each_identifier.endswith("(")
                    and not each_identifier.lower().startswith("evil")
                    and not each_identifier.lower().startswith("hklm\\")
                    and not each_identifier.lower().startswith("hkcu\\")
                    and not each_identifier.lower().startswith("hkey\\")
                    and not each_identifier.lower().startswith("[hklm")
                    and not each_identifier.lower().startswith("[hkcu")
                    and not each_identifier.lower().startswith("[hkey")
                    and not each_identifier == ", and "
                ):
                    identifier = (
                        each_identifier.lower()
                        .replace("“", '"')
                        .replace("”", '"')
                        .replace("\\\\\\\\\\\\\\\\", "\\")
                        .replace("\\\\\\\\\\\\\\\\", "\\")
                        .replace("\\\\\\\\\\\\", "\\")
                        .replace("\\\\\\\\", "\\")
                        .replace("\\\\\\", "\\")
                        .replace("\\\\", "\\")
                        .replace("£\\\    £", "\\\   ")
                        .replace('""', '"')
                        .replace("  ", " ")
                        .replace("[.]", ".")
                        .replace("[:]", ":")
                        .replace("&#42;", "*")
                        .replace("&lbrace;", "{")
                        .replace("&rbrace;", "}")
                        .replace("&lt;", "<")
                        .replace("&gt;", ">")
                        .replace("[username]", "%username%")
                        .replace("\\]\\", "]\\")
                        .replace('""', '"')
                        .replace('""', '"')
                        .replace("\\\\\\\\", "\\")
                        .strip("\\")
                        .strip()
                    )
                    if len(identifier) > 1:
                        valid_identifiers.append(identifier)
        cmd_identifiers = list(filter(None, list(set(valid_identifiers))))
        return cmd_identifiers

    def extract_cve_indicators(description):
        cve_identifiers = re.findall(r"(CVE\-\d{4}\-\d{3,5})", description)
        cve_identifiers = list(filter(None, list(set(cve_identifiers))))
        return cve_identifiers

    def extract_software_indicators(description):
        software_identifiers = re.findall(
            r"\[([^\]]+)\]\(https://attack\.mitre\.org/software/S\d+\)", description
        )
        software_identifiers = list(filter(None, list(set(software_identifiers))))
        return software_identifiers

    extracted_results = []
    # extracting ports
    port_identifiers = extract_port_indicators(description)
    if len(port_identifiers) > 0:
        evidence_type = "ports"
        for evidence_identified in port_identifiers:
            extracted_results.append(
                "{}::{}".format(evidence_type, str(evidence_identified))
            )
    # extracting event IDs
    if "Event ID" in description or "EID" in description or "EventId" in description:
        evt_identifiers = extract_evt_indicators(description)
        if len(evt_identifiers) > 0:
            evidence_type = "evt"
            for evidence_identified in evt_identifiers:
                extracted_results.append(
                    "{}::{}".format(
                        evidence_type,
                        str(evidence_identified).replace("'', ", "")[2:-2],
                    )
                )
    # extracting registry artefacts
    if (
        "hklm\\" in description.lower()
        or "hkcu\\" in description.lower()
        or "hkey\\" in description.lower()
        or "hkey_" in description.lower()
        or "hklm]" in description.lower()
        or "hkcu]" in description.lower()
        or "hkey_local_machine]" in description.lower()
        or "hkey_current_user]" in description.lower()
    ):
        reg_identifiers = extract_reg_indicators(description)
        if len(reg_identifiers) > 0:
            evidence_type = "reg"
            for evidence_identified in reg_identifiers:
                extracted_results.append(
                    "{}::{}".format(evidence_type, str(evidence_identified))
                )
    # extracting commands
    if "<code>" in description or "`" in description:
        cmd_identifiers = extract_cmd_indicators(description)
        if len(cmd_identifiers) > 0:
            evidence_type = "cmd"
            for evidence_identified in cmd_identifiers:
                extracted_results.append(
                    "{}::{}".format(evidence_type, str(evidence_identified))
                )
    # extracting links with CVEs
    if "CVE" in description.upper():
        cve_identifiers = extract_cve_indicators(description)
        if len(cve_identifiers) > 0:
            evidence_type = "cve"
            for evidence_identified in cve_identifiers:
                extracted_results.append(
                    "{}::{}".format(evidence_type, str(evidence_identified))
                )
    if "/software/" in description.lower():
        software_identifiers = extract_software_indicators(description)
        if len(software_identifiers) > 0:
            evidence_type = "software"
            for evidence_identified in software_identifiers:
                extracted_results.append(
                    "{}::{}".format(evidence_type, str(evidence_identified))
                )
    return list(filter(None, list(set(extracted_results))))


def cleanup_evidence(evidence):
    port_list, evt_list, reg_list, cmd_list, cve_list, software_list = (
        [] for _ in range(6)
    )
    port_dict, evt_dict, reg_dict, cmd_dict, cve_dict, software_dict = (
        {} for _ in range(6)
    )
    clean_evidence = sorted(
        list(
            set(
                evidence.replace("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\", "\\\\")
                .replace("\\\\\\\\\\\\\\\\", "\\\\")
                .replace("\\\\\\\\", "\\\\")
                .replace("\\\\\\\\", "\\\\")
                .replace("\\\\\\", "\\\\")
                .replace("\\\\", "\\")
                .split("#, #")
            )
        )
    )
    for item in clean_evidence:
        # port results
        port_results = re.findall(r"ports::([\S\s]+)", item)
        for port_result in port_results:
            port_list.append(port_result)
        if len(port_list) > 0:
            port_dict["ports"] = port_list
        # event log results
        evt_results = re.findall(
            r"evt::([\S\s]+)", item.replace("(\\'", "'").replace("\\')", "'")
        )
        for evt_result in evt_results:
            evt_list.append(evt_result.strip("'"))
        if len(evt_list) > 0:
            evt_dict["evts"] = evt_list
        # registry results
        reg_results = re.findall(r"reg::([\S\s]+)", item)
        for reg_result in reg_results:
            reg_list.append(reg_result)
        if len(reg_list) > 0:
            reg_dict["regs"] = reg_list
        # command line results
        cmd_results = re.findall(r"cmd::([\S\s]+)", item)
        for cmd_result in cmd_results:
            if (
                cmd_result != "who"
                and cmd_result != "$user"
                and cmd_result != "%username%"
            ):
                cmd_list.append(cmd_result)
        if len(cmd_list) > 0:
            cmd_dict["cmds"] = cmd_list
        # cve results
        cve_results = re.findall(r"cve::([\S\s]+)", item)
        for cve_result in cve_results:
            cve_list.append(cve_result)
        if len(cve_list) > 0:
            cve_dict["cves"] = cve_list
        # software results
        software_results = re.findall(r"software::([\S\s]+)", item)
        for software_result in software_results:
            software_list.append(software_result)
        if len(software_list) > 0:
            software_dict["software"] = software_list
    return port_dict, evt_dict, reg_dict, cmd_dict, cve_dict, software_dict


def cleanup_dict_values(dict_values):
    evidence_insert = (
        dict_values.replace("dict_values([['", "")
        .replace('dict_values([["', "")
        .replace("\\\\\\'", "'")
        .replace("\\\\'", "'")
        .replace("\\'", "'")
        .replace("', '", "`, `")
        .strip("\\")
    )
    evidence_insert = re.sub(r'([^\\])"', r"\1", evidence_insert)
    evidence_insert = re.sub(r"#\]'\]\]\)", r"", evidence_insert)
    evidence_insert = re.sub(r"'\]\]\)", r"", evidence_insert.strip('"'))
    evidence_insert = re.sub(
        r"([^\{])(\{)([^\{])", r"\1\2\2\3", evidence_insert.strip('"')
    )
    evidence_insert = re.sub(
        r"([^\}])(\})([^\}])", r"\1\2\2\3", evidence_insert.strip('"')
    )
    return evidence_insert


def cleanup_description(desc):
    desc = re.sub(
        r"\\\\('[s])",
        r"\1",
        re.sub(
            r" ?(\d{1,2}\. )",
            r"<br>&nbsp;&nbsp;&nbsp;&nbsp;\1",
            desc.strip('"')
            .replace("..  ", ". ")
            .replace("* ", "<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;* ")
            .replace("£  £", " ")
            .replace('"', ""),
        ),
    )
    desc = re.sub(
        r"</?code>",
        r"`",
        re.sub(
            r"(\[[^\]]+\]\()https://attack\.mitre\.org/[^/]+/(\S{1,2}\d{4}\))",
            r"\1\2",
            desc.replace("\\'s", "'s")
            .replace("\\'t", "'t")
            .replace("\\\\\\", "\\")
            .replace("\\\\", "\\")
            .replace(". .  ", ". ")
            .replace("..  ", ". ")
            .replace(".. ", ". "),
        ),
    )
    desc = re.sub(
        r"(\.)<br>	\d+\. ( )",
        r"\1\2",
        re.sub(r"((?:\\u202f\\u202)|\\xa)", r"", str(desc)),
    )
    desc = re.sub(r"( \w)<br>	(\d+\. )", r"\1\2", desc)
    desc = re.sub(r"([^\{])({)([^\{])", r"\1\2\2\3", desc)
    desc = re.sub(r"([^\}])(})([^\}])", r"\1\2\2\3", desc)
    desc = re.sub(
        r"\[([^\]]+)\](\(TA?\d+[^\)]+\))", r"<em><strong>\1</strong>\2</em>", desc
    )
    return desc


def build_tactic_html_and_xml_py(
    tactic_page,
    tid,
    name,
    desc,
    link,
    tactics,
    platform,
    evidence,
    port_dict,
    evt_dict,
    reg_dict,
    cmd_dict,
    cve_dict,
    software_dict,
):
    if not os.path.exists(
        os.path.join(
            "/opt/elrond/elrond/rivendell/post/splunk/app/views/html",
            "{}.py".format(tactic_page),
        )
    ):
        with open(
            os.path.join(
                "/opt/elrond/elrond/rivendell/post/splunk/app/views/html",
                "{}.py".format(tactic_page),
            ),
            "w",
        ) as tactic_py:
            tactic_py.write(
                "#!/usr/bin/env python3 -tt\n\n\ndef create_{}_html(sd, header, headings, footer):\n".format(
                    tactic_page
                )
            )
    if not os.path.exists(
        os.path.join(
            "/opt/elrond/elrond/rivendell/post/splunk/app/views/xml",
            "{}.py".format(tactic_page),
        )
    ):
        with open(
            os.path.join(
                "/opt/elrond/elrond/rivendell/post/splunk/app/views/xml",
                "{}.py".format(tactic_page),
            ),
            "w",
        ) as tactic_py:
            tactic_py.write(
                "#!/usr/bin/env python3 -tt\n\n\ndef create_{}_xml(sd):\n".format(
                    tactic_page
                )
            )
    desc = cleanup_description(desc)
    evidence = re.sub(r'([^\\])"', r"\1", evidence)
    # writing the content of html and xml files according to evidence
    if evidence == [] or evidence == "[]":
        with open(
            os.path.join(
                "/opt/elrond/elrond/rivendell/post/splunk/app/views/html",
                "{}.py".format(tactic_page),
            ),
            "a",
        ) as tacic_html_py:
            tacic_html_py.write(
                '    with open(sd + "{}.html", "w") as {}html:\n        {}html.write("{{}}{}<br>More information: <a href=\\"{}\\" target=\\"_blank\\">{}</a><br>".format(header))  # description\n        {}html.write("{{}}{}</td>\\n        <td>".format(headings))  # id\n        {}html.write("{}</td>\\n        <td>")  # platforms\n        {}html.write("{}</td>\\n        <td>")  # tactics\n        {}html.write("{}{{}}".format(footer))\n'.format(
                    tid.lower(),
                    tid.lower(),
                    tid.lower(),
                    desc,
                    link,
                    link,
                    tid.lower(),
                    tid.upper(),
                    tid.lower(),
                    platform.replace('"', ""),
                    tid.lower(),
                    tactics,
                    tid.lower(),
                    evidence.replace("[]", "N/A"),
                )
            )
        with open(
            os.path.join(
                "/opt/elrond/elrond/rivendell/post/splunk/app/views/xml",
                "{}.py".format(tactic_page),
            ),
            "a",
        ) as tactic_xml_py:
            tactic_xml_py.write('    with open(sd + "{}.xml", "w") as {}xml:\n        {}xml.write(\'<form version="1.1" stylesheet="mitre.css" theme="dark">\\n  <label>{}: {}</label>\\n  <description>If a dashboard panel is not showing, no events exist which satisify that log source for this technique.</description>\\n  <search id="base">\\n    <query>index=* | dedup index | search index=$case_tok$ host=$host_tok$ | table index host</query>\\n    <earliest>$time_tok.earliest$</earliest>\\n    <latest>$time_tok.latest$</latest>\\n  </search>\\n  <search id="mitre_base">\\n    <query>index=$case_tok$ host=$host_tok$ mitre_technique!=-</query>\\n    <earliest>$time_tok.earliest$</earliest>\\n    <latest>$time_tok.latest$</latest>\\n  </search>\\n  <search id="dash">\\n    <query>| rest /servicesNS/-/-/data/ui/views | search "eai:acl.app"=elrond label=T*</query>\\n    <earliest>$time_tok.earliest$</earliest>\\n    <latest>$time_tok.latest$</latest>\\n  </search>\\n  <fieldset submitButton="false">\\n    <input type="checkbox" token="it_tok">\\n      <label></label>\\n      <search>\\n        <query><![CDATA[| gentimes start=-1 | eval it="Toggle MITRE Information"]]></query>\\n      </search>\\n      <fieldForLabel>it</fieldForLabel>\\n      <fieldForValue>it</fieldForValue>\\n    </input>\\n    <input type="dropdown" token="case_tok" searchWhenChanged="true">\\n      <label>Select a Case:</label>\\n      <choice value="*">All</choice>\\n      <default>*</default>\\n      <initialValue>*</initialValue>\\n      <fieldForLabel>index</fieldForLabel>\\n      <fieldForValue>index</fieldForValue>\\n      <search base="base">\\n        <query>| dedup index | sort index</query>\\n      </search>\\n    </input>\\n    <input type="dropdown" token="host_tok" searchWhenChanged="true">\\n      <label>Select a Host:</label>\\n      <choice value="*">All</choice>\\n      <default>*</default>\\n      <initialValue>*</initialValue>\\n      <fieldForLabel>host</fieldForLabel>\\n      <fieldForValue>host</fieldForValue>\\n      <search base="base">\\n        <query>| dedup host | sort host</query>\\n      </search>\\n    </input>\\n    <input type="dropdown" token="mitre_tok" searchWhenChanged="true">\\n      <label>Select MITRE Technique:</label>\\n      <choice value="*">All</choice>\\n      <fieldForLabel>mitre_technique</fieldForLabel>\\n      <fieldForValue>mitre_technique</fieldForValue>\\n      <search base="mitre_base">\\n        <query>| `MITRE_lookup` | search id="{}" | stats count BY mitre_id mitre_technique | sort mitre_id | fields - mitre_id</query>\\n      </search>\\n      <default>*</default>\\n      <prefix>"*</prefix>\\n      <suffix>"</suffix>\\n      <initialValue>*</initialValue>\\n    </input>\\n    <input type="time" token="time_tok" searchWhenChanged="true">\\n      <label>Select a Time Range:</label>\\n      <default>\\n        <earliest>-1d@h</earliest>\\n        <latest></latest>\\n      </default>\\n    </input>\\n  </fieldset>\\n  <row>\\n    <panel>\\n      <html depends="$it_tok$" src="{}.html"/>\\n    </panel>\\n  </row>\\n  <row>\\n    <panel>\\n      <html src="na.html"/>\\n    </panel>\\n  </row>\\n</form>\')\n'.format(
                    tid.lower(), tid.lower(), tid.lower(), tid, name, tid, tid.lower()
                )
            )
    else:
        log_sources = []
        with open(
            os.path.join(
                "/opt/elrond/elrond/rivendell/post/splunk/app/views/html",
                "{}.py".format(tactic_page),
            ),
            "a",
        ) as tacic_html_py:
            evidence_prefix = "'{}' is potentially detectable based on one or more of the following indicators:<br>".format(
                name
            )
            if len(port_dict) > 0:
                evidence_insert = cleanup_dict_values(str(port_dict.values()))
                port_evidence_insert = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - Ports: `{}`<br>".format(
                    evidence_insert
                )
            else:
                port_evidence_insert = ""
            if len(evt_dict) > 0:
                evidence_insert = cleanup_dict_values(str(evt_dict.values()))
                evt_evidence_insert = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - Event IDs: `{}`<br>".format(
                    evidence_insert
                )
            else:
                evt_evidence_insert = ""
            if len(reg_dict) > 0:
                evidence_insert = cleanup_dict_values(str(reg_dict.values()))
                reg_evidence_insert = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - Registry Keys: `{}`<br>".format(
                    evidence_insert
                )
            else:
                reg_evidence_insert = ""
            if len(cmd_dict) > 0:
                evidence_insert = cleanup_dict_values(str(cmd_dict.values()))
                cmd_evidence_insert = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - Commands: `{}`<br>".format(
                    evidence_insert
                )
            else:
                cmd_evidence_insert = ""
            if len(cve_dict) > 0:
                evidence_insert = cleanup_dict_values(str(cve_dict.values()))
                cve_evidence_insert = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - CVEs: `{}`<br>".format(
                    evidence_insert
                )
            else:
                cve_evidence_insert = ""
            if len(software_dict) > 0:
                evidence_insert = cleanup_dict_values(str(software_dict.values()))
                software_evidence_insert = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - Software: `{}`<br>".format(
                    evidence_insert
                )
            else:
                software_evidence_insert = ""
            tacic_html_py.write(
                '    with open(sd + "{}.html", "w") as {}html:\n        {}html.write("{{}}{}<br>More information: <a href=\\"{}\\" target=\\"_blank\\">{}</a><br>".format(header))  # description\n        {}html.write("{{}}{}</td>\\n        <td>".format(headings))  # id\n        {}html.write("{}</td>\\n        <td>")  # platforms\n        {}html.write("{}</td>\\n        <td>")  # tactics\n        {}html.write("{}{}{}{}{}{}{}{{}}".format(footer))\n'.format(
                    tid.lower(),
                    tid.lower(),
                    tid.lower(),
                    desc,
                    link,
                    link,
                    tid.lower(),
                    tid.upper(),
                    tid.lower(),
                    platform.replace('"', ""),
                    tid.lower(),
                    tactics,
                    tid.lower(),
                    evidence_prefix,
                    port_evidence_insert,
                    evt_evidence_insert,
                    reg_evidence_insert,
                    cmd_evidence_insert,
                    cve_evidence_insert,
                    software_evidence_insert,
                )
            )
        # collecting transform assignments
        with open(
            "/opt/elrond/elrond/rivendell/post/splunk/app/transforms.py"
        ) as transformspy:
            transform_lines = transformspy.readlines()
        with open(
            os.path.join(
                "/opt/elrond/elrond/rivendell/post/splunk/app/views/xml",
                "{}.py".format(tactic_page),
            ),
            "a",
        ) as tactic_xml_py:
            tactic_xml_py.write('    with open(sd + "{}.xml", "w") as {}xml:\n        {}xml.write(\'<form version="1.1" stylesheet="mitre.css" theme="dark">\\n  <label>{}: {}</label>\\n  <description>If a dashboard panel is not showing, no events exist which satisify that log source for this technique.</description>\\n  <search id="base">\\n    <query>index=* | dedup index | search index=$case_tok$ host=$host_tok$ | table index host</query>\\n    <earliest>$time_tok.earliest$</earliest>\\n    <latest>$time_tok.latest$</latest>\\n  </search>\\n  <search id="mitre_base">\\n    <query>index=$case_tok$ host=$host_tok$ mitre_technique!=-</query>\\n    <earliest>$time_tok.earliest$</earliest>\\n    <latest>$time_tok.latest$</latest>\\n  </search>\\n  <search id="dash">\\n    <query>| rest /servicesNS/-/-/data/ui/views | search "eai:acl.app"=elrond label=T*</query>\\n    <earliest>$time_tok.earliest$</earliest>\\n    <latest>$time_tok.latest$</latest>\\n  </search>\\n  <fieldset submitButton="false">\\n    <input type="checkbox" token="it_tok">\\n      <label></label>\\n      <search>\\n        <query><![CDATA[| gentimes start=-1 | eval it="Toggle MITRE Information"]]></query>\\n      </search>\\n      <fieldForLabel>it</fieldForLabel>\\n      <fieldForValue>it</fieldForValue>\\n    </input>\\n    <input type="dropdown" token="case_tok" searchWhenChanged="true">\\n      <label>Select a Case:</label>\\n      <choice value="*">All</choice>\\n      <default>*</default>\\n      <initialValue>*</initialValue>\\n      <fieldForLabel>index</fieldForLabel>\\n      <fieldForValue>index</fieldForValue>\\n      <search base="base">\\n        <query>| dedup index | sort index</query>\\n      </search>\\n    </input>\\n    <input type="dropdown" token="host_tok" searchWhenChanged="true">\\n      <label>Select a Host:</label>\\n      <choice value="*">All</choice>\\n      <default>*</default>\\n      <initialValue>*</initialValue>\\n      <fieldForLabel>host</fieldForLabel>\\n      <fieldForValue>host</fieldForValue>\\n      <search base="base">\\n        <query>| dedup host | sort host</query>\\n      </search>\\n    </input>\\n    <input type="dropdown" token="mitre_tok" searchWhenChanged="true">\\n      <label>Select MITRE Technique:</label>\\n      <choice value="*">All</choice>\\n      <fieldForLabel>mitre_technique</fieldForLabel>\\n      <fieldForValue>mitre_technique</fieldForValue>\\n      <search base="mitre_base">\\n        <query>| `MITRE_lookup` | search id="{}" | stats count BY mitre_id mitre_technique | sort mitre_id | fields - mitre_id</query>\\n      </search>\\n      <default>*</default>\\n      <prefix>"*</prefix>\\n      <suffix>"</suffix>\\n      <initialValue>*</initialValue>\\n    </input>\\n    <input type="time" token="time_tok" searchWhenChanged="true">\\n      <label>Select a Time Range:</label>\\n      <default>\\n        <earliest>-1d@h</earliest>\\n        <latest></latest>\\n      </default>\\n    </input>\\n  </fieldset>\\n  <row>\\n    <panel>\\n      <html depends="$it_tok$" src="{}.html"/>\\n    </panel>\\n  </row>\\n'.format(tid.lower(), tid.lower(), tid.lower(), tid, name, tid,  tid.lower()))
            evidence_locations = re.findall(r' {8}"([^_]+)_\|_[^#]+": "([^"]+)",', str(transform_lines))
            for evidence_location in evidence_locations:
                if tid in str(evidence_location):
                    log_sources.append(evidence_location[0])
            log_sources = list(set(log_sources))
            # in order of volatility
            if "Command" in str(log_sources) or "Process" in str(log_sources) or "ForeignPort" in str(log_sources) or "LocalPort" in str(log_sources):
                tactic_xml_py.write('  <row>\\n    <panel depends="${}_memory_panel$">\\n      <table>\\n        <title>Volatile activity in memory</title>\\n        <search>\\n          <query>index=$case_tok$ host=$host_tok$ mitre_technique!=- mitre_technique=$mitre_tok$ logtype=memory | `MITRE_lookup` | search id="{}" | stats count values(LocalAddress) AS LocalAddresses values(ForeignAddress) AS ForeignAddresses BY host ProcessName PID LocalPort ForeignPort Protocol State | sort -count | table host ProcessName PID LocalAddresses LocalPort ForeignAddresses ForeignPort Protocol State count</query>\\n          <earliest>$time_tok.earliest$</earliest>\\n          <latest>$time_tok.latest$</latest>\\n          <sampleRatio>1</sampleRatio>\\n          <progress>\\n            <condition match="\\\'job.resultCount\\\' > 0">\\n              <set token="{}_memory_panel">true</set>\\n            </condition>\\n            <condition>\\n              <unset token="{}_memory_panel"/>\\n            </condition>\\n          </progress>\\n        </search>\\n        <option name="count">5</option>\\n        <option name="dataOverlayMode">none</option>\\n        <option name="drilldown">none</option>\\n        <option name="percentagesRow">false</option>\\n        <option name="refresh.display">progressbar</option>\\n        <option name="rowNumbers">false</option>\\n        <option name="totalsRow">false</option>\\n        <option name="wrap">false</option>\\n      </table>\\n    </panel>\\n  </row>\\n'.format(tid.lower(), tid, tid.lower(), tid.lower()))
            if "url" in str(log_sources):
                tactic_xml_py.write('  <row>\\n    <panel depends="${}_browser_panel$">\\n      <table>\\n        <title>Browser activity</title>\\n        <search>\\n          <query>index=$case_tok$ host=$host_tok$ logtype=browser | `MITRE_lookup` | `browser_name` | `browser_domain` | table index host logtype LastWriteTime browser Domain url title Profile Protocol | fillnull value=-</query>\\n          <earliest>$time_tok.earliest$</earliest>\\n          <latest>$time_tok.latest$</latest>\\n          <sampleRatio>1</sampleRatio>\\n          <progress>\\n            <condition match="\\\'job.resultCount\\\' > 0">\\n              <set token="{}_browser_panel">true</set>\\n            </condition>\\n            <condition>\\n              <unset token="{}_browser_panel"/>\\n            </condition>\\n          </progress>\\n        </search>\\n        <option name="count">5</option>\\n        <option name="dataOverlayMode">none</option>\\n        <option name="drilldown">none</option>\\n        <option name="percentagesRow">false</option>\\n        <option name="rowNumbers">false</option>\\n        <option name="totalsRow">false</option>\\n        <option name="wrap">false</option>\\n      </table>\\n    </panel>\\n  </row>\\n'.format(tid.lower(), tid.lower(), tid.lower()))
            if "EventID" in str(log_sources):
                tactic_xml_py.write('  <row>\\n    <panel depends="${}_evt_panel$">\\n      <table>\\n      <title>Windows event log activity</title>\\n        <search>\\n          <query>index=$case_tok$ host=$host_tok$ mitre_technique!=- mitre_technique=$mitre_tok$ logtype=evt | `MITRE_lookup` | search id="{}" | eval TargetSids=mvappend(TargetSid,TargetUserSid) | table SystemTime host Computer Channel EventID LogonType SubjectUserName SubjectUserSid DisplayName WorkstationName TargetSids</query>\\n          <earliest>$time_tok.earliest$</earliest>\\n          <latest>$time_tok.latest$</latest>\\n          <sampleRatio>1</sampleRatio>\\n          <progress>\\n            <condition match="\\\'job.resultCount\\\' > 0">\\n              <set token="{}_evt_panel">true</set>\\n            </condition>\\n            <condition>\\n              <unset token="{}_evt_panel"/>\\n            </condition>\\n          </progress>\\n        </search>\\n        <option name="count">5</option>\\n        <option name="dataOverlayMode">none</option>\\n        <option name="drilldown">none</option>\\n        <option name="percentagesRow">false</option>\\n        <option name="refresh.display">progressbar</option>\\n        <option name="rowNumbers">false</option>\\n        <option name="totalsRow">false</option>\\n        <option name="wrap">false</option>\\n      </table>\\n    </panel>\\n  </row>\\n'.format(tid.lower(), tid, tid.lower(), tid.lower()))
            if "Filename" in str(log_sources):
                tactic_xml_py.write('  <row>\\n    <panel depends="${}_journal_panel$">\\n      <table>\\n        <title>Windows-based file activity</title>\\n        <search>\\n          <query>index=$case_tok$ host=$host_tok$ mitre_technique!=- mitre_technique=$mitre_tok$ logtype=journal | `MITRE_lookup` | search id="{}" | `make_fileinfo` | table index host mitre_id mitre_technique LastWriteTime Filepath Filename Fileext</query>\\n          <earliest>$time_tok.earliest$</earliest>\\n          <latest>$time_tok.latest$</latest>\\n          <sampleRatio>1</sampleRatio>\\n          <progress>\\n            <condition match="\\\'job.resultCount\\\' > 0">\\n              <set token="{}_journal_panel">true</set>\\n            </condition>\\n            <condition>\\n              <unset token="{}_journal_panel"/>\\n            </condition>\\n          </progress>\\n        </search>\\n        <option name="count">5</option>\\n        <option name="dataOverlayMode">none</option>\\n        <option name="drilldown">none</option>\\n        <option name="percentagesRow">false</option>\\n        <option name="refresh.display">progressbar</option>\\n        <option name="rowNumbers">false</option>\\n        <option name="totalsRow">false</option>\\n        <option name="wrap">false</option>\\n      </table>\\n    </panel>\\n  </row>\\n'.format(tid.lower(), tid, tid.lower(), tid.lower()))
            if "Message" in str(log_sources):
                tactic_xml_py.write('  <row>\\n    <panel depends="${}_unix_log_panel$">\\n      <table>\\n        <title>Unix log activity</title>\\n        <search>\\n          <query>index=$case_tok$ host=$host_tok$ mitre_technique!=- mitre_technique=$mitre_tok$ logtype=log | `MITRE_lookup` | search id="{}" | table index host mitre_id mitre_technique LastWriteTime Device Service PID Message | fillnull value=-</query>\\n          <earliest>$time_tok.earliest$</earliest>\\n          <latest>$time_tok.latest$</latest>\\n          <sampleRatio>1</sampleRatio>\\n          <progress>\\n            <condition match="\\\'job.resultCount\\\' > 0">\\n              <set token="{}_unix_log_panel">true</set>\\n            </condition>\\n            <condition>\\n              <unset token="{}_unix_log_panel"/>\\n            </condition>\\n          </progress>\\n        </search>\\n        <option name="count">5</option>\\n        <option name="dataOverlayMode">none</option>\\n        <option name="drilldown">none</option>\\n        <option name="percentagesRow">false</option>\\n        <option name="rowNumbers">false</option>\\n        <option name="totalsRow">false</option>\\n        <option name="wrap">false</option>\\n      </table>\\n    </panel>\\n  </row>\\n'.format(tid.lower(), tid, tid.lower(), tid.lower()))
            if "Registry" in str(log_sources):
                tactic_xml_py.write('  <row>\\n    <panel depends="${}_reg_panel$">\\n      <table>\\n        <title>Registry activity</title>\\n        <search>\\n          <query>index=$case_tok$ host=$host_tok$ mitre_technique!=- mitre_technique=$mitre_tok$ logtype=registry | `MITRE_lookup` | search id="{}" RegistryKey=* | table index host mitre_id mitre_technique Plugin AccountProfile RegistryHive RegistryKey CommandParameters</query>\\n          <earliest>$time_tok.earliest$</earliest>\\n          <latest>$time_tok.latest$</latest>\\n          <sampleRatio>1</sampleRatio>\\n          <progress>\\n            <condition match="\\\'job.resultCount\\\' > 0">\\n              <set token="{}_reg_panel">true</set>\\n            </condition>\\n            <condition>\\n              <unset token="{}_reg_panel"/>\\n            </condition>\\n          </progress>\\n        </search>\\n        <option name="count">5</option>\\n        <option name="dataOverlayMode">none</option>\\n        <option name="drilldown">none</option>\\n        <option name="percentagesRow">false</option>\\n        <option name="refresh.display">progressbar</option>\\n        <option name="rowNumbers">false</option>\\n        <option name="totalsRow">false</option>\\n        <option name="wrap">false</option>\\n      </table>\\n    </panel>\\n  </row>\\n'.format(tid.lower(), tid, tid.lower(), tid.lower()))
            if "Plist" in str(log_sources):
                tactic_xml_py.write('  <row>\\n    <panel depends="${}_plist_panel$">\\n      <table>\\n        <title>Plist entries</title>\\n        <search>\\n          <query>index=$case_tok$ host=$host_tok$ mitre_technique!=- mitre_technique=$mitre_tok$ logtype=plist | `MITRE_lookup` | search id="{}" | table index host mitre_id mitre_technique Plist KeepAlive POSIXSpawnType "ProgramArguments{{}}"</query>\\n          <earliest>$time_tok.earliest$</earliest>\\n          <latest>$time_tok.latest$</latest>\\n          <sampleRatio>1</sampleRatio>\\n          <progress>\\n            <condition match="\\\'job.resultCount\\\' > 0">\\n              <set token="{}_plist_panel">true</set>\\n            </condition>\\n            <condition>\\n              <unset token="{}_plist_panel"/>\\n            </condition>\\n          </progress>\\n        </search>\\n        <option name="count">5</option>\\n        <option name="dataOverlayMode">none</option>\\n        <option name="drilldown">none</option>\\n        <option name="percentagesRow">false</option>\\n        <option name="rowNumbers">false</option>\\n        <option name="totalsRow">false</option>\\n        <option name="wrap">false</option>\\n      </table>\\n    </panel>\\n  </row>\\n'.format(tid.lower(), tid, tid.lower(), tid.lower()))
            if "Artefact" in str(log_sources):
                tactic_xml_py.write('  <row>\\n    <panel depends="${}_usb_panel$">\\n      <table>\\n        <title>USB activity</title>\\n        <search>\\n          <query>index=$case_tok$ host=$host_tok$ mitre_technique=$mitre_tok$ `usb_out`</query>\\n          <earliest>$time_tok.earliest$</earliest>\\n          <latest>$time_tok.latest$</latest>\\n          <sampleRatio>1</sampleRatio>\\n          <progress>\\n            <condition match="\\\'job.resultCount\\\' > 0">\\n              <set token="{}_usb_panel">true</set>\\n            </condition>\\n            <condition>\\n              <unset token="{}_usb_panel"/>\\n            </condition>\\n          </progress>\\n        </search>\\n        <option name="count">5</option>\\n        <option name="dataOverlayMode">none</option>\\n        <option name="drilldown">none</option>\\n        <option name="percentagesRow">false</option>\\n        <option name="refresh.display">progressbar</option>\\n        <option name="rowNumbers">false</option>\\n        <option name="totalsRow">false</option>\\n        <option name="wrap">false</option>\\n      </table>\\n    </panel>\\n  </row>\\n'.format(tid.lower(), tid.lower(), tid.lower()))
                tactic_xml_py.write('  <row>\\n    <panel depends="${}_timeline_panel$">\\n      <table>\\n        <title>Timeline activity</title>\\n        <search>\\n          <query>index=$case_tok$ host=$host_tok$ mitre_technique!=- mitre_technique=$mitre_tok$ logtype=timeline | `MITRE_lookup` | search id="{}" | stats count BY index host mitre_id mitre_technique LastWriteTime source_long Artefact Message | sort 0 -count LastWriteTime | fields - count</query>\\n          <earliest>$time_tok.earliest$</earliest>\\n          <latest>$time_tok.latest$</latest>\\n          <sampleRatio>1</sampleRatio>\\n          <progress>\\n            <condition match="\\\'job.resultCount\\\' > 0">\\n              <set token="{}_timeline_panel">true</set>\\n            </condition>\\n            <condition>\\n              <unset token="{}_timeline_panel"/>\\n            </condition>\\n          </progress>\\n        </search>\\n        <option name="count">5</option>\\n        <option name="dataOverlayMode">none</option>\\n        <option name="drilldown">none</option>\\n        <option name="percentagesRow">false</option>\\n        <option name="refresh.display">progressbar</option>\\n        <option name="rowNumbers">false</option>\\n        <option name="totalsRow">false</option>\\n        <option name="wrap">false</option>\\n      </table>\\n    </panel>\\n  </row>\\n'.format(tid.lower(), tid, tid.lower(), tid.lower()))
            if "Filename" in str(log_sources):
                tactic_xml_py.write('  <row>\\n    <panel depends="${}_audit_panel$">\\n      <table>\\n        <title>Audit file entries</title>\\n        <search>\\n          <query>index=$case_tok$ host=$host_tok$ mitre_technique!=- mitre_technique=$mitre_tok$ logtype=audit | `MITRE_lookup` | search id="{}" | `audit_assignments` | table index host mitre_id mitre_technique audit_file LastAccessTime Filename Filesize Entropy SHA256 | fillnull value=-</query>\\n          <earliest>$time_tok.earliest$</earliest>\\n          <latest>$time_tok.latest$</latest>\\n          <sampleRatio>1</sampleRatio>\\n          <progress>\\n            <condition match="\\\'job.resultCount\\\' > 0">\\n              <set token="{}_audit_panel">true</set>\\n            </condition>\\n            <condition>\\n              <unset token="{}_audit_panel"/>\\n            </condition>\\n          </progress>\\n        </search>\\n        <option name="count">5</option>\\n        <option name="dataOverlayMode">none</option>\\n        <option name="drilldown">none</option>\\n        <option name="percentagesRow">false</option>\\n        <option name="rowNumbers">false</option>\\n        <option name="totalsRow">false</option>\\n        <option name="wrap">false</option>\\n      </table>\\n    </panel>\\n  </row>\\n'.format(tid.lower(), tid, tid.lower(), tid.lower()))
            tactic_xml_py.write("</form>')\n")
        log_sources.clear()


def main():
    # collecting techniques
    try:
        mitre_spreadsheet = requests.get(
            "https://attack.mitre.org/docs/enterprise-attack-v15.1/enterprise-attack-v15.1-techniques.xlsx"
        )
    except requests.exceptions.ConnectionError:
        print("\n\n\tUnable to connect to the Internet. Please try again.\n\n\n")
        sys.exit()
    with open(
        "/opt/elrond/elrond/tools/enterprise-attack-v15.1-techniques.xlsx", "wb"
    ) as spreadsheet_file:
        spreadsheet_file.write(mitre_spreadsheet.content)
    xlsx_file = pandas.read_excel(
        "/opt/elrond/elrond/tools/enterprise-attack-v15.1-techniques.xlsx",
        "techniques",
        engine="openpyxl",
    )
    xlsx_file.to_csv(
        "/opt/elrond/elrond/tools/attack-navigator/.enterprise-attack.temp", index=None, header=True
    )
    if not os.path.exists("/opt/elrond/elrond/tools/attack-navigator/"):
        os.mkdir("/opt/elrond/elrond/tools/attack-navigator/")
    with open("/opt/elrond/elrond/tools/attack-navigator/.enterprise-attack.temp") as csv_with_new_lines:
        malformed_csv = str(csv_with_new_lines.readlines())[2:-2]
        malformed_csv = re.sub(r"\    ", r"£\    £", malformed_csv)
        malformed_csv = re.sub(r"\\n', '", r"\n", malformed_csv)
        malformed_csv = re.sub(r"\n\"\\n', \"", r"\"\n", malformed_csv)
        malformed_csv = re.sub(r"\n\"\n", r"\"\n", malformed_csv)
        malformed_csv = re.sub(r"\n( ?[^S])", r"\1", malformed_csv)
        malformed_csv = re.sub(r"\\n', \"", r"\"\n", malformed_csv)
        malformed_csv = re.sub(r"\\n\", '", r"\"\n", malformed_csv)
        malformed_csv = re.sub(r"([\)\"])\n([^S])", r"\1.  \2", malformed_csv)
        formatted_csv = malformed_csv.replace('\\"', '"')
    with open(
        "/opt/elrond/elrond/tools/attack-navigator/.enterprise-attack-v15.1-techniques.csv", "w"
    ) as final_csv:
        final_csv.write(formatted_csv)
    os.remove("/opt/elrond/elrond/tools/attack-navigator/.enterprise-attack.temp")
    # collecting procedure examples
    with open(
        "/opt/elrond/elrond/tools/enterprise-attack-v15.1-techniques.xlsx", "wb"
    ) as spreadsheet_file:
        spreadsheet_file.write(mitre_spreadsheet.content)
    xlsx_file = pandas.read_excel(
        "/opt/elrond/elrond/tools/enterprise-attack-v15.1-techniques.xlsx",
        "procedure examples",
        engine="openpyxl",
    )
    xlsx_file.to_csv(
        "/opt/elrond/elrond/tools/attack-navigator/.enterprise-attack.temp", index=None, header=True
    )
    with open("/opt/elrond/elrond/tools/attack-navigator/.enterprise-attack.temp") as csv_with_new_lines:
        malformed_csv = str(csv_with_new_lines.readlines())[2:-2]
        malformed_csv = re.sub(r"\    ", r"£\    £", malformed_csv)
        malformed_csv = re.sub(r"\\n', '", r"\n", malformed_csv)
        malformed_csv = re.sub(r"\n\"\\n', \"", r"\"\n", malformed_csv)
        malformed_csv = re.sub(r"\n\"\n", r"\"\n", malformed_csv)
        malformed_csv = re.sub(r"\n( ?[^S])", r"\1", malformed_csv)
        malformed_csv = re.sub(r"\\n', \"", r"\"\n", malformed_csv)
        malformed_csv = re.sub(r"\\n\", '", r"\"\n", malformed_csv)
        malformed_csv = re.sub(r"([\)\"])\n([^S])", r"\1.  \2", malformed_csv)
        formatted_csv = malformed_csv.replace('\\"', '"')
    with open(
        "/opt/elrond/elrond/tools/attack-navigator/.enterprise-attack-v15.1-procedures.csv", "w"
    ) as final_csv:
        final_csv.write(formatted_csv)
    os.remove("/opt/elrond/elrond/tools/attack-navigator/.enterprise-attack.temp")
    # extracting data from mitre files
    (
        csv_rows,
        html_page_info,
        html_pages_content,
        technique_evidence,
        parent_technique_evidence,
    ) = ([] for _ in range(5))
    (
        technique_data,
        parent_technique_all_evidence,
    ) = ({} for _ in range(2))
    with open(
        "/opt/elrond/elrond/tools/enterprise-attack-v15.1-techniques.csv", "w"
    ) as mitre_csv:
        mitre_csv.write(
            "id,name,technique_description,url,tactic,detection,platform,procedure_example\n"
        )
    # cleaning the newline formatting in the csv
    with open(
        "/opt/elrond/elrond/tools/attack-navigator/.enterprise-attack-v15.1-techniques.csv",
    ) as techniquecsv:
        techniques_file_content = str(techniquecsv.readlines())
        techniques_contents = re.sub(
            r"(T\d{4}(?:\.\d{3})?,attack-pattern--)",
            r"\n\1",
            techniques_file_content.replace("\\n', '", " "),
        )
    related_threat_actors = []
    for row in techniques_contents[2:-7].split("\n")[1:]:
        row_elements = re.findall(
            r"^([^,]+),[^,]+,([^,]+),(.*),(https:\/\/attack\.mitre\.org\/techniques\/T[^,]+),[^,]+,[^,]+,enterprise-attack,\d+\.\d+,\"?((?:Reconnaissance|Resource Development|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact)(?:, (?:Reconnaissance|Resource Development|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact)){0,6})\"?,(.*),(\"?(?:Azure AD|Containers|Google Workspace|IaaS|Linux|Network|Office 365|PRE|SaaS|Windows|macOS)(?:(?:, (?:Azure AD|Containers|Google Workspace|IaaS|Linux|Network|Office 365|PRE|SaaS|Windows|macOS))?){0,10}\"?),",
            row,
        )
        tid = row_elements[0][0]
        name = row_elements[0][1]
        description = re.sub(
            r"([^A-Za-z] ){2,}([^A-Za-z])",
            r"\1\2",
            re.sub(
                r"[^\.] ( )",
                r"\1",
                re.sub(
                    r"\[([^\]]+)\]\(https:\/\/attack\.mitre\.org\/(?:techniques|group)\/([^\)]+)\)",
                    r"[\1](\2)",
                    re.sub(
                        r"\(Citation: [^\)]+\)",
                        r"",
                        row_elements[0][2].replace(",", "‚"),
                    ),
                ),
            ),
        )
        description = (
            description.replace(".    ", ". ")
            .replace(". .  ", ". ")
            .replace(". . ", ". ")
            .replace(" .  ", ". ")
            .replace('.  "', '."')
            .replace('""', '"')
            .replace("\\\\\\\\", "\\\\")
            .replace("\\\\\\", "\\\\")
            .replace("\\\\\\'s", "'s")
        )
        description = re.sub(r"([a-z]). ( [a-z])", r"\1\2", description)
        url = row_elements[0][3]
        tactics = row_elements[0][4].replace(",", ";")
        detection = re.sub(
            r"([^A-Za-z] ){2,}([^A-Za-z])",
            r"\1\2",
            re.sub(
                r"[^\.] ( )",
                r"\1",
                re.sub(
                    r"\[([^\]]+)\]\(https:\/\/attack\.mitre\.org\/(?:techniques|group)\/([^\)]+)\)",
                    r"[\1](\2)",
                    re.sub(
                        r"\(Citation: [^\)]+\)",
                        r"",
                        row_elements[0][5].replace(",", "‚"),
                    ),
                ),
            ),
        )
        detection = (
            detection.replace(".    ", ". ")
            .replace(". .  ", ". ")
            .replace(". . ", ". ")
            .replace(" .  ", ". ")
            .replace('.  "', '."')
            .replace('""', '"')
            .replace("\\\\\\\\", "\\\\")
            .replace("\\\\\\", "\\\\")
            .replace("\\\\\\'s", "'s")
        )
        detection = re.sub(r"([a-z]). ( [a-z])", r"\1,\2", detection)
        if detection == '"':
            detection = ""
        platforms = row_elements[0][6].replace(",", ";")
        if "." not in tid and ":" not in name:
            html_page_info.append(
                "{}||{}||{}||{}||{}||{}".format(
                    tid, name, description, url, tactics, platforms
                )
            )
        csv_row = "{}||{}||{}||{}||{}||{}||{}".format(
            tid, name, description, url, tactics, detection, platforms
        )
        csv_rows.append(csv_row.replace('||"||', "||"))
        procedure_examples = append_threat_actors(related_threat_actors, csv_row)
        with open(
            "/opt/elrond/elrond/tools/enterprise-attack-v15.1-techniques.csv", "a"
        ) as mitre_csv:
            mitre_csv.write(
                "{},{}\n".format(
                    csv_row.replace(",", "‚").replace("||", ","), procedure_examples
                )
            )
        related_threat_actors.clear()
    html_page_info = sorted(list(set(html_page_info)))
    csv_rows = sorted(list(set(csv_rows)))
    # obtaining the parent techniques
    for csv_row in csv_rows:
        for page_info in html_page_info:
            if csv_row.split("||")[0].split(".")[0] == page_info.split("||")[0]:
                extracted_results = extract_indicators(
                    "{}||{}".format(csv_row.split("||")[2], csv_row.split("||")[5])
                )
                technique_data[
                    "{}::{}".format(page_info.split("||")[0], csv_row.split("||")[0])
                ] = extracted_results
    # collecting the evidence/indicators of each parent and each respective sub-technique
    for page_info in html_page_info:
        for technique_ids, extracted_indicators in technique_data.items():
            if page_info.split("||")[0] == technique_ids.split("::")[0]:
                if len(extracted_indicators) > 0:
                    for extracted_indicator in extracted_indicators:
                        extracted_indicator = (
                            extracted_indicator.replace("\\\\\\'", '"')
                            .replace("\\\\'", '"')
                            .replace("\\\\\\\\", "\\")
                            .replace("\\\\\\", "\\")
                            .replace("\\\\", "\\")
                            .strip("\\")
                            .strip(":")
                        )
                        technique_evidence.append(extracted_indicator)
        technique_evidence = sorted(list(set(technique_evidence)))
        parent_technique_all_evidence[
            "{}||{}".format(page_info, technique_evidence)
        ] = "-"
        technique_evidence.clear()
    # cleaning up the evidence 'list' due to presence of single quotes
    for messy_evidence, _ in parent_technique_all_evidence.items():
        clean_evidence = re.sub(
            r"'(, )'((?:cmd|cve|evt|ports|reg|software)::)", r"#\1#\2", messy_evidence
        )
        clean_evidence = re.sub(
            r"(\[)'((?:cmd|cve|evt|ports|reg|software)::)", r"\1#\2", clean_evidence
        )
        clean_evidence = re.sub(
            r"((?:cmd|cve|evt|ports|reg|software)::.*)'(\])", r"\1#\2", clean_evidence
        )
        clean_evidence = re.sub(
            r"(\|\|\[)((?:cmd|cve|evt|ports|reg|software)::)", r"\1#\2", clean_evidence
        )
        clean_evidence = re.sub(r"\\(\*)", r"\1", clean_evidence.replace("\\\\", "\\"))
        parent_technique_evidence.append(clean_evidence.replace("\\\\", "\\"))
    # replacing tactics in numerical order and consolidating the html page content
    for technique_info in parent_technique_evidence:
        technique_id = technique_info.split("||")[0]
        technique_name = technique_info.split("||")[1]
        technique_desc = technique_info.split("||")[2]
        technique_link = technique_info.split("||")[3]
        technique_tactics = technique_info.split("||")[4]
        if ";" in technique_tactics:
            technique_tactics = (
                technique_tactics.replace("Initial Access", "01Initial Access")
                .replace("Execution", "02Execution")
                .replace("Persistence", "03Persistence")
                .replace("Privilege Escalation", "04Privilege Escalation")
                .replace("Defense Evasion", "05Defense Evasion")
                .replace("Credential Access", "06Credential Access")
                .replace("Discovery", "07Discovery")
                .replace("Lateral Movement", "08Lateral Movement")
                .replace("Collection", "09Collection")
                .replace("Command and Control", "10Command and Control")
                .replace("Exfiltration", "11Exfiltration")
                .replace("Impact", "12Impact")
            )
            technique_tactic = re.sub(
                r"(; )\d{2}",
                r"\1",
                str(sorted(technique_tactics.split("; ")))[4:-2].replace("', '", "; "),
            )
        else:
            technique_tactic = technique_tactics
        technique_platform = technique_info.split("||")[5]
        evidence = technique_info.split("||")[6]
        html_page = "{}||{}||{}||{}||{}||{}||{}".format(
            technique_id,
            technique_name,
            technique_desc,
            technique_link,
            technique_tactic,
            technique_platform,
            evidence,
        )
        html_pages_content.append(html_page)
    # creating necessary directories
    if not os.path.exists("/opt/elrond/elrond/rivendell/post/splunk/app/views/html"):
        os.makedirs("/opt/elrond/elrond/rivendell/post/splunk/app/views/html")
    if not os.path.exists("/opt/elrond/elrond/rivendell/post/splunk/app/views/xml"):
        os.makedirs("/opt/elrond/elrond/rivendell/post/splunk/app/views/xml")
    # outputting the results into respective tactic pages for splunk app
    for html_page_content in html_pages_content:
        tid, name, desc, link, tactics, platform, evidence = html_page_content.split(
            "||"
        )
        if len(evidence) > 2:
            (
                port_dict,
                evt_dict,
                reg_dict,
                cmd_dict,
                cve_dict,
                software_dict,
            ) = cleanup_evidence(evidence)
        else:
            port_dict, evt_dict, reg_dict, cmd_dict, cve_dict, software_dict = (
                {} for _ in range(6)
            )
        if (
            "Initial Access" in html_page_content.split("||")[4]
            and "Resource Development" not in html_page_content.split("||")[4]
            and "Reconnaissance" not in html_page_content.split("||")[4]
        ):
            build_tactic_html_and_xml_py(
                "initial_access",
                tid,
                name,
                desc,
                link,
                tactics,
                platform,
                evidence,
                port_dict,
                evt_dict,
                reg_dict,
                cmd_dict,
                cve_dict,
                software_dict,
            )
        elif (
            "Execution" in tactics
            and "Initial Access" not in tactics
            and "Resource Development" not in tactics
            and "Reconnaissance" not in tactics
        ):
            build_tactic_html_and_xml_py(
                "execution",
                tid,
                name,
                desc,
                link,
                tactics,
                platform,
                evidence,
                port_dict,
                evt_dict,
                reg_dict,
                cmd_dict,
                cve_dict,
                software_dict,
            )
        elif (
            "Persistence" in tactics
            and "Execution" not in tactics
            and "Initial Access" not in tactics
            and "Resource Development" not in tactics
            and "Reconnaissance" not in tactics
        ):
            build_tactic_html_and_xml_py(
                "persistence",
                tid,
                name,
                desc,
                link,
                tactics,
                platform,
                evidence,
                port_dict,
                evt_dict,
                reg_dict,
                cmd_dict,
                cve_dict,
                software_dict,
            )
        elif (
            "Privilege Escalation" in tactics
            and "Persistence" not in tactics
            and "Execution" not in tactics
            and "Initial Access" not in tactics
            and "Resource Development" not in tactics
            and "Reconnaissance" not in tactics
        ):
            build_tactic_html_and_xml_py(
                "privilege_escalation",
                tid,
                name,
                desc,
                link,
                tactics,
                platform,
                evidence,
                port_dict,
                evt_dict,
                reg_dict,
                cmd_dict,
                cve_dict,
                software_dict,
            )
        elif (
            "Defense Evasion" in tactics
            and "Privilege Escalation" not in tactics
            and "Persistence" not in tactics
            and "Execution" not in tactics
            and "Initial Access" not in tactics
            and "Resource Development" not in tactics
            and "Reconnaissance" not in tactics
        ):
            build_tactic_html_and_xml_py(
                "defense_evasion",
                tid,
                name,
                desc,
                link,
                tactics,
                platform,
                evidence,
                port_dict,
                evt_dict,
                reg_dict,
                cmd_dict,
                cve_dict,
                software_dict,
            )
        elif (
            "Credential Access" in tactics
            and "Defense Evasion" not in tactics
            and "Privilege Escalation" not in tactics
            and "Persistence" not in tactics
            and "Execution" not in tactics
            and "Initial Access" not in tactics
            and "Resource Development" not in tactics
            and "Reconnaissance" not in tactics
        ):
            build_tactic_html_and_xml_py(
                "credential_access",
                tid,
                name,
                desc,
                link,
                tactics,
                platform,
                evidence,
                port_dict,
                evt_dict,
                reg_dict,
                cmd_dict,
                cve_dict,
                software_dict,
            )
        elif (
            "Discovery" in tactics
            and "Credential Access" not in tactics
            and "Defense Evasion" not in tactics
            and "Privilege Escalation" not in tactics
            and "Persistence" not in tactics
            and "Execution" not in tactics
            and "Initial Access" not in tactics
            and "Resource Development" not in tactics
            and "Reconnaissance" not in tactics
        ):
            build_tactic_html_and_xml_py(
                "discovery",
                tid,
                name,
                desc,
                link,
                tactics,
                platform,
                evidence,
                port_dict,
                evt_dict,
                reg_dict,
                cmd_dict,
                cve_dict,
                software_dict,
            )
        elif (
            "Lateral Movement" in tactics
            and "Discovery" not in tactics
            and "Credential Access" not in tactics
            and "Defense Evasion" not in tactics
            and "Privilege Escalation" not in tactics
            and "Persistence" not in tactics
            and "Execution" not in tactics
            and "Initial Access" not in tactics
            and "Resource Development" not in tactics
            and "Reconnaissance" not in tactics
        ):
            build_tactic_html_and_xml_py(
                "lateral_movement",
                tid,
                name,
                desc,
                link,
                tactics,
                platform,
                evidence,
                port_dict,
                evt_dict,
                reg_dict,
                cmd_dict,
                cve_dict,
                software_dict,
            )
        elif (
            "Collection" in tactics
            and "Lateral Movement" not in tactics
            and "Discovery" not in tactics
            and "Credential Access" not in tactics
            and "Defense Evasion" not in tactics
            and "Privilege Escalation" not in tactics
            and "Persistence" not in tactics
            and "Execution" not in tactics
            and "Initial Access" not in tactics
            and "Resource Development" not in tactics
            and "Reconnaissance" not in tactics
        ):
            build_tactic_html_and_xml_py(
                "collection",
                tid,
                name,
                desc,
                link,
                tactics,
                platform,
                evidence,
                port_dict,
                evt_dict,
                reg_dict,
                cmd_dict,
                cve_dict,
                software_dict,
            )
        elif (
            "Command and Control" in tactics
            and "Collection" not in tactics
            and "Lateral Movement" not in tactics
            and "Discovery" not in tactics
            and "Credential Access" not in tactics
            and "Defense Evasion" not in tactics
            and "Privilege Escalation" not in tactics
            and "Persistence" not in tactics
            and "Execution" not in tactics
            and "Initial Access" not in tactics
            and "Resource Development" not in tactics
            and "Reconnaissance" not in tactics
        ):
            build_tactic_html_and_xml_py(
                "command_and_control",
                tid,
                name,
                desc,
                link,
                tactics,
                platform,
                evidence,
                port_dict,
                evt_dict,
                reg_dict,
                cmd_dict,
                cve_dict,
                software_dict,
            )
        elif (
            "Exfiltration" in tactics
            and "Command and Control" not in tactics
            and "Collection" not in tactics
            and "Lateral Movement" not in tactics
            and "Discovery" not in tactics
            and "Credential Access" not in tactics
            and "Defense Evasion" not in tactics
            and "Privilege Escalation" not in tactics
            and "Persistence" not in tactics
            and "Execution" not in tactics
            and "Initial Access" not in tactics
            and "Resource Development" not in tactics
            and "Reconnaissance" not in tactics
        ):
            build_tactic_html_and_xml_py(
                "exfiltration",
                tid,
                name,
                desc,
                link,
                tactics,
                platform,
                evidence,
                port_dict,
                evt_dict,
                reg_dict,
                cmd_dict,
                cve_dict,
                software_dict,
            )
        elif (
            "Impact" in tactics
            and "Exfiltration" not in tactics
            and "Command and Control" not in tactics
            and "Collection" not in tactics
            and "Lateral Movement" not in tactics
            and "Discovery" not in tactics
            and "Credential Access" not in tactics
            and "Defense Evasion" not in tactics
            and "Privilege Escalation" not in tactics
            and "Persistence" not in tactics
            and "Execution" not in tactics
            and "Initial Access" not in tactics
            and "Resource Development" not in tactics
            and "Reconnaissance" not in tactics
        ):
            build_tactic_html_and_xml_py(
                "impact",
                tid,
                name,
                desc,
                link,
                tactics,
                platform,
                evidence,
                port_dict,
                evt_dict,
                reg_dict,
                cmd_dict,
                cve_dict,
                software_dict,
            )


if __name__ == "__main__":
    main()
