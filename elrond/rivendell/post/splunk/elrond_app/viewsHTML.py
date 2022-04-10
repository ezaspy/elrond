#!/usr/bin/env python3 -tt
from rivendell.post.splunk.html.initial_access import create_initial_access_html
from rivendell.post.splunk.html.execution import create_execution_html
from rivendell.post.splunk.html.persistence import create_persistence_html
from rivendell.post.splunk.html.privilege_escalation import (
    create_privilege_escalation_html,
)
from rivendell.post.splunk.html.defence_evasion import create_defence_evasion_html
from rivendell.post.splunk.html.credential_access import (
    create_credential_access_html,
)
from rivendell.post.splunk.html.discovery import create_discovery_html
from rivendell.post.splunk.html.lateral_movement import create_lateral_movement_html
from rivendell.post.splunk.html.collection import create_collection_html
from rivendell.post.splunk.html.command_control import create_command_control_html
from rivendell.post.splunk.html.exfiltration import create_exfiltration_html
from rivendell.post.splunk.html.impact import create_impact_html


def create_htmls(sd):
    header = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">\n  <head>\n    <p><font size="3"><strong>Description</strong></font></p>\n      '
    headings = '</li>\n      </ul>\n  </head>\n  <body>\n    <p><br></p><p><font size="3"><strong>Information</strong></font></p>\n    <table id="mitre">\n      <tr>\n        <th width="5%">ID</th>\n        <th width="15%">Operating Systems</th>\n        <th width="35%">Tactics</th>\n        <th width="45%">Sub-Techniques</th>\n      </tr>\n      <tr>\n        <td>'
    iocs = '</td>\n      </tr>\n    </table>\n    <br><br>\n    <p><font size="3"><strong>Indicators of Compromise</strong></font></p>\n      <ul>\n        <li>'
    related = '</li>          </ul>\n    <p><br></p><p><font size="3"><strong>Related Techniques</strong></font></p>\n    <table id="id">\n      <tr>\n        <th width="5%">ID</th>\n        <th width="95%">Title</th>\n      </tr>\n      <tr>\n        <td>'
    insert = "</td>\n      </tr>\n      <tr>\n        <td>"
    mitigations = '</td>\n      </tr>\n    </table>\n    <p><br></p><p><font size="3"><strong>Mitigations</strong></font></p>\n    <table id="id">\n      <tr>\n        <th width="15%">Mitigation</th>\n        <th width="85%">Description</th>\n      </tr>\n      <tr>\n        <td>'
    footer = '</td>\n      </tr>\n    </table>\n    <br/>\n    <table id="break">\n      <tr>\n        <th></th>\n      </tr>\n    </table>\n  </body>\n</html>'
    create_initial_access_html(
        sd, header, headings, iocs, related, insert, mitigations, footer
    )
    create_execution_html(
        sd, header, headings, iocs, related, insert, mitigations, footer
    )
    create_persistence_html(
        sd, header, headings, iocs, related, insert, mitigations, footer
    )  # unfinished: 1 custom
    create_privilege_escalation_html(
        sd, header, headings, iocs, related, insert, mitigations, footer
    )
    create_defence_evasion_html(
        sd, header, headings, iocs, related, insert, mitigations, footer
    )
    create_credential_access_html(
        sd, header, headings, iocs, related, insert, mitigations, footer
    )
    create_discovery_html(
        sd, header, headings, iocs, related, insert, mitigations, footer
    )
    create_lateral_movement_html(
        sd, header, headings, iocs, related, insert, mitigations, footer
    )
    create_collection_html(
        sd, header, headings, iocs, related, insert, mitigations, footer
    )
    create_command_control_html(
        sd, header, headings, iocs, related, insert, mitigations, footer
    )
    create_exfiltration_html(
        sd, header, headings, iocs, related, insert, mitigations, footer
    )
    create_impact_html(sd, header, headings, iocs, related, insert, mitigations, footer)
