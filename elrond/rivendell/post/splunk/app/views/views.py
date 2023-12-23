#!/usr/bin/env python3 -tt
from rivendell.post.splunk.app.views.pages import create_ascii
from rivendell.post.splunk.app.views.pages import create_ports
from rivendell.post.splunk.app.views.pages import create_subnet
from rivendell.post.splunk.app.views.html.initial_access import (
    create_initial_access_html,
)
from rivendell.post.splunk.app.views.html.execution import create_execution_html
from rivendell.post.splunk.app.views.html.persistence import create_persistence_html
from rivendell.post.splunk.app.views.html.privilege_escalation import (
    create_privilege_escalation_html,
)
from rivendell.post.splunk.app.views.html.defense_evasion import (
    create_defense_evasion_html,
)
from rivendell.post.splunk.app.views.html.credential_access import (
    create_credential_access_html,
)
from rivendell.post.splunk.app.views.html.discovery import create_discovery_html
from rivendell.post.splunk.app.views.html.lateral_movement import (
    create_lateral_movement_html,
)
from rivendell.post.splunk.app.views.html.collection import create_collection_html
from rivendell.post.splunk.app.views.html.command_and_control import (
    create_command_and_control_html,
)
from rivendell.post.splunk.app.views.html.exfiltration import create_exfiltration_html
from rivendell.post.splunk.app.views.html.impact import create_impact_html
from rivendell.post.splunk.app.views.xml.initial_access import create_initial_access_xml
from rivendell.post.splunk.app.views.xml.execution import create_execution_xml
from rivendell.post.splunk.app.views.xml.persistence import create_persistence_xml
from rivendell.post.splunk.app.views.xml.privilege_escalation import (
    create_privilege_escalation_xml,
)
from rivendell.post.splunk.app.views.xml.defense_evasion import (
    create_defense_evasion_xml,
)
from rivendell.post.splunk.app.views.xml.credential_access import (
    create_credential_access_xml,
)
from rivendell.post.splunk.app.views.xml.discovery import create_discovery_xml
from rivendell.post.splunk.app.views.xml.lateral_movement import (
    create_lateral_movement_xml,
)
from rivendell.post.splunk.app.views.xml.collection import create_collection_xml
from rivendell.post.splunk.app.views.xml.command_and_control import (
    create_command_and_control_xml,
)
from rivendell.post.splunk.app.views.xml.exfiltration import create_exfiltration_xml
from rivendell.post.splunk.app.views.xml.impact import create_impact_xml


def create_htmls(sd):
    header = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">\n  <head>\n    <p><font size="3"><strong>Description</strong></font></p>\n      '
    headings = '</li>\n      </ul>\n  </head>\n  <body>\n    <p><br></p><p><font size="3"><strong>Information</strong></font></p>\n    <table id="mitre">\n      <tr>\n        <th width="5%">ID</th>\n        <th width="15%">Operating Systems</th>\n        <th width="30%">Tactics</th>\n        <th width="50%">Detection</th>\n      </tr>\n      <tr>\n        <td>'
    footer = '</td>\n      </tr>\n    </table>\n    <br/>\n    <table id="break">\n      <tr>\n        <th></th>\n      </tr>\n    </table>\n  </body>\n</html>'
    create_initial_access_html(sd, header, headings, footer)
    create_execution_html(sd, header, headings, footer)
    create_persistence_html(sd, header, headings, footer)  # unfinished: 1 custom
    create_privilege_escalation_html(sd, header, headings, footer)
    create_defense_evasion_html(sd, header, headings, footer)
    create_credential_access_html(sd, header, headings, footer)
    create_discovery_html(sd, header, headings, footer)
    create_lateral_movement_html(sd, header, headings, footer)
    create_collection_html(sd, header, headings, footer)
    create_command_and_control_html(sd, header, headings, footer)
    create_exfiltration_html(sd, header, headings, footer)
    create_impact_html(sd, header, headings, footer)


def create_static_pages(sd):
    create_ascii(sd)
    create_ports(sd)
    create_subnet(sd)


def create_xmls(sd):
    create_initial_access_xml(sd)
    create_execution_xml(sd)
    create_persistence_xml(sd)  # unfinished: 1 custom
    create_privilege_escalation_xml(sd)
    create_defense_evasion_xml(sd)
    create_credential_access_xml(sd)
    create_discovery_xml(sd)
    create_lateral_movement_xml(sd)
    create_collection_xml(sd)
    create_command_and_control_xml(sd)
    create_exfiltration_xml(sd)
    create_impact_xml(sd)
