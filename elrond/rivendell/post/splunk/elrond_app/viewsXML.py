#!/usr/bin/env python3 -tt
from rivendell.post.splunk.xml.initial_access import create_initial_access_xml
from rivendell.post.splunk.xml.execution import create_execution_xml
from rivendell.post.splunk.xml.persistence import create_persistence_xml
from rivendell.post.splunk.xml.privilege_escalation import (
    create_privilege_escalation_xml,
)
from rivendell.post.splunk.xml.defence_evasion import create_defence_evasion_xml
from rivendell.post.splunk.xml.credential_access import create_credential_access_xml
from rivendell.post.splunk.xml.discovery import create_discovery_xml
from rivendell.post.splunk.xml.lateral_movement import create_lateral_movement_xml
from rivendell.post.splunk.xml.collection import create_collection_xml
from rivendell.post.splunk.xml.command_control import create_command_control_xml
from rivendell.post.splunk.xml.exfiltration import create_exfiltration_xml
from rivendell.post.splunk.xml.impact import create_impact_xml


def create_xmls(sd):
    create_initial_access_xml(sd)
    create_execution_xml(sd)
    create_persistence_xml(sd)  # unfinished: 1 custom
    create_privilege_escalation_xml(sd)
    create_defence_evasion_xml(sd)
    create_credential_access_xml(sd)
    create_discovery_xml(sd)
    create_lateral_movement_xml(sd)
    create_collection_xml(sd)
    create_command_control_xml(sd)
    create_exfiltration_xml(sd)
    create_impact_xml(sd)
