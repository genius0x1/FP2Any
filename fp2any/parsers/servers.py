"""Server parser: all server-role elements into one Servers sheet.

Heterogeneous types share identity + a representative address. Core columns only.
"""
from __future__ import annotations

from typing import Dict
import xml.etree.ElementTree as ET

from .base import BaseParser

SERVER_TAGS = {
    "dhcp_server", "log_server", "mgt_server", "active_directory_server",
    "ntp_server", "smtp_server", "icap_server", "user_id_service", "snmp_agent",
}


def _first_address(el: ET.Element) -> str:
    """Representative address: mvia_address/@address, else any descendant @address."""
    c = el.find("mvia_address")
    if c is not None and c.get("address"):
        return c.get("address")
    for d in el.iter():
        if d is el:
            continue
        if d.get("address"):
            return d.get("address")
    return ""


class ServerParser(BaseParser):
    SHEET = "Servers"
    TAGS = SERVER_TAGS
    # 'engines' is filled by a post-processing pass (engines that reference this
    # server via *_server_ref / snmp_ref / ntp / dhcp-relay) — see extractor._link_engines.
    COLUMNS = ["name", "server_type", "address", "engines"]

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        return {
            "name": self.attr(el, "name"),
            "db_key": self.attr(el, "db_key"),
            "server_type": el.tag,
            "comment": self.attr(el, "comment"),
            "address": _first_address(el),
            "location_ref": self.attr(el, "location_ref"),
        }
