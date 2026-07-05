"""Service parser: TCP + UDP services combined into one sheet with a protocol
column (per user decision). Faithful extraction.
"""
from __future__ import annotations

from typing import Dict
import xml.etree.ElementTree as ET

from .base import BaseParser


class ServiceParser(BaseParser):
    SHEET = "Services"
    TAGS = {"service_tcp", "service_udp"}
    COLUMNS = ["name", "protocol", "min_dst_port", "max_dst_port"]

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        # protocol derived from the tag only (tcp/udp) — not a value transform.
        protocol = "tcp" if el.tag == "service_tcp" else "udp"
        return {
            "name": self.attr(el, "name"),
            "db_key": self.attr(el, "db_key"),
            "protocol": protocol,
            "comment": self.attr(el, "comment"),
            "min_dst_port": self.attr(el, "min_dst_port"),
            "max_dst_port": self.attr(el, "max_dst_port"),
            "min_src_port": self.attr(el, "min_src_port"),
            "max_src_port": self.attr(el, "max_src_port"),
            "protocol_agent_ref": self.attr(el, "protocol_agent_ref"),
        }
