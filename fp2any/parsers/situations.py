"""Situation parser: Forcepoint <situation> elements.

In this export every situation is a ``url_list_application`` — a customer-built
URL-list / application object referenced by rules as a "service". These are the
custom URL-filtering objects that won't exist by default on FortiGate/Palo Alto,
so they must be migrated by hand; this sheet captures them faithfully (name,
type, categories, ports, and the literal URL entries) to drive that mapping.

Raw/faithful extraction — no normalization.
"""
from __future__ import annotations

from typing import Dict
import xml.etree.ElementTree as ET

from .base import BaseParser


class SituationParser(BaseParser):
    # Sheet is named "URLs" (user-facing); the source XML element is <situation>.
    SHEET = "URLs"
    TAGS = {"situation"}
    COLUMNS = ["name", "type", "categories", "ports", "url_count", "urls",
               "description"]

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        ports = []
        for ap in el.findall("application_port"):
            proto = ap.get("protocol_ref", "")
            frm = ap.get("from", "")
            to = ap.get("to", "")
            tls = ap.get("tls", "")
            span = frm if (not to or to == frm) else f"{frm}-{to}"
            piece = f"{proto} {span}".strip()
            if tls:
                piece += f" tls:{tls}"
            ports.append(piece)
        urls = self.collect(el, "url_entry", "url")
        desc = el.find("description")
        return {
            "name": self.attr(el, "name"),
            "db_key": self.attr(el, "db_key"),
            "type": self.attr(el, "type"),
            "severity": self.attr(el, "severity"),
            "categories": self.joined(el, "category_ref", "ref"),
            "ports": "; ".join(ports),
            "url_count": str(len(urls)),
            "urls": "; ".join(urls),
            "description": (desc.text or "").strip() if desc is not None else "",
        }
