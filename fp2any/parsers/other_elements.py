"""Catch-all parser for element types not yet given a dedicated sheet.

Captures identity verbatim plus a compact dump of remaining attributes so no
information is silently lost (Phase 5 graceful degradation). Also used to log
unknown/unsupported tags.
"""
from __future__ import annotations

from typing import Dict
import xml.etree.ElementTree as ET

from .base import BaseParser

_ID_ATTRS = ("name", "db_key", "comment")


class OtherElementParser(BaseParser):
    SHEET = "Other_Elements"
    TAGS: set[str] = set()  # populated dynamically by the registry (fallback)
    COLUMNS = ["element_type", "name", "db_key", "comment", "other_attributes", "child_tags"]

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        other = {k: v for k, v in el.attrib.items() if k not in _ID_ATTRS}
        other_str = ", ".join(f"{k}={v}" for k, v in sorted(other.items()))
        child_tags = ", ".join(sorted({c.tag for c in el}))
        return {
            "element_type": el.tag,
            "name": self.attr(el, "name"),
            "db_key": self.attr(el, "db_key"),
            "comment": self.attr(el, "comment"),
            "other_attributes": other_str,
            "child_tags": child_tags,
        }
