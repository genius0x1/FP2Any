"""Shared base class for all element parsers.

Each parser declares:
  - SHEET    : the Excel sheet name it feeds.
  - TAGS     : the set of top-level XML tag names it consumes.
  - COLUMNS  : ordered list of output column names (the sheet header).

and implements ``parse_element(el) -> dict`` returning one row (a mapping of
column name -> raw string value). The base class guarantees every declared
column is present (missing -> "") and that values are faithful copies.
"""
from __future__ import annotations

from typing import Dict, Iterator, List, Tuple
import xml.etree.ElementTree as ET

# Faithful multi-value join separator (used for member/child lists).
JOIN = "; "


class BaseParser:
    SHEET: str = ""
    TAGS: set[str] = set()
    COLUMNS: List[str] = []

    # Parsers that feed more than one sheet (e.g. the policy parser emits a
    # Policies overview plus Access_Rules / NAT_Rules) declare the extra sheets
    # here as {sheet_name: columns}. They appear right after SHEET in the book.
    EXTRA_SHEETS: Dict[str, List[str]] = {}

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        """Return one output row for a single top-level element.

        Subclasses override this. The default copies all attributes 1:1.
        """
        return dict(el.attrib)

    def emit(self, el: ET.Element) -> Iterator[Tuple[str, Dict[str, str]]]:
        """Yield ``(sheet_name, row)`` pairs for one top-level element.

        Default: a single row into ``self.SHEET``. Parsers that expand one
        element into many rows / multiple sheets override this.
        """
        yield self.SHEET, self.row(el)

    # ----- helpers (shared, all return raw values) -----------------------
    @staticmethod
    def attr(el: ET.Element, name: str, default: str = "") -> str:
        """Raw attribute value, verbatim (no strip, no transform)."""
        return el.get(name, default)

    @staticmethod
    def child_attr(el: ET.Element, child_tag: str, attr: str, default: str = "") -> str:
        """First matching child's attribute, verbatim."""
        c = el.find(child_tag)
        if c is None:
            return default
        return c.get(attr, default)

    @staticmethod
    def collect(el: ET.Element, child_tag: str, attr: str) -> List[str]:
        """All values of ``attr`` across direct children named ``child_tag``."""
        out = []
        for c in el.findall(child_tag):
            v = c.get(attr)
            if v is not None:
                out.append(v)
        return out

    @classmethod
    def joined(cls, el: ET.Element, child_tag: str, attr: str) -> str:
        return JOIN.join(cls.collect(el, child_tag, attr))

    def row(self, el: ET.Element) -> Dict[str, str]:
        """Normalize a parsed row to exactly COLUMNS (fill missing with '')."""
        return self.fit(self.parse_element(el), self.COLUMNS)

    @staticmethod
    def fit(raw: Dict[str, str], columns: List[str]) -> Dict[str, str]:
        """Project a raw dict onto ``columns`` (missing -> '', values stringified)."""
        return {col: ("" if raw.get(col) is None else str(raw.get(col))) for col in columns}
