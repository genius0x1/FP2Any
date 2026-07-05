"""Parser registry: maps top-level XML tag -> parser instance.

Tags without a dedicated parser are skipped (counted as unknown, not written to
any sheet). There is no Other_Elements catch-all sheet.
"""
from __future__ import annotations

from typing import Dict, List

from .base import BaseParser
from .network_elements import (
    HostParser, NetworkParser, AddressRangeParser, DomainNameParser, ZoneParser,
    RouterElementParser, IpListParser, GroupParser, ServiceGroupParser, ExpressionParser,
)
from .services import ServiceParser
from .situations import SituationParser
from .engines import EngineParser
from .servers import ServerParser
from .policies import PolicyParser

# Order here = order sheets are created in the workbook.
DEDICATED_PARSERS: List[BaseParser] = [
    HostParser(),
    NetworkParser(),
    AddressRangeParser(),
    DomainNameParser(),
    ZoneParser(),
    RouterElementParser(),
    IpListParser(),
    GroupParser(),
    ServiceGroupParser(),
    ServiceParser(),
    SituationParser(),
    ExpressionParser(),
    EngineParser(),     # publishes the Routers + Interfaces sheets (per engine)
    ServerParser(),
    PolicyParser(),     # publishes Policies + Access_Rules + NAT_Rules + Tags
]


def build_tag_map() -> Dict[str, BaseParser]:
    """tag name -> parser instance (dedicated parsers only)."""
    tag_map: Dict[str, BaseParser] = {}
    for parser in DEDICATED_PARSERS:
        for tag in parser.TAGS:
            tag_map[tag] = parser
    return tag_map


def build_sheet_columns() -> Dict[str, List[str]]:
    """sheet name -> ordered columns, across dedicated parsers (incl. extras)."""
    cols: Dict[str, List[str]] = {}
    for parser in DEDICATED_PARSERS:
        cols.setdefault(parser.SHEET, parser.COLUMNS)
        for sheet, sheet_cols in parser.EXTRA_SHEETS.items():
            cols.setdefault(sheet, sheet_cols)
    return cols


def _sheet_order() -> List[str]:
    order: List[str] = []
    for p in DEDICATED_PARSERS:
        order.append(p.SHEET)
        order.extend(p.EXTRA_SHEETS.keys())
    # de-dupe while preserving order (a sheet may be declared once)
    seen: set[str] = set()
    return [s for s in order if not (s in seen or seen.add(s))]


# Sheet ordering for the writer.
SHEET_ORDER: List[str] = _sheet_order()
