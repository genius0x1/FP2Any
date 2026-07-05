"""Orchestrator: parse a Forcepoint exported.xml into per-sheet rows.

Returns an ExtractionResult holding:
  - sheets: ordered dict of sheet name -> (columns, rows)
  - counts: element count per sheet
  - unknown_tags: tags routed to Other_Elements (no dedicated parser)
  - meta: root attributes (build / update_package_version) + source filename
"""
from __future__ import annotations

from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
import logging
import os
import re
import xml.etree.ElementTree as ET

from .parsers.registry import (
    build_tag_map, build_sheet_columns, SHEET_ORDER,
)
from .parsers.engines import ENGINE_TAGS

# Engine attributes that reference a server by name.
_SERVER_REF_ATTRS = (
    "log_server_ref", "snmp_ref", "user_id_service_ref",
    "alert_server_ref", "smtp_server_ref",
)
# Child elements (anywhere under an engine) that reference a server by @ref.
_SERVER_REF_CHILDREN = ("ntp_server_ref", "dhcp_server_list")

log = logging.getLogger("fp2any")

# Sheets whose rows belong to a specific engine (filterable by engine name).
ENGINE_SCOPED_SHEETS = ("Interfaces", "Routers")
# Sheets whose rows belong to a specific firewall policy (filterable by policy name).
# NOTE: the XML has no engine->policy link, so engine and policy are independent filters.
POLICY_SCOPED_SHEETS = ("Policies", "Access_Rules", "NAT_Rules", "Tags")

ALL = "__all__"
ALL_ENGINES = ALL  # backward-compatible alias
# "None" filter: exclude that dimension entirely. policy=NONE + engine=X ->
# only what belongs to engine X (infra + the objects its routes reference; no
# rule sheets). engine=NONE + policy=Y -> only what belongs to policy Y (rules
# + referenced objects; no infra sheets).
NONE = "__none__"


@dataclass
class ExtractionResult:
    source_filename: str
    meta: Dict[str, str]
    sheets: "OrderedDict[str, Tuple[List[str], List[Dict[str, str]]]]"
    counts: Dict[str, int]
    unknown_tags: Dict[str, int] = field(default_factory=dict)
    total_elements: int = 0
    engines: List[str] = field(default_factory=list)
    policies: List[str] = field(default_factory=list)
    # Every zone element name in the export, regardless of filtering — lets the
    # PAN-OS generator recognize another engine's zone named in a rule even
    # though the Zones SHEET is strictly engine-scoped.
    zone_names: List[str] = field(default_factory=list)


class FP2AnyExtractor:
    def __init__(self) -> None:
        self.tag_map = build_tag_map()
        # sheet name -> columns (from whichever parser owns that sheet)
        self._sheet_columns: Dict[str, List[str]] = build_sheet_columns()

    def extract_file(self, path: str) -> ExtractionResult:
        tree = ET.parse(path)
        root = tree.getroot()
        return self._extract(root, os.path.basename(path))

    def extract_string(self, data: bytes | str, source_filename: str = "uploaded.xml") -> ExtractionResult:
        root = ET.fromstring(data)
        return self._extract(root, source_filename)

    def _extract(self, root: ET.Element, source_filename: str) -> ExtractionResult:
        if root.tag != "generic_import_export":
            log.warning("Unexpected root <%s> (expected generic_import_export)", root.tag)

        rows_by_sheet: Dict[str, List[Dict[str, str]]] = {s: [] for s in SHEET_ORDER}
        unknown = Counter()
        total = 0

        for el in root:
            total += 1
            parser = self.tag_map.get(el.tag)
            if parser is None:
                # No dedicated parser -> skip (no Other_Elements sheet), but record it.
                unknown[el.tag] += 1
                continue
            try:
                for sheet, row in parser.emit(el):
                    rows_by_sheet.setdefault(sheet, []).append(row)
            except Exception as exc:  # graceful degradation — never abort the run
                log.error("Failed to parse <%s db_key=%s>: %s", el.tag, el.get("db_key"), exc)

        # Assemble ordered sheets, dropping empties except keep Summary handled by writer.
        sheets: "OrderedDict[str, Tuple[List[str], List[Dict[str, str]]]]" = OrderedDict()
        counts: Dict[str, int] = {}
        for sheet in SHEET_ORDER:
            rows = rows_by_sheet[sheet]
            if not rows:
                continue
            sheets[sheet] = (self._sheet_columns[sheet], rows)
            counts[sheet] = len(rows)

        _link_engines(root, sheets)
        _engine_address_rows(sheets)
        if "Servers" in sheets:
            counts["Servers"] = len(sheets["Servers"][1])

        meta = {
            "build": root.get("build", ""),
            "update_package_version": root.get("update_package_version", ""),
        }
        result = ExtractionResult(
            source_filename=source_filename,
            meta=meta,
            sheets=sheets,
            counts=counts,
            unknown_tags=dict(unknown),
            total_elements=total,
            engines=_engine_names(sheets),
            policies=_policy_names(sheets),
            zone_names=[r["name"] for r in sheets.get("Zones", ((), []))[1]
                        if r.get("name")],
        )
        log.info("Extracted %d elements from %s into %d sheets; engines=%s; policies=%s; unknown: %s",
                 total, source_filename, len(sheets), result.engines, result.policies, dict(unknown))
        return result


def _link_engines(root: ET.Element, sheets) -> None:
    """Fill the 'engines' column on the Zones, Servers and Router_Elements sheets
    by scanning each engine for the zones (interface zone_ref) and servers (*_ref)
    it references, and the Routers sheet for the router elements its routes use.
    An element may belong to several engines, or none (global -> left blank)."""
    zone_engines: Dict[str, set] = defaultdict(set)
    server_engines: Dict[str, set] = defaultdict(set)

    for eng in root:
        if eng.tag not in ENGINE_TAGS:
            continue
        ename = eng.get("name", "")
        for attr in _SERVER_REF_ATTRS:
            v = eng.get(attr)
            if v:
                server_engines[v].add(ename)
        for node in eng.iter():
            zr = node.get("zone_ref")
            if zr:
                zone_engines[zr].add(ename)
            if node.tag in _SERVER_REF_CHILDREN and node.get("ref"):
                server_engines[node.get("ref")].add(ename)

    if "Zones" in sheets:
        _cols, rows = sheets["Zones"]
        for r in rows:
            r["engines"] = "; ".join(sorted(zone_engines.get(r.get("name", ""), ())))
    if "Servers" in sheets:
        _cols, rows = sheets["Servers"]
        for r in rows:
            r["engines"] = "; ".join(sorted(server_engines.get(r.get("name", ""), ())))
    if "Router_Elements" in sheets and "Routers" in sheets:
        router_engines: Dict[str, set] = defaultdict(set)
        _cols, routes = sheets["Routers"]
        for r in routes:
            for ref in _route_row_refs(r):
                router_engines[ref].add(r.get("engine", ""))
        _cols, rows = sheets["Router_Elements"]
        for r in rows:
            r["engines"] = "; ".join(sorted(router_engines.get(r.get("name", ""), ())))


def _engine_address_rows(sheets) -> None:
    """Append one Servers-sheet row per engine (server_type='engine') whose
    address is the engine's interface-0 CVI address WITH the interface's
    real prefix length (e.g. 10.96.63.18/28) — per the user's convention,
    that represents the firewall itself. Fallbacks when there is no plain
    interface 0: the 'single' address on non-cluster engines, else the
    lowest 0.x VLAN sub-interface (CVI preferred over single at each
    step). Rules use engines as source/destination; this gives those
    references one address object."""
    if "Interfaces" not in sheets:
        return
    cand: Dict[str, List[tuple]] = {}
    for r in sheets["Interfaces"][1]:
        engine = (r.get("engine") or "").strip()
        iid = (r.get("interface_id") or "").strip()
        ips = [v.strip() for v in (r.get("ip_address") or "").split(";") if v.strip()]
        if engine and iid and ips and r.get("kind") in ("cvi", "single"):
            # Keep the interface's real mask: '10.96.63.18' on network
            # '10.96.63.16/28' -> '10.96.63.18/28'.
            network = (r.get("network") or "").strip()
            addr = ips[0]
            if "/" in network and "/" not in addr:
                addr = f"{addr}/{network.split('/', 1)[1]}"
            cand.setdefault(engine, []).append((iid, r.get("kind"), addr))
    if not cand:
        return
    if "Servers" not in sheets:
        sheets["Servers"] = (["name", "server_type", "address", "engines"], [])
    _cols, rows = sheets["Servers"]
    existing = {r.get("name") for r in rows}

    def order(item: tuple) -> tuple:
        iid, kind, _ip = item
        parts = [int(p) for p in iid.split(".") if p.isdigit()] or [9999]
        return (iid != "0", kind != "cvi", parts)

    for engine, lst in cand.items():
        if engine in existing:  # a real server already carries this name
            continue
        _iid, _kind, ip = min(lst, key=order)
        rows.append({"name": engine, "server_type": "engine",
                     "address": ip, "engines": engine})


def _engine_names(sheets) -> List[str]:
    """Unique engine names found in the engine-scoped sheets (sorted)."""
    names: set[str] = set()
    for sheet in ENGINE_SCOPED_SHEETS:
        if sheet in sheets:
            _cols, rows = sheets[sheet]
            names.update(r["engine"] for r in rows if r.get("engine"))
    return sorted(names)


def _policy_names(sheets) -> List[str]:
    """Firewall policy names (from the Policies sheet), in sheet order."""
    if "Policies" not in sheets:
        return []
    _cols, rows = sheets["Policies"]
    seen: List[str] = []
    for r in rows:
        n = r.get("name")
        if n and n not in seen:
            seen.append(n)
    return seen


def _base_policy(name: str) -> str:
    """Strip the embedded rule-tag suffix from an Access_Rules policy_name
    (e.g. 'HQ_External_Policy_2101814.0' -> 'HQ_External_Policy'). The tag is
    always '<digits>.<digits>' (optionally just digits); only the final one is removed."""
    return re.sub(r"_\d+(?:\.\d+)?$", "", name)


def _split(value: str) -> List[str]:
    return [v.strip() for v in value.split(";") if v.strip()]


def _nat_ne(token: str) -> str:
    """Pull the element name out of a NAT translation token, e.g.
    'dynamic_nat:HQ-100M-ML (1024-65535)' -> 'HQ-100M-ML'."""
    t = token.split(":", 1)[1] if ":" in token else token
    return t.split(" (", 1)[0].strip()


_PAREN_REF = re.compile(r"\(([^)]+)\)\s*$")


def _route_row_refs(row: Dict[str, str]) -> List[str]:
    """Element names a Routers-sheet row references: the gateway element
    ('Name (ip)' -> Name) and the destination element ('ip (Name)' -> Name)."""
    refs: List[str] = []
    gw = (row.get("gateway") or "").split(" (", 1)[0].strip()
    if gw:
        refs.append(gw)
    m = _PAREN_REF.search(row.get("destination") or "")
    if m and m.group(1).strip():
        refs.append(m.group(1).strip())
    return refs


def _route_referenced_names(result: ExtractionResult, engine: str | None = None) -> set[str]:
    """Element names referenced by the engines' routing tables (Routers sheet):
    gateways and destination elements. Scoped to one engine when given."""
    refs: set[str] = set()
    if "Routers" in result.sheets:
        for r in result.sheets["Routers"][1]:
            if engine and r.get("engine") != engine:
                continue
            refs.update(_route_row_refs(r))
    return refs


def _referenced_names(result: ExtractionResult, policy: str) -> set[str]:
    """Names referenced by a policy's access + NAT rules (sources, destinations,
    services, NAT translation targets)."""
    refs: set[str] = set()
    if "Access_Rules" in result.sheets:
        _c, rows = result.sheets["Access_Rules"]
        for r in rows:
            if _base_policy(r.get("policy_name", "")) != policy:
                continue
            for field in ("sources", "destinations", "services"):
                refs.update(_split(r.get(field, "")))
    if "NAT_Rules" in result.sheets:
        _c, rows = result.sheets["NAT_Rules"]
        for r in rows:
            if r.get("policy_name", "") != policy:
                continue
            for field in ("sources", "destinations", "services"):
                refs.update(_split(r.get(field, "")))
            for field in ("nat_source", "nat_destination"):
                for tok in _split(r.get(field, "")):
                    refs.add(_nat_ne(tok))
    return refs


def _resolve_refs(refs: set[str], result: ExtractionResult) -> set[str]:
    """Expand group / service-group / expression references transitively to members."""
    members: Dict[str, List[str]] = {}
    if "Groups" in result.sheets:
        _c, rows = result.sheets["Groups"]
        for r in rows:
            members[r.get("name", "")] = _split(r.get("members", ""))
    if "Service_Groups" in result.sheets:
        _c, rows = result.sheets["Service_Groups"]
        for r in rows:
            members[r.get("name", "")] = _split(r.get("services", ""))
    if "Expressions" in result.sheets:
        _c, rows = result.sheets["Expressions"]
        for r in rows:
            members[r.get("name", "")] = _split(r.get("members", ""))

    resolved: set[str] = set()
    work = list(refs)
    while work:
        name = work.pop()
        if name in resolved:
            continue
        resolved.add(name)
        for child in members.get(name, ()):
            if child not in resolved:
                work.append(child)
    return resolved


# Rule sheets filtered to the selected policy. (Migration_Review rows are
# keyed by rule_name; the sheet is regenerated on the filtered result by
# attach_review, so its rows pass through here untouched.)
_RULE_SHEETS = ("Policies", "Access_Rules", "NAT_Rules", "Tags",
                "Migration_Review")
# Object sheets filtered to objects the policy rules OR the (engine-scoped)
# routing tables reference.
_OBJECT_SHEETS = ("Hosts", "Networks", "Address_Ranges", "Domain_Names",
                  "Router_Elements", "IP_Lists", "Groups", "Service_Groups",
                  "Services", "URLs", "Expressions")
# Infra sheets filtered by engine. Interfaces/Routers carry a single 'engine';
# Zones/Router_Elements carry an 'engines' list (see _link_engines).
# NOTE: Router_Elements is in both groups — with a policy filter it follows the
# reference cascade (which already scopes route refs to the engine); with an
# engine-only filter it falls through to the 'engines' match.
# Servers are deliberately NOT here (user decision 2026-07-02): every server —
# global ones included — is extracted regardless of the engine filter.
_ENGINE_FILTER_SHEETS = ("Interfaces", "Routers", "Zones", "Router_Elements")


def _engine_match(sheet: str, row: Dict[str, str], engine: str) -> bool:
    if sheet in ("Interfaces", "Routers"):
        return row.get("engine") == engine
    return engine in _split(row.get("engines", ""))  # Zones, Router_Elements


def filter_result(result: ExtractionResult, engine: str | None = ALL,
                  policy: str | None = ALL) -> ExtractionResult:
    """Return a copy of ``result`` scoped by policy and/or engine.

    - policy filters the rule sheets to that policy and the object sheets to the
      objects those rules reference (groups/service-groups/expressions resolved)
      PLUS the objects the routing tables reference (engine-scoped when an
      engine is also selected) — routes point at hosts/networks/routers the
      rules never mention.
    - engine filters the infra sheets (Interfaces, Routers, Zones,
      Router_Elements) to that engine; Servers are always kept in full. Zones
      are STRICTLY engine-scoped (only that engine's zones on the sheet);
      rule-referenced Router_Elements of other engines survive.
    - NONE excludes a dimension entirely: policy=NONE drops the rule sheets and
      keeps only objects the (selected) engine's routes reference — i.e.
      "everything related to the engine only"; engine=NONE drops the infra
      sheets (except Router_Elements the selected policy's rules reference by
      name) — "everything related to the policy only".
    ALL / None (Python None) on either means "don't filter that dimension".
    """
    pol_on = bool(policy) and policy != ALL
    eng_on = bool(engine) and engine != ALL
    if not pol_on and not eng_on:
        return result

    pol_none = policy == NONE
    eng_none = engine == NONE
    refs: set[str] = set()
    if pol_on:
        if not pol_none:
            refs = _referenced_names(result, policy)
        if not eng_none:
            refs |= _route_referenced_names(result, engine if eng_on else None)
        refs = _resolve_refs(refs, result)

    new_sheets: "OrderedDict[str, Tuple[List[str], List[Dict[str, str]]]]" = OrderedDict()
    new_counts: Dict[str, int] = {}
    for name, (cols, rows) in result.sheets.items():
        if pol_on and name in _RULE_SHEETS:
            if pol_none:  # every rule belongs to some policy -> nothing left
                rows = []
            elif name == "Policies":
                rows = [r for r in rows if r.get("name") == policy]
            elif name == "Access_Rules":
                rows = [r for r in rows if _base_policy(r.get("policy_name", "")) == policy]
            elif name == "Migration_Review":
                pass  # regenerated per filter by attach_review (rule_name keyed)
            else:  # NAT_Rules, Tags
                rows = [r for r in rows if r.get("policy_name") == policy]
        elif pol_on and name in _OBJECT_SHEETS:
            rows = [r for r in rows if r.get("name") in refs]
        elif eng_on and name in _ENGINE_FILTER_SHEETS:
            if eng_none:
                # No engine dimension: infra dropped, except Router_Elements
                # the selected policy's rules reference by name.
                rows = [r for r in rows
                        if name == "Router_Elements"
                        and r.get("name") and r.get("name") in refs]
            else:
                # Rule-referenced Router_Elements stay even when they belong
                # to another engine (a rule can use an element defined
                # elsewhere). Interfaces/Routers/Zones stay strictly
                # engine-scoped: the user wants ONLY the engine's zones on the
                # sheet — the generator recognizes other engines' zone tokens
                # via result.zone_names instead.
                rows = [r for r in rows
                        if _engine_match(name, r, engine)
                        or (name == "Router_Elements"
                            and r.get("name") and r.get("name") in refs)]
        if not rows:
            continue
        new_sheets[name] = (cols, rows)
        new_counts[name] = len(rows)

    return ExtractionResult(
        source_filename=result.source_filename,
        meta=result.meta,
        sheets=new_sheets,
        counts=new_counts,
        unknown_tags=result.unknown_tags,
        total_elements=result.total_elements,
        engines=result.engines,
        policies=result.policies,
        zone_names=result.zone_names,
    )


def filter_by_policy(result: ExtractionResult, policy: str | None = ALL) -> ExtractionResult:
    """Backward-compatible helper: filter by policy only."""
    return filter_result(result, engine=ALL, policy=policy)
