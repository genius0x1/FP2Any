"""Policy parser: the firewall rulebase.

A ``fw_policy`` is the actual access-control + NAT rulebase — the core asset for
migration. It expands into three sheets:

  * ``Policies``      one row per policy (overview + rule counts + referenced policies)
  * ``Access_Rules``  one row per access rule_entry (source/dest/service/action/...)
  * ``NAT_Rules``     one row per NAT rule_entry (match + translation)

Every rule_entry keeps its db_key, rank, name and comment so the original order
and structure are reconstructable. Section separators (``comment_rule``) are kept
as rows of rule_type=comment so the rulebase layout is preserved. Faithful 1:1 —
object references are kept by name, no normalization.
"""
from __future__ import annotations

from typing import Dict, Iterator, List, Tuple
import xml.etree.ElementTree as ET

from .base import BaseParser

POLICY_TAGS = {"fw_policy", "inspection_template_policy", "file_filtering_policy"}

# container tag -> (sheet, ip_version) for the rule-bearing children of fw_policy
_ACCESS_CONTAINERS = {"access_entry": "ipv4", "ipv6_access_entry": "ipv6"}
_NAT_CONTAINERS = {"nat_entry": "ipv4", "ipv6_nat_entry": "ipv6"}


def _refs(rule_entry: ET.Element, container: str, ref_tag: str) -> str:
    """Join the @value of every <ref_tag> under <container> (verbatim names)."""
    vals = [r.get("value", "") for r in rule_entry.findall(f".//{container}/{ref_tag}")]
    return "; ".join(v for v in vals if v)


def _users(rule_entry: ET.Element) -> str:
    out = []
    for u in rule_entry.findall(".//user_match/user"):
        name = u.get("display_name") or u.get("ref") or ""
        dom = u.get("domain")
        out.append(f"{name} ({dom})" if dom else name)
    return "; ".join(o for o in out if o)


def _nat_translation(rule_entry: ET.Element, side_tag: str) -> str:
    """Summarize the NAT translation on one side (nat_src / nat_dst).

    e.g. ``dynamic_nat:AIC-100M-ML (1024-65535)``. Faithful: keeps the wrapper
    kind, the target element name (ne_ref) and any port range.
    """
    side = rule_entry.find(f".//{side_tag}")
    if side is None:
        return ""
    parts: List[str] = []
    for kind_el in side:  # dynamic_nat / static_nat / ...
        kind = kind_el.tag
        for node in kind_el.iter():
            ne = node.get("ne_ref")
            if ne:
                fp, lp = node.get("first_port"), node.get("last_port")
                seg = f"{kind}:{ne}"
                if fp or lp:
                    seg += f" ({fp or ''}-{lp or ''})"
                parts.append(seg)
        if kind_el.find(".//*[@ne_ref]") is None:  # static with no ne_ref node
            parts.append(kind)
    return "; ".join(parts)


def _rule_type(rule_entry: ET.Element) -> str:
    if rule_entry.find("access_rule") is not None:
        return "access"
    if rule_entry.find("nat_rule") is not None:
        return "nat"
    if rule_entry.find("comment_rule") is not None:
        return "comment"
    return "other"


class PolicyParser(BaseParser):
    SHEET = "Policies"
    TAGS = POLICY_TAGS
    COLUMNS = [
        "name", "policy_type", "comment",
        "template_policy_ref", "inspection_policy_ref", "file_filtering_policy_ref",
        "access_rule_count", "nat_rule_count", "tag_count",
    ]

    # policy_name embeds the rule tag (e.g. HQ_Internal_Policy_2101814.0); no separate tag column.
    ACCESS_COLUMNS = [
        "policy_name", "is_disabled", "rule_type", "sources", "destinations",
        "services", "users", "action", "comment",
    ]
    NAT_COLUMNS = [
        "policy_name", "ip_version", "rule_id", "rank", "name", "comment",
        "is_disabled", "rule_type", "sources", "destinations", "services",
        "action", "nat_source", "nat_destination", "valid_engine", "log_level", "tag",
    ]
    # Section-separator rows (comment_rule) extracted out of the rulebase.
    TAG_COLUMNS = ["policy_name", "tag", "comment"]
    EXTRA_SHEETS = {
        "Access_Rules": ACCESS_COLUMNS,
        "NAT_Rules": NAT_COLUMNS,
        "Tags": TAG_COLUMNS,
    }

    # ------------------------------------------------------------------ emit
    def emit(self, el: ET.Element) -> Iterator[Tuple[str, Dict[str, str]]]:
        policy_name = el.get("name", "")

        access_rows: List[Dict[str, str]] = []
        nat_rows: List[Dict[str, str]] = []
        tag_rows: List[Dict[str, str]] = []

        rule_count = 0
        if el.tag == "fw_policy":
            for container, ipv in _ACCESS_CONTAINERS.items():
                for re_ in el.findall(f"{container}/rule_entry"):
                    row = self._access_row(policy_name, ipv, re_)
                    tag = re_.get("tag", "")
                    # Embed the tag in the policy name: HQ_Internal_Policy_2101814.0
                    row["policy_name"] = f"{policy_name}_{tag}" if tag else policy_name
                    if row["rule_type"] == "comment":
                        # Comment/section rows stay inline in Access_Rules
                        # AND are collected into the Tags sheet.
                        access_rows.append(row)
                        tag_rows.append(self.fit({
                            "policy_name": policy_name,
                            "tag": tag,
                            "comment": re_.get("comment", ""),
                        }, self.TAG_COLUMNS))
                    else:
                        rule_count += 1
                        access_rows.append(row)
            for container, ipv in _NAT_CONTAINERS.items():
                for re_ in el.findall(f"{container}/rule_entry"):
                    nat_rows.append(self._nat_row(policy_name, ipv, re_))

        # Policy overview row first
        yield self.SHEET, self.fit({
            "name": policy_name,
            "policy_type": el.tag,
            "comment": el.get("comment", ""),
            "template_policy_ref": el.get("template_policy_ref", ""),
            "inspection_policy_ref": el.get("inspection_policy_ref", ""),
            "file_filtering_policy_ref": el.get("file_filtering_policy_ref", ""),
            "access_rule_count": str(rule_count),
            "nat_rule_count": str(len(nat_rows)),
            "tag_count": str(len(tag_rows)),
        }, self.COLUMNS)

        for r in access_rows:
            yield "Access_Rules", r
        for r in nat_rows:
            yield "NAT_Rules", r
        for r in tag_rows:
            yield "Tags", r

    # ------------------------------------------------------------ row builders
    def _access_row(self, policy: str, ipv: str, re_: ET.Element) -> Dict[str, str]:
        action = re_.find(".//action")
        vpn_action = re_.find(".//vpn_action")
        opt = re_.find(".//option")
        log = re_.find(".//log_policy")
        return self.fit({
            "policy_name": policy,
            "ip_version": ipv,
            "rule_id": re_.get("db_key", ""),
            "rank": re_.get("rank", ""),
            "name": re_.get("name", ""),
            "comment": re_.get("comment", ""),
            "is_disabled": re_.get("is_disabled", ""),
            "rule_type": _rule_type(re_),
            "sources": _refs(re_, "match_sources", "match_source_ref"),
            "destinations": _refs(re_, "match_destinations", "match_destination_ref"),
            "services": _refs(re_, "match_services", "match_service_ref"),
            "users": _users(re_),
            "action": action.get("type", "") if action is not None else "",
            "vpn_action": vpn_action.get("type", "") if vpn_action is not None else "",
            "vpn": "; ".join(v.get("ref", "") for v in re_.findall(".//vpn_ref")),
            "deep_inspection": opt.get("deep_inspection", "") if opt is not None else "",
            "decrypting": opt.get("decrypting", "") if opt is not None else "",
            "log_level": log.get("log_level", "") if log is not None else "",
            "tag": re_.get("tag", ""),
        }, self.ACCESS_COLUMNS)

    def _nat_row(self, policy: str, ipv: str, re_: ET.Element) -> Dict[str, str]:
        action = re_.find(".//action")
        nat_rule = re_.find("nat_rule")
        log = re_.find(".//log_policy")
        return self.fit({
            "policy_name": policy,
            "ip_version": ipv,
            "rule_id": re_.get("db_key", ""),
            "rank": re_.get("rank", ""),
            "name": re_.get("name", ""),
            "comment": re_.get("comment", ""),
            "is_disabled": re_.get("is_disabled", ""),
            "rule_type": _rule_type(re_),
            "sources": _refs(re_, "match_sources", "match_source_ref"),
            "destinations": _refs(re_, "match_destinations", "match_destination_ref"),
            "services": _refs(re_, "match_services", "match_service_ref"),
            "action": action.get("type", "") if action is not None else "",
            "nat_source": _nat_translation(re_, "nat_src"),
            "nat_destination": _nat_translation(re_, "nat_dst"),
            "valid_engine": nat_rule.get("valid_fw_ref", "") if nat_rule is not None else "",
            "log_level": log.get("log_level", "") if log is not None else "",
            "tag": re_.get("tag", ""),
        }, self.NAT_COLUMNS)
