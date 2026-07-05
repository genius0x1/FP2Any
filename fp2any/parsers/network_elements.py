"""Network Element parsers: hosts, networks, ranges, domains, zones, routers,
ip lists, groups, service groups, expressions.

All extraction is raw/faithful — no normalization.
"""
from __future__ import annotations

from typing import Dict
import xml.etree.ElementTree as ET

from .base import BaseParser


class HostParser(BaseParser):
    SHEET = "Hosts"
    TAGS = {"host"}
    COLUMNS = ["name", "address", "secondary_addresses"]

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        return {
            "name": self.attr(el, "name"),
            "db_key": self.attr(el, "db_key"),
            "comment": self.attr(el, "comment"),
            "address": self.child_attr(el, "mvia_address", "address"),
            "secondary_addresses": self.joined(el, "secondary", "address"),
        }


class NetworkParser(BaseParser):
    SHEET = "Networks"
    TAGS = {"network"}
    COLUMNS = ["name", "ipv4_network"]

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        return {
            "name": self.attr(el, "name"),
            "db_key": self.attr(el, "db_key"),
            "comment": self.attr(el, "comment"),
            "ipv4_network": self.attr(el, "ipv4_network"),
            "ipv6_network": self.attr(el, "ipv6_network"),
            "broadcast": self.attr(el, "broadcast"),
        }


class AddressRangeParser(BaseParser):
    SHEET = "Address_Ranges"
    TAGS = {"address_range"}
    COLUMNS = ["name", "ip_range"]

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        return {
            "name": self.attr(el, "name"),
            "db_key": self.attr(el, "db_key"),
            "comment": self.attr(el, "comment"),
            "ip_range": self.attr(el, "ip_range"),
        }


class DomainNameParser(BaseParser):
    SHEET = "Domain_Names"
    TAGS = {"domain_name"}
    COLUMNS = ["name", "comment"]

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        return {
            "name": self.attr(el, "name"),
            "db_key": self.attr(el, "db_key"),
            "comment": self.attr(el, "comment"),
            "entries": self.joined(el, "domain_name_entry", "name"),
        }


class ZoneParser(BaseParser):
    SHEET = "Zones"
    TAGS = {"interface_zone"}
    # 'engines' is filled by a post-processing pass (zones referenced by an
    # engine's interfaces via zone_ref) — see extractor._link_engines.
    COLUMNS = ["name", "comment", "engines"]

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        return {
            "name": self.attr(el, "name"),
            "db_key": self.attr(el, "db_key"),
            "comment": self.attr(el, "comment"),
        }


class RouterElementParser(BaseParser):
    """<router> network elements (next-hop routers referenced by engine routing
    tables and occasionally by rules). Distinct from the Routers sheet, which
    holds the engines' routing tables."""

    SHEET = "Router_Elements"
    TAGS = {"router"}
    # 'engines' is filled by a post-processing pass (engines whose routing
    # table references the router) — see extractor._link_engines.
    COLUMNS = ["name", "address", "comment", "engines"]

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        return {
            "name": self.attr(el, "name"),
            "db_key": self.attr(el, "db_key"),
            "comment": self.attr(el, "comment"),
            "address": self.child_attr(el, "mvia_address", "address"),
        }


class IpListParser(BaseParser):
    SHEET = "IP_Lists"
    TAGS = {"ip_list"}
    COLUMNS = ["name", "ip_count", "ips"]

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        ips = self.collect(el, "ip", "value")
        return {
            "name": self.attr(el, "name"),
            "db_key": self.attr(el, "db_key"),
            "type": self.attr(el, "type"),
            "hidden": self.attr(el, "hidden"),
            "ip_count": str(len(ips)),
            "ips": "; ".join(ips),
        }


class GroupParser(BaseParser):
    SHEET = "Groups"
    TAGS = {"group"}
    COLUMNS = ["name", "member_count", "members"]

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        members = self.collect(el, "ne_list", "ref")
        return {
            "name": self.attr(el, "name"),
            "db_key": self.attr(el, "db_key"),
            "is_monitored": self.attr(el, "is_monitored"),
            "member_count": str(len(members)),
            "members": "; ".join(members),
        }


class ServiceGroupParser(BaseParser):
    SHEET = "Service_Groups"
    TAGS = {"gen_service_group"}
    COLUMNS = ["name", "service_count", "services"]

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        services = self.collect(el, "service_ref", "ref")
        return {
            "name": self.attr(el, "name"),
            "db_key": self.attr(el, "db_key"),
            "comment": self.attr(el, "comment"),
            "service_count": str(len(services)),
            "services": "; ".join(services),
        }


class ExpressionParser(BaseParser):
    """Handles both ``expression`` (recursive boolean tree, leaves carry ne_ref)
    and ``match_expression`` (flat list of match_element_entry refs)."""

    SHEET = "Expressions"
    TAGS = {"expression", "match_expression"}
    COLUMNS = ["name", "kind", "operator", "member_count", "members"]

    def parse_element(self, el: ET.Element) -> Dict[str, str]:
        if el.tag == "match_expression":
            members = [c.get("ref", "") for c in el.findall("match_element_entry")]
            operator = ""
        else:  # expression — flatten all descendant ne_ref values
            members = [d.get("ne_ref") for d in el.iter("expression_value") if d.get("ne_ref")]
            operator = self.attr(el, "operator")
        members = [m for m in members if m]
        return {
            "name": self.attr(el, "name"),
            "db_key": self.attr(el, "db_key"),
            "kind": el.tag,
            "operator": operator,
            "member_count": str(len(members)),
            "members": "; ".join(members),
        }
