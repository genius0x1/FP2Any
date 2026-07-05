"""Engine parser: firewall engines across Forcepoint versions.

Version drift (see docs/phase0_mapping.md):
  v6.10 -> master_engine, virtual_fw
  v7.2  -> fw_cluster, fw_single
Core columns only (per user decision) — identity + key refs, not the dozens of
deep tuning attributes.
"""
from __future__ import annotations

from typing import Dict, Iterator, List, Tuple
import xml.etree.ElementTree as ET

from .base import BaseParser

# Known engine tags; the registry also routes any tag ending in these via pattern.
ENGINE_TAGS = {"master_engine", "virtual_fw", "fw_cluster", "fw_single", "fw_layer2"}


# Interface element families (across v6.10 / v7.2).
_PHYS_TAGS = {"physical_interface", "virtual_physical_interface"}
_VLAN_TAGS = {"vlan_interface", "virtual_vlan_interface"}
# Addressed interfaces: tag -> kind label.
_ADDR_TAGS = {
    "cluster_virtual_interface": "cvi",
    "node_interface": "ndi",
    "fw_single_interface": "single",
}


def _addresses(el: ET.Element) -> str:
    return "; ".join(a.get("address", "") for a in el.findall("mvia_address") if a.get("address"))


def _roles(el: ET.Element) -> str:
    """Summarize the true management/role flags on an addressed interface."""
    flags = [
        ("primary_mgt", "mgmt"), ("backup_mgt", "backup-mgmt"),
        ("primary_heartbeat", "heartbeat"), ("backup_heartbeat", "backup-heartbeat"),
        ("outgoing", "outgoing"), ("auth_request", "auth"),
    ]
    return "; ".join(label for attr, label in flags if el.get(attr) == "true")


def _interfaces(engine_el: ET.Element) -> List[Dict[str, str]]:
    """All interface definitions on an engine: physical ports, port-channels
    (link aggregation), VLANs, addressed interfaces (CVI/NDI/single) and tunnels.
    Values verbatim; the IP comes from the child <mvia_address>."""
    engine_name = engine_el.get("name", "")
    rows: List[Dict[str, str]] = []
    for el in engine_el.iter():
        tag = el.tag
        if tag in _PHYS_TAGS:
            agg = el.get("aggregate_mode", "")
            is_pc = agg not in ("", "none")
            rows.append({
                "engine": engine_name,
                "kind": "port_channel" if is_pc else "physical",
                "interface_id": el.get("interface_id", ""),
                "zone": el.get("zone_ref", ""),
                "aggregate_mode": agg,
                "aggregate_with": el.get("second_interface_id", ""),
                "mac": el.get("macaddress", ""),
                "comment": el.get("comment", ""),
            })
        elif tag in _VLAN_TAGS:
            rows.append({
                "engine": engine_name,
                "kind": "vlan",
                "interface_id": el.get("interface_id", ""),
                "zone": el.get("zone_ref", ""),
                "comment": el.get("comment", ""),
            })
        elif tag in _ADDR_TAGS:
            rows.append({
                "engine": engine_name,
                "kind": _ADDR_TAGS[tag],
                "interface_id": el.get("nicid", ""),
                "ip_address": _addresses(el),
                "network": el.get("network_value", ""),
                "node": el.get("nodeid", ""),
                "management": _roles(el),
                "name": el.get("name", ""),
                "comment": el.get("comment", ""),
            })
        elif tag == "tunnel_interface":
            rows.append({
                "engine": engine_name,
                "kind": "tunnel",
                "interface_id": el.get("interface_id", ""),
                "zone": el.get("zone_ref", ""),
                "comment": el.get("comment", ""),
            })
    return rows


def _routes(engine_el: ET.Element) -> List[Dict[str, str]]:
    """Engine static routing table from <routing_node>.

    Walk routing_node > interface_rn_level (nicid) > gateway_rn_level (next-hop)
    > any_rn_level (destination network). Emits one row per route. A
    gateway_rn_level with no any_rn_level children (routes via tunnel
    interfaces) is itself the destination, with no gateway. Values kept
    verbatim; gateway/destination show the element name + the IP/CIDR.
    """
    rows: List[Dict[str, str]] = []
    for rn in engine_el.iter("routing_node"):
        engine_name = rn.get("name") or engine_el.get("name", "")
        for iface in rn.findall("interface_rn_level"):
            nicid = iface.get("nicid", "")
            for gw in iface.iter("gateway_rn_level"):
                gw_ref = gw.get("ne_ref", "")
                gw_ip = gw.get("ipaddress", "")
                gateway = f"{gw_ref} ({gw_ip})" if gw_ip else gw_ref
                dests = gw.findall("any_rn_level")
                if not dests:
                    # Leaf entry with nothing under it (typical under tunnel
                    # interfaces): the node itself IS the routed network/host,
                    # reachable directly via this interface — there is no
                    # separate next-hop gateway.
                    if gw_ip or gw_ref:
                        rows.append({
                            "engine": engine_name,
                            "interface": nicid,
                            "gateway": "",
                            "destination": f"{gw_ip} ({gw_ref})" if gw_ref else gw_ip,
                        })
                    continue
                for dest in dests:
                    d_ip = dest.get("ipaddress", "")
                    d_ref = dest.get("ne_ref", "")
                    destination = f"{d_ip} ({d_ref})" if d_ref else d_ip
                    rows.append({
                        "engine": engine_name,
                        "interface": nicid,
                        "gateway": gateway,
                        "destination": destination,
                    })
    return rows


class EngineParser(BaseParser):
    """Consumes engine elements but only to publish their routing table to the
    Routers sheet — there is no standalone Engines sheet."""

    SHEET = "Routers"
    TAGS = ENGINE_TAGS
    COLUMNS = ["engine", "interface", "gateway", "destination"]

    INTERFACE_COLUMNS = [
        "engine", "kind", "interface_id", "zone", "ip_address", "network",
        "aggregate_mode", "aggregate_with", "mac", "node", "management",
        "name", "comment",
    ]
    EXTRA_SHEETS = {"Interfaces": INTERFACE_COLUMNS}

    def emit(self, el: ET.Element) -> Iterator[Tuple[str, Dict[str, str]]]:
        for r in _interfaces(el):
            yield "Interfaces", self.fit(r, self.INTERFACE_COLUMNS)
        for r in _routes(el):
            yield self.SHEET, self.fit(r, self.COLUMNS)
