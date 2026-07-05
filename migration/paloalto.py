"""Generate Palo Alto (PAN-OS) `set` CLI from an ExtractionResult.

Command style follows the customer reference PaloAlto_CLI_HQ-internal_FW.txt:

  set address <name> ip-netmask <cidr> | ip-range <a-b> | fqdn <domain>
  set address-group <name> static [ m1 m2 ... ]
  set service <name> protocol <tcp|udp> port <p[-p]>
  set service-group <name> members [ s1 s2 ... ]
  set tag "<section>" color colorN
  set zone <name> network layer3 [ ifaces ]   (bare `set zone <name>` when unbound)
  set rulebase security rules <Rule> from any / to any / source X / destination Y
                                       / service Z / application any / action allow|deny
                                       / disabled yes / tag "<section>"
  set rulebase nat rules <Rule> from/to/source/destination/service
                                / source-translation dynamic-ip-and-port|static-ip
                                  translated-address X
                                / destination-translation translated-address Y
                                  [translated-port N]

Object names are sanitized the same way everywhere (so rules reference the exact
same names): '/' and "'" -> '_', surrounding whitespace stripped, and any name
with spaces or unusual characters is double-quoted. "ANY"/"Any network" -> any.

Rule from/to zones are INFERRED (modeled on the customer's zone_assign.py
workflow): each source/destination is resolved to its IPs (groups expanded
recursively), matched most-specific-first against a zone->subnet table
auto-derived from the engine's interfaces (zone_ref + interface network,
extended by its static routes); no match -> the 'External' zone. The inferred
zones are reported back on the Access_Rules sheet (source_zone /
destination_zone columns) for review.
This is a best-effort, faithful translation — review before committing to a device.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Iterable

from fp2any.extractor import ExtractionResult

# Forcepoint tokens that mean "match anything".
_ANY = {"ANY", "Any", "any", "Any network", "ALL", "All"}
# Actions that become a PAN-OS deny.
_DENY = {"discard", "refuse", "reject", "drop", "block"}

# Common Forcepoint predefined services (not exported as <service_*>) -> (proto, port).
# Auto-created when referenced by a group/rule but otherwise undefined, so PAN-OS
# doesn't reject the reference. Standard IANA ports; review for your environment.
_PREDEFINED = {
    "DNS": ("udp", "53"), "DNS-TCP": ("tcp", "53"),
    "HTTP": ("tcp", "80"), "HTTPS": ("tcp", "443"),
    "SSH": ("tcp", "22"), "Telnet": ("tcp", "23"), "TELNET": ("tcp", "23"),
    "SMTP": ("tcp", "25"), "FTP": ("tcp", "21"),
    "TFTP": ("udp", "69"), "NTP": ("udp", "123"),
    "SNMP": ("udp", "161"), "LDAP": ("tcp", "389"),
    "POP3": ("tcp", "110"), "IMAP": ("tcp", "143"),
    "RADIUS": ("udp", "1812"), "RDP": ("tcp", "3389"),
    "Kerberos": ("tcp", "88"), "Syslog": ("udp", "514"),
    # Voice signaling (main signaling port only — review for full media ranges).
    "H.323": ("tcp", "1720"), "SCCP": ("tcp", "2000"),
    # Common Forcepoint predefined names seen referenced by rules (standard ports).
    "Remote_Desktop": ("tcp", "3389"), "Microsoft-DS": ("tcp", "445"),
    "MSSQL_TCP": ("tcp", "1433"), "SNMP_TCP": ("tcp", "161"), "SNMP_UDP": ("udp", "161"),
    "NTP_TCP": ("tcp", "123"), "LDAP_TCP": ("tcp", "389"), "LDAP_UDP": ("udp", "389"),
    "MSRPC_TCP": ("tcp", "135"), "MSRPC_UDP": ("udp", "135"),
    "MSRPC_Endpoint_Mapper_TCP": ("tcp", "135"), "MSRPC_EPM_Exchange": ("tcp", "135"),
    "Kerberos_Administration_TCP": ("tcp", "749"),
    "Microsoft_Global_Catalog_LDAP_TCP": ("tcp", "3268"),
    "Microsoft_Global_Catalog_LDAPS_TCP": ("tcp", "3269"),
    "MSMQ-RPC_Message_Queuing_tcp_2103": ("tcp", "2103"),
    "MSMQ-RPC_Message_Queuing_tcp_2105": ("tcp", "2105"),
    "BOOTPS_UDP": ("udp", "67"), "BOOTPC_UDP": ("udp", "68"),
}

# Forcepoint "services" that are really protocols/apps -> PAN-OS App-ID (application field).
_APPLICATIONS = {
    "ICMP": "ping", "Echo_Request_No_Code": "ping", "Echo_Request_Any_Code": "ping",
    "Ping_RPC": "ping", "Traceroute_Status_No_Route": "traceroute",
    "QUIC": "quic", "Microsoft-Teams": "ms-teams", "Microsoft_Teams": "ms-teams",
    "Microsoft-Outlook": "ms-office365", "Microsoft-OneDrive": "ms-onedrive",
    "Microsoft-SharePoint-Online": "ms-sharepoint-online",
    "Zoom": "zoom", "WhatsApp": "whatsapp", "Yahoo": "yahoo-mail",
}

_SIMPLE = re.compile(r"^[A-Za-z0-9._\-]+$")
_MAX_NAME = 63  # PAN-OS object/tag/rule name length limit
# Valid PAN-OS tag colors: color1-color42 EXCEPT color18 (not a valid value).
# More tags than colors -> cycle/reuse (color is cosmetic).
_PAN_COLORS = [f"color{i}" for i in range(1, 43) if i != 18]
# Characters PAN-OS rejects in an OBJECT name (anything but alnum . _ -).
_ILLEGAL = re.compile(r"[^A-Za-z0-9._\-]+")
# Tags may also contain spaces (quoted); everything else illegal is replaced.
_ILLEGAL_TAG = re.compile(r"[^A-Za-z0-9._\- ]+")


def pan_name(raw: str) -> str:
    """Sanitize a Forcepoint element name into a PAN-OS object name.

    Every run of characters PAN-OS disallows (incl. '/', "'", '&', '[', ']',
    spaces) becomes a single '_'; leading/trailing '_' stripped; truncated to 63.
    Applied identically to definitions and references so they always match
    (matches the customer reference's sanitization)."""
    n = _ILLEGAL.sub("_", (raw or "").strip()).strip("_")
    return n[:_MAX_NAME]


def pan_tag(raw: str) -> str:
    """Sanitize a tag/section label — like pan_name but spaces are kept (quoted)."""
    n = _ILLEGAL_TAG.sub("_", (raw or "").strip()).strip()
    return n[:_MAX_NAME]


def _ipcmd(value: str) -> tuple[str, str]:
    """Return (kind, value) for an address: ranges -> ip-range, bare IP -> /32."""
    v = (value or "").strip()
    if "-" in v:
        return "ip-range", v
    if "/" in v:
        return "ip-netmask", v
    return "ip-netmask", f"{v}/32"


def tok(name: str) -> str:
    """Render a name as a CLI token, quoting it if it isn't a simple identifier."""
    return name if _SIMPLE.match(name) else '"' + name.replace('"', "") + '"'


def _ref(raw: str) -> str:
    """A source/destination/service reference: 'any' for ANY-tokens, else sanitized."""
    if raw in _ANY:
        return "any"
    return tok(pan_name(raw))


def _members(raw_list: Iterable[str]) -> str:
    return "[ " + " ".join(tok(pan_name(m)) for m in raw_list) + " ]"


def _split(value: str) -> List[str]:
    return [v.strip() for v in (value or "").split(";") if v.strip()]


_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MAX_VR = 31    # PAN-OS virtual-router name length limit (< object-name 63)
_MAX_ZONE = 31  # PAN-OS zone name length limit
# Zone assigned when a source/destination doesn't match any derived subnet
# (internet IPs, FQDNs, unresolvable refs) — per the customer's convention.
_FALLBACK_ZONE = "External"


def pan_zone(raw: str) -> str:
    """Zone name: like pan_name but capped at PAN-OS's 31-char zone limit."""
    return pan_name(raw)[:_MAX_ZONE].rstrip("_")


_MAX_URLCAT = 31  # PAN-OS custom-url-category name length limit


def pan_urlcat(raw: str) -> str:
    """Custom-url-category name: like pan_name, capped at PAN-OS's 31-char limit
    (applied to both the definition and the rule reference so they match)."""
    return pan_name(raw)[:_MAX_URLCAT].rstrip("_")


def _url_entry_issue(entry: str) -> str:
    """Short reason a Forcepoint url_entry needs a human before it works as a
    PAN-OS custom-url-category list entry, or '' if it's a plain domain that
    ports cleanly. Faithful — the entry is still emitted verbatim; this only
    flags it for review."""
    e = (entry or "").strip().rstrip("/")
    host = e.split("/", 1)[0]
    if _IPV4.match(host):
        return "IP literal — use an address object + destination match instead"
    if "*" in entry:
        return "wildcard — verify PAN-OS wildcard syntax (e.g. *.example.com)"
    if "/" in e:
        return "path-based URL — only matches over HTTPS with TLS decryption"
    return ""


def _route_dest(raw: str) -> str:
    """Destination CIDR from a Routers 'destination' cell like
    '10.96.63.5 (Management Server)' -> '10.96.63.5/32' (host) or
    '0.0.0.0/0 (Any network)' -> '0.0.0.0/0'. Blank if no IP."""
    token = (raw or "").split(" (", 1)[0].strip()
    if not token:
        return ""
    return token if "/" in token else f"{token}/32"


def _route_nexthop(raw: str) -> str:
    """Next-hop IP from a Routers 'gateway' cell like
    'Core_Switch_10.96.63.17 (10.96.63.17)' -> '10.96.63.17'. Blank if the
    trailing parens don't hold an IPv4 address."""
    m = re.search(r"\(([^)]+)\)\s*$", raw or "")
    val = m.group(1).strip() if m else ""
    return val if _IPV4.match(val) else ""


_NAT_SEG = re.compile(r"^(\w+):(.*?)(?:\s*\((\d*)-(\d*)\))?$")


def _nat_side(cell: str) -> tuple:
    """Parse a NAT_Rules nat_source/nat_destination cell into
    (kind, translated_name, first_port, last_port).

    The cell holds 'kind:ORIGINAL[; kind:TRANSLATED] [ (first-last)]', e.g.
    'static_nat:AdminZone-10.96.14.132; static_nat:HQ-EtisalatePublic-41.65.245.163'
    or 'dynamic_nat:Etisalate_BelleVie_PublicIP (1024-65535)'. The LAST named
    element is the translation target (a single segment names it directly)."""
    kind = name = fp = lp = ""
    for seg in _split(cell):
        m = _NAT_SEG.match(seg)
        if not m:
            continue
        kind = m.group(1)
        if m.group(2).strip():
            name = m.group(2).strip()
        if m.group(3) or m.group(4):
            fp, lp = m.group(3) or "", m.group(4) or ""
    return kind, name, fp, lp


class PaloAltoGenerator:
    def __init__(self, result: ExtractionResult):
        self.r = result
        self.lines: List[str] = []
        self._addr_seen: set[str] = set()      # address object names (sanitized)
        self._addrgrp: set[str] = set()         # address-group names (sanitized)
        self._svc: set[str] = set()             # service object names (sanitized)
        self._svcgrp: set[str] = set()          # service-group names (sanitized)
        self._url_cats: set[str] = set()        # custom-url-category names (sanitized)
        # URL objects (situations) flagged as containing IP/path/wildcard
        # entries -> a Migration_Review row for the rules that use them.
        self._url_review: set[str] = set()      # raw URL-object names needing review
        # Multi-IP Servers rows (engines): (name, [ips]) — become an
        # address-group in address_groups() after their per-IP objects.
        self._server_groups: List[tuple] = []
        # (engine, interface_id) of tunnel interfaces, so nicids like '1004'
        # resolve to tunnel.1004 instead of a nonexistent ethernet port.
        self._tunnel_ids: set[tuple] = {
            (row.get("engine", ""), (row.get("interface_id") or "").strip())
            for row in self._rows("Interfaces") if row.get("kind") == "tunnel"
        }
        # Zone inference (modeled on the customer's zone_assign.py): resolve
        # rule sources/destinations to IPs, match against the zone->subnet
        # table derived from the engine's interfaces + routes.
        # Zone-token recognition uses EVERY zone name in the export
        # (result.zone_names), not the engine-scoped Zones sheet — a rule can
        # name another engine's zone element, which must still be seen as a
        # zone (and mapped to External) rather than an unknown object.
        self._zone_names: set[str] = set(getattr(self.r, "zone_names", None) or ()) or {
            row["name"] for row in self._rows("Zones") if row.get("name")
        }
        self._value_lookup = self._build_value_lookup()
        self._groups_map: Dict[str, List[str]] = {
            row["name"]: _split(row.get("members", ""))
            for row in self._rows("Groups") if row.get("name")
        }
        self._zone_table = self._build_zone_table()  # needs the two above
        # Zones actually bound to interfaces in scope (the selected engine's
        # own zones). Zone tokens outside this set map to External.
        self._scope_zones: set = set(self._zone_of.values())
        # Access_Rules row index -> ('; '-joined from zones, to zones),
        # filled by security_rules and written back onto the sheet as the
        # source_zone / destination_zone columns (attach_review).
        self._zone_cols: Dict[int, tuple] = {}
        # Per-token memo for _zones_for — rules repeat the same objects
        # constantly and resolving groups per rule is wasteful.
        self._token_cache: Dict[str, tuple] = {}
        # Optional fine-grained progress inside security_rules (set by
        # generate() when it has a progress callback).
        self._sect_progress = None

    # ---- zone inference --------------------------------------------------
    def _build_zone_table(self) -> List[tuple]:
        """Auto-derived zone->subnet table, most-specific (longest prefix)
        first. Sources: the network on each addressed interface whose
        physical/VLAN/tunnel parent carries a zone_ref, extended by the
        static routes (a destination routed via an interface belongs to that
        interface's zone). Default routes are skipped on purpose so
        unmatched traffic falls back to the External zone."""
        zone_of: Dict[tuple, str] = {}  # (engine, nicid) -> zone name
        for row in self._rows("Interfaces"):
            zone = (row.get("zone") or "").strip()
            nicid = (row.get("interface_id") or "").strip()
            if zone and nicid:
                zone_of[((row.get("engine") or "").strip(), nicid)] = zone
        self._zone_of = zone_of  # reused by the ZONES section (zone bindings)

        table: List[tuple] = []
        seen: set[tuple] = set()

        def add(zone: str, value: str) -> None:
            try:
                net = ipaddress.ip_network(value.strip(), strict=False)
            except ValueError:
                return
            if net.prefixlen == 0:  # default route -> leave to _FALLBACK_ZONE
                return
            key = (zone, str(net))
            if key not in seen:
                seen.add(key)
                table.append((zone, net))

        for row in self._rows("Interfaces"):
            if row.get("kind") not in ("cvi", "ndi", "single"):
                continue
            engine = (row.get("engine") or "").strip()
            nicid = (row.get("interface_id") or "").strip()
            zone = zone_of.get((engine, nicid))
            network = (row.get("network") or "").strip()
            if zone and network:
                add(zone, network)
        for row in self._rows("Routers"):
            engine = (row.get("engine") or "").strip()
            nicid = (row.get("interface") or "").strip()
            zone = zone_of.get((engine, nicid))
            if not zone:
                continue
            # Resolve the referenced element first (like the customer's
            # zone_assign.py): the destination cell's bare IP has no prefix
            # ('10.96.52.0' for a /24 network), but the named Network object
            # carries the real CIDR.
            cell = row.get("destination", "")
            m = re.search(r"\(([^)]+)\)\s*$", cell)
            resolved = self._resolve_values(m.group(1).strip()) if m else []
            got = False
            for kind, val in resolved:
                if kind == "ip":
                    add(zone, val)
                    got = True
            if not got:
                dest = _route_dest(cell)
                if dest:
                    add(zone, dest)

        table.sort(key=lambda t: t[1].prefixlen, reverse=True)
        return table

    def _build_value_lookup(self) -> Dict[str, List[tuple]]:
        """name -> [(kind, value)] for every addressable element in the
        result. kind: 'ip' (bare IP or CIDR), 'range', 'fqdn'."""
        vals: Dict[str, List[tuple]] = {}

        def put(name: str, kind: str, value: str) -> None:
            if name and value:
                vals.setdefault(name, []).append((kind, value))

        for sheet, col in (("Hosts", "address"), ("Networks", "ipv4_network"),
                           ("Servers", "address"), ("Router_Elements", "address")):
            for row in self._rows(sheet):
                for v in _split(row.get(col, "")):
                    put(row.get("name", ""), "ip", v)
        for row in self._rows("Address_Ranges"):
            for v in _split(row.get("ip_range", "")):
                put(row.get("name", ""), "range", v)
        for row in self._rows("IP_Lists"):
            for v in _split(row.get("ips", "")):
                put(row.get("name", ""), "range" if "-" in v else "ip", v)
        for row in self._rows("Domain_Names"):
            put(row.get("name", ""), "fqdn", row.get("name", ""))
        return vals

    def _resolve_values(self, name: str, visited: set | None = None) -> List[tuple]:
        """Recursively resolve an element name to [(kind, value)]; groups are
        expanded, literal IPs/CIDRs accepted as-is, unknowns -> 'unresolved'."""
        if visited is None:
            visited = set()
        if name in visited:
            return []
        visited.add(name)
        try:
            ipaddress.ip_network(name, strict=False)
            return [("ip", name)]
        except ValueError:
            pass
        if name in self._groups_map:
            out: List[tuple] = []
            for member in self._groups_map[name]:
                out.extend(self._resolve_values(member, visited))
            return out
        if name in self._value_lookup:
            return self._value_lookup[name]
        return [("unresolved", name)]

    def _net_zones(self, net) -> List[str]:
        """Zones for one network. Most-specific-only: the first (longest
        prefix) zone subnet containing it wins. If the net is wider than any
        zone subnet, collect the zones it contains instead."""
        for zone, znet in self._zone_table:
            if net.version == znet.version and net.subnet_of(znet):
                return [zone]
        out: List[str] = []
        for zone, znet in self._zone_table:
            if net.version == znet.version and znet.subnet_of(net):
                if zone not in out:
                    out.append(zone)
        return out

    def _range_zones(self, rng: str) -> List[str]:
        """Zones covering an 'a.b.c.d-a.b.c.e' range (unmatched parts ->
        External). Empty on a malformed range."""
        parts = rng.split("-")
        if len(parts) != 2:
            return []
        try:
            nets = ipaddress.summarize_address_range(
                ipaddress.ip_address(parts[0].strip()),
                ipaddress.ip_address(parts[1].strip()))
        except ValueError:
            return []
        out: List[str] = []
        for net in nets:
            for z in (self._net_zones(net) or [_FALLBACK_ZONE]):
                if z not in out:
                    out.append(z)
        return out

    def _is_zone_token(self, raw: str) -> bool:
        """True if a rule source/destination token is a Forcepoint zone (and
        not shadowed by an address object/group of the same name)."""
        return (raw in self._zone_names
                and pan_name(raw) not in self._addr_seen
                and pan_name(raw) not in self._addrgrp)

    def _token_zones(self, t: str) -> tuple:
        """(zones, nets, comments) for ONE source/destination token, memoized
        — rules reference the same objects over and over."""
        cached = self._token_cache.get(t)
        if cached is not None:
            return cached
        zones: List[str] = []
        nets: List[str] = []
        comments: List[str] = []

        def add_zone(z: str) -> None:
            if z not in zones:
                zones.append(z)

        if self._is_zone_token(t):
            if t in self._scope_zones:  # a zone of the engine(s) in scope
                add_zone(t)
                comments.append(f"{t}: zone element, used directly")
            else:  # another engine's zone — not valid here
                add_zone(_FALLBACK_ZONE)
                comments.append(f"{t}: zone of another engine -> {_FALLBACK_ZONE}")
        else:
            for kind, val in self._resolve_values(t):
                if kind == "ip":
                    try:
                        net = ipaddress.ip_network(val.strip(), strict=False)
                    except ValueError:
                        add_zone(_FALLBACK_ZONE)
                        comments.append(f"{t}: bad address '{val}' -> {_FALLBACK_ZONE}")
                        continue
                    matched = self._net_zones(net) or [_FALLBACK_ZONE]
                    for z in matched:
                        add_zone(z)
                    nets.append(f"{val} -> {', '.join(matched)}")
                elif kind == "range":
                    matched = self._range_zones(val) or [_FALLBACK_ZONE]
                    for z in matched:
                        add_zone(z)
                    nets.append(f"{val} -> {', '.join(matched)}")
                elif kind == "fqdn":
                    add_zone(_FALLBACK_ZONE)
                    comments.append(f"{t}: FQDN -> {_FALLBACK_ZONE}")
                else:  # unresolved
                    add_zone(_FALLBACK_ZONE)
                    comments.append(f"{t}: unresolved -> {_FALLBACK_ZONE}")
        self._token_cache[t] = (zones, nets, comments)
        return self._token_cache[t]

    def _zones_for(self, tokens: List[str]) -> tuple:
        """(zones, nets, comments) for a rule's sources or destinations.
        ANY -> ['any']; zone elements pass through as themselves; everything
        else resolves to IPs and matches the derived table; no match /
        FQDN / unresolved -> External."""
        if not tokens or any(t in _ANY for t in tokens):
            return ["any"], [], []
        zones: List[str] = []
        nets: List[str] = []
        comments: List[str] = []
        for t in tokens:
            t_zones, t_nets, t_comments = self._token_zones(t)
            for z in t_zones:
                if z not in zones:
                    zones.append(z)
            nets.extend(t_nets)
            comments.extend(t_comments)
        if not zones:
            zones = [_FALLBACK_ZONE]
        return zones, nets, comments

    # ---- helpers -------------------------------------------------------
    def _header(self, num: int, title: str) -> None:
        bar = "# " + "=" * 67
        self.lines += [bar, f"# {num}. {title}", bar]

    def _emit(self, line: str) -> None:
        self.lines.append(line)

    def _rows(self, sheet: str):
        if sheet not in self.r.sheets:
            return []
        return self.r.sheets[sheet][1]

    def _ifname(self, engine: str, nicid: str) -> str:
        """The PAN-OS interface name for a Forcepoint nicid on an engine — the
        ONE mapping shared by interface definitions and static-route references.
        Tunnel ids (per the Interfaces sheet) -> 'tunnel.<id>'; dotted ids
        ('6.299') -> VLAN subif on an aggregate link 'ae6.299'; plain ids
        ('3') -> physical 'ethernet1/3'."""
        nicid = (nicid or "").strip()
        if not nicid:
            return ""
        base, _, tag = nicid.partition(".")
        if (engine, base) in self._tunnel_ids:
            return f"tunnel.{base}"
        if tag:
            return f"ae{base}.{tag}"
        return f"ethernet1/{nicid}"

    def _address(self, name: str, kind: str, value: str) -> None:
        """Emit a `set address` line once per unique object name."""
        san = pan_name(name)
        if not san or san in self._addr_seen:
            return
        self._addr_seen.add(san)
        self._emit(f"set address {tok(san)} {kind} {value}")

    # ---- sections ------------------------------------------------------
    def addresses(self) -> None:
        self._header(1, "ADDRESS OBJECTS")
        for row in self._rows("Hosts"):
            addr = (row.get("address") or "").strip()
            if addr:
                kind, val = _ipcmd(addr)
                self._address(row["name"], kind, val)
        for row in self._rows("Networks"):
            net = (row.get("ipv4_network") or "").strip()
            if net:
                self._address(row["name"], "ip-netmask", net)
        for row in self._rows("Address_Ranges"):
            rng = (row.get("ip_range") or "").strip()
            if rng:
                self._address(row["name"], "ip-range", rng)
        for row in self._rows("Domain_Names"):
            self._address(row["name"], "fqdn", tok(row["name"].strip()))
        # IP lists: emit each member as an address (group is created below).
        for row in self._rows("IP_Lists"):
            for ip in _split(row.get("ips", "")):
                kind, val = _ipcmd(ip)
                self._address(ip, kind, val)
        # Servers are referenced as source/destination in rules -> need
        # addresses. Engine rows (server_type='engine') carry the engine's
        # interface-0 CVI address, so they emit as plain objects. Should a
        # cell ever hold several IPs, they become per-IP objects + an
        # address-group under the row's name (ADDRESS GROUPS section).
        for row in self._rows("Servers"):
            vals = _split(row.get("address", ""))
            if not vals:
                continue
            if len(vals) == 1:
                kind, val = _ipcmd(vals[0])
                self._address(row["name"], kind, val)
            else:
                for ip in vals:
                    kind, val = _ipcmd(ip)
                    self._address(ip, kind, val)
                self._server_groups.append((row["name"], vals))
        # Router elements (route next-hops, occasionally used in rules) too.
        for row in self._rows("Router_Elements"):
            addr = (row.get("address") or "").strip()
            if addr:
                kind, val = _ipcmd(addr)
                self._address(row["name"], kind, val)

    def address_groups(self) -> None:
        groups = self._rows("Groups")
        ip_lists = self._rows("IP_Lists")
        if not groups and not ip_lists and not self._server_groups:
            return
        self._header(2, "ADDRESS GROUPS")
        for row in groups:
            members = _split(row.get("members", ""))
            if members:
                self._addrgrp.add(pan_name(row["name"]))
                self._emit(f"set address-group {tok(pan_name(row['name']))} static {_members(members)}")
        for row in ip_lists:
            ips = _split(row.get("ips", ""))
            if ips:
                self._addrgrp.add(pan_name(row["name"]))
                self._emit(f"set address-group {tok(pan_name(row['name']))} static {_members(ips)}")
        # Multi-IP server rows (engines): group under the element's own name.
        for name, ips in self._server_groups:
            san = pan_name(name)
            if san in self._addr_seen or san in self._addrgrp:
                continue  # the name is already a real object
            self._addrgrp.add(san)
            self._emit(f"set address-group {tok(san)} static {_members(ips)}")

    def _group_members(self) -> set[str]:
        """Service names referenced as service-group members (these must be real
        service/service-group objects or PAN-OS rejects the group)."""
        refs: set[str] = set()
        for row in self._rows("Service_Groups"):
            refs.update(_split(row.get("services", "")))
        return refs

    def _rule_services(self) -> set[str]:
        refs: set[str] = set()
        for sheet in ("Access_Rules", "NAT_Rules"):
            for row in self._rows(sheet):
                refs.update(_split(row.get("services", "")))
        return refs

    def services(self) -> None:
        rows = self._rows("Services")
        self._header(3, "SERVICE OBJECTS")
        defined: set[str] = set()  # raw service names that exist as objects
        seen: set[tuple] = set()
        for row in rows:
            name = pan_name(row["name"])
            proto = (row.get("protocol") or "").strip().lower()
            mn = (row.get("min_dst_port") or "").strip()
            mx = (row.get("max_dst_port") or "").strip()
            defined.add(row["name"])
            if not name or proto not in ("tcp", "udp") or not mn:
                continue
            port = mn if (not mx or mx == mn) else f"{mn}-{mx}"
            key = (name, proto, port)
            if key in seen:
                continue
            seen.add(key)
            self._svc.add(name)
            self._emit(f"set service {tok(name)} protocol {proto} port {port}")

        # Auto-create referenced-but-undefined standard predefined services
        # (needed by either groups or rules), so references resolve.
        group_names = {row["name"] for row in self._rows("Service_Groups")}
        referenced = (self._group_members() | self._rule_services()) - defined - group_names - _ANY
        created = []
        for raw in sorted(referenced):
            if raw in _PREDEFINED:
                proto, port = _PREDEFINED[raw]
                self._svc.add(pan_name(raw))
                self._emit(f"set service {tok(pan_name(raw))} protocol {proto} port {port}")
                created.append(raw)
        if created:
            self._emit(f"# (auto-created {len(created)} predefined service(s): {', '.join(created)})")

        # Warn only about service-GROUP members still undefined — those break the
        # group set. (Undefined rule 'services' are usually Forcepoint applications
        # that belong in PAN-OS application field, handled separately.)
        unresolved = sorted(self._group_members() - defined - group_names - set(created) - _ANY)
        if unresolved:
            self._emit("# WARNING: service-group members below are undefined (Forcepoint "
                       "predefined/application services) — create or remap them in PAN-OS,")
            self._emit("# otherwise the containing service-group will be rejected:")
            for u in unresolved:
                self._emit(f"#   {u}")

    def service_groups(self) -> None:
        rows = self._rows("Service_Groups")
        if not rows:
            return
        self._header(4, "SERVICE GROUPS")
        for row in self._topo_sorted(rows):
            members = _split(row.get("services", ""))
            if members:
                self._svcgrp.add(pan_name(row["name"]))
                self._emit(f"set service-group {tok(pan_name(row['name']))} members {_members(members)}")

    @staticmethod
    def _topo_sorted(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Order service-groups so a group is emitted AFTER any service-group it
        contains (nested groups must exist before they're referenced)."""
        by_name = {row["name"]: row for row in rows}
        group_names = set(by_name)
        state: Dict[str, int] = {}  # 0=visiting, 1=done
        order: List[Dict[str, str]] = []

        def visit(name: str) -> None:
            if state.get(name) is not None:
                return  # done or currently visiting (cycle) -> stop
            state[name] = 0
            for member in _split(by_name[name].get("services", "")):
                if member in group_names:
                    visit(member)
            state[name] = 1
            order.append(by_name[name])

        for row in rows:
            visit(row["name"])
        return order

    def url_categories(self) -> None:
        """Emit a PAN-OS custom URL category per Forcepoint url_list_application
        (the URLs sheet). Each becomes:
            set profiles custom-url-category <name> type "URL List"
            set profiles custom-url-category <name> list <url>
        Rules that referenced the situation as a 'service' wire it into their
        `category` field (see security_rules). URL entries are emitted verbatim
        (faithful); IP/path/wildcard entries get a per-entry `# review:` comment
        and put the object into Migration_Review for a human."""
        rows = self._rows("URLs")
        if not rows:
            return
        self._header(5, "URL CATEGORIES (custom-url-category from Forcepoint URL lists)")
        for row in rows:
            raw = row.get("name", "")
            name = pan_urlcat(raw)
            if not name or name in self._url_cats:
                continue
            entries = _split(row.get("urls", ""))
            if not entries:
                continue
            self._url_cats.add(name)
            self._emit(f'set profiles custom-url-category {tok(name)} type "URL List"')
            flagged = False
            for entry in entries:
                self._emit(f"set profiles custom-url-category {tok(name)} list {tok(entry)}")
                issue = _url_entry_issue(entry)
                if issue:
                    self._emit(f"#   review: '{entry}' — {issue}")
                    flagged = True
            if flagged:
                self._url_review.add(raw)

    def tags(self) -> None:
        rows = self._rows("Tags")
        if not rows:
            return
        self._header(6, "TAGS")
        seen: set[str] = set()
        for row in rows:
            label = pan_tag(row.get("comment") or "")
            if not label or label in seen:
                continue
            color = _PAN_COLORS[len(seen) % len(_PAN_COLORS)]
            seen.add(label)
            self._emit(f"set tag {tok(label)} color {color}")

    def _used_zone_names(self) -> set:
        """Every zone name the security/NAT rules will reference as from/to —
        pass-through zone elements and inferred zones (incl. External).
        Warms the per-token cache, so the rule sections reuse the work."""
        used: set = set()
        rule_rows = [r for sheet in ("Access_Rules", "NAT_Rules")
                     for r in self._rows(sheet) if r.get("rule_type") != "comment"]
        for idx, row in enumerate(rule_rows):
            if self._sect_progress and idx % 200 == 0:
                self._sect_progress(idx / len(rule_rows))
            for field in ("sources", "destinations"):
                zones, _, _ = self._zones_for(_split(row.get(field, "")) or ["ANY"])
                used.update(z for z in zones if z != "any")
        return used

    def zones(self) -> None:
        """Emit `set zone` definitions so the rulebase commits: layer3 zones
        with the addressed interfaces bound to them (per the engines'
        zone_refs, limited to interfaces the NETWORK INTERFACES section
        emits), then bare definitions for every other zone the rules
        reference (zone elements used directly and the External fallback) —
        those get their interface bindings on the device."""
        bound: Dict[str, Dict[str, List[str]]] = {}  # engine -> zone -> ifnames
        for row in self._rows("Interfaces"):
            if row.get("kind") != "cvi":
                continue
            engine = (row.get("engine") or "").strip()
            nicid = (row.get("interface_id") or "").strip()
            zone = self._zone_of.get((engine, nicid))
            if zone and nicid:
                ifname = self._ifname(engine, nicid)
                names = bound.setdefault(engine, {}).setdefault(zone, [])
                if ifname not in names:
                    names.append(ifname)
        used = self._used_zone_names()
        if not bound and not used:
            return
        self._header(7, "ZONES")
        bound_names: set = set()
        for engine in sorted(bound):
            self._emit(f"# --- engine: {engine} ---")
            for zone, ifaces in bound[engine].items():
                bound_names.add(pan_zone(zone))
                base = f"set zone {tok(pan_zone(zone))} network layer3"
                self._emit(f"{base} [ {' '.join(ifaces)} ]" if len(ifaces) > 1
                           else f"{base} {ifaces[0]}")
        rest = sorted(z for z in used if pan_zone(z) not in bound_names)
        if rest:
            self._emit("# zones referenced by the rules below with no addressed "
                       "interface here — created empty, bind interfaces on the device:")
            for z in rest:
                self._emit(f"set zone {tok(pan_zone(z))}")

    def security_rules(self) -> None:
        rows = self._rows("Access_Rules")
        if not rows:
            return
        self._header(10, "SECURITY POLICIES")
        section = ""
        for idx, row in enumerate(rows):
            if self._sect_progress and idx % 200 == 0:
                self._sect_progress(idx / len(rows))
            if row.get("rule_type") == "comment":
                section = (row.get("comment") or "").strip()
                if section:
                    self._emit(f"# ===== SECTION: {section} =====")
                continue
            # The policy_name cell already embeds the rule tag
            # ('HQ_Internal_Policy_2101814.0') — used verbatim as the rule name.
            name = pan_name(row.get("policy_name", ""))
            base = f"set rulebase security rules {tok(name)}"

            # Infer from/to zones from the resolved sources/destinations
            # (reported on the Access_Rules sheet as source_zone/destination_zone).
            srcs = _split(row.get("sources", "")) or ["ANY"]
            dsts = _split(row.get("destinations", "")) or ["ANY"]
            src_zones, _, _ = self._zones_for(srcs)
            dst_zones, _, _ = self._zones_for(dsts)
            for z in src_zones:
                self._emit(f"{base} from {'any' if z == 'any' else tok(pan_zone(z))}")
            for z in dst_zones:
                self._emit(f"{base} to {'any' if z == 'any' else tok(pan_zone(z))}")

            # Zone-element tokens are interface zones, not addresses — they
            # go to from/to above and are left out of source/destination.
            src_addrs = [s for s in srcs if not self._is_zone_token(s)]
            for s in src_addrs:
                self._emit(f"{base} source {_ref(s)}")
            if not src_addrs:
                self._emit(f"{base} source any")
            dst_addrs = [d for d in dsts if not self._is_zone_token(d)]
            for d in dst_addrs:
                self._emit(f"{base} destination {_ref(d)}")
            if not dst_addrs:
                self._emit(f"{base} destination any")

            self._zone_cols[idx] = ("; ".join(src_zones), "; ".join(dst_zones))
            # Split the Forcepoint "service" list. URL-list situations become a
            # custom-url-category match (`category` field); the rest split into
            # PAN-OS port-services vs applications (App-ID) as before.
            svcs = _split(row.get("services", ""))
            url_cats = [s for s in svcs if pan_urlcat(s) in self._url_cats]
            rest = [s for s in svcs if s not in url_cats]
            apps = [_APPLICATIONS[s] for s in rest if s in _APPLICATIONS]
            port_svcs = [s for s in rest if s not in _APPLICATIONS and s not in _ANY]
            if not rest or all(s in _ANY for s in rest):
                self._emit(f"{base} service any")
            elif port_svcs:
                for sv in port_svcs:
                    self._emit(f"{base} service {_ref(sv)}")
            else:  # only applications -> let App-ID use its default ports
                self._emit(f"{base} service application-default")
            for uc in dict.fromkeys(pan_urlcat(s) for s in url_cats):
                self._emit(f"{base} category {tok(uc)}")
            for user in _split(row.get("users", "")):
                u = user.split(" (", 1)[0].strip()
                if u:
                    self._emit(f"{base} source-user {tok(pan_name(u))}")

            if apps:
                for a in dict.fromkeys(apps):
                    self._emit(f"{base} application {tok(a)}")
            else:
                self._emit(f"{base} application any")
            action = (row.get("action") or "").strip().lower()
            self._emit(f"{base} action {'deny' if action in _DENY else 'allow'}")
            if (row.get("is_disabled") or "").strip().lower() == "true":
                self._emit(f"{base} disabled yes")
            if section:
                self._emit(f"{base} tag {tok(pan_tag(section))}")

    def nat_rules(self) -> None:
        """Emit `set rulebase nat rules` from the NAT_Rules sheet.

        Mapping (faithful to the Forcepoint cells): dynamic_nat ->
        source-translation dynamic-ip-and-port; static_nat on the source ->
        source-translation static-ip; static_nat on the destination ->
        destination-translation (+ translated-port when the cell carries a
        single port). Rows with no translation are Forcepoint NAT-bypass
        rules — emitted without a translation, which is PAN-OS's no-NAT
        form. PAN-OS NAT takes ONE 'to' zone and ONE service; extra values
        get a WARNING comment (split those rules manually)."""
        rows = [r for r in self._rows("NAT_Rules") if r.get("rule_type") != "comment"]
        if not rows:
            return
        self._header(11, "NAT POLICIES")
        addr_defined = self._addr_seen | self._addrgrp
        for row in rows:
            name = pan_name(f"{row.get('policy_name', '')}_{row.get('rule_id', '')}")
            base = f"set rulebase nat rules {tok(name)}"
            srcs = _split(row.get("sources", "")) or ["ANY"]
            dsts = _split(row.get("destinations", "")) or ["ANY"]
            src_zones, _, _ = self._zones_for(srcs)
            dst_zones, _, _ = self._zones_for(dsts)
            for z in src_zones:
                self._emit(f"{base} from {'any' if z == 'any' else tok(pan_zone(z))}")
            if len(dst_zones) > 1:
                self._emit(f"# WARNING: destination spans several zones "
                           f"({', '.join(dst_zones)}) — PAN-OS NAT takes one "
                           f"'to' zone; using the first, split the rule if needed")
            to = dst_zones[0]
            self._emit(f"{base} to {'any' if to == 'any' else tok(pan_zone(to))}")

            src_addrs = [s for s in srcs if not self._is_zone_token(s)]
            for s in src_addrs:
                self._emit(f"{base} source {_ref(s)}")
            if not src_addrs:
                self._emit(f"{base} source any")
            dst_addrs = [d for d in dsts if not self._is_zone_token(d)]
            for d in dst_addrs:
                self._emit(f"{base} destination {_ref(d)}")
            if not dst_addrs:
                self._emit(f"{base} destination any")

            svcs = [s for s in _split(row.get("services", "")) if s not in _ANY]
            port_svcs = [s for s in svcs if s not in _APPLICATIONS]
            if not port_svcs:
                if svcs:  # only application-type tokens (ICMP etc.)
                    self._emit(f"# WARNING: service(s) {'; '.join(svcs)} are "
                               f"applications — PAN-OS NAT needs a service object; using any")
                self._emit(f"{base} service any")
            else:
                if len(svcs) > 1:
                    self._emit(f"# WARNING: {len(svcs)} services ({'; '.join(svcs)}) — "
                               f"PAN-OS NAT takes one; using the first, split the rule for the rest")
                self._emit(f"{base} service {_ref(port_svcs[0])}")

            skind, sname, _sfp, _slp = _nat_side(row.get("nat_source", ""))
            if sname:
                if pan_name(sname) not in addr_defined:
                    self._emit(f"# WARNING: translated address '{sname}' is not an "
                               f"exported address object — create it (see Migration_Review)")
                mode = ("dynamic-ip-and-port" if skind == "dynamic_nat" else "static-ip")
                self._emit(f"{base} source-translation {mode} "
                           f"translated-address {tok(pan_name(sname))}")
            dkind, dname, dfp, dlp = _nat_side(row.get("nat_destination", ""))
            if dname:
                if pan_name(dname) not in addr_defined:
                    self._emit(f"# WARNING: translated address '{dname}' is not an "
                               f"exported address object — create it (see Migration_Review)")
                self._emit(f"{base} destination-translation "
                           f"translated-address {tok(pan_name(dname))}")
                if dfp and dfp == dlp:
                    self._emit(f"{base} destination-translation translated-port {dfp}")
                elif dfp or dlp:
                    self._emit(f"# WARNING: destination port range {dfp}-{dlp} — "
                               f"PAN-OS translated-port takes one port; set manually")
            if not sname and not dname:
                self._emit(f"# (no translation — Forcepoint NAT-bypass rule; "
                           f"keep it ABOVE translating rules)")
            if (row.get("is_disabled") or "").strip().lower() == "true":
                self._emit(f"{base} disabled yes")

    def network_interfaces(self) -> None:
        """Emit `set network interface` lines from the Interfaces sheet.

        Only addressed cluster interfaces (kind=cvi) carry an IP. Names come
        from _ifname(): dotted interface_id ('6.299') -> VLAN sub-interface on
        an aggregate link (ae6 unit ae6.299 tag 299), plain id ('3') ->
        physical ethernet1/3, tunnel ids -> tunnel.<id>. The netmask comes
        from the 'network' column (PAN-OS requires it). Rows are grouped
        under an engine comment so a multi-engine export stays attributable."""
        rows = [r for r in self._rows("Interfaces") if r.get("kind") == "cvi"]
        if not rows:
            return
        self._header(8, "NETWORK INTERFACES")
        last_engine = None
        for row in rows:
            engine = (row.get("engine") or "").strip()
            iface_id = (row.get("interface_id") or "").strip()
            if not iface_id:
                continue
            if engine != last_engine:
                self._emit(f"# --- engine: {engine} ---")
                last_engine = engine
            ifname = self._ifname(engine, iface_id)
            network = (row.get("network") or "").strip()
            mask = network.split("/", 1)[1] if "/" in network else ""
            if not mask:
                self._emit(f"# WARNING: no netmask on {engine} interface {iface_id} "
                           f"— PAN-OS needs ip/<len>; fix the line(s) below manually")
            for ip in _split(row.get("ip_address", "")):
                ipm = f"{ip}/{mask}" if mask else ip
                if ifname.startswith("tunnel."):
                    self._emit(f"set network interface tunnel units {ifname} ip {ipm}")
                elif "." in ifname:
                    parent, tag = ifname.rsplit(".", 1)
                    self._emit(
                        f"set network interface aggregate-ethernet {parent} layer3 "
                        f"units {ifname} tag {tag} ip {ipm}"
                    )
                else:
                    self._emit(
                        f"set network interface ethernet {ifname} layer3 ip {ipm}"
                    )

    def _iface_networks(self) -> Dict[tuple, list]:
        """(engine, nicid) -> [ip_network] the interface is directly attached to,
        from the Interfaces 'network' column. Used to detect connected routes."""
        nets: Dict[tuple, list] = {}
        for row in self._rows("Interfaces"):
            engine = (row.get("engine") or "").strip()
            nicid = (row.get("interface_id") or "").strip()
            network = (row.get("network") or "").strip()
            if not nicid or not network:
                continue
            try:
                net = ipaddress.ip_network(network, strict=False)
            except ValueError:
                continue
            nets.setdefault((engine, nicid), []).append(net)
        return nets

    @staticmethod
    def _connected_net(dest: str, iface_nets):
        """Return the interface subnet that directly contains `dest` (making it a
        connected route), else None. `dest` is connected when it equals or is a
        subnet of one of the interface's own attached networks — the interface
        already has an IP in that subnet, so PAN-OS auto-installs the route.
        A destination BROADER than the interface subnet (a default route or a
        summary) is NOT connected and stays as a static route."""
        try:
            dn = ipaddress.ip_network(dest, strict=False)
        except ValueError:
            return None
        for ifn in iface_nets:
            if dn.version == ifn.version and (dn == ifn or dn.subnet_of(ifn)):
                return ifn
        return None

    def virtual_routers(self) -> None:
        """Emit `set network virtual-router ... static-route` lines from the
        Routers sheet (the engine's Forcepoint static routing table).

        VR name = <engine>-VR (underscores -> dashes, matching the customer
        reference; capped at PAN-OS's 31-char VR limit). Routes numbered
        static-route-N per VR. Destination host routes get /32; next-hop comes
        from the gateway IP (routes via tunnels have none); the interface name
        comes from _ifname(), matching network_interfaces().

        Per VR we first emit a single aggregate `interface [ ... ]` line listing
        every interface its static routes bind to, then ONE line per route with
        destination, interface and nexthop ip-address (omitted for tunnel routes)
        all combined (they are sibling leaves under the same static-route node).

        CONNECTED routes are skipped: if the destination is within the route
        interface's own attached subnet (the interface already has an IP there),
        PAN-OS installs the connected route from the interface config, so a
        static route would be redundant. The interface is still bound to the VR
        and a `# connected route skipped ...` comment records the drop."""
        rows = self._rows("Routers")
        if not rows:
            return
        self._header(9, "VIRTUAL ROUTERS (static routes)")
        iface_nets = self._iface_networks()   # (engine, nicid) -> [ip_network]
        # Group routes by VR so the aggregate interface line can precede them.
        vr_order: List[str] = []
        vr_routes: Dict[str, list] = {}
        vr_ifaces: Dict[str, list] = {}    # ordered-unique interfaces per VR
        vr_skipped: Dict[str, list] = {}   # connected routes dropped, for comments
        for row in rows:
            engine = (row.get("engine") or "").strip()
            dest = _route_dest(row.get("destination", ""))
            if not engine or not dest:
                continue
            name = pan_name(engine).replace("_", "-")
            vr = name[:_MAX_VR - 3].rstrip("-") + "-VR"
            if vr not in vr_routes:
                vr_order.append(vr)
                vr_routes[vr] = []
            nicid = (row.get("interface") or "").strip()
            ifname = self._ifname(engine, nicid)
            # The interface stays bound to the VR even for connected routes,
            # so the auto-installed connected route actually has a nexthop iface.
            if ifname:
                ifaces = vr_ifaces.setdefault(vr, [])
                if ifname not in ifaces:
                    ifaces.append(ifname)
            connected = self._connected_net(dest, iface_nets.get((engine, nicid), ()))
            if connected is not None:
                vr_skipped.setdefault(vr, []).append((dest, ifname, str(connected)))
                continue
            nexthop = _route_nexthop(row.get("gateway", ""))
            vr_routes[vr].append((dest, nexthop, ifname))
        for vr in vr_order:
            ifaces = vr_ifaces.get(vr, [])
            if ifaces:
                self._emit(f"set network virtual-router {tok(vr)} "
                           f"interface [ {' '.join(ifaces)} ]")
            for dest, ifname, ifn in vr_skipped.get(vr, []):
                on = f" (on {ifname})" if ifname else ""
                self._emit(f"# connected route skipped — {dest} is within "
                           f"interface subnet {ifn}{on}; PAN-OS auto-creates it")
            for n, (dest, nexthop, ifname) in enumerate(vr_routes.get(vr, []), 1):
                base = (f"set network virtual-router {tok(vr)} routing-table ip "
                        f"static-route static-route-{n}")
                line = f"{base} destination {dest}"
                if ifname:
                    line += f" interface {ifname}"
                if nexthop:
                    line += f" nexthop ip-address {nexthop}"
                self._emit(line)

    # Human-readable reason per unresolved-reference category.
    _REASON = {
        "engine": "engine/firewall used as a match but it has no interface IPs in this "
                  "scope — create an address object for it or rework the rule",
        "expression": "Forcepoint expression/dynamic object — map to a PAN-OS address-group or EDL",
        "identity": "undefined source/destination — likely an AD user (use source-user) or a "
                    "missing object/zone",
        "service": "undefined service — add to the predefined/application map or create it manually",
        "url": "custom URL category (Forcepoint URL list) — created as a "
               "custom-url-category and matched via the rule's category field, but it "
               "has IP/path/wildcard entries; verify them (see the URLs sheet)",
        "nat": "NAT translation target is not an exported address object (often a "
               "multilink/netlink element) — create the address in PAN-OS",
        "zone": "zone element bound to ANOTHER engine used in the rule — mapped to "
                "'External' in from/to; remap to the right local zone manually",
    }

    def _scan_unresolved(self):
        """Yield (rule, field, ref, category) for every rule reference that
        won't resolve to a PAN-OS object. Call after generate() so the defined-name
        sets are populated."""
        addr_defined = self._addr_seen | self._addrgrp
        svc_defined = self._svc | self._svcgrp
        engines = set(self.r.engines)
        expr_names = {row["name"] for row in self._rows("Expressions")}
        for sheet in ("Access_Rules", "NAT_Rules"):
            for row in self._rows(sheet):
                rule = pan_name(row.get("policy_name", ""))
                if sheet == "NAT_Rules":  # NAT policy_name has no embedded tag
                    rid = (row.get("rule_id") or "").strip()
                    if rid:
                        rule = pan_name(f"{row.get('policy_name', '')}_{rid}")
                for field in ("sources", "destinations"):
                    for raw in _split(row.get(field, "")):
                        if raw in _ANY or pan_name(raw) in addr_defined:
                            continue
                        if self._is_zone_token(raw):
                            if raw not in self._scope_zones:
                                yield rule, field, raw, "zone"
                            continue  # in scope -> assigned as from/to zone
                        cat = ("engine" if raw in engines else
                               "expression" if raw in expr_names else "identity")
                        yield rule, field, raw, cat
                for raw in _split(row.get("services", "")):
                    if raw in _ANY or raw in _APPLICATIONS or pan_name(raw) in svc_defined:
                        continue
                    if pan_urlcat(raw) in self._url_cats:
                        # Now a custom-url-category; only flag it if some of its
                        # entries (IP/path/wildcard) need a human.
                        if raw in self._url_review:
                            yield rule, "service", raw, "url"
                        continue
                    yield rule, "service", raw, "service"
                if sheet == "NAT_Rules":
                    for cell in (row.get("nat_source", ""), row.get("nat_destination", "")):
                        _kind, nm, _fp, _lp = _nat_side(cell)
                        if nm and pan_name(nm) not in addr_defined:
                            yield rule, "nat", nm, "nat"

    def review_rows(self) -> List[Dict[str, str]]:
        """Per-rule review rows {rule_name, note} — one row per (rule, ref)."""
        agg: Dict[tuple, list] = {}  # (rule, ref) -> [category, {fields}]
        for rule, field, ref, cat in self._scan_unresolved():
            entry = agg.setdefault((rule, ref), [cat, set()])
            entry[1].add(field)
        rows: List[Dict[str, str]] = []
        for (rule, ref), (cat, fields) in sorted(agg.items()):
            where = "service" if cat == "service" else "/".join(sorted(fields))
            note = f"'{ref}' [{where}] — {self._REASON[cat]}"
            rows.append({"rule_name": rule, "note": note})
        return rows

    def review(self) -> None:
        """Append the review as a comment block in the CLI text too."""
        cats: Dict[str, set] = {}
        for _rule, _field, ref, cat in self._scan_unresolved():
            cats.setdefault(cat, set()).add(ref)
        if not cats:
            return
        self._header(12, "REVIEW — references needing manual handling (see Migration_Review sheet)")
        titles = {"engine": "ENGINES used as source/destination",
                  "expression": "EXPRESSIONS / dynamic objects",
                  "identity": "IDENTITY / other undefined source-dest",
                  "service": "UNDEFINED services",
                  "url": "URL CATEGORIES with IP/path/wildcard entries to verify",
                  "nat": "NAT translation targets missing as address objects",
                  "zone": "ZONES of other engines used in rules (mapped to External)"}
        for cat in ("engine", "expression", "identity", "service", "url", "nat", "zone"):
            items = cats.get(cat)
            if not items:
                continue
            self._emit(f"# {titles[cat]} ({len(items)}) — {self._REASON[cat]}")
            for it in sorted(items):
                self._emit(f"#   {it}")

    # ---- driver --------------------------------------------------------
    def generate(self, progress=None) -> str:
        """Build the full CLI text. ``progress`` is an optional callback
        ``(pct: int, stage: str)`` reporting each section (used by the web
        UI's progress bar)."""
        steps = [
            (self.addresses, "Address objects"),
            (self.address_groups, "Address groups"),
            (self.services, "Service objects"),
            (self.service_groups, "Service groups"),
            (self.url_categories, "URL categories"),
            (self.tags, "Tags"),
            (self.zones, "Zones"),
            (self.network_interfaces, "Network interfaces"),
            (self.virtual_routers, "Virtual routers"),
            (self.security_rules, "Security policies"),
            (self.nat_rules, "NAT policies"),
            (self.review, "Review"),
        ]
        for i, (fn, label) in enumerate(steps):
            lo, hi = int(i * 100 / len(steps)), int((i + 1) * 100 / len(steps))
            if progress:
                progress(lo, label)
                # Long sections (security_rules) report per-rule progress
                # inside their own percentage span.
                self._sect_progress = (
                    lambda frac, lo=lo, hi=hi, label=label:
                        progress(int(lo + (hi - lo) * frac), label))
            fn()
            self._sect_progress = None
        if progress:
            progress(100, "Done")
        return "\n".join(self.lines) + "\n"


def generate_panos(result: ExtractionResult, progress=None) -> str:
    """Return PAN-OS `set` CLI text for the given (optionally filtered) result."""
    return PaloAltoGenerator(result).generate(progress)


REVIEW_SHEET = "Migration_Review"
REVIEW_COLUMNS = ["rule_name", "note"]


def _attach_zone_columns(result: ExtractionResult, gen: PaloAltoGenerator) -> None:
    """Write the inferred zones back onto the Access_Rules sheet as
    source_zone / destination_zone columns (next to sources/destinations).
    Rows are copied — filtered views share row dicts with the full result."""
    if "Access_Rules" not in result.sheets:
        return
    cols, rows = result.sheets["Access_Rules"]
    new_cols = list(cols)
    for col, after in (("source_zone", "sources"), ("destination_zone", "destinations")):
        if col not in new_cols:
            new_cols.insert(new_cols.index(after) + 1, col)
    new_rows = []
    for idx, row in enumerate(rows):
        src_zone, dst_zone = gen._zone_cols.get(idx, ("", ""))
        new_rows.append(dict(row, source_zone=src_zone, destination_zone=dst_zone))
    result.sheets["Access_Rules"] = (new_cols, new_rows)
    result.counts["Access_Rules"] = len(new_rows)


def attach_zones(result: ExtractionResult,
                 gen: PaloAltoGenerator | None = None,
                 progress=None) -> None:
    """Attach ONLY the Access_Rules source_zone / destination_zone columns
    (the inferred PAN-OS zones), WITHOUT the Migration_Review sheet. Used by
    the plain XML -> Excel path — the review is a Palo Alto migration artifact
    and belongs only to the 'Migrate to Palo Alto' output."""
    if gen is None:
        gen = PaloAltoGenerator(result)
        gen.generate(progress)
    _attach_zone_columns(result, gen)


def attach_review(result: ExtractionResult,
                  gen: PaloAltoGenerator | None = None,
                  progress=None) -> List[Dict[str, str]]:
    """Compute the migration review sheet and the per-rule zone columns and
    attach them to ``result``. Pass an already-generated ``gen`` to reuse its
    pass (the CLI does); otherwise one is run here (``progress`` is forwarded
    to it). Returns the review rows."""
    if gen is None:
        gen = PaloAltoGenerator(result)
        gen.generate(progress)  # populates the defined-name sets used by the review
    rows = gen.review_rows()
    result.sheets[REVIEW_SHEET] = (REVIEW_COLUMNS, rows)
    result.counts[REVIEW_SHEET] = len(rows)
    _attach_zone_columns(result, gen)
    return rows
