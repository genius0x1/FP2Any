# Phase 0 — Forcepoint XML Structure Analysis & Mapping

Source samples analysed:

| File | DTD version | build | update_pkg | distinct top-level types |
|---|---|---|---|---|
| `aic_exported_data.xml`   | `generic_import_export_v6.10.dtd` | 11163 | 1507 | 32 |
| `emaar_exported_data.xml` | `generic_import_export_v7.2.dtd`  | 11590 | 2031 | 38 |

## 0. Global facts
- **Root element:** `<generic_import_export build="…" update_package_version="…">`.
- **No XML namespaces.** Plain tags → `xml.etree.ElementTree` is sufficient.
- **Flat layout:** every object is a *direct child* of the root; the **tag name = object type**.
- **Identity:** every object has `db_key` (numeric, unique) and almost always `name`.
- **Cross-references point to `name`, not `db_key`.** e.g. `<ne_list ref="EHG2"/>`,
  `<service_ref ref="CM-Phone-tcp"/>`, `<expression_value ne_ref="private-10.0.0.0/8"/>`.
  Each carries a `class_id` (Forcepoint element-type id). **Keep raw — do not resolve/rename.**
- **Version drift is real** (see §3). Parsers must key off a *set* of tag names per role and
  tolerate missing attributes (graceful degradation, per plan Phase 5).

## 1. Sheet ↔ XML element mapping

| Excel Sheet | XML tag(s) | Key columns (raw attribs) | Notes |
|---|---|---|---|
| `Hosts` | `host` | name, db_key, comment, address (`mvia_address/@address`) | `secondary`, `category_ref` children exist in v6.10 |
| `Networks` | `network` | name, db_key, comment, ipv4_network, broadcast | |
| `Address_Ranges` | `address_range` | name, db_key, ip_range | |
| `Domain_Names` | `domain_name` | name, db_key, comment | v7.2 may add `domain_name_entry` child |
| `Zones` | `interface_zone` | name, db_key, comment | |
| `Routers` | `router` | name, db_key, comment, address (`mvia_address/@address`) | |
| `IP_Lists` | `ip_list` | name, db_key, type, hidden, ips (join of `ip/@value`) | |
| `Groups` | `group` | name, db_key, is_monitored, members (join of `ne_list/@ref`) | members reference by name |
| `Service_Groups` | `gen_service_group` | name, db_key, comment, services (join of `service_ref/@ref`) | |
| `Expressions` | `expression`, `match_expression` | name, db_key, operator, members | `expression_value` nests recursively; `match_element_entry` is flat |
| `Services` | `service_tcp`, `service_udp` (+ `service_*`) | name, db_key, comment, protocol, min/max src+dst port | split TCP/UDP or one sheet w/ `protocol` col |
| `Engines` | `master_engine`, `virtual_fw`, `fw_cluster`, `fw_single` | name, db_key, type(tag), + many engine attribs | **version-dependent tag set** (see §3) |
| `Policies` | `fw_policy`, `inspection_template_policy`, `file_filtering_policy` | name, db_key, *_policy_ref columns, access/nat rule counts | policy-level overview row |
| `Access_Rules` | `fw_policy/access_entry/rule_entry` (+ `ipv6_access_entry`) | policy_name, rule_id, rank, sources, destinations, services, users, action, vpn, deep_inspection, decrypting, log_level, tag | **one row per firewall rule** — the rulebase; faithful object names |
| `NAT_Rules` | `fw_policy/nat_entry/rule_entry` (+ `ipv6_nat_entry`) | policy_name, rule_id, rank, sources, destinations, services, action, nat_source, nat_destination, valid_engine, log_level | one row per NAT rule incl. translation (`dynamic_nat:NE (ports)`) |
| `Servers` | `dhcp_server`, `log_server`, `mgt_server`, `active_directory_server`, `ntp_server`, `smtp_server`, `icap_server`, `user_id_service`, `snmp_agent` | name, db_key, type(tag), address | heterogeneous; common cols = name/db_key/type/address |
| `Other_Elements` | everything else (see §2) | name, db_key, type(tag) | catch-all; revisit if a type proves important |

## 2. Full element inventory (union of both files)

`aic`-only, `emaar`-only, or both — and proposed sheet:

| tag | aic | emaar | sheet |
|---|---|---|---|
| host | 374 | 406 | Hosts |
| network | 125 | 350 | Networks |
| address_range | 25 | 7 | Address_Ranges |
| domain_name | 12 | 26 | Domain_Names |
| interface_zone | 31 | 39 | Zones |
| router | 5 | 25 | Routers |
| ip_list | 5 | 3 | IP_Lists |
| group | 12 | 9 | Groups |
| gen_service_group | 18 | 17 | Service_Groups |
| expression | 2 | 1 | Expressions |
| match_expression | 8 | 632 | Expressions |
| service_tcp | 194 | 313 | Services |
| service_udp | 58 | 72 | Services |
| master_engine | 1 | – | Engines |
| virtual_fw | 1 | – | Engines |
| fw_cluster | – | 3 | Engines |
| fw_single | – | 1 | Engines |
| fw_policy | 1 | 1 | Policies |
| inspection_template_policy | – | 1 | Policies |
| file_filtering_policy | – | 1 | Policies |
| dhcp_server | 4 | 5 | Servers |
| log_server | 2 | 2 | Servers |
| mgt_server | 2 | 2 | Servers |
| active_directory_server | 1 | 1 | Servers |
| ntp_server | – | 1 | Servers |
| smtp_server | – | 1 | Servers |
| icap_server | – | 1 | Servers |
| user_id_service | – | 1 | Servers |
| snmp_agent | – | 1 | Servers |
| certificate | 1 | 4 | Other_Elements |
| certificate_authority | 4 | 3 | Other_Elements |
| tls_certificate_authority | – | 1 | Other_Elements |
| netlink | 2 | 6 | Other_Elements |
| outbound_multilink | 1 | – | Other_Elements |
| server_pool | 1 | – | Other_Elements |
| situation | – | 11 | Other_Elements |
| vpn | 1 | – | Other_Elements |
| vpn_profile | 1 | – | Other_Elements |
| client_gateway | 1 | – | Other_Elements |
| category | 1 | – | Other_Elements |
| admin_domain | 1 | – | Other_Elements |
| internal_user_domain | 1 | – | Other_Elements |
| external_ldap_user_domain | 1 | 1 | Other_Elements |
| location | – | 2 | Other_Elements |
| qos_class | – | 1 | Other_Elements |
| logging_profile | – | 1 | Other_Elements |
| tls_profile | – | 1 | Other_Elements |
| tls_cryptography_suite_set | – | 1 | Other_Elements |

## 3. Version differences (v6.10 vs v7.2) — must handle
- **Engine tag set differs:** v6.10 = `master_engine`, `virtual_fw`; v7.2 = `fw_cluster`, `fw_single`.
  → `Engines` parser must accept all four (and unknown future engine tags by pattern).
- **`service_udp`** gains `max_src_port`/`min_src_port` in v7.2.
- **`category_ref` children** decorate many NE objects in v6.10; largely absent in v7.2.
- **`location_ref`** appears on servers/engines only in v7.2.
- **`*_ref_key`** companion attributes appear inconsistently → keep the `*_ref` (name) value.
- Many v7.2-only object types (`situation`, `location`, `snmp_agent`, `tls_*`, `icap_server`, …)
  → land in `Other_Elements` until prioritised.

## 4. Reference / child-element shapes (for member columns)
- `group/ne_list` → `@ref` (member name), `@class_id`.
- `gen_service_group/service_ref` → `@ref` (service name), `@class_id`.
- `match_expression/match_element_entry` → `@ref`, `@class_id`, sometimes `@ref_key`.
- `expression/expression_value` → **recursive tree**; leaves carry `@ne_ref`, branches carry `@operator`.
  For raw extraction: flatten all descendant `@ne_ref` values + record top-level `@operator`.
- `ip_list/ip` → `@value`.
- `host/mvia_address`, `router/mvia_address`, `*_server/mvia_address` → `@address`.

## 5. Decisions for Phase 1
1. Parser engine: `xml.etree.ElementTree` (no namespaces). `lxml` optional, not needed.
2. One parser module per role; each emits `List[Dict]` with a fixed column order.
3. Multi-value children → join into a single cell (e.g. `"; "`-separated) — faithful, no transform.
4. Unknown tags → routed to `Other_Elements` and logged (Phase 5 graceful degradation).
5. No normalization anywhere: values copied verbatim incl. trailing spaces / Arabic / special chars.
