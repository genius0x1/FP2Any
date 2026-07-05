# FP2Any

**FP2Any** ("Forcepoint → Any") extracts the configuration from a **Forcepoint
firewall** `exported.xml` file and turns it into two migration-ready artifacts:

1. A **structured Excel workbook** — one sheet per element type (Hosts, Networks,
   Zones, Services, Policies/rules, NAT, Interfaces, Routers, …), a **faithful 1:1
   copy** of what's in the Forcepoint export (no renaming, no reformatting, no unit
   conversion — values are kept verbatim).
2. A **Palo Alto PAN-OS `set` CLI** script — addresses, groups, services, URL
   categories, tags, zones, network interfaces, virtual routers (static routes),
   security policies and NAT policies — generated as a starting point for migrating
   the firewall to Palo Alto.

It ships with both a **command-line interface** and a **web GUI** (upload → pick
scope → download).

> **FortiGate** output is planned for a later phase and is not available yet.

> ⚠️ **This is a migration *aid*, not an automated migration.** The Excel export is
> a source-of-truth reference; the PAN-OS CLI is a best-effort translation (zones
> and some services are inferred) and **must be reviewed before applying to any
> device**. FP2Any never contacts a firewall — it only reads the XML you give it.

---

## Features

- **Faithful extraction** of Forcepoint network elements, policies, NAT rules,
  interfaces, routers, zones and more into named Excel sheets, with a `Summary`
  sheet (element counts, source filename, timestamp).
- **Scoping filters** — extract everything, or narrow to a single firewall
  **policy** (`-p`) and/or **engine** (`-e`); objects are trimmed to only what the
  selected rules/routes actually reference (groups resolved transitively).
- **PAN-OS `set` CLI generation** (`--panos`) with a `Migration_Review` sheet that
  flags anything a human needs to resolve. Connected routes are detected and left
  for PAN-OS to auto-create; default routes and summaries are preserved.
- **Web GUI** — drag-and-drop upload, live policy/engine scope with rule/interface
  counts, in-browser sheet preview with search, and one-click downloads.
- **Graceful degradation** — an unexpected/newer Forcepoint version still produces
  what it can and reports unknown tags rather than failing outright.

---

## Requirements

- **Python 3.10+**
- Dependencies (installed via `requirements.txt`):
  - `openpyxl` — Excel generation
  - `fastapi`, `uvicorn[standard]`, `python-multipart`, `jinja2` — web interface
  - `pytest` — tests

---

## Installation

```bash
# 1. Clone
git clone <your-repo-url> fp2any
cd fp2any

# 2. Create and activate a virtual environment
python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# macOS / Linux:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

Then place a Forcepoint `exported.xml` in the project folder (for the CLI) or
upload it through the web GUI.

---

## Usage

### Command line

Run as a module: `python -m fp2any.cli <input.xml> [options]`.

**1. Discover what's in the export first**

```bash
python -m fp2any.cli exported.xml --list-policies   # firewall policies
python -m fp2any.cli exported.xml --list-engines    # engines / clusters
```

**2. Full extraction to Excel** (writes `<input>.xlsx` next to the input)

```bash
python -m fp2any.cli exported.xml
python -m fp2any.cli exported.xml -o output.xlsx    # custom output path
```

**3. Scope to a policy and/or engine**

```bash
# One policy: its rules + only the objects those rules use
python -m fp2any.cli exported.xml -p "HQ_Internal_Policy"

# One engine: infra sheets (Interfaces/Routers/Zones) scoped to it
python -m fp2any.cli exported.xml -e "HQ-Internal_FW"

# Both together — the usual migration run
python -m fp2any.cli exported.xml -p "HQ_Internal_Policy" -e "HQ-Internal_FW"

# Drop a dimension with 'none' (e.g. engine data only, no rule sheets)
python -m fp2any.cli exported.xml -p none -e "HQ-Internal_FW"
```

**4. Also generate the Palo Alto PAN-OS CLI**

```bash
# Writes both the .xlsx (with a Migration_Review sheet) and <input>[_<policy>]_panos.txt
python -m fp2any.cli exported.xml -p "HQ-External-Policy" -e "HQ-External_FW" --panos

# Custom PAN-OS filename
python -m fp2any.cli exported.xml -p "HQ-External-Policy" -e "HQ-External_FW" --panos "hq_external_panos.txt"
```

Add `-v` for verbose parser logging. If writing the `.xlsx` fails with a
permission error, the file is probably open in Excel — close it or use `-o`.

Run `python -m fp2any.cli --help` for the full list of options.

### Web GUI

```bash
python -m web.app
# or, with auto-reload during development:
uvicorn web.app:app --reload
```

Open **http://127.0.0.1:8000**, then:

1. Upload a Forcepoint `exported.xml`.
2. Pick the **policy / engine scope** (dropdowns show live rule/interface counts).
3. Choose an operation:
   - **XML to Excel** — browse every sheet in the browser and download the workbook.
   - **Migrate to Palo Alto** — view the PAN-OS CLI and download the `.txt`, plus a
     separate Migration Review workbook.
   - **Migrate to FortiGate** — placeholder (coming soon).

Every operation is stateless: upload → process → download. Nothing is stored server-side.

---

## Output sheets

| Sheet | Contents |
|---|---|
| `Summary` | Element counts, source filename, conversion timestamp |
| `Hosts`, `Networks`, `Address_Ranges`, `Domain_Names`, `IP_Lists` | Network address objects |
| `Groups`, `Service_Groups` | Object groups (members kept as-is) |
| `Services` | Service / protocol-port definitions |
| `URLs` | Custom URL-list objects |
| `Expressions` | Forcepoint expressions / dynamic objects |
| `Zones`, `Interfaces`, `Routers`, `Router_Elements` | Engine infrastructure |
| `Engines`, `Servers` | Firewall engines and server elements |
| `Policies`, `Access_Rules`, `NAT_Rules`, `Tags` | The firewall rulebase (one row per rule) |
| `Migration_Review` | *(PAN-OS runs only)* items needing manual review |

---

## Project structure

```
fp2any/            # extraction engine (parsers, extractor, Excel writer)
  parsers/         # one parser per element type
  extractor.py     # orchestrates parsing + policy/engine filtering
  excel_writer.py  # builds the .xlsx workbook
  cli.py           # command-line entry point
migration/
  paloalto.py      # PAN-OS `set` CLI generator + Migration_Review
web/
  app.py           # FastAPI web interface
  templates/       # Jinja2 HTML
  static/          # CSS + vendor logos
requirements.txt
```

---

## Notes on privacy

Forcepoint exports contain your organisation's real firewall configuration. The
included [`.gitignore`](.gitignore) excludes all `*.xml` inputs, generated `*.xlsx`
workbooks, `*_panos.txt` CLI files and logs so they are **never committed**. Keep it
that way — don't force-add exported configs to the repository.

---

## Roadmap

- [x] Faithful XML → Excel extraction (all element types)
- [x] Policy / engine scoping filters
- [x] Web GUI
- [x] Palo Alto PAN-OS `set` CLI generation + Migration Review
- [ ] Palo Alto App-ID mapping for predefined-application services
- [ ] FortiGate (FortiOS) CLI generation

---

## License

No license is set yet. Until one is added, all rights are reserved by the author —
add a `LICENSE` file (e.g. MIT) before sharing publicly if you intend others to reuse it.
