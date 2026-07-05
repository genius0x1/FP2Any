# FP2Any

**FP2Any** ("Forcepoint → Any") reads a **Forcepoint firewall** `exported.xml` and
turns it into:

1. A **structured Excel workbook** — one sheet per element type (Hosts, Networks,
   Zones, Services, Policies, NAT, Interfaces, Routers, …), a faithful 1:1 copy of
   the export.
2. A **Palo Alto PAN-OS `set` CLI** script — a starting point for migrating the
   firewall to Palo Alto.

Available as a **command-line tool** and a **web GUI**. (FortiGate output is planned.)

> ⚠️ A migration *aid*, not an automated migration — review the PAN-OS CLI before
> applying it to any device. FP2Any only reads the XML you give it.

## Requirements

- Python 3.10+
- Dependencies in `requirements.txt` (`openpyxl`, `fastapi`, `uvicorn`, `jinja2`, …)

## Installation

```bash
git clone https://github.com/genius0x1/FP2Any.git
cd FP2Any
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1   |   macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Command line

```bash
# See what's in the export
python -m fp2any.cli exported.xml --list-policies
python -m fp2any.cli exported.xml --list-engines

# Extract to Excel (writes <input>.xlsx)
python -m fp2any.cli exported.xml

# Scope to a policy and/or engine
python -m fp2any.cli exported.xml -p "HQ_Internal_Policy" -e "HQ-Internal_FW"

# Also generate the Palo Alto PAN-OS CLI
python -m fp2any.cli exported.xml -p "HQ-External-Policy" -e "HQ-External_FW" --panos
```

Run `python -m fp2any.cli --help` for all options.

### Web GUI

```bash
python -m web.app
```

Open **http://127.0.0.1:8000**, upload the XML, pick the policy/engine scope, then
generate the Excel workbook or the Palo Alto CLI. Stateless: upload → process →
download.

## Owner & Credits

**Ahmed Abdelslam**

- LinkedIn: https://www.linkedin.com/in/ahmed-abdelslam-845796238/
- WhatsApp: +201055001264
