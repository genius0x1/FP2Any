"""Command-line entry: convert a Forcepoint XML to Excel.

Usage:
    python -m fp2any.cli input.xml [-o output.xlsx]
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys

from .extractor import FP2AnyExtractor, filter_result, NONE
from .excel_writer import write_excel


def _norm_filter(value: str | None) -> str | None:
    """Map the literal 'none' (any case) to the NONE sentinel."""
    if value and value.strip().lower() == "none":
        return NONE
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Forcepoint XML -> Excel extractor")
    parser.add_argument("input", help="Path to Forcepoint exported .xml")
    parser.add_argument("-o", "--output", help="Output .xlsx path")
    parser.add_argument(
        "-p", "--policy",
        help="Scope to one firewall policy: its rules + only the objects those rules "
             "use (plus objects the selected engine's routes use). Use 'none' to drop "
             "the policy dimension entirely — extract only what relates to the engine.",
    )
    parser.add_argument(
        "-e", "--engine",
        help="Scope the infra sheets (Interfaces/Routers/Zones/Router_Elements) "
             "to one engine (Servers are always extracted in full). Use 'none' to drop "
             "the engine dimension entirely — extract only what relates to the policy.",
    )
    parser.add_argument(
        "--panos", metavar="FILE", nargs="?", const="",
        help="Also write Palo Alto (PAN-OS) set CLI to FILE (default: "
             "<input>[_<policy>]_panos.txt). Respects --policy/--engine filters.",
    )
    parser.add_argument(
        "--list-policies", action="store_true",
        help="List the firewall policies found in the file and exit.",
    )
    parser.add_argument(
        "--list-engines", action="store_true",
        help="List the engines found in the file and exit.",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    if not os.path.isfile(args.input):
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 2

    out = args.output or os.path.splitext(args.input)[0] + ".xlsx"

    result = FP2AnyExtractor().extract_file(args.input)

    if args.list_policies:
        print("Policies found:")
        for name in result.policies:
            print(f"  {name}")
        return 0

    if args.list_engines:
        print("Engines found:")
        for name in result.engines:
            print(f"  {name}")
        return 0

    args.policy = _norm_filter(args.policy)
    args.engine = _norm_filter(args.engine)
    if args.policy and args.policy != NONE and args.policy not in result.policies:
        print(f"Policy '{args.policy}' not found. Available policies (or 'none'):",
              file=sys.stderr)
        for name in result.policies:
            print(f"  {name}", file=sys.stderr)
        return 2
    if args.engine and args.engine != NONE and args.engine not in result.engines:
        print(f"Engine '{args.engine}' not found. Available engines (or 'none'):",
              file=sys.stderr)
        for name in result.engines:
            print(f"  {name}", file=sys.stderr)
        return 2

    if args.policy or args.engine:
        result = filter_result(result, engine=args.engine, policy=args.policy)
        if args.policy == NONE:
            print("Policy NONE: rule sheets omitted - extracting engine-related data only")
        elif args.policy:
            print(f"Scoped to policy: {args.policy} (rules + referenced objects)")
        if args.engine == NONE:
            print("Engine NONE: infra sheets omitted - extracting policy-related data only")
        elif args.engine:
            print(f"Scoped infra to engine: {args.engine} (Interfaces/Routers/Zones/Router_Elements)")
        if args.policy == NONE and args.engine == NONE:
            print("WARNING: both filters are 'none' - nothing is selected, output will be empty",
                  file=sys.stderr)

    # Run the PAN-OS generator once: it produces the CLI text plus the
    # Access_Rules source/destination_zone columns. The Migration_Review sheet
    # is a Palo Alto migration artifact, so it is only added to the workbook
    # when --panos is requested (plain XML -> Excel stays free of it).
    from migration.paloalto import PaloAltoGenerator, attach_review, attach_zones
    want_panos = args.panos is not None
    gen = PaloAltoGenerator(result)
    panos_text = gen.generate()
    if want_panos:
        attach_review(result, gen)   # Migration_Review sheet + zone columns
    else:
        attach_zones(result, gen)    # zone columns only

    try:
        write_excel(result, out)
    except PermissionError:
        print(
            f"\nCannot write '{out}' — the file is open (likely in Excel).\n"
            f"Close it and run again, or use -o to write to a different name.",
            file=sys.stderr,
        )
        return 3

    if want_panos:
        stem = os.path.splitext(args.input)[0]
        if args.policy:  # tag the default filename with the selected policy
            tag = "none" if args.policy == NONE else \
                re.sub(r"[^A-Za-z0-9]+", "_", args.policy).strip("_")
            stem += f"_{tag}"
        panos_path = args.panos or stem + "_panos.txt"
        with open(panos_path, "w", encoding="utf-8") as fh:
            fh.write(panos_text)
        print(f"Wrote PAN-OS CLI {panos_path}")

    print(f"\nWrote {out}")
    print(f"Total elements: {result.total_elements}")
    for sheet, count in result.counts.items():
        print(f"  {sheet:20s} {count}")
    if result.unknown_tags:
        print("Unknown tags ->", result.unknown_tags)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
