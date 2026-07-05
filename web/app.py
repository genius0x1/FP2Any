"""Phase 4 — FP2Any FastAPI web interface for the Forcepoint XML -> Excel extractor.

Stateless flow: upload XML -> parse -> choose an operation (Excel sheets /
Palo Alto CLI / FortiGate placeholder). Each operation runs as a background
job whose completion percentage is polled by the page, then redirects to
its output view.

Run with:
    uvicorn web.app:app --reload
or simply:
    python -m web.app
"""
from __future__ import annotations

import io
import sys
import threading
import uuid
from collections import Counter
from pathlib import Path
from urllib.parse import urlencode

from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Make the project root importable when run directly.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fp2any.extractor import (  # noqa: E402
    FP2AnyExtractor, ExtractionResult, filter_result, ALL, NONE, _base_policy,
)
from fp2any.excel_writer import build_workbook, build_selected_workbook  # noqa: E402
from migration.paloalto import (  # noqa: E402
    PaloAltoGenerator, attach_review, attach_zones,
)

BASE = Path(__file__).resolve().parent
UPLOADS = BASE / "uploads"
OUTPUTS = BASE / "outputs"
UPLOADS.mkdir(exist_ok=True)
OUTPUTS.mkdir(exist_ok=True)

app = FastAPI(title="FP2Any")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE / "templates"))

# token -> (ExtractionResult, download_stem) for parsed uploads.
_RESULTS: dict[str, tuple[ExtractionResult, str]] = {}
# Background operations started from the options page: job_id -> state.
_JOBS: dict[str, dict] = {}
# Prepared outputs keyed by (token, policy, engine): a finished job's output
# downloads instantly and repeated views don't regenerate.
_XLSX_CACHE: dict[tuple, bytes] = {}
_PANOS_CACHE: dict[tuple, str] = {}
# Filtered views keyed by (token, policy, engine). The Access_Rules zone
# columns are computed on the scoped data (per selected engine). These views
# do NOT carry the Migration_Review sheet — that is a Palo Alto artifact.
_VIEW_CACHE: dict[tuple, ExtractionResult] = {}
# Filtered views WITH the Migration_Review sheet, produced by the PAN-OS path.
# Kept separate so the plain "XML -> Excel" view never picks up the review.
_PANOS_VIEW_CACHE: dict[tuple, ExtractionResult] = {}

MAX_BYTES = 50 * 1024 * 1024     # 50 MB upload cap
PREVIEW_ROWS = 1000              # max rows rendered per sheet in the browser
CLI_PREVIEW_LINES = 3000         # max CLI lines rendered in the browser
XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"error": None})


@app.post("/convert", response_class=HTMLResponse)
async def convert(request: Request, file: UploadFile = File(...)):
    filename = file.filename or "uploaded.xml"
    if not filename.lower().endswith(".xml"):
        return _error(request, "Please upload a Forcepoint .xml export file.")

    data = await file.read()
    if not data:
        return _error(request, "The uploaded file is empty.")
    if len(data) > MAX_BYTES:
        return _error(request, "File too large (limit 50 MB).")

    try:
        result = FP2AnyExtractor().extract_string(data, source_filename=filename)
    except Exception as exc:  # invalid / unparseable XML
        return _error(request, f"Could not parse the XML: {exc}")

    # Migration_Review + the Access_Rules zone columns are attached lazily by
    # _view()/_panos_text() once the user has picked the policy/engine scope —
    # that keeps the upload fast and computes them on the scoped data.
    token = uuid.uuid4().hex
    stem = Path(filename).stem
    _RESULTS[token] = (result, stem)
    return RedirectResponse(f"/options/{token}", status_code=303)


# ---------------------------------------------------------------- options --
@app.get("/options/{token}", response_class=HTMLResponse)
def options_page(request: Request, token: str, policy: str = ALL, engine: str = ALL):
    entry = _RESULTS.get(token)
    if not entry:
        return RedirectResponse("/", status_code=303)
    full, _stem = entry
    # Per-selection counts for the live scope hint under the dropdowns.
    rule_counts: Counter = Counter()
    for r in full.sheets.get("Access_Rules", ([], []))[1]:
        if r.get("rule_type") != "comment":
            rule_counts[_base_policy(r.get("policy_name", ""))] += 1
    iface_counts: Counter = Counter()
    for r in full.sheets.get("Interfaces", ([], []))[1]:
        if r.get("engine"):
            iface_counts[r["engine"]] += 1
    return templates.TemplateResponse(
        request,
        "options.html",
        {
            "token": token,
            "source": full.source_filename,
            "build": full.meta.get("build", ""),
            "version": full.meta.get("update_package_version", ""),
            "total": full.total_elements,
            "policies": full.policies,
            "engines": full.engines,
            "selected_policy": policy,
            "selected_engine": engine,
            "all_token": ALL,
            "none_token": NONE,
            "rule_counts": dict(rule_counts),
            "iface_counts": dict(iface_counts),
        },
    )


@app.post("/run/{token}/{op}")
def run_op(token: str, op: str, policy: str = ALL, engine: str = ALL):
    """Start a background job for one of the options, scoped to the
    policy/engine chosen on the options page; the page polls its progress
    via /progress/{job_id}."""
    if token not in _RESULTS or op not in ("excel", "panos"):
        return {"error": "Unknown upload or operation."}
    job_id = uuid.uuid4().hex
    job = {"pct": 0, "stage": "Starting", "done": False, "error": "", "redirect": ""}
    _JOBS[job_id] = job
    threading.Thread(target=_run_job, args=(job, token, op, policy, engine),
                     daemon=True).start()
    return {"job": job_id}


def _run_job(job: dict, token: str, op: str, policy: str, engine: str) -> None:
    try:
        suffix = "?" + urlencode({"policy": policy, "engine": engine})
        if op == "excel":
            # Scope + analyze (zone columns / review), then build the full
            # workbook now (per-sheet progress) so the download is instant.
            view = _view(token, policy, engine,
                         progress=lambda p, s: job.update(
                             pct=int(p * 0.40), stage=f"Analyzing — {s}"))
            wb = build_workbook(
                view, progress=lambda p, s: job.update(pct=40 + int(p * 0.45), stage=s))
            job.update(pct=90, stage="Saving workbook")
            buf = io.BytesIO()
            wb.save(buf)
            _XLSX_CACHE[(token, policy, engine)] = buf.getvalue()
            job["redirect"] = f"/result/{token}{suffix}"
        else:  # panos
            _panos_text(token, policy, engine,
                        progress=lambda p, s: job.update(pct=int(p * 0.95), stage=s))
            job["redirect"] = f"/panos-view/{token}{suffix}"
        job.update(pct=100, stage="Done", done=True)
    except Exception as exc:  # surface the failure on the options page
        job.update(error=str(exc), done=True)


@app.get("/progress/{job_id}")
def progress(job_id: str):
    job = _JOBS.get(job_id)
    if not job:
        return {"pct": 0, "stage": "", "done": True, "error": "Unknown job.", "redirect": ""}
    return job


# ----------------------------------------------------------- excel output --
@app.get("/result/{token}", response_class=HTMLResponse)
def result_page(request: Request, token: str, policy: str = ALL, engine: str = ALL):
    entry = _RESULTS.get(token)
    if not entry:
        return RedirectResponse("/", status_code=303)
    full, stem = entry
    view = _view(token, policy, engine)

    sheets_view = []
    for name, (columns, rows) in view.sheets.items():
        sheets_view.append({
            "name": name,
            "columns": columns,
            "rows": rows[:PREVIEW_ROWS],
            "total": len(rows),
            "truncated": len(rows) > PREVIEW_ROWS,
        })

    return templates.TemplateResponse(
        request,
        "result.html",
        {
            "token": token,
            "stem": stem,
            "source": full.source_filename,
            "build": full.meta.get("build", ""),
            "version": full.meta.get("update_package_version", ""),
            "total": full.total_elements,
            "sheets": sheets_view,
            "unknown": full.unknown_tags,
            "preview_rows": PREVIEW_ROWS,
            "policies": full.policies,
            "engines": full.engines,
            "selected_policy": policy,
            "selected_engine": engine,
            "all_token": ALL,
            "none_token": NONE,
        },
    )


def _view(token: str, policy: str, engine: str,
          progress=None) -> ExtractionResult | None:
    """Filtered copy of the parse for the plain XML -> Excel path: the
    Access_Rules zone columns are computed on the scoped result (zones from
    the selected engine's interfaces/routes), but NO Migration_Review sheet
    is attached — that is a Palo Alto migration artifact produced only by the
    'Migrate to Palo Alto' operation. Attachment is lazy."""
    key = (token, policy, engine)
    if key not in _VIEW_CACHE:
        entry = _RESULTS.get(token)
        if not entry:
            return None
        full, _stem = entry
        view = filter_result(full, engine=engine, policy=policy)
        if "Access_Rules" in view.sheets:
            attach_zones(view, progress=progress)
        _VIEW_CACHE[key] = view
    return _VIEW_CACHE[key]


def _resolve(token: str, policy: str, engine: str):
    entry = _RESULTS.get(token)
    if not entry:
        return None, None
    return _view(token, policy, engine), entry[1]


def _filter_suffix(policy: str, engine: str) -> str:
    parts = [("none" if p == NONE else p) for p in (policy, engine) if p and p != ALL]
    return ("_" + "_".join(parts)) if parts else ""


def _xlsx_bytes(token: str, policy: str, engine: str) -> bytes | None:
    key = (token, policy, engine)
    if key not in _XLSX_CACHE:
        result, _stem = _resolve(token, policy, engine)
        if result is None:
            return None
        buf = io.BytesIO()
        build_workbook(result).save(buf)
        _XLSX_CACHE[key] = buf.getvalue()
    return _XLSX_CACHE[key]


@app.get("/download/{token}")
def download_all(token: str, policy: str = ALL, engine: str = ALL):
    data = _xlsx_bytes(token, policy, engine)
    if data is None:
        return RedirectResponse("/", status_code=303)
    stem = _RESULTS[token][1]
    return _stream(data, XLSX_MIME, f"{stem}{_filter_suffix(policy, engine)}.xlsx")


@app.get("/download/{token}/{sheet}")
def download_sheet(token: str, sheet: str, policy: str = ALL, engine: str = ALL):
    result, stem = _resolve(token, policy, engine)
    if result is None or sheet not in result.sheets:
        return RedirectResponse("/", status_code=303)
    wb = build_selected_workbook(result, [sheet])
    buf = io.BytesIO()
    wb.save(buf)
    return _stream(buf.getvalue(), XLSX_MIME, f"{stem}_{sheet}.xlsx")


# ---------------------------------------------------------- pan-os output --
def _panos_text(token: str, policy: str, engine: str, progress=None) -> str | None:
    key = (token, policy, engine)
    if key not in _PANOS_CACHE:
        entry = _RESULTS.get(token)
        if not entry:
            return None
        full, _stem = entry
        view = filter_result(full, engine=engine, policy=policy)
        # One generator pass yields BOTH the CLI text and the Migration_Review
        # + zone sheets. This reviewed view is cached SEPARATELY from the plain
        # Excel view so the review never leaks into "XML -> Excel".
        gen = PaloAltoGenerator(view)
        text = gen.generate(progress)
        if "Access_Rules" in view.sheets:
            attach_review(view, gen)
        _PANOS_VIEW_CACHE[key] = view
        _PANOS_CACHE[key] = text
    return _PANOS_CACHE[key]


@app.get("/panos-view/{token}", response_class=HTMLResponse)
def panos_view(request: Request, token: str, policy: str = ALL, engine: str = ALL):
    entry = _RESULTS.get(token)
    if not entry:
        return RedirectResponse("/", status_code=303)
    full, stem = entry
    text = _panos_text(token, policy, engine)
    lines = text.splitlines()
    return templates.TemplateResponse(
        request,
        "panos.html",
        {
            "token": token,
            "source": full.source_filename,
            "total_lines": len(lines),
            "preview": "\n".join(lines[:CLI_PREVIEW_LINES]),
            "truncated": len(lines) > CLI_PREVIEW_LINES,
            "preview_lines": CLI_PREVIEW_LINES,
            "policies": full.policies,
            "engines": full.engines,
            "selected_policy": policy,
            "selected_engine": engine,
            "all_token": ALL,
            "none_token": NONE,
        },
    )


@app.get("/panos/{token}")
def download_panos(token: str, policy: str = ALL, engine: str = ALL):
    text = _panos_text(token, policy, engine)
    if text is None:
        return RedirectResponse("/", status_code=303)
    stem = _RESULTS[token][1]
    suffix = ("_none" if policy == NONE else f"_{policy}") if policy != ALL else ""
    return _stream(text.encode("utf-8"), "text/plain", f"{stem}{suffix}_panos.txt")


@app.get("/panos-xlsx/{token}")
def download_panos_xlsx(token: str, policy: str = ALL, engine: str = ALL):
    """The Migration_Review sheet for the Palo Alto migration — ONLY that
    sheet (undefined refs needing manual handling), not the full export. The
    config itself is the PAN-OS CLI .txt; this workbook is just the review.
    Only reachable from the PAN-OS result page."""
    if _panos_text(token, policy, engine) is None:
        return RedirectResponse("/", status_code=303)
    view = _PANOS_VIEW_CACHE.get((token, policy, engine))
    if view is None or "Migration_Review" not in view.sheets:
        return RedirectResponse("/", status_code=303)
    stem = _RESULTS[token][1]
    buf = io.BytesIO()
    build_selected_workbook(view, ["Migration_Review"]).save(buf)
    return _stream(buf.getvalue(), XLSX_MIME,
                   f"{stem}{_filter_suffix(policy, engine)}_migration_review.xlsx")


# ------------------------------------------------------------------ misc --
def _stream(data: bytes, mime: str, filename: str) -> StreamingResponse:
    return StreamingResponse(
        io.BytesIO(data),
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _error(request: Request, message: str) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "index.html", {"error": message}, status_code=400
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("web.app:app", host="127.0.0.1", port=8000, reload=False)
