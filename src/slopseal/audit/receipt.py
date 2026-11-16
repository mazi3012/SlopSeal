"""Render the audit log as one self-contained HTML receipt page (R-5.7.1, R-5.7.2).

The page uses inline CSS only. It has no scripts, no images, no links, and no requests to
other hosts. Every value from the log is escaped before it is written, because package names,
reasons, and README text are untrusted data (AGENTS.md: treat package metadata as data).

Light and dark colours come from prefers-color-scheme.

Requirements: R-5.7.1, R-5.7.2. Layer 4 (audit presentation). Pure.
"""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from typing import Any

from slopseal.audit.log import LineCheck, VerifyReport

_BADGE = {"ALLOW": "allow", "BLOCK": "block", "QUARANTINE": "quarantine"}

_CSS = """
:root { color-scheme: light dark; --bg:#f6f7f9; --card:#ffffff; --ink:#1b1f24; --muted:#5b6470;
  --line:#d8dde3; --allow:#1a7f37; --block:#cf222e; --quarantine:#9a6700;
  --ok:#1a7f37; --bad:#cf222e; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0d1117; --card:#161b22; --ink:#e6edf3; --muted:#9aa4b2; --line:#30363d;
    --allow:#3fb950; --block:#ff7b72; --quarantine:#d29922; --ok:#3fb950; --bad:#ff7b72; } }
* { box-sizing: border-box; }
body { margin:0; padding:24px; background:var(--bg); color:var(--ink);
  font:14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
main { max-width: 920px; margin: 0 auto; }
h1 { font-size: 22px; margin: 0 0 4px; } .sub { color: var(--muted); margin: 0 0 20px; }
.summary { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:20px; }
.stat { background:var(--card); border:1px solid var(--line); border-radius:8px;
  padding:10px 14px; }
.stat b { display:block; font-size:20px; }
.verdict { background:var(--card); border:1px solid var(--line); border-radius:8px;
  padding:14px 16px; margin-bottom:12px; }
.head { display:flex; flex-wrap:wrap; align-items:center; gap:10px; }
.pkg { font-weight:600; word-break:break-all; }
.badge { display:inline-block; padding:2px 10px; border-radius:999px; color:#fff; font-size:12px;
  font-weight:700; letter-spacing:.03em; }
.badge.allow { background:var(--allow); } .badge.block { background:var(--block); }
.badge.quarantine { background:var(--quarantine); } .badge.other { background:var(--muted); }
.meta { color:var(--muted); font-size:12px; margin-top:6px; word-break:break-all; }
ul.checks { margin:8px 0 0; padding-left:18px; } ul.checks li { margin:2px 0; }
.seal-ok { color:var(--ok); font-weight:600; } .seal-bad { color:var(--bad); font-weight:700; }
.reason { margin-top:6px; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px;
  word-break:break-all; }
.banner { border-radius:8px; padding:12px 16px; margin-bottom:20px; border:1px solid var(--line); }
.banner.ok { border-color:var(--ok); } .banner.bad { border-color:var(--bad); }
@media print { body { background:#fff; color:#000; }
  .verdict, .stat, .banner { border-color:#999; } }
"""


def is_verified(report: VerifyReport, checks: list[LineCheck]) -> bool:
    """True when the whole log passes the chain check and no line has an invalid seal."""
    return report.ok and all(c.chain_ok and c.seal != "invalid" for c in checks)


def _e(value: object) -> str:
    """Escape any value taken from the log. None becomes an empty string."""
    return html.escape("" if value is None else str(value), quote=True)


def _badge(outcome: str) -> str:
    css = _BADGE.get(outcome, "other")
    return f'<span class="badge {css}">{_e(outcome)}</span>'


def _checks_list(checks: Any) -> str:
    if not isinstance(checks, list) or not checks:
        return "<p class='meta'>No checks recorded.</p>"
    items = "".join(f"<li>{_e(check)}</li>" for check in checks)
    return f"<ul class='checks'>{items}</ul>"


def _seal_html(check: LineCheck) -> str:
    if check.seal == "ok":
        seal = "<span class='seal-ok'>seal verified</span>"
    elif check.seal == "not applicable":
        seal = "genesis (no seal)"
    else:
        seal = f"<span class='seal-bad'>seal {_e(check.seal)}</span>"
    chain = "chain verified" if check.chain_ok else "<span class='seal-bad'>chain broken</span>"
    problem = f"<div class='reason'>{_e(check.problem)}</div>" if check.problem else ""
    return f"<div class='meta'>{seal} &middot; {chain}</div>{problem}"


def _verdict_card(record: dict[str, Any], check: LineCheck) -> str:
    outcome = str(record.get("outcome", ""))
    package = f"{record.get('package', '')}"
    version = record.get("version")
    name = f"{package}=={version}" if version else package
    blocked_by = record.get("blocked_by")
    warnings = record.get("warning_details") or []
    warning_lines = "".join(
        f"<li>WARN {_e(w.get('check'))}: {_e(w.get('reason'))}</li>"
        for w in warnings
        if isinstance(w, dict)
    )
    extra = f"<div class='meta'>blocked by: {_e(blocked_by)}</div>" if blocked_by else ""
    warn_block = f"<ul class='checks'>{warning_lines}</ul>" if warning_lines else ""
    return (
        "<section class='verdict'>"
        f"<div class='head'>{_badge(outcome)}<span class='pkg'>{_e(name)}</span>"
        f"<span class='meta'>{_e(record.get('ecosystem'))} &middot; seq {_e(record.get('seq'))}"
        f" &middot; {_e(record.get('ts'))}</span></div>"
        f"<div class='reason'>{_e(record.get('reason'))}</div>"
        f"{extra}{warn_block}"
        f"<div class='meta'>Checks run:</div>{_checks_list(record.get('checks_run'))}"
        f"<div class='meta'>Policy hash: <code>{_e(record.get('policy_hash'))}</code></div>"
        f"<div class='meta'>Snapshot: <code>{_e(record.get('snapshot_id'))}</code></div>"
        f"{_seal_html(check)}"
        "</section>"
    )


def _event_card(record: dict[str, Any], check: LineCheck) -> str:
    event = str(record.get("event", ""))
    if event == "resolution":
        head = f"{_badge(str(record.get('outcome', '')))}<span class='pkg'>resolve then pin</span>"
        body = (
            f"<div class='meta'>original: <code>{_e(record.get('original_command'))}</code></div>"
            f"<div class='meta'>rewritten: <code>{_e(record.get('rewritten_command'))}</code></div>"
        )
    else:
        head = f"<span class='badge other'>{_e(event)}</span>"
        body = ""
    return (
        "<section class='verdict'>"
        f"<div class='head'>{head}<span class='meta'>seq {_e(record.get('seq'))}"
        f" &middot; {_e(record.get('ts'))}</span></div>{body}{_seal_html(check)}"
        "</section>"
    )


def render_receipt(
    lines: list[str],
    checks: list[LineCheck],
    report: VerifyReport,
    *,
    log_name: str,
    generated: datetime,
) -> str:
    records: list[dict[str, Any] | None] = []
    for text in lines:
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            value = None
        records.append(value if isinstance(value, dict) else None)

    counts = {"ALLOW": 0, "BLOCK": 0, "QUARANTINE": 0}
    cards: list[str] = []
    for index, record in enumerate(records):
        check = checks[index] if index < len(checks) else LineCheck(None, False, "unreadable", None)
        if record is None:
            cards.append(
                "<section class='verdict'><div class='head'>"
                "<span class='badge other'>unreadable</span></div>"
                f"{_seal_html(check)}</section>"
            )
            continue
        if record.get("event") == "verdict":
            outcome = str(record.get("outcome", ""))
            if outcome in counts:
                counts[outcome] += 1
            cards.append(_verdict_card(record, check))
        else:
            cards.append(_event_card(record, check))

    if is_verified(report, checks):
        banner = (
            "<div class='banner ok'><span class='seal-ok'>Audit log verified.</span>"
            " The hash chain and every seal check out.</div>"
        )
    else:
        failure = report.failure_check or "a line failed its chain or seal check"
        where = "" if report.failure_seq is None else f" (at seq {report.failure_seq})"
        banner = (
            "<div class='banner bad'><span class='seal-bad'>Audit log failed verification."
            f"</span> {_e(failure)}{_e(where)}</div>"
        )

    head_seq = report.head_seq if report.head_seq is not None else "none"
    head_hash = report.head_hash or "none"
    summary = (
        "<div class='summary'>"
        f"<div class='stat'><b>{counts['ALLOW']}</b>ALLOW</div>"
        f"<div class='stat'><b>{counts['BLOCK']}</b>BLOCK</div>"
        f"<div class='stat'><b>{counts['QUARANTINE']}</b>QUARANTINE</div>"
        f"<div class='stat'><b>{len(lines)}</b>log lines</div>"
        "</div>"
    )
    stamp = generated.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        "<!doctype html>\n<html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<meta name='color-scheme' content='light dark'>"
        f"<title>SlopSeal receipt: {_e(log_name)}</title><style>{_CSS}</style></head><body><main>"
        "<h1>SlopSeal audit receipt</h1>"
        f"<p class='sub'>Log: <code>{_e(log_name)}</code> &middot; generated {_e(stamp)}"
        f" &middot; head seq {_e(head_seq)} &middot; head <code>{_e(head_hash)}</code></p>"
        f"{banner}{summary}{''.join(cards)}"
        "</main></body></html>\n"
    )
