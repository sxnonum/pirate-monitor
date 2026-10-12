"""Collects events during a session and writes a self-contained HTML report at the end."""

from __future__ import annotations

import datetime as _dt
import html
import os
from collections import Counter, defaultdict
from typing import Dict, List, Optional

from .core import Event, severity_rank
from .output import describe
from .util import human_size, shorten

MAX_EVENTS = 100_000
MAX_ROWS_PER_TABLE = 20_000


def _noise_group(ev: Event) -> str:
    if ev.category in ("file", "registry"):
        sep = "\\" if "\\" in ev.target else "/"
        parts = ev.target.split(sep)
        return sep.join(parts[:7]) + (sep + "..." if len(parts) > 7 else "")
    if ev.category == "process":
        return ev.details.get("name") or ev.target
    if ev.category == "network":
        return f"{ev.details.get('process')} ({ev.action})"
    return ev.target


class ReportCollector:
    def __init__(self):
        self.events: List[Event] = []
        self.system: List[Event] = []
        self.category_counts: Counter = Counter()
        self.severity_counts: Counter = Counter()
        self.noise_total = 0
        self.noise_groups: Counter = Counter()
        self.truncated = 0
        self.total = 0

    def handle(self, ev: Event) -> None:
        if ev.category == "system":
            self.system.append(ev)
            return
        self.total += 1
        if ev.noise:
            self.noise_total += 1
            self.noise_groups[(ev.category, _noise_group(ev))] += 1
            return
        self.category_counts[ev.category] += 1
        self.severity_counts[ev.severity] += 1
        if len(self.events) < MAX_EVENTS:
            self.events.append(ev)
        else:
            self.truncated += 1

    def close(self) -> None:
        pass

    def findings(self, min_level: str = "warning") -> List[Event]:
        rank = severity_rank(min_level)
        return [e for e in self.events if severity_rank(e.severity) >= rank]

    def write_html(self, path: str, meta: Dict[str, str]) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_html(self, meta))


# --------------------------------------------------------------------------------------------
def _e(value) -> str:
    return html.escape("" if value is None else str(value))


def _time(ev: Event) -> str:
    return _dt.datetime.fromtimestamp(ev.timestamp).strftime("%H:%M:%S.%f")[:-3]


def _nw(value) -> str:
    return f'<span class="nw">{_e(value)}</span>'


def _sev(ev: Event) -> str:
    return f'<span class="sev sev-{ev.severity}">{ev.severity.upper()}</span>'


def _reasons(ev: Event) -> str:
    return "<br>".join(_e(r) for r in ev.reasons)


def _track_mark(ev: Event) -> str:
    return '<span class="tracked" title="tracked process tree">&#9733;</span> ' if ev.tracked else ""


def _table(table_id: str, headers: List[str], rows: List[List[str]], empty: str) -> str:
    if not rows:
        return f'<p class="empty">{_e(empty)}</p>'
    note = ""
    if len(rows) > MAX_ROWS_PER_TABLE:
        note = f'<p class="note">Showing the first {MAX_ROWS_PER_TABLE:,} of {len(rows):,} rows - see events.jsonl for everything.</p>'
        rows = rows[:MAX_ROWS_PER_TABLE]
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "\n".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return (
        f'<input class="filter" type="search" placeholder="Filter rows..." data-filter="{table_id}">{note}'
        f'<div class="scroll"><table id="{table_id}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'
    )


def _detail_cell(ev: Event) -> str:
    return "<br>".join(_e(shorten(line, 600)) for line in describe(ev))


def _findings_rows(events: List[Event]) -> List[List[str]]:
    return [
        [_time(e), _sev(e), _nw(e.category), _nw(e.action), _track_mark(e) + f"<code>{_e(e.target)}</code>",
         _detail_cell(e), _reasons(e)]
        for e in events
    ]


def _process_tree(events: List[Event]) -> str:
    procs = [e for e in events if e.category == "process" and e.action in ("started", "tracking") and e.tracked]
    if not procs:
        return '<p class="empty">No tracked processes. Use --run, --track or --track-pid to follow a sample.</p>'
    children: Dict[Optional[int], List[Event]] = defaultdict(list)
    pids = {e.details.get("pid") for e in procs}
    for e in procs:
        parent = e.details.get("ppid")
        children[parent if parent in pids else None].append(e)

    seen = set()

    def render(nodes: List[Event]) -> str:
        items = []
        for e in sorted(nodes, key=lambda x: x.timestamp):
            if e.id in seen:
                continue
            seen.add(e.id)
            d = e.details
            label = (
                f"{_sev(e)} <b>{_e(d.get('name'))}</b> <span class='muted'>pid {_e(d.get('pid'))} &middot; {_time(e)}</span>"
            )
            if d.get("exe"):
                label += f"<div class='muted'><code>{_e(d['exe'])}</code></div>"
            if d.get("cmdline"):
                label += f"<div><code>{_e(shorten(d['cmdline'], 800))}</code></div>"
            if e.reasons:
                label += f"<div class='reasons'>{_reasons(e)}</div>"
            sub = children.get(d.get("pid"), [])
            items.append(f"<li>{label}{render(sub) if sub else ''}</li>")
        return "<ul class='tree'>" + "".join(items) + "</ul>"

    return render(children[None])


def _dropped_rows(events: List[Event]) -> List[List[str]]:
    latest: Dict[str, Event] = {}
    for e in events:
        if e.category == "file" and e.action == "executable":
            latest[os.path.normcase(e.target)] = e
    executed = {
        os.path.normcase(e.details["exe"])
        for e in events
        if e.category == "process" and e.action == "started" and e.details.get("exe")
    }
    rows = []
    for key, e in sorted(latest.items(), key=lambda kv: kv[1].timestamp):
        d = e.details
        sha = d.get("sha256") or ""
        sha_cell = _e(sha)
        if len(sha) == 64:
            sha_cell = f'<a href="https://www.virustotal.com/gui/file/{sha}" target="_blank" rel="noopener">{sha}</a>'
        rows.append([
            _time(e), _sev(e), f"<code>{_e(e.target)}</code>", _e(d.get("kind")), _e(human_size(d.get("size"))),
            f"<code>{sha_cell}</code>", "yes" if key in executed else "", _reasons(e),
        ])
    return rows


def render_html(col: ReportCollector, meta: Dict[str, str]) -> str:
    events = sorted(col.events, key=lambda e: e.timestamp)
    by_cat: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        by_cat[e.category].append(e)
    findings = [e for e in events if severity_rank(e.severity) >= severity_rank("warning")]
    findings.sort(key=lambda e: (-severity_rank(e.severity), e.timestamp))

    proc_rows = [
        [_time(e), _sev(e), _nw(e.action), _track_mark(e) + f"<b>{_e(e.details.get('name'))}</b>",
         _nw(e.details.get("pid")), _e(e.details.get("parent")),
         f"<code>{_e(shorten(e.details.get('cmdline') or e.details.get('exe') or '', 800))}</code>",
         f"<code>{_e((e.details.get('sha256') or '')[:16])}</code>", _reasons(e)]
        for e in by_cat["process"]
    ]
    net_rows = [
        [_time(e), _sev(e), _nw(e.action), _track_mark(e) + _e(e.details.get("process")), _nw(e.details.get("pid")),
         _e(e.details.get("proto")), _e(e.details.get("local")), _e(e.details.get("remote")),
         _e(e.details.get("direction") or e.details.get("status")), _reasons(e)]
        for e in by_cat["network"]
    ]
    file_rows = [
        [_time(e), _sev(e), _nw(e.action), f"<code>{_e(e.target)}</code>", _detail_cell(e), _reasons(e)]
        for e in by_cat["file"]
    ]
    reg_rows = [
        [_time(e), _sev(e), _nw(e.action), f"<code>{_e(e.target)}</code>", _detail_cell(e), _reasons(e)]
        for e in by_cat["registry"]
    ]
    noise_rows = [
        [_e(cat), f"<code>{_e(group)}</code>", f"{count:,}"]
        for (cat, group), count in col.noise_groups.most_common(300)
    ]
    system_rows = [[_time(e), _e(e.severity), _e(e.target)] for e in col.system]

    cards = [
        ("Alerts", col.severity_counts.get("alert", 0), "alert"),
        ("Warnings", col.severity_counts.get("warning", 0), "warning"),
        ("Processes", col.category_counts.get("process", 0), ""),
        ("Network", col.category_counts.get("network", 0), ""),
        ("File changes", col.category_counts.get("file", 0), ""),
        ("Registry changes", col.category_counts.get("registry", 0), ""),
        ("Hidden noise", col.noise_total, "muted"),
    ]
    cards_html = "".join(
        f'<div class="card {cls}"><div class="num">{num:,}</div><div class="lbl">{_e(lbl)}</div></div>'
        for lbl, num, cls in cards
    )
    meta_html = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in meta.items())
    truncated = (
        f'<p class="note">{col.truncated:,} further events were not kept in memory for this report; '
        f"they are all in events.jsonl.</p>" if col.truncated else ""
    )

    sections = [
        ("findings", f"Findings ({len(findings):,})",
         "Everything graded warning or alert, most severe first. The reasons column says why it was flagged.",
         _table("t-findings", ["Time", "Severity", "Type", "Action", "Target", "Details", "Why"],
                _findings_rows(findings), "Nothing was flagged as suspicious.")),
        ("tree", "Tracked process tree", "The sample and everything it started (directly or via dropped files).",
         _process_tree(events)),
        ("dropped", "Executables & scripts written", "Files that can run code, created or changed during the session.",
         _table("t-dropped", ["Time", "Severity", "Path", "Kind", "Size", "SHA-256 (VirusTotal)", "Executed", "Why"],
                _dropped_rows(events), "No executables or scripts were written.")),
        ("processes", f"Processes ({len(proc_rows):,})", "",
         _table("t-proc", ["Time", "Severity", "Action", "Name", "PID", "Parent", "Command line", "SHA-256", "Why"],
                proc_rows, "No process activity recorded.")),
        ("network", f"Network ({len(net_rows):,})", "",
         _table("t-net", ["Time", "Severity", "Action", "Process", "PID", "Proto", "Local", "Remote", "Direction / state", "Why"],
                net_rows, "No new network activity recorded.")),
        ("files", f"File system ({len(file_rows):,})", "",
         _table("t-files", ["Time", "Severity", "Action", "Path", "Details", "Why"], file_rows, "No file changes recorded.")),
        ("registry", f"Registry ({len(reg_rows):,})", "",
         _table("t-reg", ["Time", "Severity", "Action", "Key", "Details", "Why"], reg_rows, "No registry changes recorded.")),
        ("noise", f"Background noise ({col.noise_total:,} events)",
         "Routine activity hidden from the live view (browser caches, Windows bookkeeping...). Counted per location; "
         "every event is still in events.jsonl.",
         _table("t-noise", ["Type", "Location / process", "Events"], noise_rows, "No background noise recorded.")),
        ("log", "Monitor messages", "", _table("t-log", ["Time", "Level", "Message"], system_rows, "No messages.")),
    ]
    nav = "".join(f'<a href="#{sid}">{_e(title.split(" (")[0])}</a>' for sid, title, _, _ in sections)
    body = "".join(
        f'<section id="{sid}"><h2>{_e(title)}</h2>' + (f'<p class="muted">{_e(intro)}</p>' if intro else "") + content + "</section>"
        for sid, title, intro, content in sections
    )
    return _TEMPLATE.format(title=_e(meta.get("Session", "Pirate Monitor report")), nav=nav, meta=meta_html,
                            cards=cards_html, truncated=truncated, body=body)


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ --bg:#f7f7f8; --panel:#fff; --text:#1b1d21; --muted:#666b74; --border:#dcdfe4; --code:#f0f1f3;
  --alert:#c62828; --warning:#b26a00; --notice:#0b7285; --info:#6c757d; --accent:#6741d9; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#14161a; --panel:#1c1f24; --text:#e6e8eb; --muted:#9aa1ab;
  --border:#2e333a; --code:#262a30; --alert:#ff6b6b; --warning:#ffb347; --notice:#4fd1e0; --info:#9aa1ab; --accent:#9775fa; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif; }}
header {{ padding:20px 24px 8px; }} h1 {{ margin:0 0 4px; font-size:22px; }}
nav {{ position:sticky; top:0; z-index:2; background:var(--bg); border-bottom:1px solid var(--border); padding:8px 24px;
  display:flex; flex-wrap:wrap; gap:6px 16px; }}
nav a {{ color:var(--accent); text-decoration:none; font-weight:600; }}
main {{ padding:8px 24px 40px; }}
section {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:14px 16px; margin:16px 0; }}
h2 {{ margin:0 0 6px; font-size:17px; }}
dl {{ display:grid; grid-template-columns:max-content 1fr; gap:2px 14px; margin:8px 0; }} dt {{ color:var(--muted); }} dd {{ margin:0; word-break:break-all; }}
.cards {{ display:flex; flex-wrap:wrap; gap:10px; margin:12px 0; }}
.card {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:10px 14px; min-width:120px; }}
.card .num {{ font-size:24px; font-weight:700; }} .card .lbl {{ color:var(--muted); font-size:12px; }}
.card.alert .num {{ color:var(--alert); }} .card.warning .num {{ color:var(--warning); }} .card.muted .num {{ color:var(--muted); }}
.scroll {{ overflow-x:auto; max-height:70vh; overflow-y:auto; border:1px solid var(--border); border-radius:8px; }}
table {{ border-collapse:collapse; width:100%; min-width:760px; font-size:13px; }}
th {{ position:sticky; top:0; background:var(--code); text-align:left; padding:6px 8px; white-space:nowrap; }}
td {{ border-top:1px solid var(--border); padding:5px 8px; vertical-align:top; word-break:break-word; }}
td:first-child {{ white-space:nowrap; color:var(--muted); font-variant-numeric:tabular-nums; }}
code {{ background:var(--code); padding:1px 4px; border-radius:4px; font:12px/1.4 ui-monospace,Consolas,monospace; word-break:break-all; }}
.nw {{ white-space:nowrap; }}
.sev {{ white-space:nowrap; display:inline-block; padding:1px 6px; border-radius:4px; font-size:11px; font-weight:700; color:#fff; }}
.sev-alert {{ background:var(--alert); }} .sev-warning {{ background:var(--warning); }}
.sev-notice {{ background:var(--notice); }} .sev-info {{ background:var(--info); }}
.tracked {{ color:var(--accent); }} .muted {{ color:var(--muted); }} .empty {{ color:var(--muted); font-style:italic; }}
.note {{ color:var(--warning); }} .reasons {{ color:var(--warning); font-size:12px; }}
.filter {{ width:100%; max-width:360px; padding:6px 8px; margin:6px 0 8px; border:1px solid var(--border); border-radius:6px;
  background:var(--panel); color:var(--text); }}
ul.tree {{ list-style:none; padding-left:18px; border-left:2px solid var(--border); margin:6px 0; }}
ul.tree li {{ margin:8px 0; }}
a {{ color:var(--accent); }}
@media (max-width:640px) {{ header, main, nav {{ padding-left:16px; padding-right:16px; }} }}
</style></head><body>
<header><h1>Pirate Monitor report</h1><dl>{meta}</dl><div class="cards">{cards}</div>{truncated}</header>
<nav>{nav}</nav>
<main>{body}</main>
<script>
document.querySelectorAll('input[data-filter]').forEach(function (input) {{
  input.addEventListener('input', function () {{
    var q = input.value.toLowerCase();
    var rows = document.getElementById(input.dataset.filter).tBodies[0].rows;
    for (var i = 0; i < rows.length; i++) {{
      rows[i].style.display = rows[i].textContent.toLowerCase().indexOf(q) === -1 ? 'none' : '';
    }}
  }});
}});
</script>
</body></html>
"""
