"""Interactive HTML report: clickable a→b→c chains + source with sensitive marks."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any


SINK_PATTERNS = (
    re.compile(r"\bexec\s*\("),
    re.compile(r"\breadObject\s*\("),
    re.compile(r"\breadExternal\s*\("),
    re.compile(r"\bRuntime\b"),
    re.compile(r"\bObjectInputStream\b"),
    re.compile(r"\bdefaultReadObject\s*\("),
    re.compile(r"\b\.invoke\s*\("),
    re.compile(r"\bnewInstance\s*\("),
    re.compile(r"\bforName\s*\("),
)


def _find_source_file(app_root: Path, method_qn: str) -> Path | None:
    type_qn = method_qn.split("#", 1)[0]
    parts = type_qn.split(".")
    name = parts[-1]
    pkg = Path(*parts[:-1]) if len(parts) > 1 else Path()
    candidates = [
        app_root / pkg / f"{name}.java",
        app_root / f"{name}.java",
    ]
    for c in candidates:
        if c.is_file():
            return c
    hits = list(app_root.rglob(f"{name}.java"))
    return hits[0] if hits else None


def _method_name(method_qn: str) -> str:
    if "#" not in method_qn:
        return method_qn
    sig = method_qn.split("#", 1)[1]
    return sig.split("(", 1)[0]


def _short_label(method_qn: str) -> str:
    type_qn, _, sig = method_qn.partition("#")
    simple = type_qn.rsplit(".", 1)[-1]
    name = sig.split("(", 1)[0] if sig else type_qn
    return f"{simple}.{name}"


def _find_method_span(lines: list[str], method_name: str) -> tuple[int, int] | None:
    """Return 1-based (start, end) inclusive for method body via brace match."""
    # Skip calls: this.foo( / obj.foo( / ).foo(
    call_like = re.compile(
        rf"(?:this\s*\.\s*|[\w)\]]\s*\.\s*){re.escape(method_name)}\s*\("
    )
    # Declaration: modifiers/return-type then name(
    decl = re.compile(
        rf"^\s*(?:@\w+(?:\([^)]*\))?\s*)*"  # annotations
        rf"(?:(?:public|private|protected|static|final|synchronized|native|abstract|default)\s+)+"
        rf".*\b{re.escape(method_name)}\s*\("
    )
    # Also: "void foo(" / "String foo(" without leading visibility (package-private)
    decl_ret = re.compile(
        rf"^\s*(?:@\w+(?:\([^)]*\))?\s*)*"
        rf"(?:[\w.<>,\[\]?]+\s+)+{re.escape(method_name)}\s*\("
    )
    decl_i = None
    for i, line in enumerate(lines):
        if call_like.search(line):
            continue
        if decl.search(line) or decl_ret.search(line):
            decl_i = i
            break
    if decl_i is None:
        return None

    # Show preceding annotations in the snippet, but brace-match from decl line
    # (annotations like @GetMapping(value={...}) contain braces).
    view_start = decl_i
    while view_start > 0 and lines[view_start - 1].strip().startswith("@"):
        view_start -= 1

    depth = 0
    seen = False
    for j in range(decl_i, len(lines)):
        for ch in lines[j]:
            if ch == "{":
                depth += 1
                seen = True
            elif ch == "}":
                depth -= 1
                if seen and depth == 0:
                    return view_start + 1, j + 1
    return view_start + 1, min(len(lines), decl_i + 40)


def _rel_file(path: Path, app_root: Path) -> str:
    try:
        return str(path.relative_to(app_root.parent.parent))  # under tmpwork/
    except ValueError:
        return str(path)


def build_method_node(
    method_qn: str,
    app_root: Path,
    *,
    highlight_lines: set[int] | None = None,
    call_targets: set[str] | None = None,
    sink_name: str | None = None,
    role: str = "step",
) -> dict[str, Any]:
    """Source node for one method: lines + mark kinds (sink|call|sensitive)."""
    highlight_lines = set(highlight_lines or [])
    call_targets = set(call_targets or [])
    path = _find_source_file(app_root, method_qn)
    name = _method_name(method_qn)
    node: dict[str, Any] = {
        "qn": method_qn,
        "label": _short_label(method_qn),
        "name": name,
        "role": role,  # entry | step | sink
        "file": "",
        "start_line": 0,
        "end_line": 0,
        "lines": [],
    }
    if not path or not path.is_file():
        return node

    text_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    span = _find_method_span(text_lines, name)
    if not span:
        # whole file window around first highlight
        center = min(highlight_lines) if highlight_lines else 1
        span = (max(1, center - 8), min(len(text_lines), center + 12))
    start, end = span
    # pad a bit of context
    start = max(1, start - 1)
    end = min(len(text_lines), end + 1)

    lines_out = []
    for ln in range(start, end + 1):
        raw = text_lines[ln - 1]
        marks: list[str] = []
        if ln in highlight_lines:
            marks.append("sink")
        for tgt in call_targets:
            if re.search(rf"\b{re.escape(tgt)}\s*\(", raw):
                marks.append("call")
                break
        if any(p.search(raw) for p in SINK_PATTERNS):
            if "sink" not in marks and "call" not in marks:
                marks.append("sensitive")
            elif "sink" not in marks and any(
                p.search(raw) for p in SINK_PATTERNS[:2]
            ):
                marks.append("sink")
        lines_out.append({"n": ln, "text": raw, "marks": marks})

    node.update(
        {
            "file": _rel_file(path, app_root),
            "start_line": start,
            "end_line": end,
            "lines": lines_out,
            "sink_name": sink_name,
        }
    )
    return node


def _resolve_app_root(app_root: Path | None) -> Path:
    if app_root is not None:
        return Path(app_root)
    root = Path(__file__).resolve().parent.parent / "tmpwork"
    apps = sorted(root.glob("*/app"))
    return apps[0] if apps else root


def enrich_report(report: dict[str, Any], app_root: Path | None = None) -> dict[str, Any]:
    """Attach interactive chain nodes (with source + marks) and finding snippets."""
    app_root = _resolve_app_root(app_root)

    # sink highlights by method
    sink_lines: dict[str, set[int]] = {}
    sink_names: dict[str, str] = {}
    for su in report.get("sink_users") or []:
        mq = su.get("method") or ""
        for s in su.get("sinks") or []:
            sink_lines.setdefault(mq, set()).add(int(s.get("line") or 0))
            sink_names[mq] = s.get("name") or sink_names.get(mq, "")
    for f in report.get("findings") or []:
        mq = f.get("method") or ""
        sink_lines.setdefault(mq, set()).add(int(f.get("line") or 0))
        sink_names[mq] = f.get("sink") or sink_names.get(mq, "")

    findings = []
    for f in report.get("findings", []):
        item = dict(f)
        node = build_method_node(
            f["method"],
            app_root,
            highlight_lines=sink_lines.get(f["method"], {int(f.get("line") or 1)}),
            sink_name=f.get("sink"),
            role="sink",
        )
        item["file"] = node.get("file", "")
        item["node"] = node
        findings.append(item)

    raw_chains = report.get("call_chains_to_sinks") or []
    # Already compressed in analyze query; still compress when loading raw JSON
    from analyze.chains import compress_call_chains

    raw_chains = compress_call_chains(raw_chains)
    seen: set[tuple] = set()
    chains: list[dict[str, Any]] = []
    for c in raw_chains:
        steps: list[str] = list(c.get("call_chain") or [])
        key = tuple(steps)
        if key in seen:
            continue
        seen.add(key)

        sink_method = c.get("sink_method") or (steps[-1] if steps else "")
        sink = c.get("sink")
        sink_vul = c.get("sink_vul") or ""
        # Infer vul from findings for this sink method
        if not sink_vul:
            for f in report.get("findings") or []:
                if f.get("method") == sink_method and f.get("vul"):
                    sink_vul = f["vul"]
                    if not sink:
                        sink = f.get("sink")
                    break
        sink_line = int(c.get("sink_line") or 0)
        if not sink_line:
            for f in report.get("findings") or []:
                if f.get("method") == sink_method and f.get("line"):
                    sink_line = int(f["line"])
                    break
        nodes = []
        for i, mq in enumerate(steps):
            nxt = _method_name(steps[i + 1]) if i + 1 < len(steps) else None
            hl = set(sink_lines.get(mq) or [])
            if mq == sink_method and sink_line:
                hl.add(sink_line)
            role = "entry" if i == 0 else ("sink" if i == len(steps) - 1 else "step")
            nodes.append(
                build_method_node(
                    mq,
                    app_root,
                    highlight_lines=hl,
                    call_targets={nxt} if nxt else set(),
                    sink_name=sink if role == "sink" else None,
                    role=role,
                )
            )
        chains.append(
            {
                "sink": sink or _short_label(sink_method),
                "sink_vul": sink_vul,
                "sink_method": sink_method,
                "sink_line": sink_line,
                "call_chain": steps,
                "nodes": nodes,
                "path_label": " → ".join(_short_label(s) for s in steps),
            }
        )

    # Prefer gadget-relevant chains in the sidebar
    def _chain_rank(c: dict[str, Any]) -> tuple:
        label = c.get("path_label") or ""
        steps = list(c.get("call_chain") or [])
        body = " ".join(steps)
        score = 0
        # Classic CC1 skeleton first
        if (
            len(steps) == 3
            and "AnnotationInvocationHandler" in steps[0]
            and "LazyMap#get" in steps[1]
            and "InvokerTransformer#transform" in steps[2]
        ):
            score += 200
            if "#invoke" in steps[0]:
                score += 30
        elif "AnnotationInvocationHandler" in body and "LazyMap" in body and "InvokerTransformer" in body:
            score += 120
        elif "AnnotationInvocationHandler" in body and "LazyMap" in body:
            score += 90
        elif "AnnotationInvocationHandler" in body:
            score += 70
        if "LazyMap.get" in label:
            score += 40
        if "TiedMapEntry" in label:
            score += 25
        if "ChainedTransformer" in label:
            score += 30
        if "InvokerTransformer" in label:
            score += 20
        if "BeanMap" in label and "InvokerTransformer" not in body:
            score -= 50
        if (c.get("sink_vul") or "") == "REFLECTION":
            score += 15
        return (-score, len(steps))

    chains.sort(key=_chain_rank)

    # Sink catalog for report UI (callers carry source nodes for click-to-view)
    sink_catalog: dict[str, dict[str, Any]] = {}
    caller_qns_by_key: dict[str, list[str]] = {}

    def _add_caller(key: str, mq: str) -> None:
        if not mq:
            return
        qns = caller_qns_by_key.setdefault(key, [])
        if mq not in qns:
            qns.append(mq)

    for f in report.get("findings") or []:
        owner = f.get("sink_owner") or ""
        name = f.get("sink") or ""
        vul = f.get("vul") or "?"
        key = f"{vul}|{owner}|{name}"
        slot = sink_catalog.setdefault(
            key,
            {
                "vul": vul,
                "owner": owner,
                "name": name,
                "count": 0,
                "callers": [],
            },
        )
        slot["count"] += 1
        _add_caller(key, f.get("method") or "")
    for su in report.get("sink_users") or []:
        for s in su.get("sinks") or []:
            owner = s.get("owner") or ""
            name = s.get("name") or ""
            vul = s.get("vul") or "?"
            key = f"{vul}|{owner}|{name}"
            if key not in sink_catalog:
                sink_catalog[key] = {
                    "vul": vul,
                    "owner": owner,
                    "name": name,
                    "count": 0,
                    "callers": [],
                }
            _add_caller(key, su.get("method") or "")

    # Prefer finding.node when available; else build from source
    finding_node_by_method: dict[str, dict[str, Any]] = {}
    for f in findings:
        mq = f.get("method") or ""
        if mq and f.get("node") and mq not in finding_node_by_method:
            finding_node_by_method[mq] = f["node"]

    for key, slot in sink_catalog.items():
        callers_out: list[dict[str, Any]] = []
        for mq in caller_qns_by_key.get(key, []):
            node = finding_node_by_method.get(mq) or build_method_node(
                mq,
                app_root,
                highlight_lines=sink_lines.get(mq, set()),
                sink_name=slot.get("name"),
                role="sink",
            )
            callers_out.append(
                {
                    "qn": mq,
                    "label": _short_label(mq),
                    "node": node,
                }
            )
        slot["callers"] = callers_out

    catalog_list = sorted(
        sink_catalog.values(),
        key=lambda x: (
            0 if x["vul"] == "REFLECTION" else 1 if x["vul"] == "SERIALIZE" else 2,
            -(x["count"] or 0),
            x["owner"],
            x["name"],
        ),
    )

    out = dict(report)
    out["findings"] = findings
    out["call_chains_to_sinks"] = chains
    out["field_paths"] = list(report.get("field_paths") or [])
    out["sink_catalog"] = catalog_list
    out["app_root"] = str(app_root)
    return out


def write_html(report: dict[str, Any], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # allow already-enriched or raw
    if report.get("call_chains_to_sinks") and report["call_chains_to_sinks"] and "nodes" in (
        report["call_chains_to_sinks"][0] or {}
    ):
        enriched = report
    else:
        enriched = enrich_report(report)

    payload = {
        "project": enriched.get("project"),
        "mode": enriched.get("mode"),
        "chains": enriched.get("call_chains_to_sinks") or [],
        "field_paths": enriched.get("field_paths") or [],
        "sink_catalog": enriched.get("sink_catalog") or [],
        "findings": [
            {
                "sink": f.get("sink"),
                "sink_owner": f.get("sink_owner"),
                "vul": f.get("vul"),
                "method": f.get("method"),
                "line": f.get("line"),
                "arg": f.get("arg"),
                "source_kind": f.get("source_kind"),
                "tainted_vars": f.get("tainted_vars") or [],
                "evidence": f.get("evidence") or [],
                "call_chains": f.get("call_chains") or [],
                "node": f.get("node"),
            }
            for f in enriched.get("findings") or []
        ],
        "stats": {
            "findings": len(enriched.get("findings") or []),
            "chains": len(enriched.get("call_chains_to_sinks") or []),
            "field_paths": len(enriched.get("field_paths") or []),
            "sinks": len(enriched.get("sink_catalog") or []),
            "methods": enriched.get("methods", 0),
            "call_sites": enriched.get("call_sites", 0),
        },
    }
    data_json = json.dumps(payload, ensure_ascii=False)

    body = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>SAST Report — {html.escape(str(enriched.get('project')))}</title>
<style>
  :root {{
    --bg:#0e1014; --panel:#161a22; --fg:#e8eaef; --muted:#8b93a7;
    --line:#2a3142; --acc:#6aa7ff; --sink:#ff6b6b; --call:#f0c674;
    --sens:#c792ea; --node:#1e2533; --node-on:#2a3a55; --node-sink:#3a2228;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:14px/1.45 ui-sans-serif,system-ui,sans-serif; background:var(--bg); color:var(--fg); }}
  header {{ padding:20px 24px 8px; border-bottom:1px solid var(--line); }}
  h1 {{ margin:0 0 6px; font-size:20px; font-weight:650; }}
  .sub {{ color:var(--muted); font-size:13px; }}
  .tabs {{ display:flex; gap:8px; margin-top:12px; }}
  .tab {{
    appearance:none; border:1px solid var(--line); background:var(--panel); color:var(--muted);
    border-radius:999px; padding:6px 12px; cursor:pointer; font-size:12px;
  }}
  .tab.active {{ color:var(--fg); border-color:var(--acc); background:#1a2436; }}
  .layout {{ display:grid; grid-template-columns:320px 1fr; min-height:calc(100vh - 120px); }}
  @media (max-width:900px) {{ .layout {{ grid-template-columns:1fr; }} }}
  .sidebar {{ border-right:1px solid var(--line); padding:12px; overflow:auto; max-height:calc(100vh - 120px); }}
  .main {{ padding:16px 20px 32px; display:flex; flex-direction:column; gap:14px; min-width:0; }}
  .chain-item, .sink-item, .finding-item, .field-item {{
    width:100%; text-align:left; background:var(--panel); border:1px solid var(--line);
    border-radius:10px; padding:10px 12px; margin-bottom:8px; color:var(--fg); cursor:pointer;
  }}
  .chain-item:hover, .sink-item:hover, .finding-item:hover, .field-item:hover {{ border-color:var(--acc); }}
  .chain-item.active, .sink-item.active, .finding-item.active, .field-item.active {{ border-color:var(--acc); background:#1a2436; }}
  .field-edge {{ color:var(--call); font-family:ui-monospace,Menlo,monospace; font-size:12px; }}
  .sink-tag {{ color:var(--sink); font-size:12px; font-weight:600; }}
  .vul {{
    display:inline-block; font-size:10px; font-weight:700; border-radius:4px;
    padding:1px 6px; margin-right:6px; background:#3a2a12; color:#f0c674;
  }}
  .vul.REFLECTION {{ background:#3a2228; color:#ffb4b4; }}
  .vul.SERIALIZE {{ background:#1e2a3a; color:#9ec1ff; }}
  .path {{ color:var(--muted); font-size:12px; margin-top:4px; word-break:break-all; }}
  .path-bar {{
    display:flex; flex-wrap:wrap; align-items:center; gap:6px; padding:12px 14px;
    background:var(--panel); border:1px solid var(--line); border-radius:12px;
  }}
  .node {{
    appearance:none; border:1px solid var(--line); background:var(--node); color:var(--fg);
    border-radius:999px; padding:7px 12px; font:13px/1 ui-monospace,Menlo,monospace;
    cursor:pointer;
  }}
  .node:hover {{ border-color:var(--acc); }}
  .node.active {{ background:var(--node-on); border-color:var(--acc); color:#fff; }}
  .node.role-sink {{ background:var(--node-sink); border-color:#7a3a42; }}
  .node.role-sink.active {{ border-color:var(--sink); }}
  .arrow {{ color:var(--muted); font-size:14px; user-select:none; padding:0 2px; }}
  .meta {{ color:var(--muted); font-size:12px; display:flex; flex-wrap:wrap; gap:10px 16px; }}
  .meta code {{ color:var(--acc); font-family:ui-monospace,Menlo,monospace; }}
  .legend {{ display:flex; gap:14px; flex-wrap:wrap; font-size:12px; color:var(--muted); }}
  .legend i {{ display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:5px; vertical-align:-1px; }}
  .legend .m-sink {{ background:var(--sink); }}
  .legend .m-call {{ background:var(--call); }}
  .legend .m-sens {{ background:var(--sens); }}
  .code-wrap {{
    background:#0b0d12; border:1px solid var(--line); border-radius:12px; overflow:auto;
    max-height:calc(100vh - 280px); font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;
  }}
  .code-line {{ display:grid; grid-template-columns:56px 1fr; gap:0; padding:0 12px; white-space:pre; }}
  .code-line .ln {{ color:#5c6578; text-align:right; padding-right:12px; user-select:none; border-right:1px solid #1c2230; }}
  .code-line .tx {{ padding-left:14px; color:#d5dae6; }}
  .code-line.mark-sink {{ background:rgba(255,107,107,.14); }}
  .code-line.mark-sink .tx {{ color:#ffc9c9; }}
  .code-line.mark-call {{ background:rgba(240,198,116,.12); }}
  .code-line.mark-call .tx {{ color:#ffe2a8; }}
  .code-line.mark-sensitive {{ background:rgba(199,146,234,.10); }}
  .code-line .badge {{
    display:inline-block; font-size:10px; font-weight:700; letter-spacing:.03em;
    border-radius:4px; padding:1px 5px; margin-right:8px; vertical-align:2px;
  }}
  .badge.sink {{ background:var(--sink); color:#1a0a0a; }}
  .badge.call {{ background:var(--call); color:#1a1405; }}
  .badge.sensitive {{ background:var(--sens); color:#1a1020; }}
  .empty {{ color:var(--muted); padding:24px; }}
  .caller {{ font-size:11px; color:var(--muted); margin-top:3px; word-break:break-all; }}
  .caller-list {{
    display:flex; flex-wrap:wrap; align-items:center; gap:6px; padding:0;
  }}
  .caller-btn {{
    appearance:none; border:1px solid var(--line); background:var(--node); color:var(--fg);
    border-radius:8px; padding:6px 10px; font:12px/1.3 ui-monospace,Menlo,monospace;
    cursor:pointer; max-width:100%; text-align:left;
  }}
  .caller-btn:hover {{ border-color:var(--acc); }}
  .caller-btn.active {{ background:var(--node-on); border-color:var(--acc); color:#fff; }}
</style>
</head>
<body>
<header>
  <h1>SAST Analyze Report</h1>
  <div class="sub">project=<span id="proj"></span> · mode=<span id="mode"></span> · sinks=<span id="stSinks"></span> · findings=<span id="stFindings"></span> · chains=<span id="stChains"></span> · fields=<span id="stFields"></span></div>
  <div class="tabs">
    <button class="tab active" data-tab="chains">Call Chains</button>
    <button class="tab" data-tab="fields">Object Graph</button>
    <button class="tab" data-tab="sinks">Sinks</button>
    <button class="tab" data-tab="findings">Findings</button>
  </div>
</header>
<div class="layout">
  <aside class="sidebar" id="sidebar"></aside>
  <section class="main">
    <div class="path-bar" id="pathBar"><span class="empty">Select an item</span></div>
    <div class="meta" id="meta"></div>
    <div class="legend">
      <span><i class="m-sink"></i>sink / 敏感点</span>
      <span><i class="m-call"></i>调用下一跳</span>
      <span><i class="m-sens"></i>危险 API</span>
    </div>
    <div class="code-wrap" id="code"><div class="empty">Click a chain / finding</div></div>
  </section>
</div>
<script>
const DATA = {data_json};

function esc(s) {{
  return String(s ?? "").replace(/[&<>"']/g, c => ({{"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"}}[c]));
}}

let tab = "chains";
let chainIdx = 0;
let nodeIdx = 0;
let findingIdx = 0;
let sinkIdx = 0;
let callerIdx = 0;
let fieldIdx = 0;

function callerLabel(c) {{
  if (!c) return "";
  if (typeof c === "string") return c;
  return c.label || c.qn || "";
}}
function callerQn(c) {{
  if (!c) return "";
  if (typeof c === "string") return c;
  return c.qn || c.label || "";
}}
function callerNode(c) {{
  if (!c || typeof c === "string") return null;
  return c.node || null;
}}

document.querySelectorAll(".tab").forEach(btn => {{
  btn.onclick = () => {{
    tab = btn.dataset.tab;
    document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === tab));
    nodeIdx = 0;
    render();
  }};
}});

function renderSidebar() {{
  const el = document.getElementById("sidebar");
  if (tab === "fields") {{
    el.innerHTML = (DATA.field_paths || []).map((p, i) => `
      <button class="field-item ${{i===fieldIdx?"active":""}}" data-i="${{i}}">
        <div class="sink-tag">MAY_REF · ${{p.hops || (p.type_chain||[]).length}} types</div>
        <div class="path">${{esc(p.path_label || "")}}</div>
      </button>
    `).join("") || '<div class="empty">No field / object-graph paths</div>';
    el.querySelectorAll(".field-item").forEach(btn => {{
      btn.onclick = () => {{ fieldIdx = +btn.dataset.i; render(); }};
    }});
    return;
  }}
  if (tab === "sinks") {{
    el.innerHTML = (DATA.sink_catalog || []).map((s, i) => `
      <button class="sink-item ${{i===sinkIdx?"active":""}}" data-i="${{i}}">
        <div class="sink-tag"><span class="vul ${{esc(s.vul)}}">${{esc(s.vul)}}</span>${{esc(s.name || "?")}} · ${{s.count || (s.callers||[]).length}} hits</div>
        <div class="path">${{esc(s.owner || "(entry / local)")}}</div>
        <div class="caller">${{esc((s.callers || []).slice(0,3).map(callerLabel).join(" · "))}}${{(s.callers||[]).length>3?" …":""}}</div>
      </button>
    `).join("") || '<div class="empty">No sinks</div>';
    el.querySelectorAll(".sink-item").forEach(btn => {{
      btn.onclick = () => {{ sinkIdx = +btn.dataset.i; callerIdx = 0; render(); }};
    }});
    return;
  }}
  if (tab === "findings") {{
    el.innerHTML = (DATA.findings || []).map((f, i) => `
      <button class="finding-item ${{i===findingIdx?"active":""}}" data-i="${{i}}">
        <div class="sink-tag"><span class="vul ${{esc(f.vul||"")}}">${{esc(f.vul || "?")}}</span>${{esc(f.sink)}} @ L${{f.line}}</div>
        <div class="path">${{esc(f.method)}}</div>
      </button>
    `).join("") || '<div class="empty">No findings</div>';
    el.querySelectorAll(".finding-item").forEach(btn => {{
      btn.onclick = () => {{ findingIdx = +btn.dataset.i; nodeIdx = 0; render(); }};
    }});
    return;
  }}
  el.innerHTML = (DATA.chains || []).map((c, i) => `
    <button class="chain-item ${{i===chainIdx?"active":""}}" data-i="${{i}}">
      <div class="sink-tag"><span class="vul ${{esc(c.sink_vul||"")}}">${{esc(c.sink_vul || "CHAIN")}}</span>${{esc(c.sink)}} · ${{c.nodes.length}} hops</div>
      <div class="path">${{esc(c.path_label)}}</div>
    </button>
  `).join("") || '<div class="empty">No chains</div>';
  el.querySelectorAll(".chain-item").forEach(btn => {{
    btn.onclick = () => {{ chainIdx = +btn.dataset.i; nodeIdx = 0; render(); }};
  }});
}}

function renderCode(node) {{
  const box = document.getElementById("code");
  if (!node || !node.lines || !node.lines.length) {{
    box.innerHTML = '<div class="empty">No source for this method</div>';
    return;
  }}
  box.innerHTML = node.lines.map(line => {{
    const marks = line.marks || [];
    const cls = marks.length ? " mark-" + marks[0] : "";
    const badges = marks.map(m => `<span class="badge ${{m}}">${{m}}</span>`).join("");
    return `<div class="code-line${{cls}}"><span class="ln">${{line.n}}</span><span class="tx">${{badges}}${{esc(line.text)}}</span></div>`;
  }}).join("");
  const hit = box.querySelector(".mark-sink, .mark-call");
  if (hit) hit.scrollIntoView({{ block: "center", behavior: "smooth" }});
}}

function render() {{
  document.getElementById("proj").textContent = DATA.project || "";
  document.getElementById("mode").textContent = DATA.mode || "";
  document.getElementById("stSinks").textContent = (DATA.stats && DATA.stats.sinks) || (DATA.sink_catalog||[]).length;
  document.getElementById("stFindings").textContent = (DATA.stats && DATA.stats.findings) || (DATA.findings||[]).length;
  document.getElementById("stChains").textContent = (DATA.stats && DATA.stats.chains) || (DATA.chains||[]).length;
  document.getElementById("stFields").textContent = (DATA.stats && DATA.stats.field_paths) || (DATA.field_paths||[]).length;
  renderSidebar();
  const bar = document.getElementById("pathBar");
  const meta = document.getElementById("meta");

  if (tab === "fields") {{
    const p = (DATA.field_paths || [])[fieldIdx];
    if (!p) {{
      bar.innerHTML = '<span class="empty">No field path</span>';
      meta.innerHTML = "";
      document.getElementById("code").innerHTML = '<div class="empty">Object-graph paths show Type —field→ Type (CHA POINTS_TO / MAY_REF)</div>';
      return;
    }}
    const types = p.type_chain || [];
    const fields = p.field_chain || [];
    bar.innerHTML = types.map((t, i) => {{
      const simple = (t || "").split(".").pop();
      const edge = i < fields.length ? `<span class="field-edge">.${{esc(fields[i])}}→</span>` : "";
      return `<span class="node role-sink">${{esc(simple)}}</span>${{edge}}`;
    }}).join("");
    meta.innerHTML = `
      <span>entry <code>${{esc(p.entry_type || "")}}</code></span>
      <span>sink type <code>${{esc(p.sink_type || "")}}</code></span>
      <span>fields <code>${{esc((fields || []).join(" → "))}}</code></span>
      <span>serializable_write <code>${{esc(JSON.stringify(p.serializable_write || []))}}</code></span>
    `;
    const rows = types.map((t, i) => {{
      const fld = fields[i] || "";
      const key = (p.field_keys || [])[i] || "";
      const ser = (p.serializable_write || [])[i];
      return `<div class="code-line"><span class="ln">${{i+1}}</span><span class="tx">${{esc(t)}}${{fld ? `  <span class="badge call">.${{esc(fld)}}</span>` : ""}}${{key ? `  // ${{esc(key)}}` : ""}}${{ser===true ? `  <span class="badge sink">ser-write</span>` : ""}}</span></div>`;
    }}).join("");
    document.getElementById("code").innerHTML = rows || '<div class="empty">No nodes</div>';
    return;
  }}

  if (tab === "sinks") {{
    const s = (DATA.sink_catalog || [])[sinkIdx];
    if (!s) {{
      bar.innerHTML = '<span class="empty">No sink</span>';
      meta.innerHTML = "";
      document.getElementById("code").innerHTML = '<div class="empty">No data</div>';
      return;
    }}
    const callers = s.callers || [];
    if (callerIdx >= callers.length) callerIdx = 0;
    bar.innerHTML = `<span class="vul ${{esc(s.vul)}}">${{esc(s.vul)}}</span> <code>${{esc(s.owner)}}#${{esc(s.name)}}</code>`;
    meta.innerHTML = `
      <span>callers <code>${{callers.length}}</code> — click to view source</span>
      <div class="caller-list" id="callerList">
        ${{callers.map((c, i) => `
          <button class="caller-btn ${{i===callerIdx?"active":""}}" data-i="${{i}}" title="${{esc(callerQn(c))}}">${{esc(callerLabel(c))}}</button>
        `).join("")}}
      </div>
    `;
    document.querySelectorAll("#callerList .caller-btn").forEach(btn => {{
      btn.onclick = () => {{ callerIdx = +btn.dataset.i; render(); }};
    }});
    const selected = callers[callerIdx];
    const node = callerNode(selected);
    if (node) {{
      renderCode(node);
    }} else {{
      // fallback: look up finding by method qn
      const mq = callerQn(selected);
      const f = (DATA.findings || []).find(x => x.method === mq);
      renderCode(f && f.node);
    }}
    return;
  }}

  if (tab === "findings") {{
    const f = (DATA.findings || [])[findingIdx];
    if (!f) {{
      bar.innerHTML = '<span class="empty">No finding</span>';
      meta.innerHTML = "";
      document.getElementById("code").innerHTML = '<div class="empty">No data</div>';
      return;
    }}
    bar.innerHTML = `<span class="vul ${{esc(f.vul||"")}}">${{esc(f.vul || "?")}}</span> <code>${{esc(f.sink_owner || "")}}#${{esc(f.sink)}}</code> @ L${{f.line}}`;
    meta.innerHTML = `
      <span>method <code>${{esc(f.method)}}</code></span>
      <span>arg <code>${{esc(f.arg)}}</code></span>
      <span>src <code>${{esc(f.source_kind)}}</code></span>
      <span>tainted <code>${{esc((f.tainted_vars||[]).join(", "))}}</code></span>
    `;
    renderCode(f.node);
    return;
  }}

  const chain = (DATA.chains || [])[chainIdx];
  if (!chain) {{
    bar.innerHTML = '<span class="empty">No chain</span>';
    meta.innerHTML = "";
    document.getElementById("code").innerHTML = '<div class="empty">No data</div>';
    return;
  }}
  bar.innerHTML = chain.nodes.map((n, i) => {{
    const active = i === nodeIdx ? " active" : "";
    const role = n.role === "sink" ? " role-sink" : "";
    const sep = i < chain.nodes.length - 1 ? '<span class="arrow">→</span>' : "";
    return `<button class="node${{active}}${{role}}" data-i="${{i}}">${{esc(n.label)}}</button>${{sep}}`;
  }}).join("");
  bar.querySelectorAll(".node").forEach(btn => {{
    btn.onclick = () => {{ nodeIdx = +btn.dataset.i; render(); }};
  }});
  const node = chain.nodes[nodeIdx];
  meta.innerHTML = `
    <span>method <code>${{esc(node.qn)}}</code></span>
    <span>file <code>${{esc(node.file)}}</code></span>
    <span>role <code>${{esc(node.role)}}</code></span>
    ${{chain.sink ? `<span>chain sink <code>${{esc(chain.sink_vul || "")}}/${{esc(chain.sink)}}</code> @ L${{chain.sink_line}}</span>` : ""}}
  `;
  renderCode(node);
}}

render();
</script>
</body>
</html>
"""
    path.write_text(body, encoding="utf-8")
    path.with_suffix(".enriched.json").write_text(
        json.dumps(enriched, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return path
