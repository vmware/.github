#!/usr/bin/env python3
"""
OpenSSF Scorecard org/targeted scanner with CSV + HTML dashboard.

Features:
- Scan an entire GitHub.com organization OR a specific repo/list/file.
- Parallel runs of the Scorecard CLI (native or Docker image via --mode docker).
- Produces per-repo JSON, a summary CSV, and a self-contained HTML dashboard.
- Skips existing JSON by default (fast re-runs); use --overwrite to force fresh scans.
- Dashboard includes:
    * Per-repo "Details" modal (all checks: name/score/reason/details/docs)
    * Deep-link to official viewer (public repos only)
    * Heatmap tab: repos (rows) × checks (columns), color-coded, CSV export

Examples:
  export GITHUB_AUTH_TOKEN=ghp_xxx[,ghp_yyy]
  python3 scorecard_org_scan.py --org YOUR_ORG --out out
  python3 scorecard_org_scan.py --repo owner/name --out out
  python3 scorecard_org_scan.py --org YOUR_ORG --repos repo1,repo2 --overwrite
"""
import argparse
import os
import sys
import json
import csv
import subprocess
import concurrent.futures as cf
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional

import requests

API = "https://api.github.com"


def gh_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}


def list_repos_from_org(
    org: str,
    token: str,
    include_archived: bool = False,
    only_private: bool = False,
    include_forks: bool = False,
) -> List[str]:
    """Enumerate repos from a GitHub.com org."""
    repos: List[str] = []
    page = 1
    while True:
        r = requests.get(
            f"{API}/orgs/{org}/repos",
            headers=gh_headers(token),
            params={
                "per_page": 100,
                "page": page,
                "type": "all",
                "sort": "full_name",
                "direction": "asc",
            },
            timeout=60,
        )
        if r.status_code != 200:
            raise RuntimeError(f"GitHub API error {r.status_code}: {r.text}")
        batch = r.json()
        if not batch:
            break
        for repo in batch:
            if not include_archived and repo.get("archived", False):
                continue
            if only_private and not repo.get("private", False):
                continue
            if not include_forks and repo.get("fork", False):
                continue
            repos.append(repo["full_name"])
        page += 1
    return repos


def normalize_repo(s: str, org_default: Optional[str]) -> str:
    """Return 'owner/name' from inputs like 'name' or 'owner/name'."""
    s = (s or "").strip().strip("/")
    if not s:
        return ""
    if "/" in s:
        return s
    if not org_default:
        raise ValueError(
            f"Repository '{s}' is missing owner. Provide as 'owner/{s}' or set --org."
        )
    return f"{org_default}/{s}"


def collect_target_repos(args, token: str) -> List[str]:
    """Collect the list of targets from flags or org enumeration."""
    targets: List[str] = []

    # Single
    if args.repo:
        targets.append(normalize_repo(args.repo, args.org))

    # Comma list
    if args.repos:
        for item in args.repos.split(","):
            if item.strip():
                targets.append(normalize_repo(item, args.org))

    # File list
    if args.repos_file:
        p = Path(args.repos_file)
        if not p.exists():
            raise FileNotFoundError(f"--repos-file not found: {p}")
        for line in p.read_text().splitlines():
            if line.strip():
                targets.append(normalize_repo(line, args.org))

    # Full org
    if not targets:
        if not args.org:
            raise SystemExit(
                "Provide --org for organization scan, or use --repo/--repos/--repos-file for explicit targets."
            )
        targets = list_repos_from_org(
            org=args.org,
            token=token,
            include_archived=args.include_archived,
            only_private=args.only_private,
            include_forks=args.include_forks,
        )

    # De-duplicate
    seen, deduped = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


def run_scorecard(
    repo: str,
    outdir: Path,
    mode: str,
    extra_args: List[str],
    overwrite: bool,
) -> Tuple[str, str]:
    """Run scorecard for a single repo; returns (repo, status)."""
    out_path = outdir / f"{repo.replace('/', '_')}.json"
    if out_path.exists() and not overwrite:
        return (repo, "skipped (exists)")

    if mode == "docker":
        cmd = [
            "docker",
            "run",
            "--rm",
            "-e",
            "GITHUB_AUTH_TOKEN=" + os.getenv("GITHUB_AUTH_TOKEN", ""),
            "gcr.io/openssf/scorecard:stable",
            f"--repo=github.com/{repo}",
            "--format=json",
            *extra_args,
        ]
    else:
        cmd = ["scorecard", f"--repo=github.com/{repo}", "--format=json", *extra_args]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        if res.returncode != 0:
            return (repo, f"fail rc={res.returncode}: {res.stderr.strip()[:300]}")
        out_path.write_text(res.stdout, encoding="utf-8")
        return (repo, "ok")
    except Exception as e:
        return (repo, f"error: {e}")


def parse_score(json_obj: Dict[str, Any]) -> Tuple[Optional[float], str, List[Dict]]:
    """Returns (score, date/timestamp, checks_list)."""
    score = json_obj.get("score") or json_obj.get("aggregateScore")
    date = json_obj.get("date") or json_obj.get("timestamp") or ""
    checks = json_obj.get("checks") or []
    return (score, date, checks)


def summarize(outdir: Path, csv_path: Path, threshold: float) -> Dict[str, Any]:
    rows, scores, details = [], [], []
    below, total = 0, 0
    for p in sorted(outdir.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8") or "{}")
        except Exception:
            data = {}
        score, date, checks = parse_score(data)
        repo_name = (data.get("repo", {}) or {}).get("name") or p.stem.replace("_", "/")
        if isinstance(score, (int, float)):
            s = float(score)
            scores.append(s)
            if s < threshold:
                below += 1
        else:
            s = None
        checks_failing = 0
        if isinstance(checks, list):
            for c in checks:
                sc = c.get("score")
                if isinstance(sc, (int, float)) and sc < threshold:
                    checks_failing += 1
        rows.append({"repo": repo_name, "score": s if s is not None else "", "date": date})
        details.append(
            {
                "repo": repo_name,
                "score": s,
                "date": date,
                "json_file": p.name,
                "checks_failing": checks_failing,
            }
        )
        total += 1
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["repo", "score", "date"])
        w.writeheader()
        w.writerows(rows)
    avg = (sum(scores) / len(scores)) if scores else None
    med = (sorted(scores)[len(scores) // 2] if scores else None)
    return {
        "total": total,
        "avg": avg,
        "median": med,
        "below": below,
        "scores": scores,
        "details": details,
    }


def make_dashboard(
    outdir: Path, dash_path: Path, stats: Dict[str, Any], org: Optional[str], title: str, threshold: float
):
    # Prepare summary
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    total = stats["total"]
    avg = f"{stats['avg']:.2f}" if stats["avg"] is not None else "n/a"
    med = f"{stats['median']:.2f}" if stats["median"] is not None else "n/a"
    below = stats["below"]
    rows_js = json.dumps(stats["details"])
    # histogram bins 0..10
    bins = [0] * 11
    for s in stats["scores"]:
        b = max(0, min(10, int(round(s))))
        bins[b] += 1
    bins_js = json.dumps(bins)
    org_txt = org if org else "(ad-hoc repo list)"

    # Full dashboard HTML/JS (Table + Details modal + official viewer link + Heatmap tab)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{title} – OpenSSF Scorecard Dashboard</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 24px; }}
h1 {{ margin: 0 0 6px 0; }}
small {{ color: #666; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px,1fr)); gap: 12px; margin: 16px 0 24px; }}
.card {{ border: 1px solid #e2e2e2; border-radius: 8px; padding: 12px; }}
.metric {{ font-size: 28px; font-weight: 700; }}
.label {{ color: #555; }}
.tabs {{ display:flex; gap:8px; margin: 18px 0 12px; border-bottom: 1px solid #eee; }}
.tab {{ padding: 8px 12px; border:1px solid #eee; border-bottom:none; border-radius:8px 8px 0 0; background:#fafafa; cursor:pointer; }}
.tab.active {{ background:#fff; border-bottom:1px solid #fff; }}
.view {{ display:none; }}
.view.active {{ display:block; }}
#controls {{ display:flex; gap:12px; align-items:center; margin: 8px 0 16px; flex-wrap: wrap; }}
input[type="search"] {{ padding: 8px 10px; border: 1px solid #ccc; border-radius: 6px; min-width: 260px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ padding: 8px 10px; border-bottom: 1px solid #eee; text-align: left; }}
th button {{ background: none; border: none; font-weight: 700; cursor: pointer; }}
.badge {{ padding: 3px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; display:inline-block; }}
.badge.good {{ background: #e6f4ea; color: #1e7b34; }}
.badge.warn {{ background: #fff4e5; color: #8c5200; }}
.badge.bad  {{ background: #fde8e8; color: #b42318; }}
.rowlink {{ color: #0366d6; text-decoration: none; }}
.footer {{ color:#777; margin-top: 24px; }}
canvas {{ max-width: 680px; width: 100%; height: 220px; border: 1px solid #eee; border-radius: 6px; }}

.details-btn {{ padding:6px 10px; border:1px solid #ddd; background:#fafafa; border-radius:6px; cursor:pointer; }}
.viewer-btn  {{ padding:6px 10px; border:1px solid #ddd; background:#eef6ff; color:#064; border-radius:6px; cursor:pointer; }}

#modal {{ position: fixed; inset: 0; display:none; background: rgba(0,0,0,.35); }}
#modal .card {{ background:#fff; max-width: 980px; margin: 5vh auto; padding:16px; border-radius:10px; box-shadow: 0 10px 30px rgba(0,0,0,.15); }}
#modal .close {{ float:right; cursor:pointer; font-weight:700; }}
.checks {{ width:100%; border-collapse: collapse; margin-top: 12px; }}
.checks th, .checks td {{ border-bottom:1px solid #eee; padding:8px 10px; text-align:left; vertical-align: top; }}
.badge.rgood {{ background:#e6f4ea; color:#1e7b34; }}
.badge.rwarn {{ background:#fff4e5; color:#8c5200; }}
.badge.rbad  {{ background:#fde8e8; color:#b42318; }}
#checkFilter {{ padding:6px 8px; border:1px solid #ccc; border-radius:6px; min-width: 240px; }}

.heat-controls {{ display:flex; gap:12px; align-items:center; margin: 8px 0 12px; flex-wrap: wrap; }}
.heat-table {{ width:100%; border-collapse:collapse; }}
.heat-table th, .heat-table td {{ border-bottom:1px solid #eee; padding:6px 8px; white-space:nowrap; }}
.cell {{ text-align:center; font-weight:600; border-radius:4px; }}
.cell.na {{ color:#999; }}
legend {{ font-size:13px; color:#666; }}
.legend-swatch {{ display:inline-block; width:16px; height:12px; vertical-align:middle; margin-right:4px; border:1px solid #ddd; }}
</style>
</head>
<body>
<h1>{title}</h1>
<small>Target: <strong>{org_txt}</strong> · Threshold: <strong>{threshold}</strong> · Generated: {now}</small>

<div class="summary">
  <div class="card"><div class="metric">{total}</div><div class="label">Repositories</div></div>
  <div class="card"><div class="metric">{avg}</div><div class="label">Average Score</div></div>
  <div class="card"><div class="metric">{med}</div><div class="label">Median Score</div></div>
  <div class="card"><div class="metric">{below}</div><div class="label">&lt; {threshold} Score</div></div>
</div>

<canvas id="hist"></canvas>

<div class="tabs">
  <div class="tab active" data-view="table">Table</div>
  <div class="tab" data-view="heatmap">Heatmap</div>
</div>

<!-- TABLE VIEW -->
<div id="table" class="view active">
  <div id="controls">
    <input id="q" type="search" placeholder="Filter by repository name…"/>
    <label><input type="checkbox" id="onlyLow"> Only below threshold</label>
  </div>

  <table id="tbl">
    <thead>
      <tr>
        <th><button data-k="repo">Repository</button></th>
        <th><button data-k="score">Score</button></th>
        <th><button data-k="checks_failing">Checks &lt; {threshold}</button></th>
        <th><button data-k="date">Date</button></th>
        <th>JSON</th>
        <th>Details</th>
        <th>Official</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>
</div>

<!-- HEATMAP VIEW -->
<div id="heatmap" class="view">
  <div class="heat-controls">
    <input id="heatFilter" type="search" placeholder="Filter repos…">
    <input id="checkNameFilter" type="search" placeholder="Filter checks…">
    <button id="exportCsv">Export CSV</button>
    <span id="heatStatus" style="color:#666;"></span>
  </div>
  <div style="overflow:auto;">
    <table id="heatTbl" class="heat-table"></table>
  </div>
  <legend>
    <span class="legend-swatch" style="background:#e6f4ea;"></span> ≥7
    <span class="legend-swatch" style="background:#fff4e5; margin-left:8px;"></span> 5–&lt;7
    <span class="legend-swatch" style="background:#fde8e8; margin-left:8px;"></span> &lt;5
    <span class="legend-swatch" style="background:#f3f4f6; margin-left:8px;"></span> n/a
  </legend>
</div>

<!-- DETAILS MODAL -->
<div id="modal">
  <div class="card">
    <span class="close" onclick="closeDetails()">✕</span>
    <h2 id="mTitle">Details</h2>
    <div id="mMeta" style="color:#555;margin-bottom:8px;"></div>
    <div style="margin: 8px 0;">
      <input id="checkFilter" type="search" placeholder="Filter by check name…">
      <a id="viewerLink" class="viewer-btn" href="#" target="_blank" rel="noopener" style="display:none;">Open Official Viewer ↗</a>
    </div>
    <table class="checks" id="checksTbl">
      <thead><tr><th>Check</th><th>Score</th><th>Reason</th><th>Details</th><th>Docs</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>
</div>

<div class="footer">OpenSSF Scorecard report. Per-repo JSON artifacts saved alongside this file.</div>

<script>
const data = {rows_js};
const threshold = {threshold};
let sortKey = 'score';
let sortAsc = false;

// ---- helpers
function fmtScore(s) {{ return (s === null || s === undefined || s === '') ? 'n/a' : Number(s).toFixed(2); }}
function badgeClass(s) {{
  if (s === null || s === undefined || s === '') return 'badge';
  if (s >= Math.max(7.0, threshold)) return 'badge good';
  if (s >= threshold) return 'badge warn';
  return 'badge bad';
}}
function riskClass(s) {{
  if (s === null || s === undefined) return 'badge';
  if (s >= 7.0) return 'badge rgood';
  if (s >= 5.0) return 'badge rwarn';
  return 'badge rbad';
}}

// ---- histogram
(function() {{
  const bins = {bins_js};
  const canvas = document.getElementById('hist');
  const ctx = canvas.getContext('2d');
  function draw() {{
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0,0,W,H);
    const maxV = Math.max(1, ...bins);
    const pad = 24;
    const bw = (W - pad*2) / bins.length;
    ctx.strokeStyle = '#999';
    ctx.beginPath(); ctx.moveTo(pad, H-pad); ctx.lineTo(W-pad, H-pad); ctx.stroke();
    ctx.fillStyle = '#888';
    bins.forEach((v,i) => {{
      const x = pad + i*bw + 2;
      const h = (H - pad*2) * (v / maxV);
      ctx.fillRect(x, H-pad - h, bw-4, h);
    }});
    ctx.fillStyle = '#444';
    ctx.font = '12px system-ui';
    for (let i=0;i<=10;i+=1) {{
      const x = pad + i*bw;
      ctx.fillText(String(i), x+2, H-6);
    }}
  }}
  function resize() {{
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.floor(canvas.clientWidth * ratio);
    canvas.height = Math.floor(220 * ratio);
    draw();
  }}
  new ResizeObserver(resize).observe(canvas);
  resize();
}})();

// ---- table rendering
function renderTable() {{
  const q = document.getElementById('q').value.toLowerCase();
  const onlyLow = document.getElementById('onlyLow').checked;
  let rows = data.filter(r => r.repo.toLowerCase().includes(q));
  if (onlyLow) rows = rows.filter(r => (r.score ?? -1) < threshold);
  rows.sort((a,b) => {{
    const x = a[sortKey], y = b[sortKey];
    if (x === y) return 0;
    if (x === null || x === undefined) return 1;
    if (y === null || y === undefined) return -1;
    if (x < y) return sortAsc ? -1 : 1;
    if (x > y) return sortAsc ? 1 : -1;
    return 0;
  }});
  const tbody = document.querySelector('#tbl tbody');
  tbody.innerHTML = rows.map(r => {{
    const badge = badgeClass(r.score);
    const scoreTxt = fmtScore(r.score);
    const viewerUrl = 'https://scorecard.dev/viewer?uri=github.com/' + encodeURIComponent(r.repo);
    return `<tr>
      <td><a class="rowlink" href="https://github.com/${{r.repo}}" target="_blank" rel="noopener">${{r.repo}}</a></td>
      <td><span class="${{badge}}">${{scoreTxt}}</span></td>
      <td>${{r.checks_failing ?? ''}}</td>
      <td>${{r.date ?? ''}}</td>
      <td><a class="rowlink" href="./${{r.json_file}}" target="_blank" rel="noopener">JSON</a></td>
      <td><button class="details-btn" onclick="openDetails('${{r.json_file}}','${{r.repo.replace(/'/g, "\\'")}')">View</button></td>
      <td><a class="viewer-btn" href="${{viewerUrl}}" target="_blank" rel="noopener" title="Open official viewer (public repos only)">Viewer</a></td>
    </tr>`;
  }}).join('');
}}
document.querySelectorAll('th button').forEach(btn => {{
  btn.addEventListener('click', () => {{
    const k = btn.dataset.k;
    if (sortKey === k) sortAsc = !sortAsc; else {{ sortKey = k; sortAsc = (k === 'repo'); }}
    renderTable();
  }});
}});
document.getElementById('q').addEventListener('input', renderTable);
document.getElementById('onlyLow').addEventListener('change', renderTable);

// ---- details modal (+ official viewer deep-link check)
async function openDetails(jsonFile, repo) {{
  try {{
    const res = await fetch(jsonFile, {{cache: 'no-store'}});
    const data = await res.json();
    const checks = Array.isArray(data.checks) ? data.checks : [];
    const tbody = document.querySelector('#checksTbl tbody');
    document.getElementById('mTitle').textContent = `Scorecard checks – ${repo}`;
    document.getElementById('mMeta').textContent = `Run date: ${{data.date || data.timestamp || ''}} · Overall score: ${{fmtScore(data.score ?? data.aggregateScore)}}`;

    // Try to detect public repo by probing official API (will fail/403 for private)
    const viewerLink = document.getElementById('viewerLink');
    viewerLink.style.display = 'none';
    try {{
      const apiUrl = 'https://api.scorecard.dev/projects/github.com/' + repo;
      const probe = await fetch(apiUrl, {{ method: 'HEAD', mode: 'cors' }});
      if (probe.ok) {{
        viewerLink.href = 'https://scorecard.dev/viewer?uri=github.com/' + repo;
        viewerLink.style.display = 'inline-block';
      }}
    }} catch (e) {{
      /* ignore; keep inline only */
    }}

    const rows = checks.map(c => {{
      const nm = c.name || (c.documentation && c.documentation.short_name) || '(unknown)';
      const sc = (typeof c.score === 'number') ? c.score : null;
      const rs = c.reason || '';
      const dt = Array.isArray(c.details) ? c.details.join('<br/>') : (c.details || '');
      const doc = (c.documentation && c.documentation.url) ? `<a class="rowlink" href="${{c.documentation.url}}" target="_blank" rel="noopener">docs</a>` : '';
      return {{nm, sc, rs, dt, doc}};
    }});

    function renderChecks(filter = '') {{
      const q = filter.toLowerCase();
      const html = rows
        .filter(r => r.nm.toLowerCase().includes(q))
        .map(r => {{
          const cls = riskClass(r.sc);
          const scTxt = (r.sc === null) ? 'n/a' : Number(r.sc).toFixed(2);
          return `<tr>
            <td>${{r.nm}}</td>
            <td><span class="${{cls}}">${{scTxt}}</span></td>
            <td>${{r.rs || ''}}</td>
            <td>${{r.dt || ''}}</td>
            <td>${{r.doc}}</td>
          </tr>`;
        }}).join('');
      tbody.innerHTML = html || `<tr><td colspan="5" style="color:#777">No checks match your filter.</td></tr>`;
    }}

    const filterEl = document.getElementById('checkFilter');
    filterEl.value = '';
    filterEl.oninput = () => renderChecks(filterEl.value);
    renderChecks();
    document.getElementById('modal').style.display = 'block';
  }} catch (e) {{
    alert('Failed to load check details:\\n' + e);
  }}
}}
function closeDetails() {{ document.getElementById('modal').style.display = 'none'; }}

// ---- tabs
document.querySelectorAll('.tab').forEach(t => {{
  t.addEventListener('click', () => {{
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    t.classList.add('active');
    document.getElementById(t.dataset.view).classList.add('active');
    if (t.dataset.view === 'heatmap') initHeatmap();
  }});
}});

// ---- heatmap (lazy-loaded)
let heatLoaded = false, heatMatrix = null, heatChecks = [], heatRepos = [];
async function initHeatmap() {{
  if (heatLoaded) return;
  heatLoaded = true;
  const statusEl = document.getElementById('heatStatus');
  statusEl.textContent = 'Building heatmap…';
  try {{
    // Fetch all JSONs
    const jsons = await Promise.all(data.map(r => fetch(r.json_file, {{cache:'no-store'}}).then(x => x.json()).catch(_=>({{repo:{{name:r.repo}}, checks:[]}}))));
    // Collect checks set
    const set = new Set();
    jsons.forEach(j => (j.checks||[]).forEach(c => set.add(c.name || (c.documentation && c.documentation.short_name) || '(unknown)')));
    heatChecks = Array.from(set).sort();
    heatRepos = data.map(r => r.repo);
    // Build matrix repo x check -> score
    heatMatrix = heatRepos.map((repo, i) => {{
      const row = Object.fromEntries(heatChecks.map(k => [k, null]));
      const checks = (jsons[i].checks || []);
      checks.forEach(c => {{
        const nm = c.name || (c.documentation && c.documentation.short_name) || '(unknown)';
        const sc = (typeof c.score === 'number') ? c.score : null;
        row[nm] = sc;
      }});
      return row;
    }});
    renderHeatmap();
    statusEl.textContent = '';
  }} catch (e) {{
    statusEl.textContent = 'Failed to build heatmap: ' + e;
  }}
}}

function colorForScore(s) {{
  if (s === null || s === undefined) return '#f3f4f6'; // gray (n/a)
  if (s >= 7) return '#e6f4ea'; // green-ish
  if (s >= 5) return '#fff4e5'; // amber-ish
  return '#fde8e8';             // red-ish
}}

function renderHeatmap() {{
  const repoQ = document.getElementById('heatFilter').value.toLowerCase();
  const checkQ = document.getElementById('checkNameFilter').value.toLowerCase();
  const checks = heatChecks.filter(c => c.toLowerCase().includes(checkQ));
  const tbl = document.getElementById('heatTbl');
  let html = '<thead><tr><th>Repository</th>' + checks.map(c => `<th title="${{c}}">${{c}}</th>`).join('') + '</tr></thead><tbody>';
  heatRepos.forEach((repo, i) => {{
    if (!repo.toLowerCase().includes(repoQ)) return;
    html += `<tr><td><a class="rowlink" href="https://github.com/${{repo}}" target="_blank" rel="noopener">${{repo}}</a></td>`;
    checks.forEach(c => {{
      const sc = heatMatrix[i][c];
      const txt = (sc === null || sc === undefined) ? 'n/a' : Number(sc).toFixed(1);
      const bg = colorForScore(sc);
      html += `<td style="background:${{bg}}"><div class="cell ${{(sc==null)?'na':''}}">${{txt}}</div></td>`;
    }});
    html += '</tr>';
  }});
  html += '</tbody>';
  tbl.innerHTML = html;
}}

document.getElementById('heatFilter').addEventListener('input', () => renderHeatmap());
document.getElementById('checkNameFilter').addEventListener('input', () => renderHeatmap());

// CSV export of heatmap
document.getElementById('exportCsv').addEventListener('click', () => {{
  if (!heatMatrix) return;
  const checkQ = document.getElementById('checkNameFilter').value.toLowerCase();
  const checks = heatChecks.filter(c => c.toLowerCase().includes(checkQ));
  let csv = 'repo,' + checks.map(c => '"' + c.replace(/"/g,'""') + '"').join(',') + '\\n';
  heatRepos.forEach((repo, i) => {{
    const row = [ '"' + repo.replace(/"/g,'""') + '"' ];
    checks.forEach(c => {{
      const sc = heatMatrix[i][c];
      row.push(sc==null? '': sc.toFixed(2));
    }});
    csv += row.join(',') + '\\n';
  }});
  const blob = new Blob([csv], {{type:'text/csv'}});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'scorecard_heatmap.csv';
  a.click();
}});

// Initial render
renderTable();
</script>
</body>
</html>
"""
    dash_path.write_text(html, encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(
        description="Run OpenSSF Scorecard across a GitHub org or explicit repo list, then build a dashboard."
    )
    # Target selection
    ap.add_argument("--org", help="GitHub organization (GitHub.com). Required for org scans or to resolve bare repo names.")
    ap.add_argument("--repo", help="Scan a single repo (owner/name or bare name if --org is set).")
    ap.add_argument("--repos", help="Comma-separated repos (owner/name or bare if --org is set).")
    ap.add_argument("--repos-file", help="Path to a file with one repo per line (owner/name or bare; requires --org to resolve bare).")
    # Behavior / outputs
    ap.add_argument("--out", default="out", help="Output folder (JSON, CSV, HTML)")
    ap.add_argument("--mode", choices=["native", "docker"], default="native", help="Run scorecard natively or via docker image")
    ap.add_argument("--concurrency", type=int, default=8, help="Parallel workers")
    ap.add_argument("--include-archived", action="store_true", help="Include archived repositories (org scans)")
    ap.add_argument("--only-private", action="store_true", help="Scan only private repositories (org scans)")
    ap.add_argument("--include-forks", action="store_true", help="Include forks (org scans; default excluded)")
    ap.add_argument("--threshold", type=float, default=7.0, help="Score threshold for dashboard badges and counts")
    ap.add_argument("--title", default="OpenSSF Scorecard Dashboard", help="Dashboard title")
    ap.add_argument("--extra-scorecard-args", default="", help="Extra args passed to the scorecard CLI, space-separated")
    ap.add_argument("--overwrite", action="store_true", help="Re-run and replace per-repo JSON even if it already exists")
    args = ap.parse_args()

    token = os.getenv("GITHUB_AUTH_TOKEN")
    if not token:
        print("ERROR: set GITHUB_AUTH_TOKEN (classic PAT). For multiple tokens, comma-separate them.", file=sys.stderr)
        sys.exit(2)

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    # Collect targets
    try:
        targets = collect_target_repos(args, token.split(",")[0])
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    print(f"Scanning {len(targets)} repositories...")
    extra_args = [a for a in args.extra_scorecard_args.split(" ") if a.strip()]

    # Run scans
    with cf.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = [ex.submit(run_scorecard, r, outdir, args.mode, extra_args, args.overwrite) for r in targets]
        for fut in cf.as_completed(futs):
            repo, status = fut.result()
            print(f"{repo}: {status}")

    # Build CSV + dashboard
    csv_path = outdir / "summary.csv"
    stats = summarize(outdir, csv_path, args.threshold)
    dash_path = outdir / "dashboard.html"
    make_dashboard(outdir, dash_path, stats, args.org, args.title, args.threshold)

    print(
        f"\nDone. Artifacts:"
        f"\n  CSV: {csv_path}"
        f"\n  HTML dashboard: {dash_path}"
        f"\n  JSON files: {outdir}/*.json"
    )


if __name__ == "__main__":
    main()
