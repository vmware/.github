#!/usr/bin/env python3
"""
OpenSSF Scorecard org/targeted scanner with CSV + HTML dashboard.

Features:
- Scan an entire GitHub.com organization OR a specific repo/list/file.
- Parallel runs of the Scorecard CLI (native or Docker image).
- Produces per-repo JSON, a summary CSV, and a self-contained HTML dashboard.
- Skips existing JSON by default (fast re-runs); use --overwrite to force fresh scans.
"""
import argparse, os, sys, json, csv, subprocess
import concurrent.futures as cf
from pathlib import Path
from datetime import datetime
import requests

API = "https://api.github.com"

def gh_headers(token: str) -> dict:
    return {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}

def list_repos_from_org(org: str, token: str, include_archived: bool=False,
                        only_private: bool=False, include_forks: bool=False) -> list[str]:
    repos = []
    page = 1
    while True:
        r = requests.get(
            f"{API}/orgs/{org}/repos",
            headers=gh_headers(token),
            params={"per_page": 100, "page": page, "type": "all",
                    "sort": "full_name", "direction": "asc"}
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

def normalize_repo(s: str, org_default: str|None) -> str:
    s = (s or "").strip().strip("/")
    if not s:
        return ""
    if "/" in s:
        return s
    if not org_default:
        raise ValueError(f"Repository '{s}' is missing owner. Provide as 'owner/{s}' or set --org.")
    return f"{org_default}/{s}"

def collect_target_repos(args, token: str) -> list[str]:
    targets: list[str] = []
    if args.repo:
        targets.append(normalize_repo(args.repo, args.org))
    if args.repos:
        for item in args.repos.split(","):
            if item.strip():
                targets.append(normalize_repo(item, args.org))
    if args.repos_file:
        p = Path(args.repos_file)
        if not p.exists():
            raise FileNotFoundError(f"--repos-file not found: {p}")
        for line in p.read_text().splitlines():
            if line.strip():
                targets.append(normalize_repo(line, args.org))
    if not targets:
        if not args.org:
            raise SystemExit("Provide --org for organization scan, or use --repo/--repos/--repos-file for explicit targets.")
        targets = list_repos_from_org(
            org=args.org,
            token=token,
            include_archived=args.include_archived,
            only_private=args.only_private,
            include_forks=args.include_forks
        )
    seen, deduped = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped

def run_scorecard(repo: str, outdir: Path, mode: str, extra_args: list[str],
                  overwrite: bool) -> tuple[str,str]:
    out_path = outdir / f"{repo.replace('/', '_')}.json"
    if out_path.exists() and not overwrite:
        return (repo, "skipped (exists)")
    if mode == "docker":
        cmd = [
            "docker","run","--rm",
            "-e","GITHUB_AUTH_TOKEN="+os.getenv("GITHUB_AUTH_TOKEN",""),
            "gcr.io/openssf/scorecard:stable",
            f"--repo=github.com/{repo}",
            "--format=json",
            *extra_args
        ]
    else:
        cmd = ["scorecard", f"--repo=github.com/{repo}", "--format=json", *extra_args]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        if res.returncode != 0:
            return (repo, f"fail rc={res.returncode}: {res.stderr.strip()[:300]}")
        out_path.write_text(res.stdout)
        return (repo, "ok")
    except Exception as e:
        return (repo, f"error: {e}")

def parse_score(json_obj: dict) -> tuple[float|None, str, list[dict]]:
    score = json_obj.get("score") or json_obj.get("aggregateScore")
    date  = json_obj.get("date") or json_obj.get("timestamp") or ""
    checks = json_obj.get("checks") or []
    return (score, date, checks)

def summarize(outdir: Path, csv_path: Path, threshold: float) -> dict:
    rows, scores, details = [], [], []
    below, total = 0, 0
    for p in sorted(outdir.glob("*.json")):
        try:
            data = json.loads(p.read_text() or "{}")
        except Exception:
            data = {}
        score, date, checks = parse_score(data)
        repo_name = (data.get("repo", {}) or {}).get("name") or p.stem.replace("_","/")
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
        details.append({"repo": repo_name, "score": s, "date": date,
                        "json_file": p.name, "checks_failing": checks_failing})
        total += 1
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["repo","score","date"])
        w.writeheader(); w.writerows(rows)
    avg = (sum(scores)/len(scores)) if scores else None
    med = (sorted(scores)[len(scores)//2] if scores else None)
    return {"total": total, "avg": avg, "median": med,
            "below": below, "scores": scores, "details": details}

def make_dashboard(outdir: Path, dash_path: Path, stats: dict,
                   org: str|None, title: str, threshold: float):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    total, avg, med, below = stats["total"], stats["avg"], stats["median"], stats["below"]
    avg = f"{avg:.2f}" if avg is not None else "n/a"
    med = f"{med:.2f}" if med is not None else "n/a"
    rows_js = json.dumps(stats["details"])
    bins = [0]*11
    for s in stats["scores"]:
        b = max(0, min(10, int(round(s))))
        bins[b] += 1
    bins_js = json.dumps(bins)
    org_txt = org if org else "(ad-hoc repo list)"
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
    </tr>
  </thead>
  <tbody></tbody>
</table>

<div class="footer">OpenSSF Scorecard report. Per-repo JSON artifacts saved alongside this file.</div>

<script>
const data = {rows_js};
const threshold = {threshold};
let sortKey = 'score';
let sortAsc = false;

function fmtScore(s) {{ return (s === null || s === undefined || s === '') ? 'n/a' : Number(s).toFixed(2); }}
function badgeClass(s) {{
  if (s === null || s === undefined || s === '') return 'badge';
  if (s >= Math.max(7.0, threshold)) return 'badge good';
  if (s >= threshold) return 'badge warn';
  return 'badge bad';
}}

function render() {{ 
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
    return `<tr>
      <td><a class="rowlink" href="https://github.com/${{r.repo}}" target="_blank" rel="noopener">${{r.repo}}</a></td>
      <td><span class="${{badge}}">${{scoreTxt}}</span></td>
      <td>${{r.checks_failing ?? ''}}</td>
      <td>${{r.date ?? ''}}</td>
      <td><a class="rowlink" href="./${{r.json_file}}" target="_blank" rel="noopener">JSON</a></td>
    </tr>`;
  }}).join('');
}}

document.querySelectorAll('th button').forEach(btn => {{
  btn.addEventListener('click', () => {{
    const k = btn.dataset.k;
    if (sortKey === k) sortAsc = !sortAsc; else {{ sortKey = k; sortAsc = (k === 'repo'); }}
    render();
  }});
}});

document.getElementById('q').addEventListener('input', render);
document.getElementById('onlyLow').addEventListener('change', render);

// Histogram
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

render();
</script>
</body>
</html>
"""
    dash_path.write_text(html, encoding="utf-8")

def main():
    ap = argparse.ArgumentParser(description="Run OpenSSF Scorecard across a GitHub org or explicit repo list, then build a dashboard.")
    ap.add_argument("--org", help="GitHub organization (GitHub.com). Required for org scans or to resolve bare repo names.")
    ap.add_argument("--repo", help="Scan a single repo (owner/name or bare name if --org is set).")
    ap.add_argument("--repos", help="Comma-separated repos (owner/name or bare if --org is set).")
    ap.add_argument("--repos-file", help="Path to a file with one repo per line.")
    ap.add_argument("--out", default="out", help="Output folder (JSON, CSV, HTML)")
    ap.add_argument("--mode", choices=["native","docker"], default="native")
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--include-archived", action="store_true")
    ap.add_argument("--only-private", action="store_true")
    ap.add_argument("--include-forks", action="store_true")
    ap.add_argument("--threshold", type=float, default=7.0)
    ap.add_argument("--title", default="OpenSSF Scorecard Dashboard")
    ap.add_argument("--extra-scorecard-args", default="")
    ap.add_argument("--overwrite", action="store_true", help="Re-run and replace JSON even if it already exists")
    args = ap.parse_args()

    token = os.getenv("GITHUB_AUTH_TOKEN")
    if not token:
        print("ERROR: set GITHUB_AUTH_TOKEN (classic PAT).", file=sys.stderr)
        sys.exit(2)

    outdir = Path(args.out); outdir.mkdir(parents=True, exist_ok=True)

    targets = collect_target_repos(args, token.split(",")[0])
    print(f"Scanning {len(targets)} repositories...")
    extra_args = [a for a in args.extra_scorecard_args.split(" ") if a.strip()]

    with cf.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = [ex.submit(run_scorecard, r, outdir, args.mode, extra_args, args.overwrite) for r in targets]
        for fut in cf.as_completed(futs):
            repo, status = fut.result()
            print(f"{repo}: {status}")

    csv_path = outdir / "summary.csv"
    stats = summarize(outdir, csv_path, args.threshold)
    dash_path = outdir / "dashboard.html"
    make_dashboard(outdir, dash_path, stats, args.org, args.title, args.threshold)

    print(f"\nDone. Artifacts:\n  CSV: {csv_path}\n  HTML dashboard: {dash_path}\n  JSON files: {
