#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_org_repo_licenses.py
---------------------------
Purpose:
  - Enumerate *public* repositories in a GitHub organization.
  - For each repo, determine the root license via:
      1) GitHub License API (fast path, returns SPDX when known)
      2) Fallback to fetching likely root license files and detecting text
         using license_detector.detect_from_text() (robust path).
  - Normalize to the catalog's canonical license *name* (via SPDX ID),
    then decide *permissiveness* using permissive_names.json.
  - Produce a JSON and CSV report summarizing results and errors.

Environment:
  - GITHUB_TOKEN  (Fine-grained PAT; see YAML comments for required perms)
  - API_BASE_URL  (default: https://api.github.com; change for GH Enterprise)
  - LICENSES_JSON / PERMISSIVE_JSON / CACHE_DIR (used by license_detector)
Hardening:
  - Rate-limit aware (sleeps until reset when near limit).
  - Concurrency control, timeouts, retries (best-effort).
  - Robust decoding of raw bytes (charset-normalizer → utf-8 → utf-8-sig → cp1252 → latin-1).

CLI:
  python detect_org_repo_licenses.py \
    --org <ORG> \
    --max-concurrency 16 \
    --timeout-s 20 \
    --output-json license_report.json \
    --output-csv  license_report.csv
"""

from __future__ import annotations
import os, sys, csv, json, asyncio, time, base64
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

import aiohttp
from aiohttp import ClientResponseError, ClientConnectorError, ClientTimeout
from pathlib import Path

# Optional robust decoder
try:
    from charset_normalizer import from_bytes as cn_from_bytes
    HAVE_CN = True
except Exception:
    HAVE_CN = False

# Local import (sibling script)
sys.path.append(str(Path(__file__).resolve().parents[1] / "scripts"))
import license_detector as ld  # type: ignore

API_BASE_URL = os.getenv("API_BASE_URL", "https://api.github.com").rstrip("/")
TOKEN = os.getenv("GITHUB_TOKEN", "")

DEFAULT_TIMEOUT_S = 20
DEFAULT_MAX_CONCURRENCY = 16

LICENSE_FILENAMES = [
    "LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE",
    "LICENSE.txt", "LICENSE.md", "COPYING.txt", "COPYRIGHT.txt", "NOTICE.txt"
]

@dataclass
class RepoResult:
    repo: str
    default_branch: Optional[str]
    license_name: Optional[str]
    license_id: Optional[str]
    match: Optional[str]
    permissive: Optional[bool]
    requires_CLA: Optional[bool]
    error: Optional[str]

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

async def _rate_limit_sleep(resp: aiohttp.ClientResponse) -> None:
    """Pause until REST rate-limit reset if we're at/near the limit."""
    try:
        remaining = int(resp.headers.get("X-RateLimit-Remaining", "1"))
        reset = int(resp.headers.get("X-RateLimit-Reset", "0"))
    except ValueError:
        return
    if remaining <= 1 and reset > 0:
        await asyncio.sleep(max(0, reset - int(time.time()) + 2))

def _auth_headers() -> Dict[str, str]:
    h = {"Accept": "application/vnd.github+json"}
    if TOKEN:
        h["Authorization"] = f"Bearer {TOKEN}"
    return h

def decode_bytes_safe(data: bytes) -> str:
    """
    Best-effort text decoding for license files.
    Order:
      1) charset-normalizer (if available)
      2) utf-8
      3) utf-8-sig (BOM)
      4) cp1252 (Windows smart quotes 0x93/0x94)
      5) latin-1
      6) utf-8 with replacement (never fail)
    """
    if not data:
        return ""
    if HAVE_CN:
        try:
            res = cn_from_bytes(data).best()
            if res:
                return str(res)
        except Exception:
            pass
    for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("utf-8", errors="replace")

async def list_public_repos(session: aiohttp.ClientSession, org: str) -> List[Dict[str, Any]]:
    """Enumerate ALL public repos in the org (paginated)."""
    out: List[Dict[str, Any]] = []
    page = 1
    per_page = 100
    url = f"{API_BASE_URL}/orgs/{org}/repos"
    params = {"type": "public", "per_page": per_page, "page": page, "sort": "full_name", "direction": "asc"}
    while True:
        async with session.get(url, headers=_auth_headers(), params=params) as resp:
            if resp.status == 404:
                raise RuntimeError(f"Org '{org}' not found or no access.")
            if resp.status == 401:
                raise RuntimeError("Unauthorized. Check GITHUB_TOKEN scopes and org access.")
            resp.raise_for_status()
            data = await resp.json()
            out.extend(data)
            await _rate_limit_sleep(resp)
            if len(data) < per_page:
                break
            page += 1
            params["page"] = page
    return [r for r in out if not r.get("private") and r.get("visibility") == "public"]

async def get_repo_license_api(session: aiohttp.ClientSession, owner: str, repo: str) -> Optional[Dict[str, Any]]:
    """GitHub 'Get the license for a repository' API (None on 404/no license)."""
    url = f"{API_BASE_URL}/repos/{owner}/{repo}/license"
    try:
        async with session.get(url, headers=_auth_headers()) as resp:
            if resp.status == 404:
                return None
            resp.raise_for_status()
            data = await resp.json()
            await _rate_limit_sleep(resp)
            return data
    except ClientResponseError as e:
        if e.status in (403, 404):
            return None
        raise

async def fetch_root_license_text(session: aiohttp.ClientSession, owner: str, repo: str, default_branch: str) -> Optional[str]:
    """
    Try common root license filenames via the 'contents' API.
    Download raw BYTES and decode robustly. If no download_url, fall back to
    base64 'content' field.
    """
    for name in LICENSE_FILENAMES:
        url = f"{API_BASE_URL}/repos/{owner}/{repo}/contents/{name}"
        params = {"ref": default_branch} if default_branch else None
        try:
            async with session.get(url, headers=_auth_headers(), params=params) as resp:
                if resp.status == 404:
                    continue
                resp.raise_for_status()
                meta = await resp.json()

                # Fast path: direct raw download
                dl = meta.get("download_url")
                if dl:
                    async with session.get(dl, headers=_auth_headers()) as r2:
                        if r2.status != 200:
                            continue
                        raw = await r2.read()
                        await _rate_limit_sleep(r2)
                        return decode_bytes_safe(raw)

                # Fallback: use base64-encoded content
                content = meta.get("content")
                enc = meta.get("encoding")
                if content and enc == "base64":
                    try:
                        raw = base64.b64decode(content, validate=False)
                        return decode_bytes_safe(raw)
                    except Exception:
                        continue

        except ClientResponseError:
            continue
        except (ClientConnectorError, asyncio.TimeoutError):
            continue
        except Exception:
            # Don't let odd content kill the run; try next candidate
            continue
    return None

async def detect_one_repo(session: aiohttp.ClientSession, owner: str, repo: Dict[str, Any], timeout_s: int) -> RepoResult:
    """
    Per-repo flow:
      1) Try License API.
      2) If NOASSERTION/unknown/timeout, fetch likely root license file and detect.
      3) Normalize to canonical catalog name (via SPDX where possible).
      4) Evaluate permissiveness (names and/or IDs; LicenseRef-aware; expressions ok).
    """
    name = repo["name"]
    default_branch = repo.get("default_branch")
    full = f"{owner}/{name}"

    # Fast path: License API
    try:
        data = await asyncio.wait_for(get_repo_license_api(session, owner, name), timeout=timeout_s)
        if data:
            spdx_id = (data.get("license") or {}).get("spdx_id")
            if spdx_id and spdx_id != "NOASSERTION":
                # Prefer canonical catalog name via SPDX; else fall back to API name
                _, id_to_name = ld.catalog_maps()
                canonical_name = id_to_name.get(spdx_id) or (data.get("license") or {}).get("name") or spdx_id
                perm = ld.is_permissive(canonical_name, spdx_id)
                cla = (None if perm is None else (not perm))
                return RepoResult(full, default_branch, canonical_name, spdx_id, "api", perm, cla, None)
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        # Continue to fallback; record later as needed
        api_err = f"license_api_error: {type(e).__name__}: {e}"

    # Fallback: fetch and detect
    try:
        text = await asyncio.wait_for(fetch_root_license_text(session, owner, name, default_branch or ""), timeout=timeout_s)
        if text:
            det = ld.detect_from_text(text)
            if det.get("matched"):
                perm = ld.is_permissive(det.get("name"), det.get("id"))
                cla = (None if perm is None else (not perm))
                return RepoResult(full, default_branch, det.get("name"), det.get("id"), det.get("match"), perm, cla, None)
            else:
                return RepoResult(full, default_branch, None, None, None, None, True, "no_high_confidence_match")
        else:
            return RepoResult(full, default_branch, None, None, None, None, True, "no_root_license_file")
    except asyncio.TimeoutError:
        return RepoResult(full, default_branch, None, None, None, None, True, "timeout_fallback_fetch")
    except Exception as e:
        return RepoResult(full, default_branch, None, None, None, None, True, f"fallback_error: {type(e).__name__}: {e}")

async def bounded_gather(tasks, limit: int):
    """Concurrency guard so we don't overload the API/runner."""
    semaphore = asyncio.Semaphore(limit)
    async def _run(coro):
        async with semaphore:
            return await coro
    return await asyncio.gather(*[_run(t) for t in tasks])

def _write_reports(results: List[RepoResult], json_path: Path, csv_path: Path) -> None:
    """Emit JSON (with summary) and CSV (tabular) reports."""
    rows = []
    errors, skipped = 0, 0
    permissive, nonpermissive, unknown = 0, 0, 0

    for r in results:
        if r.error:
            errors += 1
        if r.requires_CLA is True and r.license_name is None:
            skipped += 1
        if r.permissive is True:
            permissive += 1
        elif r.permissive is False:
            nonpermissive += 1
        else:
            unknown += 1

        rows.append({
            "repo": r.repo,
            "default_branch": r.default_branch,
            "license_name": r.license_name,
            "spdx_id": r.license_id,
            "match": r.match,
            "permissive": r.permissive,
            "requires_CLA": r.requires_CLA,
            "error": r.error
        })

    summary = {
        "generated_at": _now_iso(),
        "total_repos": len(results),
        "permissive": permissive,
        "nonpermissive": nonpermissive,
        "unknown": unknown,
        "errors": errors,
        "skipped_or_no_license": skipped
    }

    json_path.write_text(json.dumps({"summary": summary, "results": rows}, indent=2, ensure_ascii=False), encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["repo","default_branch","license_name","spdx_id","match","permissive","requires_CLA","error"])
        for r in results:
            w.writerow([r.repo, r.default_branch, r.license_name, r.license_id, r.match, r.permissive, r.requires_CLA, r.error])

def _parse_args(argv: List[str]) -> Dict[str, Any]:
    import argparse
    p = argparse.ArgumentParser(description="Scan public repos of an org and report licenses + permissiveness.")
    p.add_argument("--org", required=True, help="Organization login (e.g., vmware)")
    p.add_argument("--max-concurrency", default=str(DEFAULT_MAX_CONCURRENCY), help="Max concurrent repo tasks (default 16)")
    p.add_argument("--timeout-s", default=str(DEFAULT_TIMEOUT_S), help="Per-request timeout seconds (default 20)")
    p.add_argument("--output-json", required=True, help="Path to write JSON report")
    p.add_argument("--output-csv", required=True, help="Path to write CSV report")
    args = p.parse_args(argv)
    return {
        "org": args.org,
        "max_conc": int(args.max_concurrency),
        "timeout_s": int(args.timeout_s),
        "json_path": Path(args.output_json),
        "csv_path": Path(args.output_csv),
    }

async def _main_async(org: str, max_conc: int, timeout_s: int, json_path: Path, csv_path: Path) -> None:
    timeout = ClientTimeout(total=None, sock_connect=timeout_s, sock_read=timeout_s)
    connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        repos = await list_public_repos(session, org)
        if not repos:
            raise RuntimeError(f"No public repos found for org '{org}' or insufficient access.")
        tasks = [detect_one_repo(session, org, r, timeout_s) for r in repos]
        results = await bounded_gather(tasks, limit=max_conc)
    _write_reports(results, json_path, csv_path)

def main() -> None:
    if not TOKEN:
        print("ERROR: GITHUB_TOKEN is not set. Add a Fine-grained PAT as ORG_REPORT_TOKEN org secret.", file=sys.stderr)
        sys.exit(2)
    args = _parse_args(sys.argv[1:])
    asyncio.run(_main_async(args["org"], args["max_conc"], args["timeout_s"], args["json_path"], args["csv_path"]))

if __name__ == "__main__":
    main()
