#!/usr/bin/env python3
"""
detect_org_repo_licenses.py
Scan all PUBLIC repos of an org, detect root license, and decide permissiveness.

Usage:
  python detect_org_repo_licenses.py --org <ORG> [--max-concurrency 16] [--timeout-s 20]
                                     --output-json license_report.json
                                     --output-csv license_report.csv

Env:
  GITHUB_TOKEN   Fine-grained PAT with repo read access (see below).
  API_BASE_URL   Defaults to https://api.github.com (set to your GHE URL if needed)
  LICENSES_JSON, PERMISSIVE_JSON, CACHE_DIR as used by license_detector.py

Required Fine-grained PAT permissions (org-scoped):
  - Repository permissions:
      * Metadata: Read
      * Contents: Read
  - Account-level/resource: limit to the single org and "All repositories" (or specific subset)
"""

from __future__ import annotations
import os, sys, csv, json, asyncio, time
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple

import aiohttp
from aiohttp import ClientResponseError, ClientConnectorError, ClientTimeout

from pathlib import Path

# local import
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

def _perm_and_cla(license_name: Optional[str]) -> Tuple[Optional[bool], Optional[bool]]:
    p = ld.is_permissive(license_name)
    cla = (None if p is None else (not p))
    return p, cla

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

async def _rate_limit_sleep(resp: aiohttp.ClientResponse):
    """
    If we are at/near the REST rate limit, sleep until reset with a small buffer.
    """
    try:
        remaining = int(resp.headers.get("X-RateLimit-Remaining", "1"))
        reset = int(resp.headers.get("X-RateLimit-Reset", "0"))
    except ValueError:
        return
    if remaining <= 1 and reset > 0:
        sleep_for = max(0, reset - int(time.time()) + 2)
        await asyncio.sleep(sleep_for)

def _headers() -> Dict[str, str]:
    h = {"Accept": "application/vnd.github+json"}
    if TOKEN:
        h["Authorization"] = f"Bearer {TOKEN}"
    return h

async def list_public_repos(session: aiohttp.ClientSession, org: str) -> List[Dict[str, Any]]:
    """
    List ALL public repos for the org (paginated).
    """
    out: List[Dict[str, Any]] = []
    page = 1
    per_page = 100
    url = f"{API_BASE_URL}/orgs/{org}/repos"
    params = {"type": "public", "per_page": per_page, "page": page, "sort": "full_name", "direction": "asc"}

    while True:
        async with session.get(url, headers=_headers(), params=params) as resp:
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
    # filter just in case
    return [r for r in out if not r.get("private") and r.get("visibility") == "public"]

async def get_repo_license_api(session: aiohttp.ClientSession, owner: str, repo: str) -> Optional[Dict[str, Any]]:
    """
    Use GitHub's 'Get the license for a repository' API.
    Returns None if 404 or no license.
    """
    url = f"{API_BASE_URL}/repos/{owner}/{repo}/license"
    try:
        async with session.get(url, headers=_headers()) as resp:
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
    Try common root license filenames via the 'Get repository content' API.
    Returns raw text of the first found candidate, else None.
    """
    for name in LICENSE_FILENAMES:
        url = f"{API_BASE_URL}/repos/{owner}/{repo}/contents/{name}"
        params = {"ref": default_branch} if default_branch else None
        try:
            async with session.get(url, headers=_headers(), params=params) as resp:
                if resp.status == 404:
                    continue
                resp.raise_for_status()
                meta = await resp.json()
                # Get raw via download_url (faster & simpler than content/base64 decode)
                dl = meta.get("download_url")
                if not dl:
                    continue
                async with session.get(dl, headers=_headers()) as r2:
                    if r2.status != 200:
                        continue
                    txt = await r2.text()
                    await _rate_limit_sleep(r2)
                    return txt
        except ClientResponseError:
            continue
        except (ClientConnectorError, asyncio.TimeoutError):
            continue
    return None

async def detect_one_repo(session: aiohttp.ClientSession, owner: str, repo: Dict[str, Any], timeout_s: int) -> RepoResult:
    name = repo["name"]
    default_branch = repo.get("default_branch")
    full = f"{owner}/{name}"

    # 1) Fast path: GitHub license API
    try:
        data = await asyncio.wait_for(get_repo_license_api(session, owner, name), timeout=timeout_s)
        if data:
            # If GitHub recognized SPDX, use that; else we'll fall back to our detector
            spdx_id = (data.get("license") or {}).get("spdx_id")
            # GitHub sometimes returns "NOASSERTION" when unknown
            if spdx_id and spdx_id != "NOASSERTION":
                license_name = (data.get("license") or {}).get("name") or spdx_id
                perm, cla = _perm_and_cla(license_name)
                return RepoResult(full, default_branch, license_name, spdx_id, "api", perm, cla, None)
    except asyncio.TimeoutError:
        # will try fallback
        pass
    except Exception as e:
        # non-fatal; try fallback
        err = f"license_api_error: {type(e).__name__}: {e}"

    # 2) Fallback: fetch root license file(s) and run detector
    try:
        text = await asyncio.wait_for(fetch_root_license_text(session, owner, name, default_branch or ""), timeout=timeout_s)
        if text:
            det = ld.detect_from_text(text)
            if det.get("matched"):
                perm, cla = _perm_and_cla(det.get("name"))
                return RepoResult(full, default_branch, det.get("name"), det.get("id"), det.get("match"), perm, cla, None)
            else:
                # Unknown → conservative
                return RepoResult(full, default_branch, None, None, None, None, True, "no_high_confidence_match")
        else:
            return RepoResult(full, default_branch, None, None, None, None, True, "no_root_license_file")
    except asyncio.TimeoutError:
        return RepoResult(full, default_branch, None, None, None, None, True, "timeout_fallback_fetch")
    except Exception as e:
        return RepoResult(full, default_branch, None, None, None, None, True, f"fallback_error: {type(e).__name__}: {e}")

async def bounded_gather(tasks, limit: int):
    semaphore = asyncio.Semaphore(limit)
    async def _run(coro):
        async with semaphore:
            return await coro
    return await asyncio.gather(*[_run(t) for t in tasks])

def _write_reports(results: List[RepoResult], json_path: Path, csv_path: Path):
    # per-repo JSON
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
        "generated_at": _now(),
        "total_repos": len(results),
        "permissive": permissive,
        "nonpermissive": nonpermissive,
        "unknown": unknown,
        "errors": errors,
        "skipped_or_no_license": skipped
    }

    json_out = {"summary": summary, "results": rows}
    json_path.write_text(json.dumps(json_out, indent=2, ensure_ascii=False), encoding="utf-8")

    # CSV
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["repo","default_branch","license_name","spdx_id","match","permissive","requires_CLA","error"])
        for r in results:
            w.writerow([r.repo, r.default_branch, r.license_name, r.license_id, r.match, r.permissive, r.requires_CLA, r.error])

def parse_args(argv: List[str]) -> Dict[str, Any]:
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--org", required=True, help="Organization login")
    p.add_argument("--max-concurrency", default=str(DEFAULT_MAX_CONCURRENCY))
    p.add_argument("--timeout-s", default=str(DEFAULT_TIMEOUT_S))
    p.add_argument("--output-json", required=True)
    p.add_argument("--output-csv", required=True)
    args = p.parse_args(argv)
    return {
        "org": args.org,
        "max_conc": int(args.max_concurrency),
        "timeout_s": int(args.timeout_s),
        "json_path": Path(args.output_json),
        "csv_path": Path(args.output_csv),
    }

async def main_async(org: str, max_conc: int, timeout_s: int, json_path: Path, csv_path: Path):
    timeout = ClientTimeout(total=None, sock_connect=timeout_s, sock_read=timeout_s)
    connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        repos = await list_public_repos(session, org)
        if not repos:
            raise RuntimeError(f"No public repos found for org '{org}' or insufficient access.")
        tasks = [detect_one_repo(session, org, r, timeout_s) for r in repos]
        results = await bounded_gather(tasks, limit=max_conc)
    _write_reports(results, json_path, csv_path)

def main():
    if not TOKEN:
        print("ERROR: GITHUB_TOKEN is not set. Provide a Fine-grained PAT in ORG_REPORT_TOKEN secret.", file=sys.stderr)
        sys.exit(2)
    args = parse_args(sys.argv[1:])
    asyncio.run(main_async(args["org"], args["max_conc"], args["timeout_s"], args["json_path"], args["csv_path"]))

if __name__ == "__main__":
    main()
