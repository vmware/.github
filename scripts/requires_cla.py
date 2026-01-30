#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
requires_cla.py
---------------
Thin wrapper around the already-working modules:
  - detect_org_repo_licenses.py  (GitHub fetch + robust decoding + case-insensitive root LICENSE)
  - license_detector.py          (matching + permissive policy + SPDX expressions + LicenseRef)

Public API:
  - requires_CLA(repo_full, token=None, api_base_url="https://api.github.com", timeout_s=20) -> bool
  - get_license_decision(repo_full, ...) -> dict with diagnostics

Keep this file alongside your existing scripts so imports work:
  <org>/.github/scripts/license_detector.py
  <org>/.github/scripts/detect_org_repo_licenses.py
  <org>/.github/scripts/requires_cla.py   <-- this file
"""

from __future__ import annotations
import asyncio
import os
from typing import Dict, Any, Optional

import aiohttp
from aiohttp import ClientTimeout

# Import your existing logic (no rewrites)
import license_detector as ld                       # match + policy
import detect_org_repo_licenses as dorl            # GitHub fetchers (we call its functions)

# --- begin: license override helpers -----------------------------------------
# These helpers load .github/cla/allowlist.yml and apply license-based
# policy overrides (require_cla / allow_dco). If the file is missing or
# unreadable, the behavior is unchanged.

from pathlib import Path
import re
# Gracefully degrade if PyYAML is missing
try:
    import yaml  # type: ignore
    _YAML_AVAILABLE = True
except ModuleNotFoundError:
    import sys
    print("WARNING: PyYAML not installed; allowlist overrides disabled", file=sys.stderr)
    _YAML_AVAILABLE = False

import yaml

_ALLOWLIST_PATH = Path(__file__).resolve().parents[1] / "cla" / "allowlist.yml"

def _norm_license_name(name: str) -> str:
    """Normalize license name/id to a lowercase SPDX-like token."""
    if not name:
        return ""
    s = str(name).strip().lower()
    return re.sub(r"[\s_]+", "-", s)

def _load_allowlist() -> dict:
    """Load .github/cla/allowlist.yml if present; return {} if missing or invalid."""
    if not _YAML_AVAILABLE:
        print("::warning::[DEBUG] PyYAML not available.")
        return {}  

    # print where we are looking
    print(f"::warning::[DEBUG] Looking for allowlist at: {_ALLOWLIST_PATH}")

    try:
        with open(_ALLOWLIST_PATH, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
            # Confirm we loaded keys
            keys = list(data.get("license_overrides", {}).keys())
            print(f"::warning::[DEBUG] Successfully loaded allowlist. Found override keys: {keys}")
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        print(f"::warning::[DEBUG] ❌ Allowlist NOT FOUND at: {_ALLOWLIST_PATH}")
        return {}
    except Exception as e:
        print(f"::warning::[DEBUG] ❌ Error loading allowlist: {e}")
        return {}

def _override_requires_cla(norm_license: str, allowlist: dict) -> None | bool:
    """
    Return True (force CLA), False (force DCO), or None (no override).
    """
    section = allowlist.get("license_overrides") or {}
    # Use list comprehension for clearer debugging of the set contents
    req = {_norm_license_name(x) for x in (section.get("require_cla") or [])}
    dco = {_norm_license_name(x) for x in (section.get("allow_dco") or [])}

    # --- DEBUG INSTRUMENTATION START ---
    print(f"::warning::[DEBUG OVERRIDE] Checking Normalized License: '{norm_license}'")
    # Convert set to sorted list for printing to avoid set string representation issues
    print(f"::warning::   -> 'require_cla' list contains: {sorted(list(req))}")
    # -----------------------------------

    if norm_license in req:
        print(f"::warning::   -> ✅ MATCH FOUND in require_cla! Forcing True.")
        return True
    if norm_license in dco:
        print(f"::warning::   -> MATCH FOUND in allow_dco! Forcing False.")
        return False
    
    print(f"::warning::   -> ❌ NO MATCH in overrides. Returning None.")
    return None
# --- end: license override helpers -------------------------------------------

# --- Small helpers (just glue; everything else is reused) ---------------------

def _auth_headers(token: Optional[str]) -> Dict[str, str]:
    """Reproduce the same auth header pattern dorl uses."""
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h

async def _get_repo_default_branch(session: aiohttp.ClientSession, owner: str, repo: str, api_base_url: str) -> Optional[str]:
    """Minimal repo metadata fetch to get default_branch."""
    url = f"{api_base_url}/repos/{owner}/{repo}"
    async with session.get(url, headers=session._auth_headers) as resp:
        if resp.status == 404:
            return None
        resp.raise_for_status()
        data = await resp.json()
        return data.get("default_branch")

# --- Main async decision ------------------------------------------------------

async def get_license_decision_async(
    repo_full: str,
    token: Optional[str] = None,
    api_base_url: str = "https://api.github.com",
    timeout_s: int = 20,
) -> Dict[str, Any]:
    """
    Detailed decision for a single repo (async).
    Returns dict with:
      repo, license_name, spdx_id, match, permissive, requires_CLA, policy_reason, error
    """
    if "/" not in repo_full:
        raise ValueError("repo_full must be like 'owner/repo'")
    owner, repo = repo_full.split("/", 1)

    timeout = ClientTimeout(total=None, sock_connect=timeout_s, sock_read=timeout_s)
    connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        # Attach same convenience attrs used in dorl (keeps code consistent)
        session._auth_headers = _auth_headers(token)
        session._api_base = api_base_url.rstrip("/")

        # 1) Fast path — reuse dorl.get_repo_license_api
        try:
            data = await dorl.get_repo_license_api(session, owner, repo)  # type: ignore[attr-defined]
            if data:
                spdx_id = (data.get("license") or {}).get("spdx_id")
                if spdx_id and spdx_id != "NOASSERTION":
                    # Map SPDX → canonical catalog name (exactly like your job)
                    _, id_to_name = ld.catalog_maps()
                    canonical_name = id_to_name.get(spdx_id) or (data.get("license") or {}).get("name") or spdx_id
                    perm, why = ld.is_permissive_with_reason(canonical_name, spdx_id)
                  
                    # --- begin: check license overrides (API path) ---------------------
                    try:
                        allow_cfg = _load_allowlist()
                        ov = _override_requires_cla(_norm_license_name(spdx_id or canonical_name), allow_cfg)
                        if ov is not None:
                            return {
                                "repo": repo_full,
                                "license_name": canonical_name,
                                "spdx_id": spdx_id,
                                "match": "api",
                                "permissive": perm,
                                "requires_CLA": ov,
                                "policy_reason": f"{why}; override={'require_cla' if ov else 'allow_dco'}",
                                "error": None,
                            }
                        # DEBUG: log when an override triggers
                        print(f"[DEBUG] Override applied for '{license_name or license_id}' "
                              f"-> requires_CLA={ov} (source: allowlist.yml)")
                                          
                    except Exception:
                        # On any override error, fall back to default behavior
                        pass
                    # --- end: check license overrides (API path) -----------------------

                    return {
                        "repo": repo_full,
                        "license_name": canonical_name,
                        "spdx_id": spdx_id,
                        "match": "api",
                        "permissive": perm,
                        "requires_CLA": (None if perm is None else (not perm)),
                        "policy_reason": why,
                        "error": None,
                    }
        except Exception as e:
            api_err = f"license_api_error: {type(e).__name__}: {e}"
        else:
            api_err = None

        # 2) Fallback — reuse dorl.fetch_root_license_text (case-insensitive & robust)
        default_branch = await _get_repo_default_branch(session, owner, repo, session._api_base)
        text = await dorl.fetch_root_license_text(session, owner, repo, default_branch or "")  # type: ignore[attr-defined]
        if text:
            det = ld.detect_from_text(text)
            if det.get("matched"):
                perm, why = ld.is_permissive_with_reason(det.get("name"), det.get("id"))
              
                # --- begin: check license overrides (text path) -----------------------
                try:
                    allow_cfg = _load_allowlist()
                    ov = _override_requires_cla(_norm_license_name(det.get("id") or det.get("name")), allow_cfg)
                    if ov is not None:
                        return {
                            "repo": repo_full,
                            "license_name": det.get("name"),
                            "spdx_id": det.get("id"),
                            "match": det.get("match"),
                            "permissive": perm,
                            "requires_CLA": ov,
                            "policy_reason": f"{why}; override={'require_cla' if ov else 'allow_dco'}",
                            "error": None,
                        }
                    # DEBUG: log when an override triggers
                    print(f"[DEBUG] Override applied for '{license_name or license_id}' "
                          f"-> requires_CLA={ov} (source: allowlist.yml)")
                      
                except Exception:
                    # On any override error, fall back to default behavior
                    pass
                # --- end: check license overrides (text path) -------------------------      
              
                return {
                    "repo": repo_full,
                    "license_name": det.get("name"),
                    "spdx_id": det.get("id"),
                    "match": det.get("match"),
                    "permissive": perm,
                    "requires_CLA": (None if perm is None else (not perm)),
                    "policy_reason": why,
                    "error": None,
                }
            else:
                return {
                    "repo": repo_full,
                    "license_name": None,
                    "spdx_id": None,
                    "match": None,
                    "permissive": None,
                    "requires_CLA": True,
                    "policy_reason": "no_high_confidence_match",
                    "error": api_err or "no_high_confidence_match",
                }
        else:
            return {
                "repo": repo_full,
                "license_name": None,
                "spdx_id": None,
                "match": None,
                "permissive": None,
                "requires_CLA": True,
                "policy_reason": "no_root_license_file",
                "error": api_err or "no_root_license_file",
            }

# --- Simple sync facades ------------------------------------------------------

def get_license_decision(repo_full: str,
                         token: Optional[str] = None,
                         api_base_url: str = "https://api.github.com",
                         timeout_s: int = 20) -> Dict[str, Any]:
    """Synchronous wrapper (runs the async function)."""
    return asyncio.run(get_license_decision_async(repo_full, token=token, api_base_url=api_base_url, timeout_s=timeout_s))

def requires_CLA(repo_full: str,
                 token: Optional[str] = None,
                 api_base_url: str = "https://api.github.com",
                 timeout_s: int = 20) -> bool:
    """
    Convenience bool: True if CLA required (non-permissive/unknown), False otherwise.
    """
    res = get_license_decision(repo_full, token=token, api_base_url=api_base_url, timeout_s=timeout_s)
    # Unknown (None) => conservative True
    return bool(res.get("requires_CLA", True))

# --- Optional: small CLI for quick checks ------------------------------------
if __name__ == "__main__":
    import sys, json
    if len(sys.argv) != 2 or "/" not in sys.argv[1]:
        print("Usage: python requires_cla.py <owner/repo>", file=sys.stderr)
        raise SystemExit(2)
    token = os.getenv("ORG_LICENSE_REPORT_TOKEN") or os.getenv("GITHUB_TOKEN")
    info = get_license_decision(sys.argv[1], token=token)
    print(json.dumps(info, indent=2, ensure_ascii=False))
