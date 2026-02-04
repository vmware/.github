#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
requires_cla.py
---------------
Thin wrapper around:
  - detect_org_repo_licenses.py (GitHub fetch)
  - license_detector.py         (Matching logic)

Now fully supports IN-MEMORY data injection for:
  - Licenses Catalog
  - Permissive Names
  - Allowlist/Overrides
"""

from __future__ import annotations
import asyncio
import os
from typing import Dict, Any, Optional, List

import aiohttp
from aiohttp import ClientTimeout

import license_detector as ld
import detect_org_repo_licenses as dorl

# --- Overrides Helper ---
from pathlib import Path
import re
try:
    import yaml
    _YAML_AVAILABLE = True
except ModuleNotFoundError:
    _YAML_AVAILABLE = False

_ALLOWLIST_PATH = Path(__file__).resolve().parents[1] / "cla" / "allowlist.yml"

def _norm_license_name(name: str) -> str:
    if not name: return ""
    return re.sub(r"[\s_]+", "-", str(name).strip().lower())

def _load_allowlist(in_memory_data: Optional[Dict] = None) -> dict:
    """
    Load allowlist configuration.
    Priority 1: In-memory data passed from controller.
    Priority 2: Disk file (Legacy fallback).
    """
    # 1. Use In-Memory Data if provided
    if in_memory_data:
        return in_memory_data

    # 2. Fallback to Disk (Legacy)
    if not _YAML_AVAILABLE:
        return {}

    try:
        with open(_ALLOWLIST_PATH, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
            return data if isinstance(data, dict) else {}
    except Exception:
        # Silent fail on disk read (expected in new architecture)
        return {}

def _override_requires_cla(norm_license: str, allowlist: dict) -> None | bool:
    """
    Return True (force CLA), False (force DCO), or None (no override).
    """
    section = allowlist.get("license_overrides") or {}
    req = {_norm_license_name(x) for x in (section.get("require_cla") or [])}
    dco = {_norm_license_name(x) for x in (section.get("allow_dco") or [])}

    print(f"::warning::[DEBUG OVERRIDE] Checking Normalized License: '{norm_license}'")
    print(f"::warning::   -> 'require_cla' list contains: {sorted(list(req))}")

    if norm_license in req:
        print(f"::warning::   -> ✅ MATCH FOUND in require_cla! Forcing True.")
        return True
    if norm_license in dco:
        print(f"::warning::   -> MATCH FOUND in allow_dco! Forcing False.")
        return False
    
    print(f"::warning::   -> ❌ NO MATCH in overrides. Returning None.")
    return None

# --- Helpers ---

def _auth_headers(token: Optional[str]) -> Dict[str, str]:
    h = {"Accept": "application/vnd.github+json"}
    if token: h["Authorization"] = f"Bearer {token}"
    return h

async def _get_repo_default_branch(session: aiohttp.ClientSession, owner: str, repo: str, api_base_url: str) -> Optional[str]:
    url = f"{api_base_url}/repos/{owner}/{repo}"
    async with session.get(url, headers=session._auth_headers) as resp:
        if resp.status == 404: return None
        resp.raise_for_status()
        data = await resp.json()
        return data.get("default_branch")

# --- Main Logic ---

async def get_license_decision_async(
    repo_full: str,
    token: Optional[str] = None,
    api_base_url: str = "https://api.github.com",
    timeout_s: int = 20,
    licenses_data: Optional[List[Dict[str, Any]]] = None,
    permissive_data: Optional[List[Any]] = None,
    allowlist_data: Optional[Dict] = None,  # <--- NEW ARGUMENT
) -> Dict[str, Any]:
    
    if "/" not in repo_full: raise ValueError("repo_full must be like 'owner/repo'")
    owner, repo = repo_full.split("/", 1)

    timeout = ClientTimeout(total=None, sock_connect=timeout_s, sock_read=timeout_s)
    connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        session._auth_headers = _auth_headers(token)
        session._api_base = api_base_url.rstrip("/")

        # Load configuration (Memory > Disk)
        allow_cfg = _load_allowlist(allowlist_data)

        # 1) Fast path (API)
        try:
            data = await dorl.get_repo_license_api(session, owner, repo)  # type: ignore
            if data:
                spdx_id = (data.get("license") or {}).get("spdx_id")
                if spdx_id and spdx_id != "NOASSERTION":
                    _, id_to_name = ld.catalog_maps(licenses_data)
                    canonical_name = id_to_name.get(spdx_id) or (data.get("license") or {}).get("name") or spdx_id
                    
                    # Check Logic
                    perm, why = ld.is_permissive_with_reason(canonical_name, spdx_id, permissive_data, licenses_data)
                    
                    # Check Overrides
                    ov = _override_requires_cla(_norm_license_name(spdx_id or canonical_name), allow_cfg)
                    
                    requires_cla_val = ov if ov is not None else (None if perm is None else (not perm))
                    reason_suffix = f"; override={'require_cla' if ov else 'allow_dco'}" if ov is not None else ""

                    return {
                        "repo": repo_full,
                        "license_name": canonical_name,
                        "spdx_id": spdx_id,
                        "match": "api",
                        "permissive": perm,
                        "requires_CLA": requires_cla_val,
                        "policy_reason": why + reason_suffix,
                        "error": None,
                    }
        except Exception:
            pass

        # 2) Fallback (Text Fetch)
        default_branch = await _get_repo_default_branch(session, owner, repo, session._api_base)
        text = await dorl.fetch_root_license_text(session, owner, repo, default_branch or "")  # type: ignore
        
        if text:
            det = ld.detect_from_text(text, catalog_data=licenses_data)
            if det.get("matched"):
                perm, why = ld.is_permissive_with_reason(det.get("name"), det.get("id"), permissive_data, licenses_data)
                
                # Check Overrides
                ov = _override_requires_cla(_norm_license_name(det.get("id") or det.get("name")), allow_cfg)
                
                requires_cla_val = ov if ov is not None else (None if perm is None else (not perm))
                reason_suffix = f"; override={'require_cla' if ov else 'allow_dco'}" if ov is not None else ""

                return {
                    "repo": repo_full,
                    "license_name": det.get("name"),
                    "spdx_id": det.get("id"),
                    "match": det.get("match"),
                    "permissive": perm,
                    "requires_CLA": requires_cla_val,
                    "policy_reason": why + reason_suffix,
                    "error": None,
                }
            else:
                return {
                    "repo": repo_full, "requires_CLA": True, "policy_reason": "no_high_confidence_match", "error": "no_high_confidence_match"
                }
        else:
            return {
                "repo": repo_full, "requires_CLA": True, "policy_reason": "no_root_license_file", "error": "no_root_license_file"
            }

# --- Facades ---

def get_license_decision(repo_full: str, token: Optional[str] = None, api_base_url: str = "https://api.github.com", timeout_s: int = 20, licenses_data=None, permissive_data=None, allowlist_data=None) -> Dict[str, Any]:
    return asyncio.run(get_license_decision_async(repo_full, token, api_base_url, timeout_s, licenses_data, permissive_data, allowlist_data))

def requires_CLA(repo_full: str, token: Optional[str] = None, api_base_url: str = "https://api.github.com", timeout_s: int = 20, licenses_data=None, permissive_data=None, allowlist_data=None) -> bool:
    res = get_license_decision(repo_full, token, api_base_url, timeout_s, licenses_data, permissive_data, allowlist_data)
    return bool(res.get("requires_CLA", True))

if __name__ == "__main__":
    import sys, json
    if len(sys.argv) != 2: raise SystemExit(2)
    token = os.getenv("GITHUB_TOKEN")
    print(json.dumps(get_license_decision(sys.argv[1], token=token), indent=2))
  
