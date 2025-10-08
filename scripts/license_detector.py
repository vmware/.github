#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
license_detector.py
-------------------
Purpose:
  - Detect the *repository root* license from raw text that might include
    prefaces like copyright lines, notices, etc.
  - Match it against a single, large catalog file (licenses_all.json/.gz)
    that contains *all* licenses you care about (SPDX + LicenseRef).
  - Provide a *catalog-aware* policy helper to decide if a license is
    "permissive" using a separate policy list (permissive_names.json).

Inputs (files):
  - data/licenses_all.json   (or data/licenses_all.json.gz)
      Structure (per license):
        {
          "name": "<canonical license name>",
          "spdx_id": "<SPDX or LicenseRef-...>",
          "text_varies": <bool>,
          "base_text": "<canonical license body text>"
          ... (other fields are ignored by this script)
        }
      NOTE: This file is generated elsewhere; we do not modify it.

  - data/permissive_names.json
      Either:
        { "permissive_names": ["MIT License", "Apache License 2.0", ...] }
      OR:
        ["MIT License", "Apache License 2.0", ...]
      This is your policy: licenses named here are treated as PERMISSIVE.

Outputs (APIs):
  - detect_from_text(text) -> dict
      {
        "matched": bool,
        "name": <canonical catalog name or None>,
        "id": <spdx_id or None>,
        "match": "hash" | "jaccard:<score>" | "fuzzy:<score>" | None,
        "notes": optional string (e.g., "spdx_hint=...")
      }

  - is_permissive(name: Optional[str], spdx_id: Optional[str]) -> Optional[bool]
      - Returns True/False when we can resolve to a canonical catalog name
        and check it against permissive_names.json. Returns None if inputs
        are insufficient and we cannot decide.
  - Permissive policy checking now supports BOTH canonical *names* and *SPDX IDs* from permissive_names.json (or a mix of both), with robust normalization.

Design notes:
  - First try an exact hash of the normalized license *body* (after preamble strip).
  - If no exact match, narrow candidates by anchor phrases + length ratio,
    then compare using:
      * Jaccard on 5-word n-grams (structure-aware)
      * RapidFuzz token_set_ratio (robust to wrapping & punctuation), if available.
  - We keep a tiny on-disk cache of the catalog (normalized text, hashes, etc.)
    at .github/tools/.cache/licenses_all.cache.json, invalidated when the
    source JSON/.gz changes (SHA256 check).
"""

from __future__ import annotations
import json, os, re, hashlib, gzip
from pathlib import Path
from typing import Dict, Tuple, List, Any, Optional

# Optional fuzzy matching (recommended)
try:
    from rapidfuzz.fuzz import token_set_ratio
    from rapidfuzz.utils import default_process
    HAVE_RAPID = True
except Exception:
    HAVE_RAPID = False

# ---------- Config (paths) ----------
LICENSES_JSON = Path(os.getenv("LICENSES_JSON", "data/licenses_all.json")).resolve()
PERMISSIVE_JSON = Path(os.getenv("PERMISSIVE_JSON", "data/permissive_names.json")).resolve()
CACHE_DIR = Path(os.getenv("CACHE_DIR", ".github/tools/.cache")).resolve()
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# ---------- Heuristics ----------
ANCHORS = [
    r"apache license[, ]+version 2\.0",
    r"gnu (lesser )?general public license",
    r"mozilla public license",
    r"permission is hereby granted, free of charge",
    r"redistribution and use in source and binary forms",
    r"creative commons (attribution|zero|by|cc0)",
    r"this is free and unencumbered software released into the public domain",
    r"the software is provided [\"'“”]?as is[\"'“”]?"
]
SPDX_LINE_RE = re.compile(r"^spdx-license-identifier:\s*(?P<expr>.+)$", re.I | re.M)

JACCARD_ACCEPT = 0.80
FUZZY_ACCEPT   = 95.0
FUZZY_STRONG   = 97.0

# Tiny safety net if we can't map an id/name via catalog
FALLBACK_PERMISSIVE_SPDX = {
    "MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC",
    "Zlib", "Unlicense", "BSL-1.0", "Python-2.0", "CC0-1.0"
}

# ---------- Small text helpers ----------
def _normalize(s: str) -> str:
    s = s.replace("\r\n", "\n").replace("\r", "\n").lower()
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()

def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _tokenize_ngrams(s: str, n=5) -> List[str]:
    tokens = re.findall(r"[a-z0-9]+", s)
    return [" ".join(tokens[i:i+n]) for i in range(max(0, len(tokens)-n+1))]

def _jaccard(a: List[str], b: List[str]) -> float:
    if not a or not b: return 0.0
    A, B = set(a), set(b)
    return len(A & B) / len(A | B)

def _contains_any_anchor(text: str) -> List[str]:
    return [a for a in ANCHORS if re.search(a, text, re.I)]

def _strip_preamble(full_norm: str) -> str:
    lines = full_norm.splitlines()
    for i, ln in enumerate(lines):
        if any(re.search(a, ln, re.I) for a in ANCHORS):
            return "\n".join(lines[i:]).strip()
    pruned, dropping = [], True
    for ln in lines:
        if dropping and re.match(r"^(copyright|all rights reserved|about|project|disclaimer|notice)\b",
                                 ln.strip(), re.I):
            continue
        dropping = False
        pruned.append(ln)
    return "\n".join(pruned).strip() or full_norm

# ---------- JSON IO ----------
def _read_json_any(path: Path) -> Any:
    if str(path).endswith(".gz"):
        with gzip.open(path, "rb") as f:
            return json.loads(f.read().decode("utf-8"))
    return json.loads(path.read_text(encoding="utf-8"))

def _hash_file_bytes(path: Path) -> str:
    if str(path).endswith(".gz"):
        with gzip.open(path, "rb") as f:
            data = f.read()
    else:
        data = path.read_bytes()
    return hashlib.sha256(data).hexdigest()

# ---------- Catalog cache ----------
def _load_catalog_with_cache(licenses_path: Path) -> Dict[str, Dict]:
    """
    catalog[name] = {
      'name', 'spdx_id', 'text_varies',
      'base_norm', 'base_hash', 'len', 'anchor_flags'
    }
    """
    src_hash = _hash_file_bytes(licenses_path)
    cache_file = CACHE_DIR / "licenses_all.cache.json"

    if cache_file.exists():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            if cached.get("source_sha256") == src_hash:
                return cached["items"]
        except Exception:
            pass

    raw = _read_json_any(licenses_path)
    if isinstance(raw, list):
        raw = {item["name"]: item for item in raw}

    items: Dict[str, Dict] = {}
    for name, rec in raw.items():
        base_text = rec.get("base_text") or ""
        base_norm = _normalize(base_text)
        items[name] = {
            "name": rec.get("name", name),
            "spdx_id": rec.get("spdx_id"),
            "text_varies": bool(rec.get("text_varies", False)),
            "base_norm": base_norm,
            "base_hash": _sha256(base_norm) if base_norm else None,
            "len": len(base_norm),
            "anchor_flags": _contains_any_anchor(base_norm),
        }

    cache_file.write_text(
        json.dumps({"source_sha256": src_hash, "items": items}, ensure_ascii=False),
        encoding="utf-8"
    )
    return items

# ---------- Permissive policy index ----------
def _load_permissive_raw(path: Path) -> List[str]:
    """
    Load the permissive list as-is. It can be either:
      { "permissive_names": [ ... ] }  OR  [ ... ]
    Entries can be canonical names OR SPDX IDs (mixed is OK).
    """
    raw = _read_json_any(path)
    return raw.get("permissive_names", raw) if isinstance(raw, dict) else raw

def _canon_key(s: str) -> str:
    """
    Robust key normalization for policy comparisons:
      - casefold
      - normalize quotes/dashes
      - strip all non-alnum (keep 0-9a-z)
    """
    s = (s or "").casefold()
    s = s.replace("’", "'").replace("“", '"').replace("”", '"').replace("–", "-").replace("—", "-")
    s = re.sub(r"[^a-z0-9]+", "", s)  # remove spaces, quotes, punctuation
    return s

def _build_perm_index() -> Tuple[set, set, set]:
    """
    Build three sets for permissive checks:
      - allow_name_raw:   lowercased names exactly as provided in policy
      - allow_id_raw:     SPDX IDs exactly as provided in policy
      - allow_canon:      canonicalized keys for both names & ids (robust match)

    Additionally, if a policy entry matches a catalog NAME, also add that
    entry's SPDX ID to allow_id_raw (and vice versa). This lets a policy
    listing either "Apache-2.0" OR "Apache License 2.0" work equivalently.
    """
    catalog = _load_catalog_with_cache(LICENSES_JSON)
    # Build maps for cross-walking names <-> ids
    name_to_id: Dict[str, str] = {}
    id_to_name: Dict[str, str] = {}
    for name, rec in catalog.items():
        spdx = (rec.get("spdx_id") or "").strip()
        if spdx:
            name_to_id[name] = spdx
            id_to_name[spdx] = name

    # Raw policy entries (could be names or spdx ids)
    entries = _load_permissive_raw(PERMISSIVE_JSON)
    entries = [e for e in entries if isinstance(e, str)]

    allow_name_raw: set = set()
    allow_id_raw: set = set()
    allow_canon: set = set()

    # First pass: store raw
    for e in entries:
        allow_canon.add(_canon_key(e))
        if e in id_to_name:   # exact SPDX ID string appears in catalog
            allow_id_raw.add(e)
            allow_canon.add(_canon_key(id_to_name[e]))  # add its name canon too
        elif e in name_to_id: # exact NAME string appears in catalog
            allow_name_raw.add(e)
            allow_canon.add(_canon_key(name_to_id[e]))  # add its id canon too
        else:
            # Unknown string (maybe punctuation variant). We'll still use canonical key.
            pass

    return allow_name_raw, allow_id_raw, allow_canon

# ---------- Public policy helpers ----------
def catalog_maps() -> Tuple[Dict[str, str], Dict[str, str]]:
    """(Kept for callers) name_lower -> spdx_id, and spdx_id -> name."""
    cat = _load_catalog_with_cache(LICENSES_JSON)
    name_to_id_lower: Dict[str, str] = {}
    id_to_name: Dict[str, str] = {}
    for name, rec in cat.items():
        spdx = (rec.get("spdx_id") or "").strip()
        if spdx:
            name_to_id_lower[name.lower()] = spdx
            id_to_name[spdx] = name
    return name_to_id_lower, id_to_name

def is_permissive(license_name: Optional[str], spdx_id: Optional[str] = None) -> Optional[bool]:
    """
    Decide permissiveness using permissive_names.json that may contain either
    canonical names OR SPDX IDs. Robust to minor punctuation/spacing differences.

    Returns True/False, or None if we cannot decide (no inputs provided).
    """
    if not license_name and not spdx_id:
        return None

    allow_name_raw, allow_id_raw, allow_canon = _build_perm_index()

    # 1) Exact raw ID match (fast, precise)
    if spdx_id and spdx_id in allow_id_raw:
        return True

    # 2) Exact raw NAME match (policy uses exact canonical names)
    if license_name and license_name in allow_name_raw:
        return True

    # 3) Canonicalized comparisons (robust)
    if spdx_id and _canon_key(spdx_id) in allow_canon:
        return True
    if license_name and _canon_key(license_name) in allow_canon:
        return True

    # 4) Last resort: tiny built-in SPDX allow set (only if we have an id)
    if spdx_id:
        return (spdx_id in FALLBACK_PERMISSIVE_SPDX)

    return False  # we had inputs, but none matched the policy

# ---------- Public detection API ----------
def detect_from_text(text: str) -> Dict[str, Any]:
    """
    Detect license from a root license file's content (string).
    Returns: { matched, name, id, match, notes }
    """
    full_norm = _normalize(text or "")
    body = _strip_preamble(full_norm)

    # Optional hint (for human debugging)
    notes = None
    m = SPDX_LINE_RE.search(text or "")
    if m:
        notes = f"spdx_hint={m.group('expr').strip()}"

    catalog = _load_catalog_with_cache(LICENSES_JSON)

    # (1) Exact hash match of the normalized "body"
    body_hash = _sha256(body)
    for name, rec in catalog.items():
        if rec["base_hash"] and body_hash == rec["base_hash"]:
            return {"matched": True, "name": name, "id": rec["spdx_id"], "match": "hash", "notes": notes}

    # (2) Narrow candidates by anchors + length ratio
    body_anchors = set(_contains_any_anchor(body))
    body_len = len(body)
    narrowed: Dict[str, str] = {}
    for name, rec in catalog.items():
        txt = rec["base_norm"]
        if not txt: continue
        if body_anchors and not (set(rec["anchor_flags"]) & body_anchors):
            continue
        if rec["len"] > 0:
            ratio = body_len / rec["len"]
            if ratio < 0.5 or ratio > 2.0:
                continue
        narrowed[name] = txt
    if not narrowed:
        shortest = sorted([(n, r["len"]) for n, r in catalog.items() if r["len"] > 0], key=lambda x: x[1])[:200]
        narrowed = {n: catalog[n]["base_norm"] for n, _ in shortest}

    # (3) Similarity scoring on narrowed set
    body_5 = _tokenize_ngrams(body, 5)
    best_j_id, best_j = None, 0.0
    for key, text_norm in narrowed.items():
        score = _jaccard(body_5, _tokenize_ngrams(text_norm, 5))
        if score > best_j:
            best_j_id, best_j = key, score

    best_f_id, best_f = None, 0.0
    if HAVE_RAPID:
        bp = default_process(body)
        for key, text_norm in narrowed.items():
            sc = float(token_set_ratio(bp, default_process(text_norm)))
            if sc > best_f:
                best_f_id, best_f = key, sc

    picked_name, picked_sig = None, ""
    if HAVE_RAPID and best_f >= FUZZY_STRONG:
        picked_name, picked_sig = best_f_id, f"fuzzy:{best_f:.1f}"
    elif best_j >= JACCARD_ACCEPT or (HAVE_RAPID and best_f >= FUZZY_ACCEPT):
        if HAVE_RAPID and (best_f - FUZZY_ACCEPT) > (best_j - JACCARD_ACCEPT):
            picked_name, picked_sig = best_f_id, f"fuzzy:{best_f:.1f}"
        else:
            picked_name, picked_sig = best_j_id, f"jaccard:{best_j:.3f}"

    if picked_name:
        rec = _load_catalog_with_cache(LICENSES_JSON)[picked_name]
        return {"matched": True, "name": picked_name, "id": rec["spdx_id"], "match": picked_sig, "notes": notes}

    return {"matched": False, "name": None, "id": None, "match": None, "notes": notes}
