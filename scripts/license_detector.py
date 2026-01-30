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
Key features:
  - Robust preamble stripping and similarity matching (hash, n-gram Jaccard, RapidFuzz).
  - Catalog cache for speed (.github/tools/.cache/licenses_all.cache.json).
  - Permissive policy supports BOTH canonical names AND SPDX IDs (mixed).
  - SPDX expression evaluation: OR / AND / WITH (parentheses supported).
  - LicenseRef normalization: treats “LicenseRef-…”, “LicenseRef_…”, “LicenseRef …”
    uniformly and also compares variants *without* the prefix for policy.
    
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
    r"\bapache license\b", # allow split header lines
    r"gnu (lesser )?general public license",
    r"mozilla public license",
    r"permission is hereby granted, free of charge",
    r"redistribution and use in source and binary forms",
    r"creative commons (attribution|zero|by|cc0)",
    r"this is free and unencumbered software released into the public domain",
    r"the software is provided [\"'“”]?as is[\"'“”]?",
    # --- ADD THESE NEW ANCHORS ---
    r"software license agreement",       # Capture custom headers like Broadcom's
    r"copyright \(c\) ca, inc",          # Capture the specific vendor copyright
    r"broadcom_source_available",        # Capture the ID if it appears in text
    # -----------------------------
]
SPDX_LINE_RE = re.compile(r"^spdx-license-identifier:\s*(?P<expr>.+)$", re.I | re.M)

JACCARD_ACCEPT = 0.80
FUZZY_ACCEPT   = 95.0
FUZZY_STRONG   = 97.0

FALLBACK_PERMISSIVE_SPDX = {
    "MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC",
    "Zlib", "Unlicense", "BSL-1.0", "Python-2.0", "CC0-1.0"
}

# --- begin: normalization helper for reuse -----------------------------------
def normalize_license_id(name_or_id: str) -> str:
    """
    Normalize a license id or name to a lowercase SPDX-like token so matching is stable.
    Keeps '.', '-', '+' which are common in SPDX; maps everything else to '-'.
    """
    if not name_or_id:
        return ""
    return re.sub(r"[^a-z0-9.\-+]", "-", name_or_id.strip().lower())
# --- end: normalization helper for reuse -------------------------------------

# ---------- Text helpers ----------
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
    """
    Remove project notices/disclaimers that precede the actual license body.
    Now Apache-aware: if we see the two-line header, cut there.
    Otherwise: use anchors and mild heuristics.
    """
    lines = full_norm.splitlines()

    # Apache: look for the canonical two-line header and cut there
    ap_start = _find_apache_header_start(lines)
    if ap_start is not None:
        return "\n".join(lines[ap_start:]).strip()

    # Generic: if we see any anchor line, cut at the first such line
    for i, ln in enumerate(lines):
        if any(re.search(a, ln, re.I) for a in ANCHORS):
            return "\n".join(lines[i:]).strip()

    # Heuristic fallback: drop leading meta lines (copyright / notice / about)
    pruned, dropping = [], True
    for ln in lines:
        if dropping and re.match(r"^(copyright|all rights reserved|about|project|disclaimer|notice)\b",
                                 ln.strip(), re.I):
            continue
        dropping = False
        pruned.append(ln)
    return "\n".join(pruned).strip() or full_norm


# --- Apache 2.0 special-cases (common & stable) ---

_APACHE_HEADER_TWO_LINES = re.compile(
    r"(?im)^\s*apache license\s*$\s*^\s*version\s*2\.0,\s*january\s*2004\s*$"
)

def _find_apache_header_start(lines: List[str]) -> Optional[int]:
    """
    Return the line index where a canonical two-line Apache header starts:
      Apache License
      Version 2.0, January 2004
    """
    for i in range(len(lines) - 1):
        if re.match(r"^\s*apache license\s*$", lines[i], re.I) and \
           re.search(r"version\s*2\.0,\s*january\s*2004", lines[i + 1], re.I):
            return i
    return None

def _apache_quick_markers(text_norm: str) -> bool:
    """
    Very high-confidence Apache-2.0 markers (robust to prefaces):
      - standard URL is present
      - canonical 'TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION' line
    """
    return (
        "http://www.apache.org/licenses/" in text_norm
        and "terms and conditions for use, reproduction, and distribution" in text_norm
    )

def _catalog_find_by_spdx(spdx: str, catalog: Dict[str, Dict]) -> Optional[str]:
    """Find catalog name by exact SPDX id."""
    for name, rec in catalog.items():
        if (rec.get("spdx_id") or "") == spdx:
            return name
    return None


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
    src_hash = _hash_file_bytes(licenses_path)
    cache_file = CACHE_DIR / "licenses_all.v2.cache.json"

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

    cache_file.write_text(json.dumps({"source_sha256": src_hash, "items": items}, ensure_ascii=False), encoding="utf-8")
    return items

# ---------- Policy loading & normalization ----------
def _flatten_permissive_entries(raw_value: Any) -> List[str]:
    """
    Normalize a permissive policy blob into a flat list of strings.
    Accepted shapes:
      1) list[str]
      2) list[dict]           -> pull 'name' and/or 'spdx_id' (or 'spdx'/'id')
      3) dict with 'permissive_names': <list[...]>
      4) dict-as-map: { "<name_or_id>": <bool|dict|any>, ... }
         - if value is truthy, include the KEY as an entry
         - if value is a dict, also pull 'name'/'spdx_id' inside it
    """
    # Case 3: dict with explicit list keys
    if isinstance(raw_value, dict):
        # Accept either "permissive_names" or "permissive"
        if "permissive_names" in raw_value:
            raw_value = raw_value["permissive_names"]
        elif "permissive" in raw_value:
            raw_value = raw_value["permissive"]

    out: List[str] = []

    # Case 1/2: top-level list
    if isinstance(raw_value, list):
        for item in raw_value:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                name = item.get("name")
                spdx = item.get("spdx_id") or item.get("spdx") or item.get("id")
                if isinstance(name, str):
                    out.append(name)
                if isinstance(spdx, str):
                    out.append(spdx)
        return out

    # Case 4: dict-as-map
    if isinstance(raw_value, dict):
        for k, v in raw_value.items():
            if v:  # truthy means "permissive"
                if isinstance(k, str):
                    out.append(k)
                if isinstance(v, dict):
                    name = v.get("name")
                    spdx = v.get("spdx_id") or v.get("spdx") or v.get("id")
                    if isinstance(name, str):
                        out.append(name)
                    if isinstance(spdx, str):
                        out.append(spdx)
        return out

    return out

def _load_permissive_entries(path: Path) -> List[str]:
    try:
        raw = _read_json_any(path)
    except Exception:
        return []
    entries = _flatten_permissive_entries(raw)
    # De-dup while preserving order
    seen = set()
    uniq = []
    for e in entries:
        if isinstance(e, str) and e not in seen:
            seen.add(e)
            uniq.append(e)
    return uniq


_LICENSE_REF_RE = re.compile(r"^\s*licenseref[\-_: ]*", flags=re.I)

def _strip_licenseref_prefix(s: str) -> str:
    return _LICENSE_REF_RE.sub("", s or "")

def _canon_key(s: str) -> str:
    s = (s or "").casefold()
    s = s.replace("’", "'").replace("“", '"').replace("”", '"').replace("–", "-").replace("—", "-")
    s = re.sub(r"[^a-z0-9]+", "", s)
    return s

def _canon_variants(s: str) -> List[str]:
    if not s:
        return []
    c1 = _canon_key(s)
    s2 = _strip_licenseref_prefix(s)
    c2 = _canon_key(s2) if s2 != s else c1
    return list(dict.fromkeys([c1, c2]))

def _build_perm_index() -> Tuple[set, set, set]:
    """
    Build permissive sets:
      - allow_name_raw: exact catalog names (raw strings)
      - allow_id_raw:   exact SPDX IDs (raw strings)
      - allow_canon:    canonical keys for both names and IDs (with/without LicenseRef)
    """
    catalog = _load_catalog_with_cache(LICENSES_JSON)
    name_to_id: Dict[str, str] = {}
    id_to_name: Dict[str, str] = {}
    for name, rec in catalog.items():
        spdx = (rec.get("spdx_id") or "").strip()
        if spdx:
            name_to_id[name] = spdx
            id_to_name[spdx] = name

    entries = [e for e in _load_permissive_entries(PERMISSIVE_JSON) if isinstance(e, str)]

    allow_name_raw: set = set()
    allow_id_raw: set = set()
    allow_canon: set = set()

    for e in entries:
        for v in _canon_variants(e):
            allow_canon.add(v)

        if e in id_to_name:
            allow_id_raw.add(e)
            for v in _canon_variants(id_to_name[e]):
                allow_canon.add(v)
        elif e in name_to_id:
            allow_name_raw.add(e)
            for v in _canon_variants(name_to_id[e]):
                allow_canon.add(v)

    return allow_name_raw, allow_id_raw, allow_canon

# ---------- SPDX expression parsing ----------
def _split_top(expr: str, op: str) -> List[str]:
    s = expr
    i, n, level = 0, len(s), 0
    parts, buf = [], []
    op_sp = f" {op} "
    while i < n:
        ch = s[i]
        if ch == '(':
            level += 1; buf.append(ch); i += 1; continue
        if ch == ')':
            level = max(0, level - 1); buf.append(ch); i += 1; continue
        if level == 0 and s[i:i+len(op_sp)].upper() == op_sp:
            parts.append("".join(buf)); buf = []; i += len(op_sp); continue
        buf.append(ch); i += 1
    parts.append("".join(buf))
    return parts

def _strip_parens(s: str) -> str:
    t = s.strip()
    if t.startswith('(') and t.endswith(')'):
        level = 0
        for ch in t:
            if ch == '(': level += 1
            elif ch == ')':
                level -= 1
                if level < 0:
                    return s.strip()
        if level == 0:
            return t[1:-1].strip()
    return t

def _remove_with(term: str) -> str:
    parts = re.split(r"\bWITH\b", term, flags=re.I)
    return parts[0].strip()

def _parse_spdx_expr(expr: str) -> List[List[str]]:
    if not expr or not isinstance(expr, str):
        return []
    ors = _split_top(expr, "OR")
    clauses: List[List[str]] = []
    for part in ors:
        part = _strip_parens(part)
        ands = _split_top(part, "AND")
        units: List[str] = []
        for a in ands:
            base = _remove_with(_strip_parens(a))
            if base:
                units.append(base)
        if units:
            clauses.append(units)
    return clauses

# ---------- Public helpers ----------
def catalog_maps() -> Tuple[Dict[str, str], Dict[str, str]]:
    cat = _load_catalog_with_cache(LICENSES_JSON)
    name_to_id_lower: Dict[str, str] = {}
    id_to_name: Dict[str, str] = {}
    for name, rec in cat.items():
        spdx = (rec.get("spdx_id") or "").strip()
        if spdx:
            name_to_id_lower[name.lower()] = spdx
            id_to_name[spdx] = name
    return name_to_id_lower, id_to_name

def _is_unit_permissive(unit: str,
                        allow_name_raw: set, allow_id_raw: set, allow_canon: set,
                        id_to_name: Dict[str, str], name_to_id_lower: Dict[str, str]) -> Tuple[Optional[bool], str]:
    """Return (decision, reason) for a single license token (no OR/AND/WITH)."""
    if not unit:
        return None, "empty_unit"

    # 1) Exact raw ID
    if unit in allow_id_raw:
        return True, "unit_exact_id"
    # 2) Exact raw NAME (only if it's an actual catalog name)
    if unit in id_to_name.values() and unit in allow_name_raw:
        return True, "unit_exact_name"

    # 3) Canonical variants for the unit itself
    for v in _canon_variants(unit):
        if v in allow_canon:
            return True, "unit_match_canon"

    # 4) Map ID → Name, then test variants
    if unit in id_to_name:
        for v in _canon_variants(id_to_name[unit]):
            if v in allow_canon:
                return True, "id_to_name_canon"
    # 5) Map Name → ID (case-insensitive), then test variants
    lower = unit.lower()
    if lower in name_to_id_lower:
        for v in _canon_variants(name_to_id_lower[lower]):
            if v in allow_canon:
                return True, "name_to_id_canon"

    # 6) Safety net for well-known permissives
    if unit in FALLBACK_PERMISSIVE_SPDX:
        return True, "fallback_spdx"

    return False, "no_match"

def _is_expr_permissive(expr: str, allow_name_raw: set, allow_id_raw: set, allow_canon: set) -> Tuple[Optional[bool], str]:
    """Evaluate SPDX expression; returns (decision, reason)."""
    name_to_id_lower, id_to_name = catalog_maps()
    clauses = _parse_spdx_expr(expr)
    if not clauses:
        return None, "expr_empty_or_unparsed"

    for clause in clauses:  # OR over clauses
        all_units_true = True
        reasons = []
        for unit in clause:  # AND within a clause
            unit_ok, why = _is_unit_permissive(unit, allow_name_raw, allow_id_raw, allow_canon,
                                               id_to_name, name_to_id_lower)
            reasons.append(f"{unit}:{why}")
            if unit_ok is False or unit_ok is None:
                all_units_true = False
                break
        if all_units_true:
            return True, "expr_OR(any_true): " + "; ".join(reasons)
    return False, "expr_OR(all_false)"

def is_permissive_with_reason(license_name: Optional[str], spdx_id: Optional[str] = None) -> Tuple[Optional[bool], str]:
    """
    Decide permissiveness with a human-readable reason for auditing.
    Returns (True/False/None, reason).
    """
    if not license_name and not spdx_id:
        return None, "no_inputs"

    allow_name_raw, allow_id_raw, allow_canon = _build_perm_index()

    # Expression detection
    expr_candidate = None
    for cand in (spdx_id, license_name):
        if isinstance(cand, str) and re.search(r"\b(OR|AND|WITH)\b|\(|\)", cand, flags=re.I):
            expr_candidate = cand
            break
    if expr_candidate:
        return _is_expr_permissive(expr_candidate, allow_name_raw, allow_id_raw, allow_canon)

    # Single unit
    name_to_id_lower, id_to_name = catalog_maps()
    if spdx_id:
        unit_ok, why = _is_unit_permissive(spdx_id, allow_name_raw, allow_id_raw, allow_canon,
                                           id_to_name, name_to_id_lower)
        if unit_ok is not None:
            return unit_ok, why
    if license_name:
        unit_ok, why = _is_unit_permissive(license_name, allow_name_raw, allow_id_raw, allow_canon,
                                           id_to_name, name_to_id_lower)
        if unit_ok is not None:
            return unit_ok, why

    return None, "insufficient_info"

def is_permissive(license_name: Optional[str], spdx_id: Optional[str] = None) -> Optional[bool]:
    """Compatibility wrapper (without reason) used by older callers."""
    decision, _ = is_permissive_with_reason(license_name, spdx_id)
    return decision

# ---------- Detection ----------
def detect_from_text(text: str) -> Dict[str, Any]:
    full_norm = _normalize(text or "")
    body = _strip_preamble(full_norm)

    notes = None
    m = SPDX_LINE_RE.search(text or "")

    # --- START PATCH: Trust the SPDX Header ---
    if m:
        spdx_hint = m.group('expr').strip()
        notes = f"spdx_hint={spdx_hint}"

        # Load catalog immediately to verify the hint
        catalog = _load_catalog_with_cache(LICENSES_JSON)
        
        # Look up the ID from the header (e.g., "LicenseRef-Broadcom-...")
        found_name = _catalog_find_by_spdx(spdx_hint, catalog)
        
        # If the header ID exists in our DB, trust it 100% and return immediately
        if found_name:
            rec = catalog[found_name]
            return {
                "matched": True,
                "name": found_name,
                "id": rec["spdx_id"],
                "match": "spdx_header_hint",
                "notes": notes
            }
    # --- END PATCH ---

    catalog = _load_catalog_with_cache(LICENSES_JSON)

      # Quick Apache-2.0 recognition (very high confidence)
    if _apache_quick_markers(full_norm):
        catalog = _load_catalog_with_cache(LICENSES_JSON)
        apache_name = _catalog_find_by_spdx("Apache-2.0", catalog)
        if apache_name:
            rec = catalog[apache_name]
            return {"matched": True, "name": apache_name, "id": rec["spdx_id"], "match": "apache_markers", "notes": notes}

    # (1) Exact hash match
    body_hash = _sha256(body)
    for name, rec in catalog.items():
        if rec["base_hash"] and body_hash == rec["base_hash"]:
            return {"matched": True, "name": name, "id": rec["spdx_id"], "match": "hash", "notes": notes}

    # (2) Narrow by anchors + length
    body_anchors = set(_contains_any_anchor(body))
    body_len = len(body)
    narrowed: Dict[str, str] = {}
    for name, rec in catalog.items():
        txt = rec["base_norm"]
        if not txt:
            continue
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

    # (3) Similarity
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

    # --- DEBUG INSTRUMENTATION START ---
    print(f"::warning::[DEBUG DETECTOR] Text Length: {len(body)}")
    print(f"::warning::   -> Jaccard Score: {best_j:.3f} | Candidate: {best_j_id}")
    if HAVE_RAPID:
        print(f"::warning::   -> Fuzzy Score:   {best_f:.1f}  | Candidate: {best_f_id}")
    else:
        print(f"::warning::   -> RapidFuzz NOT installed.")
        
    if m:
        print(f"::warning::   -> SPDX Header Found: {m.group('expr').strip()}")
    # -----------------------------------
  
    picked_name, picked_sig = None, ""

    # --- REPLACE THE DECISION BLOCK ABOVE WITH THIS SAFE VERSION ---


    # 1. TRUST STRUCTURE FIRST (The Fix)
    # If Jaccard is > 0.85, the structure is nearly identical. 
    # This correctly disqualifies "Subsets" (like MIT inside Broadcom).
    if best_j >= 0.85:
        picked_name, picked_sig = best_j_id, f"jaccard:{best_j:.3f}"

    # 2. FALLBACK TO FUZZY (The Safety Net)
    # Only if structure was poor (e.g. massive header text, weird formatting),
    # we let Fuzzy take over to find the "best partial match".
    elif HAVE_RAPID and best_f >= FUZZY_STRONG:
        picked_name, picked_sig = best_f_id, f"fuzzy:{best_f:.1f}"
        
    elif best_j >= JACCARD_ACCEPT: # Lower threshold (0.80)
        picked_name, picked_sig = best_j_id, f"jaccard:{best_j:.3f}"
        
    elif HAVE_RAPID and best_f >= FUZZY_ACCEPT:
        picked_name, picked_sig = best_f_id, f"fuzzy:{best_f:.1f}"
    # -----------------------------------------------------------
      
    if picked_name:
        rec = _load_catalog_with_cache(LICENSES_JSON)[picked_name]
        return {"matched": True, "name": picked_name, "id": rec["spdx_id"], "match": picked_sig, "notes": notes}

    return {"matched": False, "name": None, "id": None, "match": None, "notes": notes}

