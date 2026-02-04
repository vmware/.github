#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
license_detector.py
-------------------
Purpose:
  - Detect the *repository root* license from raw text.
  - Match it against a catalog (licenses_all.json).
  - Provide a policy helper (permissive vs strict).
Key features:
  - Supports loading catalog from FILE (legacy) or MEMORY (List/Dict).
  - Robust to input format changes (List vs Dict catalog).
  - Normalizes text and computes hashes on the fly.
"""

from __future__ import annotations
import json, os, re, hashlib, gzip
from pathlib import Path
from typing import Dict, Tuple, List, Any, Optional

# Optional fuzzy matching
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
    r"\bapache license\b", 
    r"gnu (lesser )?general public license",
    r"mozilla public license",
    r"permission is hereby granted, free of charge",
    r"redistribution and use in source and binary forms",
    r"creative commons (attribution|zero|by|cc0)",
    r"this is free and unencumbered software released into the public domain",
    r"the software is provided [\"'“”]?as is[\"'“”]?",
    r"software license agreement",       
    r"copyright \(c\) ca, inc",          
    r"broadcom_source_available",        
]
SPDX_LINE_RE = re.compile(r"^spdx-license-identifier:\s*(?P<expr>.+)$", re.I | re.M)

JACCARD_ACCEPT = 0.80
FUZZY_ACCEPT   = 95.0
FUZZY_STRONG   = 97.0

FALLBACK_PERMISSIVE_SPDX = {
    "MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC",
    "Zlib", "Unlicense", "BSL-1.0", "Python-2.0", "CC0-1.0"
}

# --- Normalization ---
def normalize_license_id(name_or_id: str) -> str:
    if not name_or_id: return ""
    return re.sub(r"[^a-z0-9.\-+]", "-", name_or_id.strip().lower())

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
    ap_start = _find_apache_header_start(lines)
    if ap_start is not None:
        return "\n".join(lines[ap_start:]).strip()

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

def _find_apache_header_start(lines: List[str]) -> Optional[int]:
    for i in range(len(lines) - 1):
        if re.match(r"^\s*apache license\s*$", lines[i], re.I) and \
           re.search(r"version\s*2\.0,\s*january\s*2004", lines[i + 1], re.I):
            return i
    return None

def _apache_quick_markers(text_norm: str) -> bool:
    return (
        "http://www.apache.org/licenses/" in text_norm
        and "terms and conditions for use, reproduction, and distribution" in text_norm
    )

def _catalog_find_by_spdx(spdx: str, catalog: Dict[str, Dict]) -> Optional[str]:
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

# ---------- Catalog Processing (THE FIX) ----------
def _process_catalog_data(raw_data: Any) -> Dict[str, Dict]:
    """
    Process raw license data (list OR dict) into the internal dict format.
    Normalized text and hashes are computed on the fly.
    """
    raw_dict = {}
    
    # CASE A: Input is a List of Dicts (e.g., [{name: "MIT", ...}])
    if isinstance(raw_data, list):
        for item in raw_data:
            if isinstance(item, dict):
                name = item.get("name")
                if name:
                    raw_dict[name] = item
                    
    # CASE B: Input is a Dict (e.g., {"MIT": {...}})
    elif isinstance(raw_data, dict):
        raw_dict = raw_data
        
    else:
        # Invalid format
        return {}

    items: Dict[str, Dict] = {}
    for name, rec in raw_dict.items():
        if not isinstance(rec, dict): continue

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
    return items

def _get_catalog(catalog_data: Any = None) -> Dict[str, Dict]:
    if catalog_data is not None:
        return _process_catalog_data(catalog_data)
    return _load_catalog_with_cache(LICENSES_JSON)

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
    # Use our robust processor to handle the file content too
    items = _process_catalog_data(raw)

    cache_file.write_text(json.dumps({"source_sha256": src_hash, "items": items}, ensure_ascii=False), encoding="utf-8")
    return items

# ---------- Policy loading ----------
def _flatten_permissive_entries(raw_value: Any) -> List[str]:
    if isinstance(raw_value, dict):
        if "permissive_names" in raw_value: raw_value = raw_value["permissive_names"]
        elif "permissive" in raw_value: raw_value = raw_value["permissive"]

    out: List[str] = []
    if isinstance(raw_value, list):
        for item in raw_value:
            if isinstance(item, str): out.append(item)
            elif isinstance(item, dict):
                name = item.get("name")
                spdx = item.get("spdx_id") or item.get("spdx") or item.get("id")
                if isinstance(name, str): out.append(name)
                if isinstance(spdx, str): out.append(spdx)
        return out

    if isinstance(raw_value, dict):
        for k, v in raw_value.items():
            if v:
                if isinstance(k, str): out.append(k)
                if isinstance(v, dict):
                    name = v.get("name")
                    spdx = v.get("spdx_id") or v.get("spdx") or v.get("id")
                    if isinstance(name, str): out.append(name)
                    if isinstance(spdx, str): out.append(spdx)
        return out
    return out

def _load_permissive_entries(path: Path) -> List[str]:
    try:
        raw = _read_json_any(path)
    except Exception:
        return []
    entries = _flatten_permissive_entries(raw)
    seen = set()
    uniq = []
    for e in entries:
        if isinstance(e, str) and e not in seen:
            seen.add(e)
            uniq.append(e)
    return uniq

_LICENSE_REF_RE = re.compile(r"^\s*licenseref[\-_: ]*", flags=re.I)
def _strip_licenseref_prefix(s: str) -> str: return _LICENSE_REF_RE.sub("", s or "")
def _canon_key(s: str) -> str:
    s = (s or "").casefold()
    s = s.replace("’", "'").replace("“", '"').replace("”", '"').replace("–", "-").replace("—", "-")
    s = re.sub(r"[^a-z0-9]+", "", s)
    return s

def _canon_variants(s: str) -> List[str]:
    if not s: return []
    c1 = _canon_key(s)
    s2 = _strip_licenseref_prefix(s)
    c2 = _canon_key(s2) if s2 != s else c1
    return list(dict.fromkeys([c1, c2]))

def _build_perm_index(permissive_data: Any = None, catalog_data: Any = None) -> Tuple[set, set, set]:
    catalog = _get_catalog(catalog_data)
    name_to_id: Dict[str, str] = {}
    id_to_name: Dict[str, str] = {}
    for name, rec in catalog.items():
        spdx = (rec.get("spdx_id") or "").strip()
        if spdx:
            name_to_id[name] = spdx
            id_to_name[spdx] = name

    if permissive_data is not None:
        entries = [e for e in _flatten_permissive_entries(permissive_data) if isinstance(e, str)]
    else:
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

# ---------- SPDX ----------
def _split_top(expr: str, op: str) -> List[str]:
    s = expr; i, n, level = 0, len(s), 0; parts, buf = [], []; op_sp = f" {op} "
    while i < n:
        ch = s[i]
        if ch == '(': level += 1; buf.append(ch); i += 1; continue
        if ch == ')': level = max(0, level - 1); buf.append(ch); i += 1; continue
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
                if level < 0: return s.strip()
        if level == 0: return t[1:-1].strip()
    return t
def _remove_with(term: str) -> str: return re.split(r"\bWITH\b", term, flags=re.I)[0].strip()
def _parse_spdx_expr(expr: str) -> List[List[str]]:
    if not expr or not isinstance(expr, str): return []
    ors = _split_top(expr, "OR"); clauses = []
    for part in ors:
        part = _strip_parens(part); ands = _split_top(part, "AND"); units = []
        for a in ands:
            base = _remove_with(_strip_parens(a))
            if base: units.append(base)
        if units: clauses.append(units)
    return clauses

def catalog_maps(catalog_data: Any = None) -> Tuple[Dict[str, str], Dict[str, str]]:
    cat = _get_catalog(catalog_data); name_to_id_lower = {}; id_to_name = {}
    for name, rec in cat.items():
        spdx = (rec.get("spdx_id") or "").strip()
        if spdx: name_to_id_lower[name.lower()] = spdx; id_to_name[spdx] = name
    return name_to_id_lower, id_to_name

def _is_unit_permissive(unit: str, allow_name_raw: set, allow_id_raw: set, allow_canon: set, id_to_name: Dict[str, str], name_to_id_lower: Dict[str, str]) -> Tuple[Optional[bool], str]:
    if not unit: return None, "empty_unit"
    if unit in allow_id_raw: return True, "unit_exact_id"
    if unit in id_to_name.values() and unit in allow_name_raw: return True, "unit_exact_name"
    for v in _canon_variants(unit):
        if v in allow_canon: return True, "unit_match_canon"
    if unit in id_to_name:
        for v in _canon_variants(id_to_name[unit]):
            if v in allow_canon: return True, "id_to_name_canon"
    lower = unit.lower()
    if lower in name_to_id_lower:
        for v in _canon_variants(name_to_id_lower[lower]):
            if v in allow_canon: return True, "name_to_id_canon"
    if unit in FALLBACK_PERMISSIVE_SPDX: return True, "fallback_spdx"
    return False, "no_match"

def _is_expr_permissive(expr: str, allow_name_raw: set, allow_id_raw: set, allow_canon: set, catalog_data: Any = None) -> Tuple[Optional[bool], str]:
    name_to_id_lower, id_to_name = catalog_maps(catalog_data); clauses = _parse_spdx_expr(expr)
    if not clauses: return None, "expr_empty_or_unparsed"
    for clause in clauses:
        all_units_true = True; reasons = []
        for unit in clause:
            unit_ok, why = _is_unit_permissive(unit, allow_name_raw, allow_id_raw, allow_canon, id_to_name, name_to_id_lower)
            reasons.append(f"{unit}:{why}")
            if unit_ok is False or unit_ok is None: all_units_true = False; break
        if all_units_true: return True, "expr_OR(any_true): " + "; ".join(reasons)
    return False, "expr_OR(all_false)"

def is_permissive_with_reason(license_name: Optional[str], spdx_id: Optional[str] = None, permissive_data: Any = None, catalog_data: Any = None) -> Tuple[Optional[bool], str]:
    if not license_name and not spdx_id: return None, "no_inputs"
    allow_name_raw, allow_id_raw, allow_canon = _build_perm_index(permissive_data, catalog_data)
    expr_candidate = None
    for cand in (spdx_id, license_name):
        if isinstance(cand, str) and re.search(r"\b(OR|AND|WITH)\b|\(|\)", cand, flags=re.I):
            expr_candidate = cand; break
    if expr_candidate: return _is_expr_permissive(expr_candidate, allow_name_raw, allow_id_raw, allow_canon, catalog_data)

    name_to_id_lower, id_to_name = catalog_maps(catalog_data)
    if spdx_id:
        unit_ok, why = _is_unit_permissive(spdx_id, allow_name_raw, allow_id_raw, allow_canon, id_to_name, name_to_id_lower)
        if unit_ok is not None: return unit_ok, why
    if license_name:
        unit_ok, why = _is_unit_permissive(license_name, allow_name_raw, allow_id_raw, allow_canon, id_to_name, name_to_id_lower)
        if unit_ok is not None: return unit_ok, why
    return None, "insufficient_info"

def is_permissive(license_name: Optional[str], spdx_id: Optional[str] = None, permissive_data: Any = None, catalog_data: Any = None) -> Optional[bool]:
    decision, _ = is_permissive_with_reason(license_name, spdx_id, permissive_data, catalog_data)
    return decision

# ---------- Detection ----------
def detect_from_text(text: str, catalog_data: Any = None) -> Dict[str, Any]:
    full_norm = _normalize(text or "")
    body = _strip_preamble(full_norm)
    notes = None
    m = SPDX_LINE_RE.search(text or "")
    catalog = _get_catalog(catalog_data)

    if m:
        spdx_hint = m.group('expr').strip()
        notes = f"spdx_hint={spdx_hint}"
        found_name = _catalog_find_by_spdx(spdx_hint, catalog)
        if found_name:
            rec = catalog[found_name]
            return {"matched": True, "name": found_name, "id": rec["spdx_id"], "match": "spdx_header_hint", "notes": notes}

    if _apache_quick_markers(full_norm):
        apache_name = _catalog_find_by_spdx("Apache-2.0", catalog)
        if apache_name:
            rec = catalog[apache_name]
            return {"matched": True, "name": apache_name, "id": rec["spdx_id"], "match": "apache_markers", "notes": notes}

    body_hash = _sha256(body)
    for name, rec in catalog.items():
        if rec["base_hash"] and body_hash == rec["base_hash"]:
            return {"matched": True, "name": name, "id": rec["spdx_id"], "match": "hash", "notes": notes}

    body_anchors = set(_contains_any_anchor(body))
    body_len = len(body)
    narrowed = {}
    for name, rec in catalog.items():
        txt = rec["base_norm"]
        if not txt: continue
        if body_anchors and not (set(rec["anchor_flags"]) & body_anchors): continue
        if rec["len"] > 0:
            ratio = body_len / rec["len"]
            if ratio < 0.5 or ratio > 2.0: continue
        narrowed[name] = txt

    if not narrowed:
        shortest = sorted([(n, r["len"]) for n, r in catalog.items() if r["len"] > 0], key=lambda x: x[1])[:200]
        narrowed = {n: catalog[n]["base_norm"] for n, _ in shortest}

    body_5 = _tokenize_ngrams(body, 5)
    best_j_id, best_j = None, 0.0
    for key, text_norm in narrowed.items():
        score = _jaccard(body_5, _tokenize_ngrams(text_norm, 5))
        if score > best_j: best_j_id, best_j = key, score

    best_f_id, best_f = None, 0.0
    if HAVE_RAPID:
        bp = default_process(body)
        for key, text_norm in narrowed.items():
            sc = float(token_set_ratio(bp, default_process(text_norm)))
            if sc > best_f: best_f_id, best_f = key, sc

    print(f"::warning::[DEBUG DETECTOR] Text Length: {len(body)}")
    print(f"::warning::   -> Jaccard Score: {best_j:.3f} | Candidate: {best_j_id}")
    if HAVE_RAPID: print(f"::warning::   -> Fuzzy Score:   {best_f:.1f}  | Candidate: {best_f_id}")

    picked_name, picked_sig = None, ""
    if best_j >= 0.85: picked_name, picked_sig = best_j_id, f"jaccard:{best_j:.3f}"
    elif HAVE_RAPID and best_f >= FUZZY_STRONG: picked_name, picked_sig = best_f_id, f"fuzzy:{best_f:.1f}"
    elif best_j >= JACCARD_ACCEPT: picked_name, picked_sig = best_j_id, f"jaccard:{best_j:.3f}"
    elif HAVE_RAPID and best_f >= FUZZY_ACCEPT: picked_name, picked_sig = best_f_id, f"fuzzy:{best_f:.1f}"

    if picked_name:
        rec = catalog[picked_name]
        return {"matched": True, "name": picked_name, "id": rec["spdx_id"], "match": picked_sig, "notes": notes}
    return {"matched": False, "name": None, "id": None, "match": None, "notes": notes}

