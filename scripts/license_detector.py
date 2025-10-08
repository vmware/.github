#!/usr/bin/env python3
"""
license_detector.py
Preamble-tolerant repo-license detector (JSON-driven, cache-aware, gzip-aware).

- Single catalog: data/licenses_all.json (or .json.gz), keyed by license "name".
  Each entry includes:
    name        (str)
    spdx_id     (str; SPDX or LicenseRef-*)
    text_varies (bool)
    base_text   (str; canonical body used for matching)

- Policy: data/permissive_names.json
  Either: {"permissive_names": ["MIT License", ...]} or a plain JSON array.

Outputs: helper functions for matching from arbitrary text (no filesystem needed).
"""

from __future__ import annotations
import json, os, re, hashlib, gzip
from pathlib import Path
from typing import Dict, Tuple, List, Any, Optional

# Optional fuzzy lib (better matching)
try:
    from rapidfuzz.fuzz import token_set_ratio
    from rapidfuzz.utils import default_process
    HAVE_RAPID = True
except Exception:
    HAVE_RAPID = False

# ---------- configuration via env (paths resolved by caller script) ----------
LICENSES_JSON = Path(os.getenv("LICENSES_JSON", "data/licenses_all.json")).resolve()
PERMISSIVE_JSON = Path(os.getenv("PERMISSIVE_JSON", "data/permissive_names.json")).resolve()
CACHE_DIR = Path(os.getenv("CACHE_DIR", ".github/tools/.cache")).resolve()
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# ---------- heuristics ----------
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

# thresholds
JACCARD_ACCEPT = 0.80
FUZZY_ACCEPT = 95.0
FUZZY_STRONG = 97.0

# ---------- helpers ----------
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

# ---------- catalog cache ----------
def _load_catalog_with_cache(licenses_path: Path) -> Dict[str, Dict]:
    """
    Returns: dict[name] = {
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

    items = {}
    for name, rec in raw.items():
        base_text = rec.get("base_text") or ""
        base_norm = _normalize(base_text)
        anchor_flags = _contains_any_anchor(base_norm)
        items[name] = {
            "name": rec.get("name", name),
            "spdx_id": rec.get("spdx_id"),
            "text_varies": bool(rec.get("text_varies", False)),
            "base_norm": base_norm,
            "base_hash": _sha256(base_norm) if base_norm else None,
            "len": len(base_norm),
            "anchor_flags": anchor_flags
        }

    cache_file.write_text(json.dumps({"source_sha256": src_hash, "items": items}, ensure_ascii=False), encoding="utf-8")
    return items

def _load_permissive_names(path: Path) -> set:
    raw = _read_json_any(path)
    names = raw.get("permissive_names", raw) if isinstance(raw, dict) else raw
    return set(n.lower() for n in names if isinstance(n, str))

# ---------- public API ----------
def detect_from_text(text: str) -> Dict[str, Any]:
    """
    Detect license from raw license file text (possibly with preamble).
    Returns a dict with keys:
      matched(bool), name(str|None), id(str|None), match(str|None), notes(str|None)
    No policy here—pure detection.
    """
    full_norm = _normalize(text or "")
    body = _strip_preamble(full_norm)
    notes = None
    m = SPDX_LINE_RE.search(text or "")
    if m:
        notes = f"spdx_hint={m.group('expr').strip()}"

    catalog = _load_catalog_with_cache(LICENSES_JSON)
    # Stage 1: body hash
    body_hash = _sha256(body)
    for name, rec in catalog.items():
        if rec["base_hash"] and body_hash == rec["base_hash"]:
            return {"matched": True, "name": name, "id": rec["spdx_id"], "match": "hash", "notes": notes}

    # Stage 2: narrow candidates
    body_anchors = set(_contains_any_anchor(body))
    body_len = len(body)
    narrowed = {}
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

    # Stage 3: similarity
    # Jaccard 5-gram
    body_5 = _tokenize_ngrams(body, 5)
    best_j_id, best_j = None, 0.0
    for key, text_norm in narrowed.items():
        score = _jaccard(body_5, _tokenize_ngrams(text_norm, 5))
        if score > best_j:
            best_j_id, best_j = key, score

    # Fuzzy
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

def is_permissive(license_name: Optional[str]) -> Optional[bool]:
    """Return True/False if name known; None if name is None or policy list missing/empty."""
    if not license_name:
        return None
    names = _load_permissive_names(PERMISSIVE_JSON)
    return (license_name.lower() in names)
