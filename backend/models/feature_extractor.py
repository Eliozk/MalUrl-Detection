# backend/models/feature_extractor.py

import re
import zlib
import numpy as np
import pandas as pd
from typing import Optional, Dict, List, Tuple
from urllib.parse import urlparse, urlunparse

try:
    from tld import get_tld
except Exception:
    get_tld = None


# ----------------------------
# URL Normalization (robust)
# ----------------------------
def normalize_url(u: str) -> str:
    """
    Normalize URL in a robust way without crashing on malformed inputs.
    Goal: consistency (lowercase scheme/host, remove fragments, fix missing scheme)
    but do NOT destroy informative parts (keep path/query as-is).
    """
    if u is None:
        return ""

    u = str(u).strip()
    if not u:
        return ""

    # Remove whitespace
    u = re.sub(r"\s+", "", u)

    # If starts with //example.com...
    if u.startswith("//"):
        u = "http:" + u

    # If missing scheme, add http:// for parsing only
    add_scheme = False
    if "://" not in u:
        add_scheme = True
        u_parse = "http://" + u
    else:
        u_parse = u

    try:
        p = urlparse(u_parse)
    except ValueError:
        # Example: "Invalid IPv6 URL"
        # Return a safe cleaned version instead of crashing
        return u.lower()

    scheme = (p.scheme or "http").lower()
    netloc = (p.netloc or "").lower()
    path = p.path or ""
    query = p.query or ""
    fragment = ""  # drop fragments

    # Remove default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    if netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    # If we added scheme for parsing and the original had none,
    # keep normalized without forcing scheme text changes beyond consistency.
    # We still output scheme://netloc/... (because your pipeline expects parseable URLs).
    out = urlunparse((scheme, netloc, path, "", query, fragment))
    return out


# ----------------------------
# Base lexical / structural features
# ----------------------------
def having_ip_address(url: str) -> int:
    ipv4_pattern = r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])"
    ipv6_pattern = r"([a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}"
    try:
        return 1 if re.search(ipv4_pattern, url) or re.search(ipv6_pattern, url) else 0
    except Exception:
        return 0


def abnormal_url(url: str) -> int:
    try:
        hostname = str(urlparse(url).hostname or "")
        return 0 if hostname and hostname in url else 1
    except Exception:
        return 1


def shortening_service(url: str) -> int:
    pattern = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs"
    try:
        return 1 if re.search(pattern, url, re.IGNORECASE) else 0
    except Exception:
        return 0


_SPECIAL_CHARS = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']


def base_features(url_norm: str) -> Dict[str, float]:
    """
    Base feature dict. Key order is stable by insertion order.
    """
    parsed = urlparse(url_norm)
    feats: Dict[str, float] = {}

    # Lexical
    feats["url_length"] = float(len(url_norm))
    feats["hostname_length"] = float(len(parsed.netloc or ""))
    feats["count_letters"] = float(sum(c.isalpha() for c in url_norm))
    feats["count_digits"] = float(sum(c.isnumeric() for c in url_norm))

    # Special character counts
    for ch in _SPECIAL_CHARS:
        col_name = f"count_{ch.replace('//', 'slashes')}"
        feats[col_name] = float(url_norm.count(ch))

    feats["count_www"] = float(url_norm.lower().count("www"))
    feats["has_ip"] = float(having_ip_address(url_norm))
    feats["abnormal_url"] = float(abnormal_url(url_norm))
    feats["short_url"] = float(shortening_service(url_norm))
    feats["https"] = float(1 if (parsed.scheme or "").lower() == "https" else 0)

    # Path structure
    feats["count_dir"] = float((parsed.path or "").count("/"))
    feats["count_embed_domain"] = float((parsed.path or "").count("//"))

    # First directory length
    try:
        parts = (parsed.path or "").split("/")
        feats["fd_length"] = float(len(parts[1])) if len(parts) > 1 else 0.0
    except Exception:
        feats["fd_length"] = 0.0

    # TLD length
    tld_len = 0.0
    try:
        if get_tld is not None:
            t = get_tld(url_norm, fail_silently=True)
            tld_len = float(len(t)) if t else 0.0
    except Exception:
        tld_len = 0.0
    feats["tld_length"] = tld_len

    # Suspicious keywords
    kw = r"paypal|login|signin|bank|account|update|free|bonus|service|ebayisapi|webscr|lucky|secure|verification|confirm"
    try:
        feats["suspicious"] = float(1 if re.search(kw, url_norm, re.IGNORECASE) else 0)
    except Exception:
        feats["suspicious"] = 0.0

    return feats


# ----------------------------
# Trigram hashing features
# ----------------------------
def _safe_crc32_bucket(s: str, mod: int) -> int:
    if mod <= 0:
        return 0
    return zlib.crc32(s.encode("utf-8", errors="ignore")) % mod


def _char_ngrams(text: str, n: int):
    if text is None:
        return
    t = str(text)
    if n <= 0 or len(t) < n:
        return
    for i in range(len(t) - n + 1):
        yield t[i : i + n]


def trigram_hash_features(url_norm: str, trigram_buckets: int = 256) -> np.ndarray:
    """
    Hashed trigram count features, L1-normalized.
    """
    if trigram_buckets <= 0:
        return np.zeros(0, dtype=np.float32)

    v = np.zeros(trigram_buckets, dtype=np.float32)
    for ng in _char_ngrams(url_norm, 3):
        b = _safe_crc32_bucket(ng, trigram_buckets)
        v[b] += 1.0

    s = float(v.sum())
    if s > 0:
        v /= s
    return v


# ----------------------------
# Benign Language Model (hashed LM) features
# ----------------------------
def build_hashed_lm_tables(
    urls_norm: List[str],
    table_size: int = 50000,
    max_urls: int = 120000,
    lm_parts: Optional[List[str]] = None
) -> Tuple[Dict[Tuple[str, int], np.ndarray], Dict]:
    """
    Build hashed count tables from benign URLs for parts in lm_parts.
    parts default: ["host","path","query"].
    n-grams: n=1..4 per part.
    """
    if lm_parts is None:
        lm_parts = ["host", "path", "query"]

    tables: Dict[Tuple[str, int], np.ndarray] = {}
    for part in lm_parts:
        for n in [1, 2, 3, 4]:
            tables[(part, n)] = np.zeros(table_size, dtype=np.int32)

    used = 0
    for u in urls_norm:
        if used >= max_urls:
            break

        try:
            p = urlparse(u)
        except Exception:
            continue

        host = (p.netloc or "").lower()
        path = (p.path or "")
        query = (p.query or "")

        parts_map = {"host": host, "path": path, "query": query}

        for part_name in lm_parts:
            text = parts_map.get(part_name, "")
            for n in [1, 2, 3, 4]:
                for ng in _char_ngrams(text, n):
                    b = _safe_crc32_bucket(ng, table_size)
                    tables[(part_name, n)][b] += 1

        used += 1

    meta = {
        "table_size": int(table_size),
        "max_urls": int(max_urls),
        "used_urls": int(used),
        "alpha": 1.0,
        "lm_parts": list(lm_parts),
    }
    return tables, meta


def lm_features_from_tables(url_norm: str, lm_tables: Dict, lm_meta: Dict) -> np.ndarray:
    """
    For each part in lm_parts and n=1..4:
      feature = average log-prob of n-grams under hashed LM tables.
    """
    try:
        p = urlparse(url_norm)
    except Exception:
        # return zeros matching expected length
        lm_parts = lm_meta.get("lm_parts", ["host", "path", "query"])
        return np.zeros(len(lm_parts) * 4, dtype=np.float32)

    host = (p.netloc or "").lower()
    path = (p.path or "")
    query = (p.query or "")

    table_size = int(lm_meta.get("table_size", 50000))
    alpha = float(lm_meta.get("alpha", 1.0))
    lm_parts = lm_meta.get("lm_parts", ["host", "path", "query"])

    parts_map = {"host": host, "path": path, "query": query}

    out: List[float] = []
    for part_name in lm_parts:
        text = parts_map.get(part_name, "")
        for n in [1, 2, 3, 4]:
            table = lm_tables[(part_name, n)]
            total = int(table.sum())
            if total <= 0:
                out.append(0.0)
                continue

            V = table_size
            denom = float(total + alpha * V)

            ngrams = list(_char_ngrams(text, n))
            if not ngrams:
                out.append(0.0)
                continue

            s = 0.0
            for ng in ngrams:
                b = _safe_crc32_bucket(ng, table_size)
                c = int(table[b])
                p_ng = (c + alpha) / denom
                s += float(np.log(p_ng))

            out.append(s / len(ngrams))

    return np.array(out, dtype=np.float32)


# ----------------------------
# Names + final vector
# ----------------------------
def get_feature_names(trigram_buckets: int = 256, lm_parts: Optional[List[str]] = None) -> List[str]:
    if lm_parts is None:
        lm_parts = ["host", "path", "query"]

    # Base names from base_features
    dummy = base_features(normalize_url("http://example.com/a?b=1"))
    base_names = list(dummy.keys())

    tri_names: List[str] = []
    if trigram_buckets and trigram_buckets > 0:
        tri_names = [f"tri_{i:04d}" for i in range(trigram_buckets)]

    lm_names: List[str] = []
    if lm_parts:
        for part in lm_parts:
            for n in [1, 2, 3, 4]:
                lm_names.append(f"lm_{part}_{n}")

    return base_names + tri_names + lm_names


def extract_feature_vector(
    url: str,
    trigram_buckets: int = 256,
    lm_tables: Optional[Dict] = None,
    lm_meta: Optional[Dict] = None,
    lm_parts: Optional[List[str]] = None,
) -> np.ndarray:
    """
    Vector: [base] + [trigram hashing] + [LM]
    Supports disabling trigram (trigram_buckets=0) and disabling LM (lm_tables=None).
    """
    url_norm = normalize_url(url)

    bf = base_features(url_norm)
    base_vec = np.array(list(bf.values()), dtype=np.float32)

    if trigram_buckets and trigram_buckets > 0:
        tri_vec = trigram_hash_features(url_norm, trigram_buckets=trigram_buckets)
    else:
        tri_vec = np.zeros(0, dtype=np.float32)

    if lm_tables is not None and lm_meta is not None:
        lm_vec = lm_features_from_tables(url_norm, lm_tables, lm_meta)
    else:
        if not lm_parts:
            lm_vec = np.zeros(0, dtype=np.float32)
        else:
            lm_vec = np.zeros(len(lm_parts) * 4, dtype=np.float32)

    return np.concatenate([base_vec, tri_vec, lm_vec]).astype(np.float32)


def extract_url_features(
    url: str,
    trigram_buckets: int = 256,
    lm_tables: Optional[Dict] = None,
    lm_meta: Optional[Dict] = None,
    lm_parts: Optional[List[str]] = None,
) -> pd.DataFrame:
    """
    Convenience: return DataFrame with named columns (useful for debugging / older code).
    If you use LM features, you MUST pass lm_tables+lm_meta from the trained bundle.
    """
    if lm_parts is None:
        if lm_meta is not None and "lm_parts" in lm_meta:
            lm_parts = lm_meta["lm_parts"]
        else:
            lm_parts = []

    names = get_feature_names(trigram_buckets=trigram_buckets, lm_parts=lm_parts)
    vec = extract_feature_vector(
        url,
        trigram_buckets=trigram_buckets,
        lm_tables=lm_tables,
        lm_meta=lm_meta,
        lm_parts=lm_parts
    )

    if len(vec) != len(names):
        raise ValueError(f"Feature length mismatch: vec={len(vec)} names={len(names)}")

    row = {names[i]: float(vec[i]) for i in range(len(names))}
    return pd.DataFrame([row], columns=names)
