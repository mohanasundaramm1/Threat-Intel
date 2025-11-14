# airflow/dags/whois_rdap_dag.py
from __future__ import annotations
import os, time, json, shutil, tempfile
from datetime import datetime
from typing import Dict, Any, List

import pandas as pd
import requests
import tldextract
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.exceptions import AirflowSkipException
import logging

log = logging.getLogger(__name__)

LABELS_UNION_BASE = "/opt/airflow/silver/labels_union"
LOOKUPS_BASE      = "/opt/airflow/lookups"

WHOIS_CACHE_PATH  = f"{LOOKUPS_BASE}/whois_cache.parquet"   # rolling cache (all time)
WHOIS_DAILY_DIR   = f"{LOOKUPS_BASE}/whois"                 # partitioned snapshots


# ---------- small helpers ----------

def _effective_ds_ts(ds: str, ts: str, **context):
    """Use ds/ts from dag_run.conf when triggered by the orchestrator."""
    dr = context.get("dag_run")
    if dr and getattr(dr, "conf", None):
        return dr.conf.get("ds", ds), dr.conf.get("ts", ts)
    return ds, ts

def _atomic_to_parquet(df: pd.DataFrame, final_path: str):
    """Write atomically to avoid partial files on failure."""
    os.makedirs(os.path.dirname(final_path), exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=os.path.dirname(final_path), delete=False, suffix=".parquet") as tmp:
        tmp_path = tmp.name
    try:
        df.to_parquet(tmp_path, index=False)
        os.replace(tmp_path, final_path)  # atomic swap on POSIX
    finally:
        if os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except Exception: pass

def _load_labels_for_day(ds: str) -> pd.DataFrame:
    """Load labels_union for ds or skip gracefully if missing/empty."""
    p = f"{LABELS_UNION_BASE}/ingest_date={ds}/labels_union.parquet"
    if not os.path.exists(p):
        raise AirflowSkipException(f"[whois_rdap] labels_union parquet not found for ds={ds}: {p}")
    df = pd.read_parquet(p)
    df = df.dropna(subset=["domain"])
    if df.empty:
        raise AirflowSkipException(f"[whois_rdap] labels_union is empty for ds={ds}, nothing to enrich.")
    return df

def _effective_domain(d: str) -> str:
    """Normalize to registered domain (example.com from foo.bar.example.com)."""
    ext = tldextract.extract(d or "")
    return ext.registered_domain.lower() if ext.registered_domain else (d or "").strip().lower()

def _requests_session() -> requests.Session:
    """Session with retries/backoff for RDAP calls."""
    sess = requests.Session()
    retry = Retry(
        total=4,
        connect=3,
        read=3,
        backoff_factor=0.6,          # 0.6, 1.2, 2.4, ...
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.headers.update({"User-Agent": "threat-intel-lab/rdap/0.1"})
    return sess

def _parse_registrar(data: dict) -> str | None:
    # Some RDAP servers return registrar in different places; best effort
    if "registrar" in data and isinstance(data["registrar"], dict):
        name = data["registrar"].get("name")
        if name:
            return name
    # Fallback via entities with role=registrar
    for ent in (data.get("entities") or []):
        if "registrar" in (ent.get("roles") or []):
            vcard = ent.get("vcardArray") or []
            if isinstance(vcard, list) and len(vcard) == 2:
                for item in vcard[1]:
                    if item and item[0] == "fn":
                        return item[3]
    return None

def _rdap_domain(domain: str, session: requests.Session) -> Dict[str, Any]:
    """Fetch RDAP for a domain and return a normalized row."""
    url = f"https://rdap.org/domain/{domain}"
    try:
        r = session.get(url, timeout=(3, 30))
        if r.status_code == 404:
            return {"domain": domain, "registrar": None, "status": "not_found",
                    "created": pd.NaT, "expires": pd.NaT, "raw": None, "error": None}
        r.raise_for_status()
        data = r.json()

        registrar = _parse_registrar(data)
        statuses = ",".join(data.get("status") or [])

        created = None
        expires = None
        for ev in (data.get("events") or []):
            if ev.get("eventAction") == "registration":
                created = ev.get("eventDate")
            if ev.get("eventAction") in ("expiration", "expire"):
                expires = ev.get("eventDate")

        return {
            "domain": domain,
            "registrar": registrar,
            "status": statuses or None,
            "created": pd.to_datetime(created, utc=True, errors="coerce"),
            "expires": pd.to_datetime(expires, utc=True, errors="coerce"),
            "raw": json.dumps(data)[:200_000],  # cap to keep file sizes sane
            "error": None,
        }
    except Exception as e:
        return {
            "domain": domain, "registrar": None, "status": None,
            "created": pd.NaT, "expires": pd.NaT, "raw": None, "error": str(e)
        }


# ---------- main task ----------

def whois_rdap_task(ds: str, ts: str, **context):
    # keep ds/ts aligned with orchestrator
    ds, ts = _effective_ds_ts(ds, ts, **context)

    os.makedirs(LOOKUPS_BASE, exist_ok=True)
    os.makedirs(WHOIS_DAILY_DIR, exist_ok=True)

    labels = _load_labels_for_day(ds)

    # normalize to registered domains
    labels["registered_domain"] = labels["domain"].map(_effective_domain)
    domains = sorted(
        d for d in labels["registered_domain"].dropna().astype(str).str.lower().unique().tolist()
        if d
    )
    if not domains:
        raise AirflowSkipException(f"[whois_rdap] no valid domains for ds={ds}")

    # load persistent cache if present (be tolerant to corruption)
    if os.path.exists(WHOIS_CACHE_PATH):
        try:
            cache = pd.read_parquet(WHOIS_CACHE_PATH)
        except Exception as e:
            log.warning("WHOIS cache unreadable (%s). Recreating empty cache.", e)
            cache = pd.DataFrame(columns=["domain","registrar","status","created","expires","raw","error"])
    else:
        cache = pd.DataFrame(columns=["domain","registrar","status","created","expires","raw","error"])

    cache["domain"] = cache["domain"].astype(str).str.lower()
    cached = set(cache["domain"])

    to_fetch = [d for d in domains if d not in cached]
    log.info("[whois_rdap] ds=%s total=%d to_fetch=%d cached=%d", ds, len(domains), len(to_fetch), len(cached))

    session = _requests_session()
    new_rows: List[dict] = []
    seen_in_run: set[str] = set()

    for i, d in enumerate(to_fetch, 1):
        if d in seen_in_run:
            continue
        new_rows.append(_rdap_domain(d, session))
        seen_in_run.add(d)
        if i % 10 == 0:  # light throttle
            time.sleep(1)

    new_df = pd.DataFrame(new_rows) if new_rows else pd.DataFrame(columns=cache.columns)

    # unify schema
    for col in ["domain","registrar","status","created","expires","raw","error"]:
        if col not in new_df.columns:
            new_df[col] = None

    # merge with cache; keep the latest row per domain
    out_cache = pd.concat([cache, new_df], ignore_index=True)
    out_cache["domain"] = out_cache["domain"].astype(str).str.lower()
    out_cache = out_cache.sort_values(["domain"]).drop_duplicates(subset=["domain"], keep="last")

    # write back persistent cache (atomic)
    _atomic_to_parquet(out_cache, WHOIS_CACHE_PATH)

    # produce the daily subset for this ds
    daily = out_cache[out_cache["domain"].isin(domains)].copy()

    # idempotent daily write (atomic)
    outdir = f"{WHOIS_DAILY_DIR}/ingest_date={ds}"
    if os.path.exists(outdir):
        shutil.rmtree(outdir)
    os.makedirs(outdir, exist_ok=True)
    _atomic_to_parquet(daily, f"{outdir}/whois.parquet")

    log.info("[whois_rdap] ds=%s fetched=%d daily_rows=%d cache_size=%d -> %s",
             ds, len(new_rows), len(daily), len(out_cache), outdir)


# ---------- DAG ----------

default_args = {"owner": "you", "retries": 0}

with DAG(
    dag_id="whois_rdap_ingest",
    start_date=datetime(2025, 11, 1),
    schedule_interval="@daily",
    catchup=False,
    max_active_runs=1,
    default_args=default_args,
    tags=["enrich","whois","lookup"],
) as dag:
    PythonOperator(
        task_id="whois_rdap_fetch",
        python_callable=whois_rdap_task,
    )
