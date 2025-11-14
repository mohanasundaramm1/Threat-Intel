from __future__ import annotations
import io, os, re, time, shutil, tempfile, logging
from datetime import datetime
from urllib.parse import urlparse

import pandas as pd
import requests
import great_expectations as ge

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.exceptions import AirflowSkipException

log = logging.getLogger(__name__)

BRONZE_BASE = "/opt/airflow/bronze/urlhaus"

# def _effective_ds_ts(ds: str, ts: str, **context):
#     dr = context.get("dag_run")
#     if dr and getattr(dr, "conf", None):
#         ds_conf = dr.conf.get("ds") or ds
#         ts_conf = dr.conf.get("ts") or ts
#         if ds_conf != ds or ts_conf != ts:
#             log.info("Overriding ds/ts from dag_run.conf: %s,%s -> %s,%s", ds, ts, ds_conf, ts_conf)
#         return ds_conf, ts_conf
#     return ds, ts


def _effective_ds_ts(ds: str, ts: str, **context):
    dr = context.get("dag_run")
    if dr and getattr(dr, "conf", None):
        ds2 = dr.conf.get("ds") or ds
        ts2 = dr.conf.get("ts") or ts
        if ds2 != ds or ts2 != ts:
            log.info("Overriding ds/ts from dag_run.conf: %s,%s -> %s,%s", ds, ts, ds2, ts2)
        return ds2, ts2
    return ds, ts

def _host(u: str):
    u = str(u).strip()
    if not re.match(r"^https?://", u):
        u = "http://" + u
    return urlparse(u).hostname

def fetch_and_write_urlhaus(ds: str, ts: str, **context):
    # align with orchestrator’s logical date/time
    ds, ts = _effective_ds_ts(ds, ts, **context)

    ds_date = pd.to_datetime(ds).date()
    today_date = pd.Timestamp.utcnow().date()
    outdir = f"{BRONZE_BASE}/ingest_date={ds}"

    # URLhaus csv_online is a *current* snapshot → never synthesize history
    if ds_date != today_date:
        if os.path.exists(outdir):
            raise AirflowSkipException(f"Historical partition exists for {ds}; skipping rewrite.")
        raise AirflowSkipException("URLhaus has no historical feed; skipping backfill.")

    # Resilient fetch
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    sess = requests.Session()
    last_exc = None
    for attempt in range(3):
        try:
            r = sess.get(url, timeout=(5, 45), headers={"User-Agent": "threat-intel-lab/0.1"})
            if r.ok and len(r.text) > 1000:
                break
            last_exc = RuntimeError(f"Bad response (status={r.status_code}, len={len(r.text)})")
        except Exception as e:
            last_exc = e
        time.sleep(2)
    else:
        raise last_exc if last_exc else RuntimeError("URLhaus fetch failed")

    # Parse CSV (skip '#')
    raw = pd.read_csv(io.StringIO(r.text), comment="#", header=None)
    if raw.shape[1] >= 9:
        df = raw.iloc[:, :9].copy()
        df.columns = ["id","dateadded","url","status","last_online","threat","tags","urlhaus_link","reporter"]
    else:
        df = raw.copy()
        df.columns = [f"c{i}" for i in range(df.shape[1])]
        url_col = next((c for c in df.columns
                        if pd.Series(df[c].astype(str)).str.startswith(("http://","https://")).mean() > 0.5),
                       df.columns[0])
        df = df.rename(columns={url_col: "url"})
        df["dateadded"] = ds

    # Normalize
    df["domain"] = df["url"].map(_host)
    df["first_seen"] = pd.Timestamp(ts, tz="UTC")
    cols = ["url","domain","threat","tags","urlhaus_link","reporter","status","last_online","dateadded","first_seen"]
    for c in cols:
        if c not in df.columns: df[c] = None
    df = df[cols].dropna(subset=["domain"]).drop_duplicates(subset=["url"])

    # # Guardrails + GE
    # n = len(df)
    # if n < 50:
    #     raise ValueError(f"urlhaus_ingest returned {n} rows (<50); failing for visibility.")
    # assert df["url"].is_unique
    # assert df["domain"].str.len().between(1, 253).all()

    # gdf = ge.from_pandas(df)
    # assert gdf.expect_column_to_exist("domain").success
    # assert gdf.expect_column_values_to_not_be_null("domain").success
    # assert gdf.expect_column_values_to_match_regex("url", r"^https?://").success
 
    # Guardrails + GE
    n = len(df)
    MIN_ROWS = 50
    if n < MIN_ROWS:
        # If today's partition already exists, skip to avoid clobbering a good snapshot
        if os.path.exists(outdir):
            raise AirflowSkipException(
                f"[urlhaus_ingest] rows={n} < {MIN_ROWS}; keeping existing partition for {ds} at {outdir}"
            )
        # First attempt for today and it's tiny -> fail loudly for visibility
        raise ValueError(f"[urlhaus_ingest] returned {n} rows (<{MIN_ROWS})")

    # Basic sanity checks
    if not df["url"].is_unique:
        raise ValueError("duplicate URLs leaked after drop_duplicates")
    if not df["domain"].str.len().between(1, 253).all():
        raise ValueError("domain length out of bounds")

    # Great Expectations (light)
    gdf = ge.from_pandas(df)
    assert gdf.expect_column_to_exist("domain").success
    assert gdf.expect_column_values_to_not_be_null("domain").success
    assert gdf.expect_column_values_to_match_regex("url", r"^https?://").success

    # Idempotent + atomic write
    if os.path.exists(outdir):
        shutil.rmtree(outdir)
    os.makedirs(outdir, exist_ok=True)
    final_path = f"{outdir}/urlhaus.parquet"
    fd, tmp = tempfile.mkstemp(suffix=".parquet", dir=outdir); os.close(fd)
    df.to_parquet(tmp, index=False)
    os.replace(tmp, final_path)
    log.info("[urlhaus_ingest] %s: wrote %d rows -> %s", ds, n, final_path)

default_args = {"owner": "you", "retries": 1}

with DAG(
    dag_id="urlhaus_ingest",
    start_date=datetime(2025, 11, 3),
    schedule_interval="@daily",
    catchup=False,
    max_active_runs=1,
    default_args=default_args,
    tags=["ingest","bronze"],
) as dag:
    PythonOperator(
        task_id="urlhaus_fetch_normalize_bronze",
        python_callable=fetch_and_write_urlhaus,
    )
