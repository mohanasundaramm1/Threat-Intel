# airflow/dags/openphish_ingest.py
from __future__ import annotations
import os, re, time, shutil, tempfile, logging
from datetime import datetime
from urllib.parse import urlparse

import pandas as pd
import requests
import great_expectations as ge

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.exceptions import AirflowSkipException

log = logging.getLogger(__name__)

BRONZE_BASE = "/opt/airflow/bronze/openphish"
MIN_ROWS = 50  # guardrail threshold

def _effective_ds_ts(ds: str, ts: str, **context):
    """Allow orchestrator to pass ds/ts via conf."""
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

def fetch_and_write_openphish(ds: str, ts: str, **context):
    # Align with orchestrator’s logical date/time
    ds, ts = _effective_ds_ts(ds, ts, **context)

    ds_date = pd.to_datetime(ds).date()
    today_date = pd.Timestamp.utcnow().date()
    outdir = f"{BRONZE_BASE}/ingest_date={ds}"

    # OpenPhish feed is a *current* snapshot → never synthesize history
    if ds_date != today_date:
        if os.path.exists(outdir):
            raise AirflowSkipException(
                f"Historical partition exists for {ds}; skipping rewrite."
            )
        raise AirflowSkipException("OpenPhish has no historical feed; skipping backfill.")

    # Resilient fetch
    url = "https://openphish.com/feed.txt"
    sess = requests.Session()
    last_exc = None
    for attempt in range(3):
        try:
            r = sess.get(url, timeout=(5, 30), headers={"User-Agent": "threat-intel-lab/0.1"})
            if r.ok and len(r.text) > 200:   # basic content sanity
                break
            last_exc = RuntimeError(f"Bad response (status={r.status_code}, len={len(r.text)})")
        except Exception as e:
            last_exc = e
        time.sleep(2)
    else:
        raise last_exc if last_exc else RuntimeError("OpenPhish fetch failed")

    # Normalize
    lines = [ln.strip() for ln in r.text.splitlines() if ln.strip() and not ln.startswith("#")]
    df = pd.DataFrame({"url": lines})
    df["domain"] = df["url"].map(_host)
    df["first_seen"] = pd.Timestamp(ts, tz="UTC")
    df = df.dropna(subset=["domain"]).drop_duplicates(subset=["url"])
    df = df[["url", "domain", "first_seen"]]

    # ----- MIN_ROWS guard (keeps old partition if today already exists) -----
    n = len(df)
    if n < MIN_ROWS:
        if os.path.exists(outdir):
            raise AirflowSkipException(
                f"[openphish_ingest] rows={n} < {MIN_ROWS}; keeping existing partition for {ds}"
            )
        # First attempt for today and tiny → fail loudly
        raise ValueError(f"[openphish_ingest] returned {n} rows (<{MIN_ROWS})")

    # Light GE checks
    gdf = ge.from_pandas(df)
    assert gdf.expect_column_to_exist("domain").success
    assert gdf.expect_column_values_to_not_be_null("domain").success
    assert gdf.expect_column_values_to_match_regex("url", r"^https?://").success

    # Idempotent + atomic write
    if os.path.exists(outdir):
        shutil.rmtree(outdir)
    os.makedirs(outdir, exist_ok=True)
    final_path = f"{outdir}/openphish.parquet"
    fd, tmp = tempfile.mkstemp(suffix=".parquet", dir=outdir); os.close(fd)
    df.to_parquet(tmp, index=False)
    os.replace(tmp, final_path)
    log.info("[openphish_ingest] %s: wrote %d rows -> %s", ds, n, final_path)

default_args = {"owner": "you", "retries": 1}

with DAG(
    dag_id="openphish_ingest",
    start_date=datetime(2025, 11, 3),
    schedule_interval="@daily",
    catchup=False,
    max_active_runs=1,
    default_args=default_args,
    tags=["ingest", "bronze"],
) as dag:
    PythonOperator(
        task_id="openphish_fetch_normalize_bronze",
        python_callable=fetch_and_write_openphish,
    )
