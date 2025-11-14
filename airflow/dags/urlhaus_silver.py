from __future__ import annotations
import os, shutil, tempfile
from datetime import datetime

import pandas as pd

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.exceptions import AirflowSkipException
import logging

log = logging.getLogger(__name__)

def _effective_ds_ts(ds: str, ts: str, **context):
    """Use ds/ts from dag_run.conf if the orchestrator passed them."""
    dr = context.get("dag_run")
    if dr and getattr(dr, "conf", None):
        ds_conf = dr.conf.get("ds") or ds
        ts_conf = dr.conf.get("ts") or ts
        if ds_conf != ds or ts_conf != ts:
            log.info("Overriding ds/ts from dag_run.conf: %s,%s -> %s,%s",
                     ds, ts, ds_conf, ts_conf)
        return ds_conf, ts_conf
    return ds, ts

BRONZE = "/opt/airflow/bronze/urlhaus"
SILVER = "/opt/airflow/silver/urlhaus"

def urlhaus_to_silver(ds: str, ts: str, **context):
    # ✅ align with orchestrator’s logical date/time if provided
    ds, ts = _effective_ds_ts(ds, ts, **context)

    bronze_path = f"{BRONZE}/ingest_date={ds}/urlhaus.parquet"

    # If bronze partition doesn't exist, SKIP (don’t fail the day)
    if not os.path.exists(bronze_path):
        raise AirflowSkipException(f"[urlhaus_silver] no bronze for {ds}: {bronze_path}")

    # Try reading; if unreadable or empty, SKIP (avoid churning downstream)
    df = pd.read_parquet(bronze_path)
    if df is None or len(df) == 0:
        raise AirflowSkipException(f"[urlhaus_silver] bronze empty for {ds}: {bronze_path}")

    # Normalize / select schema
    out = pd.DataFrame({
        "domain": df.get("domain", pd.Series(dtype="object")).astype("string"),
        "url": df.get("url", pd.Series(dtype="object")).astype("string"),
        "first_seen": pd.to_datetime(df.get("first_seen"), utc=True, errors="coerce"),
        "label": df.get("threat", "unknown").astype("string"),
        "source": "urlhaus",
    })

    # Hygiene & dedupe
    out = out.dropna(subset=["domain", "first_seen"])
    out = out.sort_values(["domain", "first_seen"]).drop_duplicates(
        subset=["domain", "first_seen"], keep="first"
    )

    # Idempotent, atomic write to ds partition
    outdir = f"{SILVER}/ingest_date={ds}"
    if os.path.exists(outdir):
        shutil.rmtree(outdir)
    os.makedirs(outdir, exist_ok=True)

    final_path = f"{outdir}/urlhaus_silver.parquet"
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".parquet", dir=outdir)
    os.close(tmp_fd)
    out.to_parquet(tmp_path, index=False)
    os.replace(tmp_path, final_path)

    log.info("[urlhaus_silver] %s: wrote %d rows -> %s", ds, len(out), final_path)

default_args = {"owner": "you", "retries": 0}

with DAG(
    dag_id="urlhaus_silver",
    start_date=datetime(2025, 11, 3),
    schedule_interval="@daily",
    catchup=False,            # Orchestrator controls the date; no auto-backfill here
    max_active_runs=1,
    default_args=default_args,
    tags=["silver", "normalize"],
) as dag:
    PythonOperator(
        task_id="urlhaus_bronze_to_silver",
        python_callable=urlhaus_to_silver,
    )
