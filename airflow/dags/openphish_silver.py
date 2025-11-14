# airflow/dags/openphish_silver_dag.py
from __future__ import annotations
import os
import shutil
import logging
from datetime import datetime

import pandas as pd

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.exceptions import AirflowSkipException

log = logging.getLogger(__name__)

def _effective_ds_ts(ds: str, ts: str, **context):
    """If the orchestrator passed ds/ts via dag_run.conf, use those."""
    dr = context.get("dag_run")
    if dr and getattr(dr, "conf", None):
        ds_conf = dr.conf.get("ds") or ds
        ts_conf = dr.conf.get("ts") or ts
        if ds_conf != ds or ts_conf != ts:
            log.info(
                "Overriding ds/ts from dag_run.conf: %s,%s -> %s,%s",
                ds, ts, ds_conf, ts_conf
            )
        return ds_conf, ts_conf
    return ds, ts

def _atomic_to_parquet(df: pd.DataFrame, final_path: str):
    """Write to a temp file then atomically replace the final file."""
    tmp_path = final_path + ".tmp"
    df.to_parquet(tmp_path, index=False)
    os.replace(tmp_path, final_path)

BRONZE = "/opt/airflow/bronze/openphish"
SILVER = "/opt/airflow/silver/openphish"

def openphish_to_silver(ds: str, ts: str, **context):
    # Align with orchestrator's ds/ts if provided
    ds, ts = _effective_ds_ts(ds, ts, **context)

    bronze_path = f"{BRONZE}/ingest_date={ds}/openphish.parquet"

    # If bronze partition doesn't exist, SKIP (avoid cascading failures)
    if not os.path.exists(bronze_path):
        raise AirflowSkipException(f"[openphish_silver] no bronze for {ds}: {bronze_path}")

    # Read; if empty, skip
    df = pd.read_parquet(bronze_path)
    if df is None or len(df) == 0:
        raise AirflowSkipException(f"[openphish_silver] bronze empty for {ds}: {bronze_path}")

    # Normalize to stable schema
    out = pd.DataFrame({
        "domain": df.get("domain", pd.Series(dtype="object")).astype("string"),
        "url": df.get("url", pd.Series(dtype="object")).astype("string"),
        "first_seen": pd.to_datetime(df.get("first_seen"), utc=True, errors="coerce"),
        "label": "phishing",
        "source": "openphish",
    })

    # Hygiene
    out = out.dropna(subset=["domain", "first_seen"])
    out = out.sort_values(["domain", "first_seen"]).drop_duplicates(
        subset=["domain", "first_seen"], keep="first"
    )

    # Idempotent write for the ds partition
    outdir = f"{SILVER}/ingest_date={ds}"
    if os.path.exists(outdir):
        shutil.rmtree(outdir)
    os.makedirs(outdir, exist_ok=True)

    _atomic_to_parquet(out, f"{outdir}/openphish_silver.parquet")
    log.info("[openphish_silver] %s: wrote %d rows -> %s", ds, len(out), outdir)

default_args = {"owner": "you", "retries": 0}

with DAG(
    dag_id="openphish_silver",
    start_date=datetime(2025, 11, 3),
    schedule_interval="@daily",
    catchup=False,            # orchestrator controls dates; don't backfill here
    max_active_runs=1,
    default_args=default_args,
    tags=["silver", "normalize"],
) as dag:
    PythonOperator(
        task_id="openphish_bronze_to_silver",
        python_callable=openphish_to_silver,
    )
