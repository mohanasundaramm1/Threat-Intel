from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator

REPO_ROOT = "/Users/mohanasundarammurugasen/dev/threat-intel"
VENV_ACTIVATE = f"source {REPO_ROOT}/.venv/bin/activate"

default_args = {
    "owner": "ct-pipeline",
    "depends_on_past": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=10),
}

with DAG(
    dag_id="ct_enrich_and_score_dag",
    default_args=default_args,
    description="Every 2 hours: enrich latest CT raw domains and score with latest model",
    schedule_interval="0 */2 * * *",  # every 2 hours on the hour
    start_date=datetime(2025, 11, 30),
    catchup=False,
    max_active_runs=1,
) as dag:

    # 1) Enrich CT domains (incremental)
    # Tune MAX_DOMAINS / CAP_ROWS / MAX_BRONZE_FILES here.
    enrich_ct = BashOperator(
        task_id="enrich_ct",
        bash_command=f"""
        bash -lc '
        cd {REPO_ROOT} && \
        {VENV_ACTIVATE} && \
        MAX_DOMAINS=2000 CAP_ROWS=50000 MAX_BRONZE_FILES=100 \
        python ct/enrich/enrich_ct.py
        '
        """
    )

    # 2) Score with latest model (uses pointer file from enrich_ct)
    score_ct = BashOperator(
        task_id="score_ct_with_latest",
        bash_command=f"""
        bash -lc '
        cd {REPO_ROOT} && \
        {VENV_ACTIVATE} && \
        python ct/score/score_ct_with_latest.py
        '
        """
    )

    enrich_ct >> score_ct
