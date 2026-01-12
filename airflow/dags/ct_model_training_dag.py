from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator

# Adjust this path if your repo lives somewhere else in the Airflow environment
REPO_ROOT = "/Users/mohanasundarammurugasen/dev/threat-intel"
VENV_ACTIVATE = f"source {REPO_ROOT}/.venv/bin/activate"

default_args = {
    "owner": "ct-pipeline",
    "depends_on_past": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=10),
}

with DAG(
    dag_id="ct_model_training_dag",
    default_args=default_args,
    description="Weekly training of CT phishing vs benign baseline model",
    schedule_interval="@weekly",  # you can change to a cron if you want a specific day/time
    start_date=datetime(2025, 11, 30),
    catchup=False,
    max_active_runs=1,
) as dag:

    train_latest_baseline = BashOperator(
        task_id="train_latest_baseline",
        bash_command=f"""
        bash -lc '
        cd {REPO_ROOT} && \
        {VENV_ACTIVATE} && \
        python ml/offline/train_latest_baseline.py
        '
        """
    )
