from datetime import datetime
from airflow import DAG
from airflow.operators.empty import EmptyOperator
from airflow.operators.trigger_dagrun import TriggerDagRunOperator
from airflow.utils.task_group import TaskGroup

# Orchestrator DAG:
# - Triggers children with matching ds/ts via conf
# - Waits for completion per stage (bronze -> silver -> union -> lookups)
# - Deferrable waiting avoids blocking under SequentialExecutor

with DAG(
    dag_id="pipeline_orchestrator",
    start_date=datetime(2025, 11, 3),
    schedule="@daily",          # <- modern param (replaces schedule_interval)
    catchup=False,
    max_active_runs=1,
    tags=["orchestration", "graph"],
) as dag:

    start = EmptyOperator(task_id="start")

    # ----- Bronze (ingest live feeds) -----
    with TaskGroup("bronze") as bronze:
        openphish_bronze = TriggerDagRunOperator(
            task_id="openphish_bronze",
            trigger_dag_id="openphish_ingest",
            reset_dag_run=True,
            wait_for_completion=True,   # <- wait on the triggered run
            deferrable=True,            # <- don't block the worker slot
            conf={"ds": "{{ ds }}", "ts": "{{ ts }}"},
        )
        urlhaus_bronze = TriggerDagRunOperator(
            task_id="urlhaus_bronze",
            trigger_dag_id="urlhaus_ingest",
            reset_dag_run=True,
            wait_for_completion=True,
            deferrable=True,
            conf={"ds": "{{ ds }}", "ts": "{{ ts }}"},
        )

    # ----- Silver (normalize) -----
    with TaskGroup("silver") as silver:
        openphish_silver = TriggerDagRunOperator(
            task_id="openphish_silver",
            trigger_dag_id="openphish_silver",
            reset_dag_run=True,
            wait_for_completion=True,
            deferrable=True,
            conf={"ds": "{{ ds }}", "ts": "{{ ts }}"},
        )
        urlhaus_silver = TriggerDagRunOperator(
            task_id="urlhaus_silver",
            trigger_dag_id="urlhaus_silver",
            reset_dag_run=True,
            wait_for_completion=True,
            deferrable=True,
            conf={"ds": "{{ ds }}", "ts": "{{ ts }}"},
        )

    # ----- Union (merge silvers) -----
    union = TriggerDagRunOperator(
        task_id="labels_union",
        trigger_dag_id="labels_union",
        reset_dag_run=True,
        wait_for_completion=True,
        deferrable=True,
        conf={"ds": "{{ ds }}", "ts": "{{ ts }}"},
    )

    # ----- Lookups (depend on union) -----
    with TaskGroup("lookups") as lookups:
        whois = TriggerDagRunOperator(
            task_id="whois_rdap",
            trigger_dag_id="whois_rdap_ingest",
            reset_dag_run=True,
            wait_for_completion=True,
            deferrable=True,
            conf={"ds": "{{ ds }}", "ts": "{{ ts }}"},
        )
        dns_geo = TriggerDagRunOperator(
            task_id="dns_ip_geo",
            trigger_dag_id="dns_ip_geo_ingest",
            reset_dag_run=True,
            wait_for_completion=True,
            deferrable=True,
            conf={"ds": "{{ ds }}", "ts": "{{ ts }}"},
        )

    # ----- MISP OSINT (independent side branch) -----
    with TaskGroup("misp") as misp:
        misp_osint = TriggerDagRunOperator(
            task_id="misp_osint",
            trigger_dag_id="misp_osint_ingest",
            reset_dag_run=True,
            wait_for_completion=True,
            deferrable=True,
            conf={"ds": "{{ ds }}", "ts": "{{ ts }}"},
        )

    end = EmptyOperator(task_id="end")

    # Graph
    start >> bronze >> silver >> union >> lookups
    start >> misp
    [lookups, misp] >> end
