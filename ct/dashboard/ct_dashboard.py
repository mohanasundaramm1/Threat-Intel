import os
import pandas as pd
import streamlit as st
import glob

from datetime import datetime

DATA_DIR = os.path.join("ct", "data", "scored")

st.set_page_config(
    page_title="CT Threat Intelligence Dashboard",
    layout="wide",
    page_icon="🛡️"
)

st.title("🛡️ Certificate Transparency Threat Dashboard")

# ---------- Load latest scored file ----------
def load_latest_scored():
    paths = sorted(glob.glob(os.path.join(DATA_DIR, "ct_scored_*.parquet")))
    if not paths:
        st.error("No scored CT files found.")
        return None
    latest = paths[-1]
    df = pd.read_parquet(latest)
    st.caption(f"Loaded: `{os.path.basename(latest)}`  •  {len(df)} rows")
    return df

df = load_latest_scored()
if df is None:
    st.stop()

# ---------- High-risk summary ----------
col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Domains", len(df))
col2.metric("High Risk (≥0.90)", (df["risk_score"] >= 0.90).sum())
col3.metric("Critical (≥0.98)", (df["risk_score"] >= 0.98).sum())
col4.metric("Unique Countries", df["sample_country"].nunique())

st.markdown("---")

# ---------- High risk table ----------
st.subheader("🚨 High-Risk Domains")

st.dataframe(
    df.sort_values("risk_score", ascending=False)[
        ["registered_domain", "domain_sample", "sample_country",
         "num_unique_ips", "risk_score"]
    ].head(50),
    use_container_width=True,
)

st.markdown("---")

# ---------- TLD Risk Chart ----------
st.subheader("🌐 TLD Risk Distribution")

df["tld"] = df["registered_domain"].apply(lambda d: d.rsplit(".",1)[-1] if "." in d else "")

tld_stats = (
    df.groupby("tld")
      .agg(count=("registered_domain", "size"),
           avg_risk=("risk_score", "mean"))
      .sort_values("avg_risk", ascending=False)
)

st.bar_chart(tld_stats.head(20)["avg_risk"])

st.markdown("---")

# ---------- Country Heatmap ----------
st.subheader("🗺️ Hosting Country Risk (Map)")

import pydeck as pdk

if "sample_country" in df.columns:
    country_counts = (
        df.groupby("sample_country")
        .agg(count=("registered_domain", "size"),
             avg_risk=("risk_score", "mean"))
        .reset_index()
    )

    st.dataframe(country_counts.sort_values("avg_risk", ascending=False).head(30))

    st.info("Full geo-map coming in next upgrade (folium/pydeck with risk shading)")
else:
    st.warning("No sample_country column available")

st.markdown("---")

# ---------- Keyword detection ----------
st.subheader("🔍 Suspicious Keyword Detection")

keywords = ["login","secure","verify","update","account",
            "password","signin","bank","office","apple","support","delivery"]

regex = "|".join(keywords)

mask = df["registered_domain"].str.contains(regex, case=False, regex=True)
df_kw = df[mask].sort_values("risk_score", ascending=False)

st.write(f"{len(df_kw)} domains contain phishing keywords.")
st.dataframe(df_kw.head(50))

st.markdown("---")

# ---------- Investigate domain ----------
st.subheader("🕵️ Investigate a Domain")

q = st.text_input("Enter a domain to investigate:")

if q:
    q = q.strip().lower()
    row = df[df["registered_domain"] == q]

    if row.empty:
        st.error("Domain not found in latest CT scored data.")
    else:
        st.success("Domain found!")
        st.json(row.iloc[0].to_dict())
