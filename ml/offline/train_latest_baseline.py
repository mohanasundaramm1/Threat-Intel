# ml/offline/train_latest_baseline.py
#
# Dynamic phishing vs benign baseline, using all available labels / lookups.
# Run from repo root:
#   source .venv/bin/activate
#   python ml/offline/train_latest_baseline.py
#
# Outputs:
#   - ml/models/registry/ct_risk_logreg_full_<TS>.joblib
#   - ml/models/registry/ct_risk_lgbm_full_<TS>.txt   (if LightGBM available)
#   - ml/models/registry/ct_risk_meta_<TS>.json
#   - "latest" copies:
#       ct_risk_logreg_full_latest.joblib
#       ct_risk_lgbm_full_latest.txt (if exists)
#       ct_risk_meta_latest.json
#

import os, glob, math, json, shutil
from datetime import datetime, timezone
from collections import Counter

import numpy as np
import pandas as pd
import tldextract

from sklearn.feature_extraction.text import HashingVectorizer, FeatureHasher
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from scipy.sparse import csr_matrix, hstack

# Optional: save models
try:
    import joblib
except ImportError:
    joblib = None

try:
    import lightgbm as lgb
except ImportError:
    lgb = None

NOW_UTC = datetime.now(timezone.utc)

# ---------------- paths ----------------

THIS_DIR = os.path.dirname(__file__)                    # .../ml/offline
ML_DIR = os.path.abspath(os.path.join(THIS_DIR, ".."))  # .../ml
REPO_ROOT = os.path.abspath(os.path.join(ML_DIR, "..")) # .../threat-intel

SILVER_LABELS_DIR = os.path.join(REPO_ROOT, "silver", "labels_union")
DNS_GEO_DIR       = os.path.join(REPO_ROOT, "lookups", "dns_geo")
WHOIS_DIR         = os.path.join(REPO_ROOT, "lookups", "whois")

MODEL_DIR = os.path.join(ML_DIR, "models", "registry")
TMP_DIR   = os.path.join(ML_DIR, "tmp")

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(TMP_DIR, exist_ok=True)

# ---------------- helpers ----------------

def reg_domain(domain: str) -> str:
    """Normalize to registered domain."""
    if not isinstance(domain, str) or not domain:
        return ""
    ext = tldextract.extract(domain)
    # keep the old behaviour for consistency with week5
    reg = getattr(ext, "registered_domain", None) or getattr(
        ext, "top_domain_under_public_suffix", None
    ) or ""
    return reg.lower().strip()


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def basic_string_feats(dom: str) -> dict:
    d = dom or ""
    feats = {}
    feats["len"] = len(d)
    feats["digits"] = sum(ch.isdigit() for ch in d)
    feats["hyphens"] = d.count("-")
    feats["dots"] = d.count(".")
    feats["digit_ratio"] = feats["digits"] / (feats["len"] + 1e-6)
    feats["hyphen_ratio"] = feats["hyphens"] / (feats["len"] + 1e-6)
    feats["entropy"] = shannon_entropy(d)
    feats["xn_punycode"] = int("xn--" in d)
    parts = d.split(".")
    feats["labels"] = len([p for p in parts if p])
    feats["tld_len"] = len(parts[-1]) if parts else 0
    return feats


def df_from_parquets(patterns):
    files = []
    for p in patterns:
        files.extend(glob.glob(p))
    dfs = []
    for f in sorted(files):
        try:
            dfs.append(pd.read_parquet(f))
        except Exception as e:
            print(f"[warn] failed {f}: {e}")
    if not dfs:
        return pd.DataFrame()
    return pd.concat(dfs, ignore_index=True)


# ---------------- load labels (dynamic) ----------------

def load_all_labels():
    pattern = os.path.join(SILVER_LABELS_DIR, "ingest_date=*/labels_union.parquet")
    print("[info] loading labels from pattern:", pattern)
    labels = df_from_parquets([pattern])
    if labels.empty:
        raise SystemExit("No labels found (check silver/labels_union).")

    print("[info] raw labels rows:", len(labels))

    # Normalise
    labels["registered_domain"] = labels["domain"].map(reg_domain)
    labels = labels[labels["registered_domain"].astype(bool)].copy()

    # Label: benign=0 if source==benign_seed else 1 (same convention as week5)
    labels["label"] = np.where(labels["source"] == "benign_seed", 0, 1)

    # only benign + phishing (ignore other weird sources if any)
    labels = labels[labels["label"].isin([0, 1])].copy()

    # ensure ingest_date is string for grouping / temporal split
    labels["ingest_date"] = labels["ingest_date"].astype(str)

    print(
        "[info] labels after filtering:",
        len(labels),
        "positives=",
        int((labels["label"] == 1).sum()),
        "negatives=",
        int((labels["label"] == 0).sum()),
    )
    return labels


labels = load_all_labels()

# pick latest ingest_date per registered_domain (for temporal split later)
last_seen = (
    labels.groupby("registered_domain")["ingest_date"]
    .max()
    .reset_index()
    .rename(columns={"ingest_date": "last_ingest_date"})
)

# ---------------- load DNS (all days) ----------------

def load_all_dns():
    pattern = os.path.join(DNS_GEO_DIR, "ingest_date=*/dns_geo.parquet")
    print("[info] loading DNS-Geo from pattern:", pattern)
    dns = df_from_parquets([pattern])
    if dns.empty:
        print("[warn] no DNS-Geo data loaded.")
        return dns
    dns = dns.rename(columns={"puny_domain": "registered_domain"})
    dns["registered_domain"] = (
        dns["registered_domain"].astype(str).str.lower().str.strip()
    )
    return dns


dns = load_all_dns()

# reduce DNS to per-domain aggregates
if not dns.empty:
    agg = (
        dns.groupby("registered_domain")
        .agg(
            num_unique_ips=("ip", "nunique"),
            has_ipv6=("family", lambda x: int((pd.Series(x) == 6).any())),
            num_countries=("country", "nunique"),
            num_asns=("asn", "nunique"),
            sample_asn=("asn", "first"),
            sample_isp=("isp", "first"),
            sample_country=("country", "first"),
        )
        .reset_index()
    )
else:
    agg = pd.DataFrame(columns=["registered_domain"])
print("[info] DNS agg rows:", len(agg))

# ---------------- load WHOIS (all days) ----------------

def load_all_whois():
    pattern = os.path.join(WHOIS_DIR, "ingest_date=*/whois.parquet")
    print("[info] loading WHOIS from pattern:", pattern)
    w = df_from_parquets([pattern])
    if w.empty:
        print("[warn] no WHOIS data loaded.")
        return w
    w = w.copy()
    w["registered_domain"] = w["domain"].astype(str).str.lower().str.strip()
    return w


whois = load_all_whois()

if not whois.empty:
    wcols = ["registered_domain", "registrar", "status", "created", "expires", "error"]
    whois = whois[wcols].copy()
    whois["created"] = pd.to_datetime(
        whois["created"], utc=True, errors="coerce"
    )
    whois["expires"] = pd.to_datetime(
        whois["expires"], utc=True, errors="coerce"
    )
    whois["age_days"] = (
        NOW_UTC - whois["created"]
    ).dt.total_seconds() / 86400.0
    whois["days_to_expiry"] = (
        whois["expires"] - NOW_UTC
    ).dt.total_seconds() / 86400.0
    whois["created_isnull"] = whois["created"].isna().astype(int)
    whois["expires_isnull"] = whois["expires"].isna().astype(int)
    whois["has_error"] = whois["error"].notna().astype(int)
    whois = whois.drop(columns=["created", "expires", "error"])
else:
    whois = pd.DataFrame(columns=["registered_domain"])
print("[info] WHOIS rows after featurization:", len(whois))

# ---------------- merge to one row per registered_domain ----------------

base = (
    labels[["registered_domain", "label"]]
    .drop_duplicates("registered_domain")
    .merge(last_seen, on="registered_domain", how="left")
)

Xdf = (
    base
    .merge(agg, on="registered_domain", how="left")
    .merge(whois, on="registered_domain", how="left")
)

print(
    "[info] merged Xdf rows:",
    len(Xdf),
    "positives=",
    int((Xdf["label"] == 1).sum()),
    "negatives=",
    int((Xdf["label"] == 0).sum()),
)

print("\n[info] sample feature rows (Xdf.head()):")
cols_to_show = [
    "registered_domain",
    "label",
    "last_ingest_date",
    "num_unique_ips",
    "num_countries",
    "sample_country",
    "sample_asn",
    "age_days",
    "days_to_expiry",
]
print(Xdf[cols_to_show].head(10))

# Save frozen Xdf for debugging / reuse
stamp = NOW_UTC.strftime("%Y%m%dT%H%M%SZ")
xdf_path = os.path.join(TMP_DIR, f"latest_Xdf_{stamp}.parquet")
Xdf.to_parquet(xdf_path, index=False)
print(f"[info] wrote Xdf to {xdf_path}")

# ---------------- build feature matrices ----------------

domains = Xdf["registered_domain"].fillna("")

# 1) string hashed (char n-grams)
char_vect = HashingVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    n_features=4096,
    lowercase=True,
    alternate_sign=False,
)
X_char = char_vect.transform(domains.tolist())

# 2) basic numeric string features
string_feats = [
    "len",
    "digits",
    "hyphens",
    "dots",
    "digit_ratio",
    "hyphen_ratio",
    "entropy",
    "xn_punycode",
    "labels",
    "tld_len",
]
S = np.vstack(
    [
        [basic_string_feats(d).get(k, 0) for k in string_feats]
        for d in domains.tolist()
    ]
)
X_string = csr_matrix(S)

# 3) DNS small numeric
dns_num_cols = ["num_unique_ips", "has_ipv6", "num_countries", "num_asns"]
for c in dns_num_cols:
    if c not in Xdf.columns:
        Xdf[c] = 0
Xdf[dns_num_cols] = Xdf[dns_num_cols].fillna(0)
X_dns_num = csr_matrix(Xdf[dns_num_cols].to_numpy(dtype=float))

# 4) hashed categoricals (ASN / ISP / country / registrar / status)
def cat_row(r):
    d = {}

    asn = r.get("sample_asn")
    if asn is not None and not (isinstance(asn, float) and math.isnan(asn)):
        asn_str = str(asn).strip()
        if asn_str and asn_str.lower() != "nan":
            d["asn=" + asn_str] = 1

    isp = r.get("sample_isp")
    if isp is not None and not (isinstance(isp, float) and math.isnan(isp)):
        d["isp=" + str(isp)] = 1

    cc = r.get("sample_country")
    if cc is not None and not (isinstance(cc, float) and math.isnan(cc)):
        d["cc=" + str(cc)] = 1

    reg = r.get("registrar")
    if reg is not None and not (isinstance(reg, float) and math.isnan(reg)):
        d["reg=" + str(reg)] = 1

    st = r.get("status")
    if st is not None and not (isinstance(st, float) and math.isnan(st)):
        d["status=" + str(st)] = 1

    return d

cats = [cat_row(r) for r in Xdf.to_dict(orient="records")]
hasher = FeatureHasher(
    n_features=256, input_type="dict", alternate_sign=False
)
X_cat = hasher.transform(cats)

# 5) WHOIS numeric
whois_num_cols = [
    "age_days",
    "days_to_expiry",
    "created_isnull",
    "expires_isnull",
    "has_error",
]
for c in whois_num_cols:
    if c not in Xdf.columns:
        Xdf[c] = 0
Xdf[whois_num_cols] = Xdf[whois_num_cols].fillna(0)
X_whois_num = csr_matrix(Xdf[whois_num_cols].to_numpy(dtype=float))

# Final feature matrices
X_lex  = hstack([X_char, X_string]).tocsr()
X_full = hstack([X_char, X_string, X_dns_num, X_cat, X_whois_num]).tocsr()
y = Xdf["label"].astype(int).to_numpy()

print(
    f"Feature matrix (lex only): {X_lex.shape} | (full): {X_full.shape} | "
    f"positives= {int(y.sum())} negatives= {int((y == 0).sum())}"
)

# ---------------- temporal / random split ----------------

def has_two_classes(arr):
    return len(np.unique(arr)) >= 2

Xtr_lex = Xte_lex = Xtr_full = Xte_full = None
y_train = y_test = None
used_temporal = False

if "last_ingest_date" in Xdf.columns and Xdf["last_ingest_date"].notna().any():
    # Use last couple of days as "test" if possible
    cutoff = sorted(Xdf["last_ingest_date"].dropna().unique())[-1]
    print("[info] temporal split cutoff last_ingest_date >=", cutoff)
    test_mask = (Xdf["last_ingest_date"] >= cutoff).to_numpy(bool)
    n_test = int(test_mask.sum())
    n_total = len(test_mask)

    y_train_temp = y[~test_mask]
    y_test_temp = y[test_mask]

    temporal_ok = (
        0 < n_test < n_total
        and has_two_classes(y_train_temp)
        and has_two_classes(y_test_temp)
    )

    if temporal_ok:
        Xtr_lex, Xte_lex = X_lex[~test_mask], X_lex[test_mask]
        Xtr_full, Xte_full = X_full[~test_mask], X_full[test_mask]
        y_train, y_test = y_train_temp, y_test_temp
        used_temporal = True
        print(
            "[info] temporal split OK:",
            "train=",
            Xtr_lex.shape[0],
            "test=",
            Xte_lex.shape[0],
        )
    else:
        print("[warn] temporal split degenerate; falling back to random split")

if not used_temporal:
    Xtr_lex, Xte_lex, y_train, y_test = train_test_split(
        X_lex,
        y,
        test_size=0.25,
        stratify=y,
        random_state=42,
    )
    Xtr_full, Xte_full, _, _ = train_test_split(
        X_full,
        y,
        test_size=0.25,
        stratify=y,
        random_state=42,
    )
    print(
        "[info] random stratified split:",
        "train=",
        Xtr_lex.shape[0],
        "test=",
        Xte_lex.shape[0],
    )

print(
    "[info] y_train: positives=",
    int((y_train == 1).sum()),
    "negatives=",
    int((y_train == 0).sum()),
)
print(
    "[info] y_test:  positives=",
    int((y_test == 1).sum()),
    "negatives=",
    int((y_test == 0).sum()),
)

# ---------------- models ----------------

def evaluate_model(name, clf, Xtr, ytr, Xte, yte):
    clf.fit(Xtr, ytr)
    p_te = clf.predict_proba(Xte)[:, 1]
    roc = roc_auc_score(yte, p_te)
    pr = average_precision_score(yte, p_te)
    fpr, tpr, thr = roc_curve(yte, p_te)
    if (fpr >= 0.01).any():
        idx = np.searchsorted(fpr, 0.01, side="right") - 1
        idx = max(idx, 0)
        r_at_1pct = float(tpr[idx])
    else:
        r_at_1pct = float(tpr[-1])
    print(
        f"[{name}] ROC-AUC={roc:.4f}  PR-AUC={pr:.4f}  "
        f"Recall@FPR=1%={r_at_1pct:.3f}"
    )
    return clf, {"roc_auc": roc, "pr_auc": pr, "recall_at_1pct": r_at_1pct}


# 1) Logistic Regression baselines
logreg_lex = LogisticRegression(
    solver="liblinear", class_weight="balanced", max_iter=200, n_jobs=None
)
logreg_full = LogisticRegression(
    solver="liblinear", class_weight="balanced", max_iter=200, n_jobs=None
)

logreg_lex,  metrics_logreg_lex  = evaluate_model(
    "LogReg[lex_only]", logreg_lex,  Xtr_lex,  y_train, Xte_lex,  y_test
)
logreg_full, metrics_logreg_full = evaluate_model(
    "LogReg[full]",     logreg_full, Xtr_full, y_train, Xte_full, y_test
)

# 2) LightGBM (optional)
metrics_lgbm_lex = metrics_lgbm_full = None
if lgb is not None:
    try:
        lgbm_lex = lgb.LGBMClassifier(
            n_estimators=600,
            learning_rate=0.05,
            num_leaves=63,
            subsample=0.9,
            colsample_bytree=0.9,
            reg_alpha=0.1,
            reg_lambda=0.1,
            objective="binary",
            class_weight="balanced",
            n_jobs=-1,
        )
        lgbm_full = lgb.LGBMClassifier(
            n_estimators=600,
            learning_rate=0.05,
            num_leaves=63,
            subsample=0.9,
            colsample_bytree=0.9,
            reg_alpha=0.1,
            reg_lambda=0.1,
            objective="binary",
            class_weight="balanced",
            n_jobs=-1,
        )

        lgbm_lex,  metrics_lgbm_lex  = evaluate_model(
            "LightGBM[lex_only]", lgbm_lex,  Xtr_lex,  y_train, Xte_lex,  y_test
        )
        lgbm_full, metrics_lgbm_full = evaluate_model(
            "LightGBM[full]",     lgbm_full, Xtr_full, y_train, Xte_full, y_test
        )
    except Exception as e:
        print("[warn] LightGBM training failed:", e)
        lgbm_lex = lgbm_full = None
else:
    print("[info] LightGBM not installed; skipping")

# ---------------- save models + metadata ----------------

ts_stamp = NOW_UTC.strftime("%Y%m%dT%H%M%SZ")

meta = {
    "created_utc": NOW_UTC.isoformat(),
    "n_rows": int(len(Xdf)),
    "n_pos": int((y == 1).sum()),
    "n_neg": int((y == 0).sum()),
    "metrics": {
        "logreg_lex": metrics_logreg_lex,
        "logreg_full": metrics_logreg_full,
        "lgbm_lex": metrics_lgbm_lex,
        "lgbm_full": metrics_lgbm_full,
    },
    "feature_shapes": {
        "X_lex":  X_lex.shape,
        "X_full": X_full.shape,
    },
}

meta_path = os.path.join(MODEL_DIR, f"ct_risk_meta_{ts_stamp}.json")
with open(meta_path, "w") as f:
    json.dump(meta, f, indent=2)
print(f"[info] wrote meta to {meta_path}")

# Logistic Regression models
logreg_lex_path = os.path.join(MODEL_DIR, f"ct_risk_logreg_lex_{ts_stamp}.joblib")
logreg_full_path = os.path.join(MODEL_DIR, f"ct_risk_logreg_full_{ts_stamp}.joblib")

if joblib is not None:
    joblib.dump(logreg_lex, logreg_lex_path)
    joblib.dump(logreg_full, logreg_full_path)
    print("[info] saved LogisticRegression models via joblib")
else:
    print("[warn] joblib missing; LogReg models not saved to disk")

# LightGBM boosters (if available)
if lgb is not None and "lgbm_full" in locals() and lgbm_full is not None:
    try:
        lgb_full_path = os.path.join(MODEL_DIR, f"ct_risk_lgbm_full_{ts_stamp}.txt")
        lgbm_full.booster_.save_model(lgb_full_path)
        print("[info] saved LightGBM full booster to", lgb_full_path)
    except Exception as e:
        print("[warn] failed to save LightGBM full booster:", e)
        lgb_full_path = None
else:
    lgb_full_path = None

# ---------------- update "latest" symlinks/copies ----------------

def _copy_latest(src, latest_name):
    if src is None or not os.path.exists(src):
        return
    latest_path = os.path.join(MODEL_DIR, latest_name)
    try:
        # copy2 to preserve mtime, works on all platforms
        shutil.copy2(src, latest_path)
        print(f"[info] updated latest model: {latest_path}")
    except Exception as e:
        print(f"[warn] failed to update latest copy {latest_path}: {e}")

# meta
_copy_latest(meta_path, "ct_risk_meta_latest.json")
# logreg
_copy_latest(logreg_full_path, "ct_risk_logreg_full_latest.joblib")
# lightgbm (if saved)
if lgb_full_path is not None:
    _copy_latest(lgb_full_path, "ct_risk_lgbm_full_latest.txt")

print("[info] training run complete.")
