# run_drain_pyod_anomaly.py
# -*- coding: utf-8 -*-
# """
# Drain 템플릿 마이닝 + 세션 벡터화 + PYOD 모델 선택형 이상탐지 파이프라인
# - 입력: SAML IdP/SP 로그 (처음 제공한 파일 경로 그대로 사용 가능)
# - 세션 키: SP-ID (AuthnRequest.ID 또는 InResponseTo)
# - 출력:
#   - ./OUTPUTS/drain_parsed_events.csv         : 라인 단위(원시→템플릿 매핑 및 플래그)
#   - ./OUTPUTS/drain_session_vectors.csv       : 세션 벡터 (cluster count matrix)
#   - ./OUTPUTS/pyod_anomaly_scores.csv        : 세션별 이상 점수/판정
#   - ./OUTPUTS/drain_pyod_anomaly_summary.json: 요약 지표
# 사용 예:
#   python run_drain_pyod_anomaly.py --model IForest --contamination 0.08
#   python run_drain_pyod_anomaly.py --model COPOD
#   python run_drain_pyod_anomaly.py --model ECOD
#   python run_drain_pyod_anomaly.py --model LOF
#   python run_drain_pyod_anomaly.py --model AutoEncoder --epochs 20
# """
import os
import re
import json
import argparse
from pathlib import Path
from collections import defaultdict, Counter

import numpy as np
import pandas as pd

from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence
from drain3.template_miner_config import TemplateMinerConfig

# --- PYOD models ---
from pyod.models.iforest import IForest
from pyod.models.copod import COPOD
from pyod.models.ecod import ECOD
from pyod.models.lof import LOF
try:
    from pyod.models.auto_encoder import AutoEncoder  # optional: needs torch
    HAS_AE = True
except Exception:
    HAS_AE = False


# -----------------------------
# 0) 입력 로그 경로
# -----------------------------
LOG_PATHS = [
    "/home/kongju/DEV/dream/DATA/LOGS/idp__ssoserver.log",
    "/home/kongju/DEV/dream/DATA/LOGS/idp_log__ssoserver.log",
    "/home/kongju/DEV/dream/DATA/LOGS/idp_log__ssoserver_20250820.log",
    "/home/kongju/DEV/dream/DATA/LOGS/sp_log__ssoagent_20250820.log",
    "/home/kongju/DEV/dream/DATA/LOGS/sp_log__ssoagent_20250821.log",
    "/home/kongju/DEV/dream/DATA/LOGS/sp1__ssoagent_20250821.log",
    "/home/kongju/DEV/dream/DATA/LOGS/sp2__ssoagent_20250821.log",
]

# -----------------------------
# 1) Drain3 설정 (마스킹: 동적 토큰 정규식)
# -----------------------------
def build_template_miner() -> TemplateMiner:
    config = TemplateMinerConfig()

    # 마스킹 규칙 (로그셋에 최적화)
    masks = [
        {"regex_pattern": r"SP-[0-9a-fA-F]{8,}", "mask_with": "<:SPID:>"},
        {"regex_pattern": r"IDP-[0-9a-fA-F]{8,}", "mask_with": "<:IDPID:>"},
        {"regex_pattern": r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", "mask_with": "<:ISO_TS:>"},
        {"regex_pattern": r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", "mask_with": "<:DATETIME:>"},
        {"regex_pattern": r"\b\d{2}:\d{2}:\d{2}\b", "mask_with": "<:TIME:>"},
        {"regex_pattern": r"https?://[^\s\">]+", "mask_with": "<:URL:>"},
        {"regex_pattern": r"\b[a-zA-Z0-9.-]+\.(com|net|org|dev|io|co)\b", "mask_with": "<:DOMAIN:>"},
        {"regex_pattern": r":\d{2,5}\b", "mask_with": "<:PORT:>"},
        {"regex_pattern": r"\b\d{1,3}(\.\d{1,3}){3}\b", "mask_with": "<:IP:>"},
        {"regex_pattern": r"\b\d{6,}\b", "mask_with": "<:NUM6P:>"},
        {"regex_pattern": r"\b\d{3,5}\b", "mask_with": "<:NUM:>"},
    ]

    # ---- 신/구 버전 모두 지원하는 안전 세터 ----
    def safe_set_drain(sim_th=None, depth=None, max_children=None, max_clusters=None):
        if hasattr(config, "drain"):
            if sim_th is not None:     config.drain.similarity_threshold = sim_th
            if depth is not None:      config.drain.depth = depth
            if max_children is not None:  config.drain.max_children = max_children
            if max_clusters is not None:  config.drain.max_clusters = max_clusters
        else:
            # 구버전 평면 속성
            if sim_th is not None:     setattr(config, "drain_sim_th", sim_th)
            if depth is not None:      setattr(config, "drain_depth", depth)
            if max_children is not None:setattr(config, "drain_max_children", max_children)
            if max_clusters is not None:setattr(config, "drain_max_clusters", max_clusters)

    def safe_set_masking(mask_list):
        if hasattr(config, "masking") and hasattr(config.masking, "mask_list"):
            # 신버전: 리스트 직접 주입 + prefix/suffix 지정 가능
            config.masking.mask_prefix = "<:"
            config.masking.mask_suffix = ":>"
            config.masking.mask_list = mask_list
        else:
            # 구버전: 문자열(JSON)로 주입
            # 일부 구버전은 config.masking 문자열 하나만 읽음
            setattr(config, "masking", json.dumps(mask_list, ensure_ascii=False))

    # ---- 파라미터 적용 ----
    safe_set_drain(sim_th=0.4, depth=6, max_children=100, max_clusters=4096)
    safe_set_masking(masks)

    # (선택) 스냅샷/압축 관련 구버전 키가 있을 수 있음 → 존재할 때만 세팅
    for k, v in {
        "snapshot_interval_minutes": 0,
        "compress_state": False
    }.items():
        if hasattr(config, k):
            setattr(config, k, v)

    # 템플릿 마이너 생성
    miner = TemplateMiner(
        persistence_handler=FilePersistence("drain3_state_pyod.bin"),
        config=config
    )
    return miner


# 세션/타임스탬프 추출
RE_SID = re.compile(r'(?:ID="(SP-[0-9a-fA-F]{8,})"|InResponseTo="(SP-[0-9a-fA-F]{8,})")')
RE_TS  = re.compile(r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|\b\d{2}:\d{2}:\d{2}\b)')

def extract_session_id(line: str):
    m = RE_SID.search(line)
    if not m:
        return None
    return m.group(1) or m.group(2)

def extract_ts(line: str):
    m = RE_TS.search(line)
    return m.group(1) if m else None


def _get_cluster_template(miner, res):
    """
    Drain3 버전에 따라:
      - res['template'] 가 직접 들어오기도 하고,
      - res['cluster'] 객체가 오기도 하고,
      - miner가 id→cluster 맵/리스트/컨테이너를 가질 수 있음.
    가능한 모든 루트를 시도해 템플릿 문자열을 반환.
    """
    # 1) result dict에 직접 템플릿이 있는 경우
    if isinstance(res, dict):
        if res.get("template"):
            return res["template"]
        if res.get("log_template"):  # 일부 포크/버전에서 키 이름
            return res["log_template"]
        if res.get("cluster") is not None:
            c = res["cluster"]
            if hasattr(c, "get_template"):
                try:
                    return c.get_template()
                except Exception:
                    pass
            if hasattr(c, "template"):
                return c.template

    # cluster_id 확보
    cid = None
    if isinstance(res, dict):
        cid = res.get("cluster_id")

    # 2) miner에 id→cluster 맵이 존재하는 경우
    for attr in ("id_to_cluster", "cluster_id_to_cluster"):
        if hasattr(miner, attr):
            mapping = getattr(miner, attr)
            if isinstance(mapping, dict) and cid in mapping:
                c = mapping[cid]
                if hasattr(c, "get_template"):
                    try:
                        return c.get_template()
                    except Exception:
                        pass
                if hasattr(c, "template"):
                    return c.template

    # 3) miner.clusters 컨테이너(리스트 or 매니저)에서 찾아보기
    if hasattr(miner, "clusters"):
        clusters = getattr(miner, "clusters")
        # 리스트 형태
        if isinstance(clusters, list):
            for c in clusters:
                if getattr(c, "cluster_id", None) == cid:
                    if hasattr(c, "get_template"):
                        try:
                            return c.get_template()
                        except Exception:
                            pass
                    return getattr(c, "template", None)
        # 매니저 객체 형태: 메서드가 있을 수 있음
        for mname in ("get_by_id", "get_cluster_by_id", "get_cluster"):
            if hasattr(clusters, mname):
                try:
                    c = getattr(clusters, mname)(cid)
                    if c is not None:
                        if hasattr(c, "get_template"):
                            try:
                                return c.get_template()
                            except Exception:
                                pass
                        return getattr(c, "template", None)
                except Exception:
                    pass

    # 4) 마지막으로 실패 시 None
    return None

# -----------------------------
# 2) 템플릿 마이닝
# -----------------------------
def run_template_mining(paths: list[str]) -> pd.DataFrame:
    miner = build_template_miner()
    events = []
    
    for path_idx, path in enumerate(paths, 1):
        print(f"[INFO] Processing file {path_idx}/{len(paths)}: {os.path.basename(path)}")
        if not Path(path).exists():
            print(f"[WARN] File not found: {path}")
            continue
            
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            total_lines = len(lines)
            print(f"[INFO] {os.path.basename(path)}: {total_lines} lines")
            
            for i, raw in enumerate(lines, 1):
                # 큰 파일의 경우만 진행률 표시 (10000줄 이상이고, 10000줄마다)
                if total_lines >= 10000 and i % 10000 == 0:
                    print(f"[INFO] {i}/{total_lines} ({i/total_lines*100:.0f}%)")
                    
                msg = raw.rstrip("\n")
                if not msg.strip():
                    continue
                res = miner.add_log_message(msg)

                # ✅ 버전-무관 템플릿 추출
                tmpl = _get_cluster_template(miner, res)

                events.append({
                    "file": os.path.basename(path),
                    "line_no": i,
                    "raw": msg,
                    "session_id": extract_session_id(msg),
                    "timestamp_raw": extract_ts(msg),
                    "cluster_id": res.get("cluster_id") if isinstance(res, dict) else None,
                    "cluster_size": res.get("cluster_size") if isinstance(res, dict) else None,
                    "change_type": res.get("change_type") if isinstance(res, dict) else None,
                    "template": tmpl,
                })
        print(f"[INFO] {os.path.basename(path)} completed")
    
    print(f"[INFO] Template mining completed. Building session vectors...")
    return pd.DataFrame(events)



# -----------------------------
# 3) 세션 벡터화 (cluster count matrix)
# -----------------------------
def build_session_vectors(df: pd.DataFrame) -> pd.DataFrame:
    # session_id 없는 라인은 제외
    sdf = df.dropna(subset=["session_id"]).copy()
    piv = pd.pivot_table(
        sdf,
        index="session_id",
        columns="cluster_id",
        values="line_no",
        aggfunc="count",
        fill_value=0
    )
    # 안정성 위해 정렬
    piv = piv.sort_index(axis=0).sort_index(axis=1)
    return piv


# -----------------------------
# 4) PYOD 모델 팩토리
# -----------------------------
def make_pyod_model(name: str,
                    contamination: float = 0.05,
                    n_estimators: int = 400,
                    n_neighbors: int = 20,
                    epochs: int = 15,
                    batch_size: int = 64,
                    random_state: int = 42):
    """
    name: IForest|COPOD|ECOD|LOF|AutoEncoder
    """
    lname = name.lower()
    if lname == "iforest":
        return IForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            behaviour="new"  # for backward compat; ignored in latest pyod
        )
    elif lname == "copod":
        return COPOD(contamination=contamination)
    elif lname == "ecod":
        return ECOD(contamination=contamination)
    elif lname == "lof":
        return LOF(contamination=contamination, n_neighbors=n_neighbors, novelty=False)
    elif lname in ("autoencoder", "auto_encoder", "ae"):
        if not HAS_AE:
            raise RuntimeError("AutoEncoder requires PyTorch. Install torch or choose another model.")
        # 단순 AutoEncoder 설정(특징 수에 따라 자동 차원 조정)
        return AutoEncoder(
            contamination=contamination,
            epochs=epochs,
            batch_size=batch_size,
            hidden_neurons=None,  # default: [n/2, n/4, n/2]
            verbose=1,
            random_state=random_state
        )
    else:
        raise ValueError(f"Unsupported model: {name}")


# -----------------------------
# 5) 이상탐지 수행
# -----------------------------
def run_pyod_anomaly(session_vectors: pd.DataFrame,
                     model_name: str,
                     contamination: float,
                     n_estimators: int,
                     n_neighbors: int,
                     epochs: int,
                     batch_size: int,
                     random_state: int) -> pd.DataFrame:
    if session_vectors.empty:
        raise RuntimeError("Session vectors are empty. Check parsing or session_id extraction.")
    X = session_vectors.values.astype(float)

    model = make_pyod_model(
        model_name,
        contamination=contamination,
        n_estimators=n_estimators,
        n_neighbors=n_neighbors,
        epochs=epochs,
        batch_size=batch_size,
        random_state=random_state
    )
    model.fit(X)

    # pyod outputs
    labels = model.labels_            # 1: outlier, 0: inlier (주의: pyod는 1=이상)
    scores = model.decision_scores_   # 큰 값일수록 이상(모델에 따라 방향성 다름, pyod는 decision_scores_는 “이상도”)

    out = pd.DataFrame({
        "session_id": session_vectors.index,
        "pyod_label": labels,
        "pyod_score": scores
    }).sort_values("pyod_score", ascending=False)
    return out


# -----------------------------
# 6) 요약/저장
# -----------------------------
def save_outputs(df_events: pd.DataFrame,
                 session_vectors: pd.DataFrame,
                 pyod_scores: pd.DataFrame,
                 out_dir: str = "./OUTPUTS"):
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    events_csv = os.path.join(out_dir, "drain_parsed_events.csv")
    sess_csv   = os.path.join(out_dir, "drain_session_vectors.csv")
    scores_csv = os.path.join(out_dir, "pyod_anomaly_scores.csv")
    summary_js = os.path.join(out_dir, "drain_pyod_anomaly_summary.json")

    df_events.to_csv(events_csv, index=False, encoding="utf-8")
    session_vectors.to_csv(sess_csv, encoding="utf-8")
    pyod_scores.to_csv(scores_csv, index=False, encoding="utf-8")

    # 희귀 템플릿 간단 집계(하위 5%)
    freq = df_events["cluster_id"].value_counts()
    rare_k = max(1, int(len(freq) * 0.05))
    rare_ids = list(freq.tail(rare_k).index)

    summary = {
        "total_lines": int(len(df_events)),
        "total_sessions": int(df_events["session_id"].notna().sum()),
        "unique_templates": int(df_events["cluster_id"].nunique()),
        "rare_templates_count": int(len(rare_ids)),
        "rare_template_ids": rare_ids,
        "top_sessions_by_pyod_score": pyod_scores.head(10)["session_id"].tolist(),
    }
    with open(summary_js, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("Saved:")
    print(" -", events_csv)
    print(" -", sess_csv)
    print(" -", scores_csv)
    print(" -", summary_js)


# -----------------------------
# 7) 메인
# -----------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", type=str, default="IForest",
                    help="PYOD model: IForest|COPOD|ECOD|LOF|AutoEncoder")
    ap.add_argument("--contamination", type=float, default=0.05,
                    help="Outlier 비율 추정치(0~0.5 권장)")
    ap.add_argument("--n_estimators", type=int, default=400,
                    help="IForest 등 트리 기반 모델의 트리 수")
    ap.add_argument("--n_neighbors", type=int, default=20,
                    help="LOF 이웃 수")
    ap.add_argument("--epochs", type=int, default=15,
                    help="AutoEncoder 학습 epoch")
    ap.add_argument("--batch_size", type=int, default=64,
                    help="AutoEncoder 배치 크기")
    ap.add_argument("--random_state", type=int, default=42)
    args = ap.parse_args()

    print(f"[INFO] Model={args.model}, contamination={args.contamination}")

    # 1) Drain 템플릿 마이닝
    print("[INFO] Starting template mining...")
    df_events = run_template_mining(LOG_PATHS)
    if df_events.empty:
        raise RuntimeError("No events parsed. Check LOG_PATHS or file encodings.")

    # 2) 세션 벡터화
    print("[INFO] Building session vectors...")
    session_vectors = build_session_vectors(df_events)
    if session_vectors.shape[0] < 5:
        # 샘플이 너무 적으면 모델 학습이 불안정할 수 있음(경고만 출력)
        print(f"[WARN] Low number of sessions: {session_vectors.shape[0]}")

    # 3) PYOD 모델로 이상탐지
    print(f"[INFO] Running {args.model} anomaly detection...")
    pyod_scores = run_pyod_anomaly(
        session_vectors,
        model_name=args.model,
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        n_neighbors=args.n_neighbors,
        epochs=args.epochs,
        batch_size=args.batch_size,
        random_state=args.random_state
    )

    # 4) 저장
    print("[INFO] Saving outputs...")
    save_outputs(df_events, session_vectors, pyod_scores, out_dir="./OUTPUTS")

    # 5) 콘솔 요약
    print("[INFO] Top 10 anomalous sessions:")
    print(pyod_scores.head(10).to_string(index=False))


if __name__ == "__main__":
    main()
