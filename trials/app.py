# app.py
# -*- coding: utf-8 -*-
import json
import io
from datetime import datetime
from typing import Optional, Tuple

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

# =========================
# 1) 유틸
# =========================
def _to_dt(s: Optional[str]) -> Optional[pd.Timestamp]:
    if pd.isna(s) or s is None:
        return None
    s = str(s).strip()
    # 허용 포맷: HH:MM:SS / YYYY-MM-DD HH:MM:SS / YYYY-MM-DDTHH:MM:SSZ
    fmts = ["%Y-%m-%d %H:%M:%S", "%H:%M:%S"]
    # ISO8601 'T' & 'Z'
    try:
        if "T" in s:
            # pandas가 잘 파싱함
            return pd.to_datetime(s, utc=True, errors="coerce")
    except Exception:
        pass
    for f in fmts:
        try:
            dt = datetime.strptime(s, f)
            # 날짜가 없는 HH:MM:SS인 경우 오늘 날짜로 보정(분석용)
            if f == "%H:%M:%S":
                dt = pd.Timestamp.combine(pd.Timestamp.today().date(), pd.Timestamp(s).time())
                return pd.to_datetime(dt, utc=True)
            return pd.to_datetime(dt, utc=True)
        except Exception:
            continue
    # 최후: pandas 파서
    return pd.to_datetime(s, utc=True, errors="coerce")


def _duration_sec(start_ts: Optional[pd.Timestamp], end_ts: Optional[pd.Timestamp]) -> Optional[float]:
    if start_ts is None or end_ts is None or pd.isna(start_ts) or pd.isna(end_ts):
        return None
    # 음수 방지
    d = (end_ts - start_ts).total_seconds()
    return d if d >= 0 else None


def load_matches(file: Optional[io.BytesIO]) -> pd.DataFrame:
    """
    매칭 테이블 로드:
    - 업로더 파일이 있으면 이를 사용
    - 없으면 기본 경로 시도(노트북/서버에서 동작 시)
    """
    if file is None:
        # 기본 경로 시도
        for path in ["./data/sso_sequence_matches.csv", "./sso_sequence_matches.xlsx",
                     "/home/kongju/DEV/trials/data/sso_sequence_matches.csv", "/home/kongju/DEV/trials/data/sso_sequence_matches.xlsx"]:
            try:
                if path.endswith(".csv"):
                    df = pd.read_csv(path)
                else:
                    df = pd.read_excel(path)
                st.info(f"Loaded matches from: {path}")
                return df
            except Exception:
                continue
        st.warning("매칭 테이블 파일을 업로드하거나, 기본 경로에 파일이 있는지 확인하세요.")
        return pd.DataFrame()
    else:
        name = getattr(file, "name", "uploaded")
        if name.endswith(".csv"):
            return pd.read_csv(file)
        elif name.endswith(".xlsx"):
            return pd.read_excel(file)
        else:
            # 확장자 모르면 CSV 시도
            try:
                return pd.read_csv(file)
            except Exception:
                file.seek(0)
                return pd.read_excel(file)


def load_analysis_json(file: Optional[io.BytesIO]) -> Optional[dict]:
    if file is None:
        # 기본 경로 시도
        for path in ["./data/analysis_result.json", "/home/kongju/DEV/trials/data/analysis_result.json"]:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    st.info(f"Loaded analysis JSON from: {path}")
                    return json.load(f)
            except Exception:
                continue
        st.warning("분석 JSON(analysis_result.json)을 업로드하거나, 기본 경로에 파일이 있는지 확인하세요.")
        return None
    else:
        try:
            return json.load(file)
        except Exception:
            st.error("analysis_result.json 파싱 실패")
            return None


def normalize_matches(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    # 표준 컬럼 이름 확인/생성
    # 기대 컬럼:
    # sp_id, sequence_status,
    # idp_ts, idp_issue_instant, idp_provider, idp_acs, idp_error, idp_file, idp_line,
    # sp_ts, sp_issue_instant, sp_provider, sp_acs, sp_status, assertion_verify, sp_agent, sp_file, sp_line
    for c in ["sp_id","sequence_status","idp_ts","sp_ts","idp_provider","sp_provider",
              "idp_issue_instant","sp_issue_instant","idp_acs","sp_acs","idp_error",
              "sp_status","assertion_verify","sp_agent","idp_file","sp_file","idp_line","sp_line"]:
        if c not in df.columns:
            df[c] = np.nan

    # TS 파싱
    df["idp_ts_parsed"] = df["idp_ts"].apply(_to_dt)
    df["sp_ts_parsed"] = df["sp_ts"].apply(_to_dt)

    # IssueInstant 파싱(UTC)
    df["idp_issue_parsed"] = pd.to_datetime(df["idp_issue_instant"], utc=True, errors="coerce")
    df["sp_issue_parsed"] = pd.to_datetime(df["sp_issue_instant"], utc=True, errors="coerce")

    # 대표 시각(분석용): SP가 있으면 SP, 없으면 IdP
    df["ts_any"] = df["sp_ts_parsed"].fillna(df["idp_ts_parsed"])

    # 응답시간: 가능한 경우 IssueInstant 또는 ts 기반으로 계산
    # 우선순위: (sp_issue - idp_issue) > (sp_ts - idp_ts)
    df["duration_sec"] = df.apply(
        lambda r: _duration_sec(r.get("idp_issue_parsed"), r.get("sp_issue_parsed")), axis=1
    )
    # 보강
    mask_na = df["duration_sec"].isna()
    df.loc[mask_na, "duration_sec"] = df[mask_na].apply(
        lambda r: _duration_sec(r.get("idp_ts_parsed"), r.get("sp_ts_parsed")), axis=1
    )

    # Provider/Agent 통합 보조 컬럼
    df["provider_any"] = df["sp_provider"].fillna(df["idp_provider"])
    df["provider_any"] = df["provider_any"].fillna("Unknown")

    df["agent_any"] = df["sp_agent"].fillna("Unknown")

    # 완료/미완료 플래그
    def _is_completed(row) -> bool:
        stv = str(row.get("sp_status")).lower() if pd.notna(row.get("sp_status")) else ""
        if "success" in stv:
            return True
        return False

    def _is_unmatched(row) -> bool:
        # IdP-only or SP-only
        if pd.isna(row.get("sp_ts")) and pd.notna(row.get("idp_ts")):
            return True
        if pd.isna(row.get("idp_ts")) and pd.notna(row.get("sp_ts")):
            return True
        return False

    df["is_completed"] = df.apply(_is_completed, axis=1)
    df["is_unmatched"] = df.apply(_is_unmatched, axis=1)

    return df


def kpi_from_json(js: Optional[dict]) -> Tuple[Optional[int], Optional[int], Optional[int], Optional[float]]:
    if not js:
        return None, None, None, None
    try:
        total = int(js["분석_요약"]["총_트랜잭션수"])
        done = int(js["분석_요약"]["완료된_트랜잭션수"])
        undone = int(js["분석_요약"]["미완료_트랜잭션수"])
        succ_rate = float(js["분석_요약"]["성공률"])
        return total, done, undone, succ_rate
    except Exception:
        return None, None, None, None


# =========================
# 2) UI - 사이드바 업로드/필터
# =========================
st.set_page_config(page_title="SSO 로그 리포트 대시보드", layout="wide")
st.title("SSO 로그 리포트 대시보드 (SAML Transaction Correlation)")

with st.sidebar:
    st.header("입력 파일 (Input Files)")
    m_file = st.file_uploader("매칭 테이블 (CSV/XLSX)", type=["csv", "xlsx"])
    a_file = st.file_uploader("분석 JSON (analysis_result.json)", type=["json"])

    st.caption("업로드를 생략하면 기본 경로에서 자동 탐색합니다.")

# 데이터 로드/정규화
matches_raw = load_matches(m_file)
analysis_js = load_analysis_json(a_file)
matches = normalize_matches(matches_raw.copy())

# =========================
# 3) KPI 카드
# =========================
st.subheader("요약 (KPI)")

# JSON KPI 우선, 부족하면 matches로 보강
total_js, done_js, undone_js, succ_js = kpi_from_json(analysis_js)

if not matches.empty:
    total_m = len(matches)
    done_m = int(matches["is_completed"].sum())
    undone_m = int(total_m - done_m)
    # 미매칭 개념은 별도로 보여줌
    unmatched_m = int(matches["is_unmatched"].sum())
    # 성공률(matches)
    succ_m = (done_m / total_m * 100.0) if total_m > 0 else np.nan

    # 응답시간 통계(matches)
    dur = matches["duration_sec"].dropna()
    avg_dur = float(np.mean(dur)) if len(dur) else np.nan
    med_dur = float(np.median(dur)) if len(dur) else np.nan
    p95_dur = float(np.percentile(dur, 95)) if len(dur) else np.nan
else:
    total_m = done_m = undone_m = unmatched_m = 0
    succ_m = avg_dur = med_dur = p95_dur = np.nan

cols = st.columns(6)
cols[0].metric("총 트랜잭션수 (Total)", total_js if total_js is not None else total_m)
cols[1].metric("완료 (Completed)", done_js if done_js is not None else done_m)
cols[2].metric("미완료 (Incomplete)", undone_js if undone_js is not None else undone_m)
cols[3].metric("성공률 (Success Rate, %)",
               f"{succ_js:.2f}" if succ_js is not None else (f"{succ_m:.2f}" if not np.isnan(succ_m) else "N/A"))
cols[4].metric("평균 응답시간 (Avg, s)", f"{avg_dur:.3f}" if not np.isnan(avg_dur) else "N/A")
cols[5].metric("p95 응답시간 (p95, s)", f"{p95_dur:.3f}" if not np.isnan(p95_dur) else "N/A")

st.caption("※ KPI는 JSON(있을 경우)과 매칭 테이블을 함께 활용합니다. JSON이 더 정밀한 응답시간을 담고 있을 수 있습니다.")

# =========================
# 4) 필터 패널
# =========================
st.subheader("필터 (Filters)")

if matches.empty:
    st.stop()

# 날짜 범위(대표 시각: ts_any)
min_ts = matches["ts_any"].min()
max_ts = matches["ts_any"].max()
if pd.isna(min_ts) or pd.isna(max_ts):
    min_ts = pd.Timestamp("2025-08-20", tz="UTC")
    max_ts = pd.Timestamp("2025-08-22", tz="UTC")

c1, c2, c3, c4 = st.columns(4)
date_range = c1.date_input(
    "날짜 범위 (UTC)", value=(min_ts.date(), max_ts.date()),
    min_value=min_ts.date(), max_value=max_ts.date()
)
providers = sorted([p for p in matches["provider_any"].dropna().unique()])
provider_sel = c2.multiselect("Provider (TEST_SP1/TEST_SP2/Unknown)", providers, default=providers)

agents = sorted([a for a in matches["agent_any"].dropna().unique()])
agent_sel = c3.multiselect("Agent (SP1/SP2/SP/Unknown)", agents, default=agents)

statuses = sorted([s for s in matches["sequence_status"].dropna().unique()])
status_sel = c4.multiselect("Sequence Status", statuses, default=statuses)

# 필터 적용
dfv = matches.copy()
start_dt = pd.Timestamp(date_range[0], tz="UTC")
end_dt = pd.Timestamp(date_range[1], tz="UTC") + pd.Timedelta(days=1)  # inclusive
dfv = dfv[(dfv["ts_any"] >= start_dt) & (dfv["ts_any"] < end_dt)]
dfv = dfv[dfv["provider_any"].isin(provider_sel)]
dfv = dfv[dfv["agent_any"].isin(agent_sel)]
dfv = dfv[dfv["sequence_status"].isin(status_sel)]

st.caption(f"필터 결과 행 수: {len(dfv)}")

# =========================
# 5) 차트
# =========================
st.subheader("차트 (Charts)")

# 5-1) 시간 추이 (완료/미완료)
ts_df = dfv.copy()
ts_df["date_hour"] = ts_df["ts_any"].dt.tz_convert("Asia/Seoul").dt.floor("H")
ts_df["completed_flag"] = np.where(ts_df["is_completed"], "Completed", "Not Completed")
trend = ts_df.groupby(["date_hour", "completed_flag"]).size().reset_index(name="count")
fig_trend = px.line(trend, x="date_hour", y="count", color="completed_flag", markers=True,
                    title="시간 추이 (Completed vs Not Completed)")
st.plotly_chart(fig_trend, use_container_width=True)

# 5-2) Provider별 완료/미완료 분포
prov = dfv.copy()
prov["completed_flag"] = np.where(prov["is_completed"], "Completed", "Not Completed")
prov_count = prov.groupby(["provider_any","completed_flag"]).size().reset_index(name="count")
fig_prov = px.bar(prov_count, x="provider_any", y="count", color="completed_flag", barmode="stack",
                  title="Provider별 Completed/Not Completed 분포")
st.plotly_chart(fig_prov, use_container_width=True)

# 5-3) Status 분포
status_count = dfv.groupby("sequence_status").size().reset_index(name="count")
fig_status = px.pie(status_count, names="sequence_status", values="count", title="Sequence Status 분포")
st.plotly_chart(fig_status, use_container_width=True)

# 5-4) Agent별 성공률
succ_by_agent = dfv.groupby("agent_any")["is_completed"].mean().reset_index()
succ_by_agent["success_rate(%)"] = (succ_by_agent["is_completed"] * 100.0).round(2)
fig_agent = px.bar(succ_by_agent, x="agent_any", y="success_rate(%)", title="Agent별 성공률(%)")
st.plotly_chart(fig_agent, use_container_width=True)

# 5-5) 응답시간 분포(히스토그램)
dur_hist = dfv["duration_sec"].dropna()
if len(dur_hist):
    fig_hist = px.histogram(dfv, x="duration_sec", nbins=30, title="응답시간 분포 (seconds)")
    st.plotly_chart(fig_hist, use_container_width=True)
else:
    st.info("응답시간(duration_sec)이 계산 가능한 행이 충분하지 않습니다.")

# =========================
# 6) 테이블
# =========================
st.subheader("테이블 (Tables)")

# 6-1) 최상위 지연 사례 Top-N
topn = st.number_input("Top-N 지연 사례 (응답시간 기준, seconds)", min_value=3, max_value=100, value=15, step=1)
slow_df = dfv.dropna(subset=["duration_sec"]).sort_values("duration_sec", ascending=False).head(topn)
st.markdown("#### 최상위 지연 사례 (Top Slow Transactions)")
st.dataframe(slow_df[[
    "sp_id","sequence_status","duration_sec","idp_ts","sp_ts",
    "idp_provider","sp_provider","idp_acs","sp_acs","sp_status","agent_any","idp_file","sp_file"
]])

# 6-2) 미매칭(IdP-only / SP-only)
unmatched_df = dfv[dfv["is_unmatched"] == True].copy()
st.markdown("#### 미매칭 트랜잭션 (Unmatched: IdP-only / SP-only)")
st.dataframe(unmatched_df[[
    "sp_id","sequence_status","idp_ts","sp_ts",
    "idp_provider","sp_provider","agent_any","idp_error","idp_file","sp_file"
]])

# 6-3) 전체(필터 적용)
st.markdown("#### 전체 결과 (필터 적용)")
st.dataframe(dfv)

