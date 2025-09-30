#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
이상 탐지를 위한 로그 데이터 전처리기

특징:
- 인증 로그 특화 파싱 및 정제
- 세션 기반 이상행위 탐지 특징 추출
- 시계열 패턴 분석 특징 생성
- 통계적 이상 탐지 기준값 제공

입력: key:value 쌍이 쉼표로 구분된 로그 라인
출력: 이상 탐지 준비된 정제 데이터셋 (events, sessions, anomaly_features)
"""

import argparse
import sys
import re
import io
from datetime import datetime, timezone
import ipaddress
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

import pandas as pd
import numpy as np
from scipy import stats

# ---------- 상수 및 설정 ----------
EXPECTED_COLUMNS = [
    "timestamp", "level", "session_id", "event", "step_id", "user_id",
    "status", "message", "source_ip", "target"
]

# 정상적인 인증 플로우 단계 순서
NORMAL_AUTH_STEPS = {
    'login_attempt': 1,
    'message_validation': 2, 
    'credential_validation': 3,
    'token_verification': 3,  # 토큰 로그인의 경우
    'business_process': 4,
    'response_return': 5
}

# 이상 탐지 임계값 설정
ANOMALY_THRESHOLDS = {
    'max_session_duration_ms': 300000,  # 5분
    'max_step_interval_ms': 30000,      # 30초
    'min_step_interval_ms': 10,         # 10ms
    'max_failed_attempts': 3,           # 연속 실패
    'rare_event_threshold': 0.05        # 5% 미만은 희소 이벤트
}

# ---------- 로그 파싱 ----------
KV_PAIR_PATTERN = re.compile(r'''
    \s*                             # leading spaces
    (?P<key>[A-Za-z0-9_\-]+)        # key
    \s*:\s*
    (                               # value:
        "(?P<qval>(?:[^"\\]|\\.)*)" #   "..." (escape 허용)
        |                           #   또는
        (?P<uval>[^,]+?)            #   비따옴표값(다음 콤마 전까지)
    )
    \s*(?:,|$)                      # 끝은 콤마 또는 라인 종료
''', re.VERBOSE)

def parse_log_line(line: str) -> Dict[str, Any]:
    """로그 라인을 dict로 파싱"""
    pos = 0
    out: Dict[str, Any] = {}
    for m in KV_PAIR_PATTERN.finditer(line):
        key = m.group("key").strip()
        if m.group("qval") is not None:
            val = m.group("qval").encode('utf-8').decode('unicode_escape')
        else:
            val = m.group("uval").strip()
        
        # 불필요한 따옴표 제거
        if len(val) >= 2 and ((val[0] == val[-1] == '"') or (val[0] == val[-1] == "'")):
            val = val[1:-1]
        out[key] = val
        pos = m.end()
    
    # 파싱되지 않은 부분
    rest = line[pos:].strip()
    if rest:
        out["_unparsed"] = rest
    return out

def parse_stream_to_records(stream: io.TextIOBase) -> List[Dict[str, Any]]:
    """스트림에서 레코드 리스트로 변환"""
    records = []
    line_number = 0
    
    for raw in stream:
        line_number += 1
        line = raw.strip()
        if not line:
            continue
        
        try:
            rec = parse_log_line(line)
            if rec:
                rec['_line_number'] = line_number
                records.append(rec)
        except Exception as e:
            print(f"경고: 라인 {line_number} 파싱 실패 - {e}", file=sys.stderr)
            continue
    
    return records

# ---------- 데이터 타입 변환 ----------
def to_datetime_utc(ts: str) -> Optional[pd.Timestamp]:
    """문자열을 UTC datetime으로 변환"""
    try:
        return pd.to_datetime(ts, utc=True, errors="coerce")
    except Exception:
        return pd.NaT

def ip_to_int(ip: str) -> Optional[int]:
    """IP 주소를 정수로 변환"""
    try:
        return int(ipaddress.ip_address(ip))
    except Exception:
        return None

def normalize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """데이터프레임 정규화 및 타입 캐스팅"""
    # 누락 컬럼 추가
    for col in EXPECTED_COLUMNS:
        if col not in df.columns:
            df[col] = pd.NA
    
    # 타입 변환
    df["timestamp"] = df["timestamp"].apply(
        lambda x: to_datetime_utc(str(x)) if pd.notna(x) else pd.NaT
    )
    df["step_id"] = pd.to_numeric(df["step_id"], errors="coerce").astype("Int64")
    df["level"] = df["level"].astype("string").str.strip().str.upper()
    df["event"] = df["event"].astype("string").str.strip()
    df["status"] = df["status"].astype("string").str.strip().str.lower()
    df["user_id"] = df["user_id"].astype("string").str.strip()
    df["session_id"] = df["session_id"].astype("string").str.strip()
    df["message"] = df["message"].astype("string")
    df["source_ip"] = df["source_ip"].astype("string").str.strip()
    df["target"] = df["target"].astype("string").str.strip()
    
    # 정렬
    df = df.sort_values(
        ["session_id", "timestamp", "step_id"], 
        na_position="last"
    ).reset_index(drop=True)
    
    return df

# ---------- 특징 공학 ----------
def add_time_features(df: pd.DataFrame) -> pd.DataFrame:
    """시간 기반 특징 추가"""
    df["ts_epoch_ms"] = (df["timestamp"].astype("int64") // 1_000_000).astype("Int64")
    df["ts_hour"] = df["timestamp"].dt.hour.astype("Int64")
    df["ts_minute"] = df["timestamp"].dt.minute.astype("Int64")
    df["ts_second"] = df["timestamp"].dt.second.astype("Int64")
    df["ts_millisecond"] = df["timestamp"].dt.microsecond.div(1000).astype("Int64")
    df["ts_dayofweek"] = df["timestamp"].dt.dayofweek.astype("Int64")
    df["ts_is_weekend"] = df["ts_dayofweek"].isin([5, 6]).astype("Int8")
    df["ts_is_business_hours"] = df["ts_hour"].between(9, 17).astype("Int8")
    
    return df

def add_ip_features(df: pd.DataFrame) -> pd.DataFrame:
    """IP 주소 기반 특징 추가"""
    df["source_ip_int"] = df["source_ip"].apply(
        lambda x: ip_to_int(x) if pd.notna(x) else None
    ).astype("Int64")
    
    # 테스트 네트워크 여부
    def is_testnet(ip: str) -> int:
        try:
            ipobj = ipaddress.ip_address(ip)
            test_networks = [
                ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
                ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
                ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
                ipaddress.ip_network("127.0.0.0/8"),     # Loopback
                ipaddress.ip_network("10.0.0.0/8"),      # Private
                ipaddress.ip_network("172.16.0.0/12"),   # Private
                ipaddress.ip_network("192.168.0.0/16")   # Private
            ]
            return int(any(ipobj in net for net in test_networks))
        except Exception:
            return 0
    
    df["source_ip_is_internal"] = df["source_ip"].apply(
        lambda x: is_testnet(x) if pd.notna(x) else 0
    ).astype("Int8")
    
    return df

def add_session_features(df: pd.DataFrame) -> pd.DataFrame:
    """세션 기반 특징 추가"""
    # 세션 내 시간 간격
    df["prev_ts"] = df.groupby("session_id")["timestamp"].shift(1)
    df["delta_ms"] = (df["timestamp"] - df["prev_ts"]).dt.total_seconds().mul(1000).fillna(0.0)
    
    # 세션 내 step 순서 검증
    df["prev_step"] = df.groupby("session_id")["step_id"].shift(1)
    df["step_increment_normal"] = (df["step_id"] == df["prev_step"] + 1).astype("Int8")
    df.loc[df["prev_step"].isna(), "step_increment_normal"] = 1  # 첫 이벤트는 정상
    
    # step 점프 감지
    df["step_gap"] = (df["step_id"] - df["prev_step"]).fillna(1).astype("Int64")
    df["step_jump"] = (df["step_gap"] > 1).astype("Int8")
    df["step_reverse"] = (df["step_gap"] < 1).astype("Int8")
    
    # 동시 이벤트 감지
    df["simultaneous_event"] = (df["delta_ms"] == 0).astype("Int8")
    
    # 예상 step과의 일치 여부 (이벤트 타입별)
    df["expected_step"] = df["event"].map(NORMAL_AUTH_STEPS)
    df["step_event_mismatch"] = (df["step_id"] != df["expected_step"]).astype("Int8")
    df.loc[df["expected_step"].isna(), "step_event_mismatch"] = 0
    
    return df

def add_anomaly_features(df: pd.DataFrame) -> pd.DataFrame:
    """이상 탐지 특화 특징 추가"""
    # 시간 간격 이상 탐지
    df["delta_too_fast"] = (
        df["delta_ms"] < ANOMALY_THRESHOLDS['min_step_interval_ms']
    ).astype("Int8")
    df["delta_too_slow"] = (
        df["delta_ms"] > ANOMALY_THRESHOLDS['max_step_interval_ms']
    ).astype("Int8")
    
    # 메시지 패턴 분석
    df["has_error_keyword"] = df["message"].str.contains(
        r'(?i)(error|fail|invalid|denied|timeout)', na=False, regex=True
    ).astype("Int8")
    
    df["message_length"] = df["message"].str.len().fillna(0).astype("Int64")
    df["message_unusual_length"] = (
        (df["message_length"] < 10) | (df["message_length"] > 200)
    ).astype("Int8")
    
    # 사용자/IP 패턴
    user_session_counts = df.groupby("user_id")["session_id"].nunique()
    df["user_multi_session"] = df["user_id"].map(user_session_counts) > 1
    df["user_multi_session"] = df["user_multi_session"].astype("Int8")
    
    ip_session_counts = df.groupby("source_ip")["session_id"].nunique()
    df["ip_multi_session"] = df["source_ip"].map(ip_session_counts) > 1
    df["ip_multi_session"] = df["ip_multi_session"].astype("Int8")
    
    return df

def add_categorical_encodings(df: pd.DataFrame, freq_threshold: int = 2) -> pd.DataFrame:
    """카테고리 변수 인코딩"""
    cat_cols = ["level", "event", "status", "target"]
    
    for col in cat_cols:
        # 빈도 인코딩
        value_counts = df[col].value_counts(dropna=False)
        df[f"{col}_freq"] = df[col].map(value_counts).astype("Int64")
        
        # 희소 카테고리 처리
        rare_mask = df[col].map(value_counts).fillna(0) < freq_threshold
        df[f"{col}_processed"] = df[col].where(~rare_mask, "RARE").astype("category")
        
        # 희소성 플래그
        df[f"{col}_is_rare"] = rare_mask.astype("Int8")
    
    # 식별자 빈도
    for col in ["user_id", "source_ip"]:
        value_counts = df[col].value_counts(dropna=False)
        df[f"{col}_freq"] = df[col].map(value_counts).astype("Int64")
    
    return df

# ---------- 세션 집계 ----------
def aggregate_sessions(df: pd.DataFrame) -> pd.DataFrame:
    """세션 단위 특징 집계"""
    # 기본 집계
    session_agg = df.groupby("session_id").agg({
        "timestamp": ["min", "max", "count"],
        "step_id": ["min", "max", "nunique"],
        "delta_ms": ["sum", "mean", "std", "max"],
        "status": lambda x: (x == "fail").sum(),
        "level": lambda x: (x == "ERROR").sum(),
        "step_jump": "sum",
        "step_reverse": "sum", 
        "step_event_mismatch": "sum",
        "delta_too_fast": "sum",
        "delta_too_slow": "sum",
        "simultaneous_event": "sum",
        "has_error_keyword": "sum",
        "source_ip": "nunique",
        "user_id": ["nunique", "first"],
        "target": ["nunique", "first"],
        "_line_number": ["min", "max"]
    }).round(3)
    
    # 컬럼명 평면화
    session_agg.columns = ['_'.join(col).strip('_') for col in session_agg.columns]
    session_agg = session_agg.reset_index()
    
    # 파생 특징 
    # 올바른 세션 지속시간 계산 (timestamp_max - timestamp_min)
    session_agg["duration_ms"] = (
        pd.to_datetime(session_agg["timestamp_max"]) - 
        pd.to_datetime(session_agg["timestamp_min"])
    ).dt.total_seconds() * 1000  # 밀리초 단위
    session_agg["avg_step_interval"] = session_agg["delta_ms_mean"]
    session_agg["n_events"] = session_agg["timestamp_count"]
    session_agg["n_unique_steps"] = session_agg["step_id_nunique"]
    session_agg["step_range"] = session_agg["step_id_max"] - session_agg["step_id_min"]
    session_agg["n_failures"] = session_agg["status_<lambda>"]
    session_agg["n_errors"] = session_agg["level_<lambda>"]
    
    # 마지막 상태
    last_status = df.sort_values(["session_id", "timestamp"]).groupby("session_id")["status"].last()
    session_agg = session_agg.merge(last_status.rename("final_status"), on="session_id")
    
    # 성공 여부
    session_agg["is_successful"] = (session_agg["final_status"] == "success").astype("Int8")
    
    # 시간 특징
    session_agg["start_hour"] = pd.to_datetime(session_agg["timestamp_min"]).dt.hour
    session_agg["start_dayofweek"] = pd.to_datetime(session_agg["timestamp_min"]).dt.dayofweek
    
    # 이상 점수 계산
    anomaly_scores = calculate_anomaly_scores(session_agg)
    session_agg = pd.concat([session_agg, anomaly_scores], axis=1)
    
    return session_agg

def calculate_anomaly_scores(df: pd.DataFrame) -> pd.DataFrame:
    """세션별 이상 점수 계산"""
    scores = pd.DataFrame(index=df.index)
    
    # Z-score 기반 이상 점수
    numeric_features = [
        "duration_ms", "avg_step_interval", "n_events", 
        "step_jump_sum", "n_failures", "delta_ms_std"
    ]
    
    z_scores = pd.DataFrame(index=df.index)
    for feature in numeric_features:
        if feature in df.columns and df[feature].std() > 0:
            z_scores[f"{feature}_zscore"] = np.abs(stats.zscore(df[feature].fillna(0)))
    
    # 종합 이상 점수
    scores["anomaly_score_statistical"] = z_scores.mean(axis=1).fillna(0)
    
    # 규칙 기반 이상 점수
    rule_score = 0
    rule_score += (df["duration_ms"] > ANOMALY_THRESHOLDS["max_session_duration_ms"]) * 0.3
    rule_score += (df["n_failures"] > ANOMALY_THRESHOLDS["max_failed_attempts"]) * 0.4
    rule_score += (df["step_jump_sum"] > 0) * 0.2
    rule_score += (df["step_reverse_sum"] > 0) * 0.1
    
    scores["anomaly_score_rules"] = rule_score
    
    # 최종 점수 (통계 + 규칙의 가중 평균)
    scores["anomaly_score_final"] = (
        0.6 * scores["anomaly_score_statistical"] + 
        0.4 * scores["anomaly_score_rules"]
    )
    
    return scores

# ---------- 전체 파이프라인 ----------
def preprocessing_pipeline(df_raw: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, Dict]:
    """전체 전처리 파이프라인 실행"""
    print(f"원본 데이터: {len(df_raw)}행, {df_raw.shape[1]}컬럼")
    
    # 1. 정규화
    df = normalize_dataframe(df_raw.copy())
    print(f"정규화 완료: {len(df)}행")
    
    # 2. 특징 추가
    df = add_time_features(df)
    df = add_ip_features(df)
    df = add_session_features(df)
    df = add_anomaly_features(df)
    df = add_categorical_encodings(df)
    print(f"특징 공학 완료: {df.shape[1]}컬럼")
    
    # 3. 세션 집계
    sessions = aggregate_sessions(df)
    print(f"세션 집계 완료: {len(sessions)}개 세션")
    
    # 4. 통계 정보
    stats_info = {
        "total_events": len(df),
        "total_sessions": len(sessions),
        "avg_events_per_session": len(df) / len(sessions),
        "success_rate": (sessions["is_successful"] == 1).mean(),
        "avg_session_duration_ms": sessions["duration_ms"].mean(),
        "anomalous_sessions_count": (sessions["anomaly_score_final"] > 1.0).sum()
    }
    
    return df, sessions, stats_info

# ---------- I/O 처리 ----------
def load_input_data(args) -> pd.DataFrame:
    """입력 데이터 로드"""
    if args.demo:
        # 내장 샘플 데이터 사용
        with open("/home/kongju/DATA/DREAM/FORMATTED/sample.txt", "r", encoding="utf-8") as f:
            records = parse_stream_to_records(f)
    elif args.input_path:
        with open(args.input_path, "r", encoding="utf-8") as f:
            records = parse_stream_to_records(f)
    else:
        # stdin
        text = sys.stdin.read()
        records = parse_stream_to_records(io.StringIO(text))
    
    return pd.DataFrame(records)

def save_outputs(df_events: pd.DataFrame, df_sessions: pd.DataFrame, 
                stats_info: Dict, output_dir: str, save_csv: bool = True):
    """결과 저장"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # 파케이 파일 저장
    events_parquet = output_path / "events_processed.parquet"
    sessions_parquet = output_path / "sessions_aggregated.parquet" 
    
    df_events.to_parquet(events_parquet, index=False)
    df_sessions.to_parquet(sessions_parquet, index=False)
    
    print(f"Parquet 저장 완료:")
    print(f"  - {events_parquet}")
    print(f"  - {sessions_parquet}")
    
    # CSV 저장 (선택사항)
    if save_csv:
        events_csv = output_path / "events_processed.csv"
        sessions_csv = output_path / "sessions_aggregated.csv"
        
        df_events.to_csv(events_csv, index=False)
        df_sessions.to_csv(sessions_csv, index=False)
        
        print(f"CSV 저장 완료:")
        print(f"  - {events_csv}")  
        print(f"  - {sessions_csv}")
    
    # 통계 정보 저장
    stats_file = output_path / "preprocessing_stats.txt"
    with open(stats_file, "w", encoding="utf-8") as f:
        f.write("=== 데이터 전처리 통계 ===\n")
        for key, value in stats_info.items():
            f.write(f"{key}: {value}\n")
        
        f.write(f"\n=== 이상 점수 분포 ===\n")
        anomaly_scores = df_sessions["anomaly_score_final"]
        f.write(f"평균: {anomaly_scores.mean():.3f}\n")
        f.write(f"표준편차: {anomaly_scores.std():.3f}\n")
        f.write(f"최소값: {anomaly_scores.min():.3f}\n")
        f.write(f"최대값: {anomaly_scores.max():.3f}\n")
        
        # 이상 세션 식별 (상위 10%)
        threshold_90 = anomaly_scores.quantile(0.9)
        anomalous_sessions = df_sessions[df_sessions["anomaly_score_final"] > threshold_90]
        f.write(f"\n상위 10% 이상 세션 ({len(anomalous_sessions)}개):\n")
        for _, session in anomalous_sessions.iterrows():
            f.write(f"  세션 {session['session_id']}: 점수 {session['anomaly_score_final']:.3f}\n")
    
    print(f"통계 정보 저장: {stats_file}")

# ---------- 메인 함수 ----------
def main():
    parser = argparse.ArgumentParser(
        description="이상 탐지를 위한 로그 데이터 전처리기",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--input", "-i", dest="input_path", 
        help="입력 로그 파일 경로 (미지정 시 stdin)"
    )
    parser.add_argument(
        "--output", "-o", dest="output_dir", default="./processed_data",
        help="출력 디렉토리 (기본: ./processed_data)"
    )
    parser.add_argument(
        "--csv", action="store_true", 
        help="CSV 파일도 함께 저장"
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="샘플 파일로 데모 실행"
    )
    
    args = parser.parse_args()
    
    try:
        # 1. 데이터 로드
        print("=== 데이터 로드 ===")
        df_raw = load_input_data(args)
        
        if df_raw.empty:
            print("오류: 입력 데이터가 비어있습니다", file=sys.stderr)
            return 1
        
        # 2. 전처리 파이프라인 실행
        print("\n=== 데이터 전처리 실행 ===")
        df_events, df_sessions, stats_info = preprocessing_pipeline(df_raw)
        
        # 3. 결과 저장
        print(f"\n=== 결과 저장 ===")
        save_outputs(df_events, df_sessions, stats_info, args.output_dir, args.csv)
        
        # 4. 요약 출력
        print(f"\n=== 처리 완료 ===")
        print(f"총 이벤트: {stats_info['total_events']:,}개")
        print(f"총 세션: {stats_info['total_sessions']:,}개") 
        print(f"성공률: {stats_info['success_rate']:.1%}")
        print(f"평균 세션 길이: {stats_info['avg_events_per_session']:.1f}개 이벤트")
        print(f"이상 세션: {stats_info['anomalous_sessions_count']:,}개")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n사용자에 의해 중단되었습니다")
        return 1
    except Exception as e:
        print(f"오류 발생: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    exit(main())
