#!/usr/bin/env python3
"""
이상 탐지 전처리기 사용 예시

다양한 사용 시나리오를 보여주는 예시 스크립트
"""

import pandas as pd
from pathlib import Path
import subprocess
import sys

def example_basic_usage():
    """기본 사용법"""
    print("=== 기본 사용법 ===")
    
    # 샘플 파일로 실행
    cmd = [
        sys.executable, 
        "anomaly_detection_preprocessor.py",
        "--input", "/home/kongju/DATA/DREAM/FORMATTED/sample.txt",
        "--output", "./analysis_results",
        "--csv"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"실행 결과: {result.returncode}")
    print(result.stdout)

def example_programmatic_usage():
    """프로그래밍 방식으로 사용"""
    print("\n=== 프로그래밍 방식 사용 ===")
    
    # 결과 파일 로드
    events_file = "processed_data/events_processed.csv"
    sessions_file = "processed_data/sessions_aggregated.csv"
    
    if Path(events_file).exists() and Path(sessions_file).exists():
        # 데이터 로드
        events_df = pd.read_csv(events_file)
        sessions_df = pd.read_csv(sessions_file)
        
        print(f"이벤트 데이터: {len(events_df)}행 x {len(events_df.columns)}컬럼")
        print(f"세션 데이터: {len(sessions_df)}행 x {len(sessions_df.columns)}컬럼")
        
        # 이상 세션 분석
        anomaly_threshold = sessions_df['anomaly_score_final'].quantile(0.8)
        anomalous_sessions = sessions_df[
            sessions_df['anomaly_score_final'] > anomaly_threshold
        ]
        
        print(f"\n이상 점수 상위 20% 세션 ({len(anomalous_sessions)}개):")
        for _, session in anomalous_sessions.iterrows():
            success = "성공" if session['is_successful'] else "실패"
            print(f"  세션 {session['session_id']}: "
                  f"점수 {session['anomaly_score_final']:.3f} ({success})")
        
        # 주요 이상 패턴 분석
        print(f"\n주요 이상 패턴:")
        pattern_counts = {
            "step_jump": (events_df['step_jump'] > 0).sum(),
            "delta_too_fast": (events_df['delta_too_fast'] > 0).sum(), 
            "delta_too_slow": (events_df['delta_too_slow'] > 0).sum(),
            "error_keywords": (events_df['has_error_keyword'] > 0).sum(),
            "step_mismatches": (events_df['step_event_mismatch'] > 0).sum()
        }
        
        for pattern, count in pattern_counts.items():
            if count > 0:
                print(f"  {pattern}: {count}개 발견")
    
    else:
        print("처리된 데이터가 없습니다. 먼저 전처리를 실행하세요.")

def example_custom_analysis():
    """커스텀 분석 예시"""
    print("\n=== 커스텀 분석 예시 ===")
    
    sessions_file = "processed_data/sessions_aggregated.csv"
    if Path(sessions_file).exists():
        sessions_df = pd.read_csv(sessions_file)
        
        # 성공률 분석
        success_rate = sessions_df['is_successful'].mean()
        print(f"전체 성공률: {success_rate:.1%}")
        
        # 세션 길이 분석
        avg_duration = sessions_df['duration_ms'].mean()
        print(f"평균 세션 시간: {avg_duration:.0f}ms")
        
        # 시간대별 패턴 분석
        hour_analysis = sessions_df.groupby('start_hour').agg({
            'is_successful': 'mean',
            'anomaly_score_final': 'mean',
            'session_id': 'count'
        }).round(3)
        
        print(f"\n시간대별 분석:")
        print(hour_analysis)
        
        # 실패 세션 심층 분석
        failed_sessions = sessions_df[sessions_df['is_successful'] == 0]
        if len(failed_sessions) > 0:
            print(f"\n실패 세션 분석:")
            print(f"  실패 세션 수: {len(failed_sessions)}개")
            print(f"  평균 이상 점수: {failed_sessions['anomaly_score_final'].mean():.3f}")
            print(f"  평균 실패 이벤트 수: {failed_sessions['n_failures'].mean():.1f}개")

if __name__ == "__main__":
    # 예시 실행
    try:
        example_basic_usage()
        example_programmatic_usage() 
        example_custom_analysis()
        
        print(f"\n=== 분석 완료 ===")
        print("상세 결과는 processed_data/ 폴더를 확인하세요.")
        
    except Exception as e:
        print(f"오류 발생: {e}")
