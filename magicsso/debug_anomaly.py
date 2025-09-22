#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSO 이상탐지 디버깅 스크립트
"""

import pandas as pd
import numpy as np
from sso_flow_analyzer import SSOFlowAnalyzer

def debug_feature_engineering():
    """특성 엔지니어링 단계별 디버깅"""
    print("🔍 SSO 이상탐지 디버깅 시작")
    print("=" * 50)
    
    # 1. 데이터 로드
    print("1️⃣ 데이터 로드 중...")
    analyzer = SSOFlowAnalyzer("/home/kongju/DEV/dream/DATA/LOGS")
    analyzer.parse_log_files()
    df = analyzer.export_to_dataframe()
    
    print(f"✅ 로드된 데이터: {df.shape}")
    print("📋 컬럼 목록:")
    for i, col in enumerate(df.columns):
        print(f"   {i+1:2d}. {col}")
    
    print(f"\n📊 transaction_duration 컬럼 상태:")
    print(f"   전체 행 수: {len(df)}")
    print(f"   결측값 수: {df['transaction_duration'].isna().sum()}")
    print(f"   유효값 수: {df['transaction_duration'].notna().sum()}")
    
    # 2. 특성 엔지니어링 테스트
    print(f"\n2️⃣ 특성 엔지니어링 테스트...")
    
    # 기본 특성 복사
    df_features = df.copy()
    
    # 시간 관련 특성
    try:
        df_features['request_timestamp'] = pd.to_datetime(df_features['request_timestamp'])
        df_features['response_timestamp'] = pd.to_datetime(df_features['response_timestamp'])
        print("✅ 시간 변환 성공")
    except Exception as e:
        print(f"❌ 시간 변환 실패: {e}")
        return
    
    # 시간 특성 추출
    try:
        df_features['hour'] = df_features['request_timestamp'].dt.hour
        df_features['minute'] = df_features['request_timestamp'].dt.minute
        df_features['day_of_week'] = df_features['request_timestamp'].dt.dayofweek
        df_features['is_weekend'] = (df_features['day_of_week'] >= 5).astype(int)
        df_features['is_business_hours'] = ((df_features['hour'] >= 9) & (df_features['hour'] <= 18)).astype(int)
        print("✅ 시간 특성 추출 성공")
    except Exception as e:
        print(f"❌ 시간 특성 추출 실패: {e}")
        return
    
    # 트랜잭션 관련 특성
    try:
        df_features['is_complete'] = (~df_features['transaction_duration'].isna()).astype(int)
        df_features['is_success'] = (df_features['status_code'].str.contains('Success', na=False)).astype(int)
        print("✅ 트랜잭션 특성 생성 성공")
        print(f"   is_complete 분포: {df_features['is_complete'].value_counts().to_dict()}")
        print(f"   is_success 분포: {df_features['is_success'].value_counts().to_dict()}")
    except Exception as e:
        print(f"❌ 트랜잭션 특성 생성 실패: {e}")
        return
    
    # transaction_duration 결측값 처리
    try:
        df_features['transaction_duration_filled'] = df_features['transaction_duration'].fillna(999.0)
        print("✅ transaction_duration 결측값 처리 성공")
    except Exception as e:
        print(f"❌ transaction_duration 결측값 처리 실패: {e}")
        return
    
    # 3. 특성 선택 테스트
    print(f"\n3️⃣ 특성 선택 테스트...")
    
    # 수치형 특성들 선택
    numeric_features = [
        'hour', 'minute', 'day_of_week', 'is_weekend', 'is_business_hours',
        'is_complete', 'is_success', 'transaction_duration_filled'
    ]
    
    print("🎯 선택하려는 특성들:")
    for feature in numeric_features:
        if feature in df_features.columns:
            print(f"   ✅ {feature}: 존재")
        else:
            print(f"   ❌ {feature}: 없음")
    
    # 실제 존재하는 특성들만 선택
    available_features = [feat for feat in numeric_features if feat in df_features.columns]
    print(f"\n📋 사용 가능한 특성들: {available_features}")
    
    try:
        df_selected = df_features[available_features].copy()
        print(f"✅ 특성 선택 성공: {df_selected.shape}")
        
        # 데이터 타입 확인
        print(f"\n📊 데이터 타입 확인:")
        for col in df_selected.columns:
            dtype = df_selected[col].dtype
            print(f"   {col}: {dtype}")
            
        # 결측값 확인
        print(f"\n📊 결측값 확인:")
        for col in df_selected.columns:
            null_count = df_selected[col].isna().sum()
            print(f"   {col}: {null_count}개")
            
    except Exception as e:
        print(f"❌ 특성 선택 실패: {e}")
        return
    
    print(f"\n🎉 디버깅 완료! 모든 단계가 성공했습니다.")
    return df_selected

if __name__ == "__main__":
    result = debug_feature_engineering()
    if result is not None:
        print(f"\n✨ 최종 결과:")
        print(f"   모양: {result.shape}")
        print(f"   컬럼들: {list(result.columns)}")
