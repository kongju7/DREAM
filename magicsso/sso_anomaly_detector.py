#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSO Anomaly Detector using Multiple Models
SSO 로그 데이터에서 다양한 이상탐지 모델 사용

Author: Kong Ju
Date: 2025-09-01
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.decomposition import PCA
from sklearn.metrics import classification_report, confusion_matrix
import warnings
warnings.filterwarnings('ignore')
from color_config import COLORS, GRAPH_COLORS, get_palette, setup_matplotlib_style
from folder_utils import get_structured_output_path
from model_config import (
    get_model_instance, get_model_info, get_file_suffix, 
    SUPPORTED_MODELS, validate_model_params
)

from sso_flow_analyzer import SSOFlowAnalyzer
from datetime import datetime, timedelta
import json
from pathlib import Path


class SSOAnomalyDetector:
    """SSO 이상탐지 클래스 - 다중 모델 지원"""
    
    def __init__(self, log_directory: str, model_name: str = 'isolation_forest', **model_params):
        """
        이상탐지 클래스 초기화
        
        Args:
            log_directory (str): 로그 파일 디렉토리
            model_name (str): 사용할 모델명 (isolation_forest, local_outlier_factor, one_class_svm, random_cut_forest)
            **model_params: 모델별 하이퍼파라미터
        """
        self.log_directory = log_directory
        self.model_name = model_name
        self.model_params = model_params
        self.analyzer = SSOFlowAnalyzer(log_directory)
        self.scaler = StandardScaler()
        self.anomaly_model = None
        self.feature_names = []
        self.df_processed = None
        self.anomaly_scores = None
        self.anomaly_labels = None
        self.file_suffix = get_file_suffix(model_name)
        
        # 모델 파라미터 유효성 검사
        is_valid, error_msg = validate_model_params(model_name, model_params)
        if not is_valid:
            raise ValueError(f"모델 파라미터 오류: {error_msg}")
        
        print(f"🤖 이상탐지 모델: {SUPPORTED_MODELS[model_name]}")
        model_info = get_model_info(model_name)
        print(f"📝 모델 설명: {model_info['description']}")
        
    def load_and_prepare_data(self):
        """데이터 로드 및 기본 준비"""
        print("📊 SSO 로그 데이터 로딩...")
        
        # 기존 분석기로 데이터 파싱
        self.analyzer.parse_log_files()
        
        # DataFrame으로 변환
        df = self.analyzer.export_to_dataframe()
        
        print(f"✅ 총 {len(df)}개의 트랜잭션 로드 완료")
        return df
    
    def engineer_features(self, df):
        """특성 엔지니어링"""
        print("🔧 특성 엔지니어링 수행...")
        
        # 기본 특성 복사
        df_features = df.copy()
        
        # 1. 시간 관련 특성
        df_features['request_timestamp'] = pd.to_datetime(df_features['request_timestamp'])
        df_features['response_timestamp'] = pd.to_datetime(df_features['response_timestamp'])
        
        # 시간 특성 추출
        df_features['hour'] = df_features['request_timestamp'].dt.hour
        df_features['minute'] = df_features['request_timestamp'].dt.minute
        df_features['day_of_week'] = df_features['request_timestamp'].dt.dayofweek
        df_features['is_weekend'] = (df_features['day_of_week'] >= 5).astype(int)
        df_features['is_business_hours'] = ((df_features['hour'] >= 9) & (df_features['hour'] <= 18)).astype(int)
        
        # 2. 트랜잭션 관련 특성
        df_features['is_complete'] = (~df_features['transaction_duration'].isna()).astype(int)
        df_features['is_success'] = (df_features['status_code'].str.contains('Success', na=False)).astype(int)
        
        # transaction_duration 결측값 처리 (완료되지 않은 트랜잭션은 매우 큰 값으로 설정)
        df_features['transaction_duration_filled'] = df_features['transaction_duration'].fillna(999.0)
        
        # 3. 로그 길이 특성 (요청 ID의 특성)
        df_features['request_id_length'] = df_features['request_id'].str.len().fillna(0)
        df_features['response_id_length'] = df_features['response_id'].str.len().fillna(0)
        
        # 4. SP 프로바이더 원핫 인코딩
        sp_dummies = pd.get_dummies(df_features['sp_provider'], prefix='sp', dummy_na=True)
        df_features = pd.concat([df_features, sp_dummies], axis=1)
        
        # 5. 로그 소스 특성
        source_dummies = pd.get_dummies(df_features['log_source'], prefix='source', dummy_na=True)
        df_features = pd.concat([df_features, source_dummies], axis=1)
        
        # 6. 시간 간격 특성 (연속 트랜잭션 간 간격)
        # NaT 값이 있는 경우를 대비하여 안전하게 처리
        df_features = df_features.sort_values('request_timestamp', na_position='last').reset_index(drop=True)
        time_diff = df_features['request_timestamp'].diff().dt.total_seconds()
        df_features['time_since_last'] = time_diff.fillna(0)
        
        # 7. 빈도 특성 (시간당 트랜잭션 수)
        # request_timestamp가 유효한 경우만 처리
        valid_timestamp_mask = df_features['request_timestamp'].notna()
        if valid_timestamp_mask.any():
            hourly_counts = df_features[valid_timestamp_mask].groupby(
                df_features[valid_timestamp_mask]['request_timestamp'].dt.floor('H')
            ).size()
            df_features['hourly_transaction_count'] = df_features['request_timestamp'].dt.floor('H').map(hourly_counts)
        else:
            df_features['hourly_transaction_count'] = 1
        df_features['hourly_transaction_count'] = df_features['hourly_transaction_count'].fillna(1)
        
        # 8. 응답 시간 관련 통계 특성
        duration_mean = df_features['transaction_duration_filled'].mean()
        duration_std = df_features['transaction_duration_filled'].std()
        if duration_std == 0 or pd.isna(duration_std):
            duration_std = 1  # 표준편차가 0인 경우 방지
        df_features['duration_z_score'] = np.abs((df_features['transaction_duration_filled'] - duration_mean) / duration_std)
        
        print(f"✅ 특성 엔지니어링 완료: {df_features.shape[1]}개 컬럼 생성")
        return df_features
    
    def select_features_for_anomaly_detection(self, df_features):
        """이상탐지를 위한 특성 선택"""
        print("🎯 이상탐지용 특성 선택...")
        
        # 수치형 특성들 선택
        numeric_features = [
            'hour', 'minute', 'day_of_week', 'is_weekend', 'is_business_hours',
            'is_complete', 'is_success', 'transaction_duration_filled',
            'request_id_length', 'response_id_length', 'time_since_last',
            'hourly_transaction_count', 'duration_z_score'
        ]
        
        # SP 프로바이더 더미 변수들
        sp_columns = [col for col in df_features.columns if col.startswith('sp_')]
        source_columns = [col for col in df_features.columns if col.startswith('source_')]
        
        # 전체 특성 리스트
        selected_features = numeric_features + sp_columns + source_columns
        
        # 실제 존재하는 컬럼만 선택
        available_features = [feat for feat in selected_features if feat in df_features.columns]
        
        # 선택된 특성들만 추출
        df_selected = df_features[available_features].copy()
        
        # 데이터 타입 확인 및 수치형으로 변환
        print("🔧 데이터 타입 확인 중...")
        for col in df_selected.columns:
            if df_selected[col].dtype == 'object' or df_selected[col].dtype == 'string':
                print(f"⚠️  {col} 컬럼이 문자열 타입입니다. 수치형으로 변환을 시도합니다.")
                try:
                    df_selected[col] = pd.to_numeric(df_selected[col], errors='coerce')
                except:
                    print(f"❌ {col} 컬럼 변환 실패. 제거합니다.")
                    df_selected = df_selected.drop(columns=[col])
                    available_features.remove(col)
        
        # 결측값 처리
        df_selected = df_selected.fillna(0)  # 남은 결측값들을 0으로 처리
        
        # 무한대값 처리
        df_selected = df_selected.replace([np.inf, -np.inf], 0)
        
        self.feature_names = available_features
        print(f"✅ {len(available_features)}개 특성 선택 완료")
        print(f"📋 최종 선택된 특성들: {available_features}")
        
        return df_selected
    
    def preprocess_data(self, df_selected):
        """데이터 전처리 및 정규화"""
        print("🔄 데이터 전처리 및 정규화 수행...")
        
        # 무한대값 및 NaN 처리
        df_processed = df_selected.replace([np.inf, -np.inf], 0)
        df_processed = df_processed.fillna(0)
        
        # 표준화 (StandardScaler)
        df_scaled = pd.DataFrame(
            self.scaler.fit_transform(df_processed),
            columns=df_processed.columns,
            index=df_processed.index
        )
        
        print(f"✅ 전처리 완료: {df_scaled.shape}")
        print(f"📊 특성 통계:")
        print(df_scaled.describe())
        
        return df_scaled
    
    def train_anomaly_model(self, df_scaled):
        """이상탐지 모델 훈련 (다중 모델 지원)"""
        model_name = SUPPORTED_MODELS[self.model_name]
        print(f"🤖 {model_name} 모델 훈련 중...")
        
        try:
            # 데이터 형태 확인
            print(f"   📊 데이터 형태: {df_scaled.shape}")
            print(f"   📊 데이터 타입: {df_scaled.dtypes.unique()}")
            
            # 모델 인스턴스 생성
            self.anomaly_model = get_model_instance(self.model_name, **self.model_params)
            
            # 모델별 훈련 방식
            if self.model_name == 'local_outlier_factor':
                # LOF는 fit과 predict가 동시에 수행됨
                self.anomaly_labels = self.anomaly_model.fit_predict(df_scaled)
                # LOF의 이상치 점수 계산 (음수이므로 부호 반전)
                self.anomaly_scores = -self.anomaly_model.negative_outlier_factor_
                
            elif self.model_name == 'one_class_svm':
                # One-Class SVM 특별 처리
                self.anomaly_model.fit(df_scaled)
                self.anomaly_labels = self.anomaly_model.predict(df_scaled)
                # One-Class SVM의 decision_function은 부호가 반대 (높을수록 정상)
                raw_scores = self.anomaly_model.decision_function(df_scaled)
                # 점수를 반전시켜 낮을수록 이상치가 되도록 조정
                self.anomaly_scores = -raw_scores
                
            elif self.model_name == 'random_cut_forest':
                # Random Cut Forest 특별 처리
                # 데이터를 numpy array로 변환
                X_array = df_scaled.values if hasattr(df_scaled, 'values') else df_scaled
                self.anomaly_model.fit(X_array)
                self.anomaly_labels = self.anomaly_model.predict(X_array)
                self.anomaly_scores = self.anomaly_model.decision_function(X_array)
                
            else:
                # Isolation Forest 등 기본 패턴
                self.anomaly_model.fit(df_scaled)
                self.anomaly_labels = self.anomaly_model.predict(df_scaled)
                # Isolation Forest: 낮을수록 이상치
                self.anomaly_scores = -self.anomaly_model.decision_function(df_scaled)
            
            # 이상치 개수 계산
            n_anomalies = np.sum(self.anomaly_labels == -1)
            n_normal = np.sum(self.anomaly_labels == 1)
            
            print(f"✅ {model_name} 모델 훈련 완료!")
            print(f"📊 탐지 결과:")
            print(f"   정상 트랜잭션: {n_normal}개 ({n_normal/len(df_scaled)*100:.1f}%)")
            print(f"   이상 트랜잭션: {n_anomalies}개 ({n_anomalies/len(df_scaled)*100:.1f}%)")
            print(f"   이상치 점수 범위: {self.anomaly_scores.min():.3f} ~ {self.anomaly_scores.max():.3f}")
            
            return self.anomaly_labels, self.anomaly_scores
            
        except Exception as e:
            print(f"❌ {model_name} 모델 훈련 실패: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def analyze_anomalies(self, df_original, df_scaled):
        """이상치 분석"""
        print("🔍 이상치 상세 분석...")
        
        # 결과를 원본 데이터에 추가
        df_analysis = df_original.copy()
        df_analysis['anomaly_label'] = self.anomaly_labels
        df_analysis['anomaly_score'] = self.anomaly_scores
        df_analysis['is_anomaly'] = (self.anomaly_labels == -1)
        
        # 이상치만 추출
        anomalies = df_analysis[df_analysis['is_anomaly']].copy()
        
        print(f"🚨 발견된 이상 트랜잭션들:")
        print("-" * 80)
        
        for idx, anomaly in anomalies.iterrows():
            print(f"\n이상치 #{idx + 1}:")
            print(f"  🔄 요청 ID: {anomaly['request_id']}")
            print(f"  📅 시간: {anomaly['request_timestamp']}")
            print(f"  🏢 SP: {anomaly['sp_provider']}")
            print(f"  ⏱️  응답시간: {anomaly['transaction_duration']:.3f}초" if pd.notna(anomaly['transaction_duration']) else "  ⏱️  응답시간: 미완료")
            
            # is_complete 컬럼이 있는지 확인
            if 'is_complete' in anomaly.index:
                print(f"  ✅ 상태: {'완료' if anomaly['is_complete'] else '미완료'}")
            else:
                # transaction_duration으로 완료 여부 판단
                is_complete = pd.notna(anomaly['transaction_duration'])
                print(f"  ✅ 상태: {'완료' if is_complete else '미완료'}")
                
            print(f"  📊 이상점수: {anomaly['anomaly_score']:.3f}")
        
        # 이상치 특성 분석
        print(f"\n📈 이상치 특성 분석:")
        print("-" * 50)
        
        if len(anomalies) > 0:
            # SP별 이상치 분포
            sp_anomaly_counts = anomalies['sp_provider'].value_counts()
            print(f"SP별 이상치 분포:")
            for sp, count in sp_anomaly_counts.items():
                print(f"  {sp}: {count}개")
            
            # 시간대별 이상치 분포 (유효한 타임스탬프만)
            valid_timestamps = anomalies['request_timestamp'].notna()
            if valid_timestamps.any():
                anomalies_with_time = anomalies[valid_timestamps].copy()
                anomalies_with_time['hour'] = pd.to_datetime(anomalies_with_time['request_timestamp']).dt.hour
                hour_anomaly_counts = anomalies_with_time['hour'].value_counts().sort_index()
                print(f"\n시간대별 이상치 분포:")
                for hour, count in hour_anomaly_counts.items():
                    print(f"  {hour:02d}시: {count}개")
            else:
                print(f"\n시간대별 이상치 분포: 유효한 타임스탬프가 없습니다.")
        
        self.df_processed = df_analysis
        return df_analysis, anomalies
    
    def create_visualizations(self, df_analysis, output_dir=None):
        """시각화 생성"""
        if not output_dir:
            output_dir = self.log_directory
        
        print("📊 이상탐지 시각화 생성...")
        
        # 공통 색상 스타일 적용
        setup_matplotlib_style()
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        
        # 1. 이상치 분포 (파이차트)
        if 'is_anomaly' in df_analysis.columns:
            anomaly_counts = df_analysis['is_anomaly'].fillna(False).value_counts()
            
            # 데이터 검증
            if len(anomaly_counts) > 0:
                # 값과 라벨 매핑 생성
                labels = []
                values = []
                colors = []
                
                for idx, count in anomaly_counts.items():
                    if idx == True:  # 이상치
                        labels.append('Anomaly')
                        colors.append(GRAPH_COLORS['anomaly_data'])
                    else:  # 정상
                        labels.append('Normal')
                        colors.append(GRAPH_COLORS['normal_data'])
                    values.append(count)
                
                axes[0,0].pie(values, labels=labels, autopct='%1.1f%%', colors=colors)
                axes[0,0].set_title('Anomaly Distribution')
            else:
                axes[0,0].text(0.5, 0.5, 'No Data', transform=axes[0,0].transAxes, 
                             ha='center', va='center', fontsize=12)
                axes[0,0].set_title('Anomaly Distribution (No Data)')
        else:
            axes[0,0].text(0.5, 0.5, 'No Anomaly Data', transform=axes[0,0].transAxes, 
                         ha='center', va='center', fontsize=12)
            axes[0,0].set_title('Anomaly Distribution (No Data)')
        
        # 2. 이상치 점수 분포
        if 'anomaly_score' in df_analysis.columns:
            scores = df_analysis['anomaly_score'].dropna()
            
            if len(scores) > 0:
                axes[0,1].hist(scores, bins=50, alpha=0.7, color=COLORS['primary'])
                
                # 이상치 임계값 표시 (가능한 경우)
                if 'is_anomaly' in df_analysis.columns:
                    anomaly_scores = df_analysis[df_analysis['is_anomaly'] == True]['anomaly_score'].dropna()
                    if len(anomaly_scores) > 0:
                        threshold = anomaly_scores.min()  # 이상치 중 최소값을 임계값으로
                        axes[0,1].axvline(threshold, color=COLORS['anomaly'], 
                                        linestyle='--', label='Anomaly Threshold')
                        axes[0,1].legend()
                
                axes[0,1].set_xlabel('Anomaly Score')
                axes[0,1].set_ylabel('Frequency')
                axes[0,1].set_title('Anomaly Score Distribution')
            else:
                axes[0,1].text(0.5, 0.5, 'No Score Data', transform=axes[0,1].transAxes, 
                             ha='center', va='center', fontsize=12)
                axes[0,1].set_title('Anomaly Score Distribution (No Data)')
        else:
            axes[0,1].text(0.5, 0.5, 'No Score Column', transform=axes[0,1].transAxes, 
                         ha='center', va='center', fontsize=12)
            axes[0,1].set_title('Anomaly Score Distribution (No Data)')
        
        # 3. 응답시간 vs 이상치
        if 'is_anomaly' in df_analysis.columns:
            normal_data = df_analysis[df_analysis['is_anomaly'] == False]
            anomaly_data = df_analysis[df_analysis['is_anomaly'] == True]
            
            plot_data = False
            
            # 응답시간 컬럼 확인
            duration_col = None
            if 'transaction_duration_filled' in df_analysis.columns:
                duration_col = 'transaction_duration_filled'
            elif 'transaction_duration' in df_analysis.columns:
                duration_col = 'transaction_duration'
            
            if duration_col is not None:
                if len(normal_data) > 0:
                    normal_times = normal_data[duration_col].fillna(999)
                    if len(normal_times) > 0:
                        axes[0,2].scatter(range(len(normal_times)), normal_times,
                                        alpha=0.6, label='Normal', s=20, color=GRAPH_COLORS['normal_data'])
                        plot_data = True
                
                if len(anomaly_data) > 0:
                    anomaly_times = anomaly_data[duration_col].fillna(999)
                    if len(anomaly_times) > 0:
                        x_offset = len(normal_data) if len(normal_data) > 0 else 0
                        axes[0,2].scatter(range(x_offset, x_offset + len(anomaly_times)), anomaly_times,
                                        alpha=0.8, label='Anomaly', s=50, color=GRAPH_COLORS['anomaly_data'])
                        plot_data = True
            
            if plot_data:
                axes[0,2].set_xlabel('Transaction Index')
                axes[0,2].set_ylabel('Response Time (seconds)')
                axes[0,2].set_title('Response Time vs Anomalies')
                axes[0,2].legend()
                try:
                    axes[0,2].set_yscale('log')
                except:
                    pass  # 로그 스케일 설정 실패 시 무시
            else:
                axes[0,2].text(0.5, 0.5, 'No Duration Data', transform=axes[0,2].transAxes, 
                             ha='center', va='center', fontsize=12)
                axes[0,2].set_title('Response Time vs Anomalies (No Data)')
        else:
            axes[0,2].text(0.5, 0.5, 'No Anomaly Data', transform=axes[0,2].transAxes, 
                         ha='center', va='center', fontsize=12)
            axes[0,2].set_title('Response Time vs Anomalies (No Data)')
        
        # 4. SP별 이상치 분포
        if 'sp_provider' in df_analysis.columns and 'is_anomaly' in df_analysis.columns:
            try:
                # NaN 제거 후 그룹화
                df_clean = df_analysis.dropna(subset=['sp_provider', 'is_anomaly'])
                
                if len(df_clean) > 0:
                    sp_anomaly = df_clean.groupby('sp_provider')['is_anomaly'].agg(['sum', 'count'])
                    sp_anomaly['normal'] = sp_anomaly['count'] - sp_anomaly['sum']
                    
                    if len(sp_anomaly) > 0:
                        sp_names = sp_anomaly.index.tolist()
                        x_pos = np.arange(len(sp_names))
                        
                        # 데이터 길이 확인
                        if len(sp_names) == len(sp_anomaly['normal']) == len(sp_anomaly['sum']):
                            axes[1,0].bar(x_pos - 0.2, sp_anomaly['normal'], 0.4, 
                                        label='Normal', color=GRAPH_COLORS['normal_data'])
                            axes[1,0].bar(x_pos + 0.2, sp_anomaly['sum'], 0.4, 
                                        label='Anomaly', color=GRAPH_COLORS['anomaly_data'])
                            axes[1,0].set_xlabel('Service Provider')
                            axes[1,0].set_ylabel('Count')
                            axes[1,0].set_title('Anomalies by Service Provider')
                            axes[1,0].set_xticks(x_pos)
                            axes[1,0].set_xticklabels(sp_names, rotation=45)
                            axes[1,0].legend()
                        else:
                            axes[1,0].text(0.5, 0.5, 'Data Length Mismatch', transform=axes[1,0].transAxes, 
                                         ha='center', va='center', fontsize=12)
                            axes[1,0].set_title('Anomalies by Service Provider (Error)')
                    else:
                        axes[1,0].text(0.5, 0.5, 'No SP Groups', transform=axes[1,0].transAxes, 
                                     ha='center', va='center', fontsize=12)
                        axes[1,0].set_title('Anomalies by Service Provider (No Groups)')
                else:
                    axes[1,0].text(0.5, 0.5, 'No Clean Data', transform=axes[1,0].transAxes, 
                                 ha='center', va='center', fontsize=12)
                    axes[1,0].set_title('Anomalies by Service Provider (No Data)')
                    
            except Exception as e:
                print(f"⚠️ SP별 분포 차트 생성 실패: {e}")
                axes[1,0].text(0.5, 0.5, 'Chart Error', transform=axes[1,0].transAxes, 
                             ha='center', va='center', fontsize=12)
                axes[1,0].set_title('Anomalies by Service Provider (Error)')
        else:
            axes[1,0].text(0.5, 0.5, 'No SP or Anomaly Data', transform=axes[1,0].transAxes, 
                         ha='center', va='center', fontsize=12)
            axes[1,0].set_title('Anomalies by Service Provider (No Data)')
        
        # 5. 시간대별 이상치 분포
        if 'request_timestamp' in df_analysis.columns and 'is_anomaly' in df_analysis.columns:
            try:
                # 유효한 타임스탬프가 있는 경우만 처리
                valid_timestamp_mask = df_analysis['request_timestamp'].notna()
                
                if valid_timestamp_mask.any():
                    df_with_valid_time = df_analysis[valid_timestamp_mask].copy()
                    df_with_valid_time['hour'] = pd.to_datetime(df_with_valid_time['request_timestamp'], errors='coerce').dt.hour
                    
                    # NaN 시간 제거
                    df_with_valid_time = df_with_valid_time.dropna(subset=['hour', 'is_anomaly'])
                    
                    if len(df_with_valid_time) > 0:
                        hourly_anomaly = df_with_valid_time.groupby('hour')['is_anomaly'].agg(['sum', 'count'])
                        hourly_anomaly['rate'] = hourly_anomaly['sum'] / hourly_anomaly['count'] * 100
                        
                        if len(hourly_anomaly) > 0:
                            hours = hourly_anomaly.index.tolist()
                            rates = hourly_anomaly['rate'].tolist()
                            
                            # 데이터 길이 확인
                            if len(hours) == len(rates):
                                axes[1,1].bar(hours, rates, color=COLORS['primary'], alpha=0.7)
                                axes[1,1].set_xlabel('Hour of Day')
                                axes[1,1].set_ylabel('Anomaly Rate (%)')
                                axes[1,1].set_title('Anomaly Rate by Hour')
                                axes[1,1].grid(True, alpha=0.3)
                            else:
                                axes[1,1].text(0.5, 0.5, 'Data Length Mismatch', transform=axes[1,1].transAxes, 
                                             ha='center', va='center', fontsize=12)
                                axes[1,1].set_title('Anomaly Rate by Hour (Error)')
                        else:
                            axes[1,1].text(0.5, 0.5, 'No hourly data', transform=axes[1,1].transAxes, 
                                         ha='center', va='center', fontsize=12)
                            axes[1,1].set_title('Anomaly Rate by Hour (No Groups)')
                    else:
                        axes[1,1].text(0.5, 0.5, 'No valid time data', transform=axes[1,1].transAxes, 
                                     ha='center', va='center', fontsize=12)
                        axes[1,1].set_title('Anomaly Rate by Hour (No Data)')
                else:
                    axes[1,1].text(0.5, 0.5, 'No valid timestamps', transform=axes[1,1].transAxes, 
                                 ha='center', va='center', fontsize=12)
                    axes[1,1].set_title('Anomaly Rate by Hour (No Data)')
                    
            except Exception as e:
                print(f"⚠️ 시간대별 분포 차트 생성 실패: {e}")
                axes[1,1].text(0.5, 0.5, 'Chart Error', transform=axes[1,1].transAxes, 
                             ha='center', va='center', fontsize=12)
                axes[1,1].set_title('Anomaly Rate by Hour (Error)')
        else:
            axes[1,1].text(0.5, 0.5, 'No timestamp or anomaly data', transform=axes[1,1].transAxes, 
                         ha='center', va='center', fontsize=12)
            axes[1,1].set_title('Anomaly Rate by Hour (No Data)')
        
        # 6. 특성 중요도 (이상치 vs 정상 비교)
        if hasattr(self, 'feature_names') and len(self.feature_names) > 0 and 'is_anomaly' in df_analysis.columns:
            try:
                # 수치형 특성들만 선택
                numeric_features = ['transaction_duration_filled', 'hour', 'minute', 'time_since_last', 'hourly_transaction_count']
                available_numeric = [f for f in numeric_features if f in df_analysis.columns]
                
                if available_numeric:
                    feature_importance = []
                    
                    # 정상과 이상치 데이터 분리
                    normal_data = df_analysis[df_analysis['is_anomaly'] == False]
                    anomaly_data = df_analysis[df_analysis['is_anomaly'] == True]
                    
                    if len(normal_data) > 0 and len(anomaly_data) > 0:
                        for feature in available_numeric[:6]:  # 상위 6개만
                            try:
                                normal_mean = normal_data[feature].dropna().mean()
                                anomaly_mean = anomaly_data[feature].dropna().mean()
                                
                                # NaN 체크
                                if not pd.isna(normal_mean) and not pd.isna(anomaly_mean):
                                    importance = abs(anomaly_mean - normal_mean) / (abs(normal_mean) + 1e-8)
                                    feature_importance.append((feature, importance))
                                    
                            except Exception as e:
                                print(f"⚠️ 특성 {feature} 중요도 계산 실패: {e}")
                                continue
                        
                        if feature_importance:
                            feature_importance.sort(key=lambda x: x[1], reverse=True)
                            features, importances = zip(*feature_importance)
                            
                            # 데이터 길이 확인
                            if len(features) == len(importances) and len(features) > 0:
                                y_pos = range(len(features))
                                axes[1,2].barh(y_pos, importances, color=COLORS['accent'])
                                axes[1,2].set_yticks(y_pos)
                                axes[1,2].set_yticklabels(features)
                                axes[1,2].set_xlabel('Feature Difference (Anomaly vs Normal)')
                                axes[1,2].set_title('Feature Importance for Anomaly Detection')
                            else:
                                axes[1,2].text(0.5, 0.5, 'Data Length Mismatch', transform=axes[1,2].transAxes, 
                                             ha='center', va='center', fontsize=12)
                                axes[1,2].set_title('Feature Importance (Error)')
                        else:
                            axes[1,2].text(0.5, 0.5, 'No Valid Features', transform=axes[1,2].transAxes, 
                                         ha='center', va='center', fontsize=12)
                            axes[1,2].set_title('Feature Importance (No Valid Data)')
                    else:
                        axes[1,2].text(0.5, 0.5, 'Insufficient Data', transform=axes[1,2].transAxes, 
                                     ha='center', va='center', fontsize=12)
                        axes[1,2].set_title('Feature Importance (Insufficient Data)')
                else:
                    axes[1,2].text(0.5, 0.5, 'No Numeric Features', transform=axes[1,2].transAxes, 
                                 ha='center', va='center', fontsize=12)
                    axes[1,2].set_title('Feature Importance (No Features)')
                    
            except Exception as e:
                print(f"⚠️ 특성 중요도 차트 생성 실패: {e}")
                axes[1,2].text(0.5, 0.5, 'Chart Error', transform=axes[1,2].transAxes, 
                             ha='center', va='center', fontsize=12)
                axes[1,2].set_title('Feature Importance (Error)')
        else:
            axes[1,2].text(0.5, 0.5, 'No Feature Names', transform=axes[1,2].transAxes, 
                         ha='center', va='center', fontsize=12)
            axes[1,2].set_title('Feature Importance (No Data)')
        
        plt.tight_layout()
        # 모델별 시각화 파일명
        viz_filename = f'sso_anomaly_{self.file_suffix}_analysis.png'
        output_path = Path(output_dir) / viz_filename
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"📈 시각화 차트가 {viz_filename}에 저장되었습니다.")
        
    def export_results(self, df_analysis, anomalies, output_dir=None):
        """결과 내보내기 (구조화된 폴더에 저장)"""
        # 구조화된 출력 디렉토리 생성
        if not output_dir:
            data_dir = str(Path(self.log_directory).parent)  # DATA 디렉토리
            output_dir = get_structured_output_path(data_dir, "anomaly", self.model_name)
        
        print(f"💾 이상탐지 결과 저장 중... ({self.model_name})")
        
        # 모델별 파일명 생성 (폴더 내에서는 간단한 이름 사용)
        base_name = "sso_anomaly_results"
        detected_name = "sso_anomaly_detected"
        
        # 1. 전체 결과 CSV
        results_path = Path(output_dir) / f"{base_name}.csv"
        df_analysis.to_csv(results_path, index=False, encoding='utf-8')
        print(f"   📄 전체 결과: {results_path}")
        
        # 2. 이상치만 별도 CSV
        detected_path = Path(output_dir) / f"{detected_name}.csv"
        anomalies.to_csv(detected_path, index=False, encoding='utf-8')
        print(f"   🚨 이상치 결과: {detected_path}")
        
        # 3. 요약 통계 JSON
        model_info = get_model_info(self.model_name)
        summary = {
            "탐지_요약": {
                "모델명": SUPPORTED_MODELS[self.model_name],
                "모델_타입": self.model_name,
                "모델_설명": model_info['description'],
                "총_트랜잭션수": len(df_analysis),
                "정상_트랜잭션수": int((df_analysis['anomaly_label'] == 1).fillna(False).sum()),
                "이상_트랜잭션수": int((df_analysis['anomaly_label'] == -1).fillna(False).sum()),
                "이상치_비율": float((df_analysis['anomaly_label'] == -1).fillna(False).mean() * 100)
            },
            "SP별_이상치_분포": anomalies['sp_provider'].fillna('Unknown').value_counts().to_dict() if 'sp_provider' in anomalies.columns else {},
            "시간대별_이상치_분포": (
                anomalies[anomalies['request_timestamp'].notna()]
                .groupby(pd.to_datetime(anomalies[anomalies['request_timestamp'].notna()]['request_timestamp']).dt.hour)
                .size().to_dict() 
                if 'request_timestamp' in anomalies.columns and anomalies['request_timestamp'].notna().any() 
                else {}
            ),
            "모델_파라미터": {
                "algorithm": SUPPORTED_MODELS[self.model_name],
                "model_type": self.model_name,
                "parameters": self.model_params,
                "features_used": len(self.feature_names),
                "feature_names": self.feature_names
            },
            "모델_성능": model_info
        }
        
        # 3. 요약 통계 JSON
        summary_file = Path(output_dir) / "sso_anomaly_summary.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2, default=str)
        
        print(f"✅ 결과 저장 완료:")
        print(f"   📊 전체 결과: {results_path}")
        print(f"   🚨 이상치 목록: {detected_path}") 
        print(f"   📋 요약 통계: {summary_file}")
    
    def run_full_analysis(self):
        """전체 이상탐지 분석 실행"""
        model_name = SUPPORTED_MODELS[self.model_name]
        print(f"🚀 SSO {model_name} 이상탐지 분석 시작")
        print("=" * 60)
        
        # 출력 경로 설정 (구조화된 폴더 사용)
        data_dir = "/home/kongju/DEV/dream/DATA"
        output_dir = get_structured_output_path(data_dir, "anomaly", self.model_name)
        
        # 1. 데이터 로드
        df = self.load_and_prepare_data()
        
        # 2. 특성 엔지니어링
        df_features = self.engineer_features(df)
        
        # 3. 특성 선택
        df_selected = self.select_features_for_anomaly_detection(df_features)
        
        # 4. 전처리
        df_scaled = self.preprocess_data(df_selected)
        
        # 5. 이상탐지 모델 훈련
        anomaly_labels, anomaly_scores = self.train_anomaly_model(df_scaled)
        
        # 6. 이상치 분석
        df_analysis, anomalies = self.analyze_anomalies(df, df_scaled)
        
        # 7. 시각화
        self.create_visualizations(df_analysis, output_dir)
        
        # 8. 결과 저장
        self.export_results(df_analysis, anomalies, output_dir)
        
        print(f"\n🎉 {model_name} 이상탐지 분석 완료!")
        return df_analysis, anomalies


def test_single_model(model_name, **model_params):
    """단일 모델 테스트"""
    print(f"🧪 {SUPPORTED_MODELS[model_name]} 단독 테스트")
    print("=" * 50)
    
    logs_dir = "/home/kongju/DEV/dream/DATA/LOGS"
    
    try:
        print(f"1️⃣ 모델 인스턴스 생성 중...")
        detector = SSOAnomalyDetector(logs_dir, model_name, **model_params)
        print(f"   ✅ 인스턴스 생성 성공")
        
        print(f"2️⃣ 데이터 로드 중...")
        df = detector.load_and_prepare_data()
        print(f"   ✅ 데이터 로드 성공: {len(df)}개 트랜잭션")
        
        print(f"3️⃣ 특성 엔지니어링 중...")
        df_features = detector.engineer_features(df)
        print(f"   ✅ 특성 엔지니어링 성공: {df_features.shape[1]}개 특성")
        
        print(f"4️⃣ 특성 선택 중...")
        df_selected = detector.select_features_for_anomaly_detection(df_features)
        print(f"   ✅ 특성 선택 성공: {df_selected.shape[1]}개 특성")
        
        print(f"5️⃣ 데이터 전처리 중...")
        df_scaled = detector.preprocess_data(df_selected)
        print(f"   ✅ 전처리 성공: {df_scaled.shape}")
        
        print(f"6️⃣ 모델 훈련 중...")
        anomaly_labels, anomaly_scores = detector.train_anomaly_model(df_scaled)
        print(f"   ✅ 모델 훈련 성공")
        
        print(f"7️⃣ 전체 분석 실행 중...")
        df_results, anomalies = detector.run_full_analysis()
        print(f"   ✅ 전체 분석 성공")
        
        return True, len(df_results), len(anomalies)
        
    except Exception as e:
        import traceback
        print(f"   ❌ 테스트 실패: {e}")
        print("   🔍 상세 오류:")
        traceback.print_exc()
        return False, 0, 0


def run_model_comparison():
    """여러 모델로 이상탐지 성능 비교"""
    print("🔬 다중 모델 이상탐지 성능 비교")
    print("=" * 70)
    
    logs_dir = "/home/kongju/DEV/dream/DATA/LOGS"
    results = {}
    
    for model_name in SUPPORTED_MODELS.keys():
        print(f"\n🤖 {SUPPORTED_MODELS[model_name]} 실행 중...")
        try:
            detector = SSOAnomalyDetector(logs_dir, model_name, contamination=0.1)
            df_results, anomalies = detector.run_full_analysis()
            
            results[model_name] = {
                'model': SUPPORTED_MODELS[model_name],
                'total': len(df_results),
                'anomalies': len(anomalies),
                'ratio': len(anomalies)/len(df_results)*100,
                'file_suffix': get_file_suffix(model_name)
            }
            print(f"   ✅ {SUPPORTED_MODELS[model_name]} 완료")
        except Exception as e:
            import traceback
            print(f"   ❌ {SUPPORTED_MODELS[model_name]} 실패: {e}")
            print(f"   🔍 상세 오류:")
            traceback.print_exc()
    
    print(f"\n📊 모델별 비교 결과:")
    print("=" * 70)
    for model_name, result in results.items():
        print(f"🤖 {result['model']}:")
        print(f"   📊 전체 트랜잭션: {result['total']}개")
        print(f"   🚨 탐지된 이상치: {result['anomalies']}개")
        print(f"   📈 이상치 비율: {result['ratio']:.2f}%")
        print(f"   📁 파일 접미사: {result['file_suffix']}")
        print()


def main():
    """메인 실행 함수"""
    print("🔍 SSO 다중 모델 이상탐지 시스템")
    print("=" * 70)
    
    # 지원 모델 목록 출력
    print("🤖 지원하는 이상탐지 모델:")
    for key, name in SUPPORTED_MODELS.items():
        print(f"   - {name} ({key})")
    
    # 기본 모델로 단일 실행
    print(f"\n🚀 기본 모델(Isolation Forest) 실행:")
    print("=" * 50)
    
    logs_dir = "/home/kongju/DEV/dream/DATA/LOGS"
    
    # 기본 Isolation Forest 실행
    detector = SSOAnomalyDetector(logs_dir, 'isolation_forest', contamination=0.1)
    df_results, anomalies = detector.run_full_analysis()
    
    print(f"\n📊 최종 요약:")
    print(f"   🔍 분석된 트랜잭션: {len(df_results)}개")
    print(f"   🚨 탐지된 이상치: {len(anomalies)}개")
    print(f"   📈 이상치 비율: {len(anomalies)/len(df_results)*100:.2f}%")
    
    if len(anomalies) > 0:
        print(f"\n🎯 주요 이상 패턴:")
        
        # 가장 이상한 트랜잭션 (가장 낮은 anomaly score)
        worst_anomaly = anomalies.loc[anomalies['anomaly_score'].idxmin()]
        print(f"   🔴 가장 의심스러운 트랜잭션:")
        print(f"      ID: {worst_anomaly['request_id']}")
        print(f"      시간: {worst_anomaly['request_timestamp']}")
        print(f"      점수: {worst_anomaly['anomaly_score']:.3f}")
    
    # 모든 모델 비교 실행 여부 확인
    print(f"\n💡 전체 모델 비교를 실행하려면 run_model_comparison() 함수를 호출하세요.")


if __name__ == "__main__":
    import sys
    
    # 커맨드라인 인자 처리
    if len(sys.argv) > 1:
        if sys.argv[1] == 'compare':
            run_model_comparison()
        elif sys.argv[1] == 'test' and len(sys.argv) > 2:
            # 특정 모델 테스트: python sso_anomaly_detector.py test one_class_svm
            model_name = sys.argv[2]
            if model_name in SUPPORTED_MODELS:
                test_single_model(model_name, contamination=0.1)
            else:
                print(f"❌ 지원하지 않는 모델: {model_name}")
                print(f"✅ 지원 모델: {list(SUPPORTED_MODELS.keys())}")
        elif sys.argv[1] in SUPPORTED_MODELS:
            # 특정 모델로 바로 실행: python sso_anomaly_detector.py one_class_svm
            model_name = sys.argv[1]
            logs_dir = "/home/kongju/DEV/dream/DATA/LOGS"
            detector = SSOAnomalyDetector(logs_dir, model_name, contamination=0.1)
            df_results, anomalies = detector.run_full_analysis()
            print(f"\n📊 최종 요약:")
            print(f"   🔍 분석된 트랜잭션: {len(df_results)}개")
            print(f"   🚨 탐지된 이상치: {len(anomalies)}개")
            print(f"   📈 이상치 비율: {len(anomalies)/len(df_results)*100:.2f}%")
        else:
            print(f"❌ 알 수 없는 명령: {sys.argv[1]}")
            print("사용법:")
            print("  python sso_anomaly_detector.py                    # 기본 실행")
            print("  python sso_anomaly_detector.py compare            # 모든 모델 비교")
            print("  python sso_anomaly_detector.py test <model_name>  # 특정 모델 테스트")
            print("  python sso_anomaly_detector.py <model_name>       # 특정 모델 실행")
            print(f"지원 모델: {list(SUPPORTED_MODELS.keys())}")
    else:
        main()
