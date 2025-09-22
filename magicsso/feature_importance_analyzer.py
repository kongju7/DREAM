#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSO Feature Importance Analyzer
다중 이상탐지 모델의 특성 중요도 분석

Author: Kong Ju
Date: 2025-09-01
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.inspection import permutation_importance
from sklearn.metrics import roc_auc_score
import warnings
warnings.filterwarnings('ignore')
from color_config import COLORS, GRAPH_COLORS, get_palette, setup_matplotlib_style
from folder_utils import get_structured_output_path
from model_config import (
    get_model_instance, get_model_info, get_file_suffix,
    SUPPORTED_MODELS, validate_model_params
)

from sso_flow_analyzer import SSOFlowAnalyzer
from pathlib import Path
import json


class FeatureImportanceAnalyzer:
    """다중 모델 특성 중요도 분석기"""
    
    def __init__(self, log_directory: str, model_name: str = 'isolation_forest', **model_params):
        """
        특성 중요도 분석기 초기화
        
        Args:
            log_directory (str): 로그 파일 디렉토리
            model_name (str): 사용할 모델명
            **model_params: 모델별 하이퍼파라미터
        """
        self.log_directory = log_directory
        self.model_name = model_name
        self.model_params = model_params
        self.analyzer = SSOFlowAnalyzer(log_directory)
        self.scaler = StandardScaler()
        self.anomaly_model = None
        self.feature_names = []
        self.df_scaled = None
        self.anomaly_labels = None
        self.anomaly_scores = None
        self.file_suffix = get_file_suffix(model_name)
        
        # 모델 파라미터 유효성 검사
        is_valid, error_msg = validate_model_params(model_name, model_params)
        if not is_valid:
            raise ValueError(f"모델 파라미터 오류: {error_msg}")
        
        print(f"🔍 특성 중요도 분석 모델: {SUPPORTED_MODELS[model_name]}")
        model_info = get_model_info(model_name)
        print(f"📝 모델 설명: {model_info['description']}")
        
    def load_existing_results(self):
        """기존 이상탐지 결과 로드"""
        try:
            # 모델별 구조화된 폴더에서 결과 파일 로드
            data_dir = str(Path(self.log_directory).parent)  # DATA 폴더 경로
            anomaly_dir = get_structured_output_path(data_dir, "anomaly", self.model_name)
            results_path = Path(anomaly_dir) / "sso_anomaly_results.csv"
            
            if results_path.exists():
                df_results = pd.read_csv(results_path)
                print(f"✅ 기존 {SUPPORTED_MODELS[self.model_name]} 결과 로드: {len(df_results)}개 트랜잭션")
                print(f"📂 로드 경로: {results_path}")
                return df_results
            else:
                print(f"❌ 기존 결과 파일이 없습니다: {results_path}")
                print("새로 분석을 실행하세요.")
                return None
        except Exception as e:
            print(f"❌ 결과 로드 실패: {e}")
            return None
    
    def prepare_data_for_analysis(self):
        """분석용 데이터 준비"""
        print("🔧 분석용 데이터 준비 중...")
        
        # 1. 원본 데이터 로드
        self.analyzer.parse_log_files()
        df = self.analyzer.export_to_dataframe()
        
        # 2. 특성 엔지니어링
        df_features = self._engineer_features(df)
        
        # 3. 특성 선택
        df_selected = self._select_features(df_features)
        
        # 4. 전처리
        self.df_scaled = self._preprocess_data(df_selected)
        
        return df, df_features, self.df_scaled
    
    def _engineer_features(self, df):
        """특성 엔지니어링"""
        df_features = df.copy()
        
        # 시간 특성
        df_features['request_timestamp'] = pd.to_datetime(df_features['request_timestamp'])
        df_features['response_timestamp'] = pd.to_datetime(df_features['response_timestamp'])
        
        df_features['hour'] = df_features['request_timestamp'].dt.hour
        df_features['minute'] = df_features['request_timestamp'].dt.minute
        df_features['day_of_week'] = df_features['request_timestamp'].dt.dayofweek
        df_features['is_weekend'] = (df_features['day_of_week'] >= 5).astype(int)
        df_features['is_business_hours'] = ((df_features['hour'] >= 9) & (df_features['hour'] <= 18)).astype(int)
        
        # 트랜잭션 특성
        df_features['is_complete'] = (~df_features['transaction_duration'].isna()).astype(int)
        df_features['is_success'] = (df_features['status_code'].str.contains('Success', na=False)).astype(int)
        df_features['transaction_duration_filled'] = df_features['transaction_duration'].fillna(999.0)
        
        # 길이 특성
        df_features['request_id_length'] = df_features['request_id'].str.len().fillna(0)
        df_features['response_id_length'] = df_features['response_id'].str.len().fillna(0)
        
        # SP 프로바이더 원핫 인코딩
        sp_dummies = pd.get_dummies(df_features['sp_provider'], prefix='sp', dummy_na=True)
        df_features = pd.concat([df_features, sp_dummies], axis=1)
        
        # 시간 간격 특성
        df_features = df_features.sort_values('request_timestamp', na_position='last').reset_index(drop=True)
        time_diff = df_features['request_timestamp'].diff().dt.total_seconds()
        df_features['time_since_last'] = time_diff.fillna(0)
        
        # 빈도 특성
        valid_timestamp_mask = df_features['request_timestamp'].notna()
        if valid_timestamp_mask.any():
            hourly_counts = df_features[valid_timestamp_mask].groupby(
                df_features[valid_timestamp_mask]['request_timestamp'].dt.floor('H')
            ).size()
            df_features['hourly_transaction_count'] = df_features['request_timestamp'].dt.floor('H').map(hourly_counts)
        else:
            df_features['hourly_transaction_count'] = 1
        df_features['hourly_transaction_count'] = df_features['hourly_transaction_count'].fillna(1)
        
        # Z-score 특성
        duration_mean = df_features['transaction_duration_filled'].mean()
        duration_std = df_features['transaction_duration_filled'].std()
        if duration_std == 0 or pd.isna(duration_std):
            duration_std = 1
        df_features['duration_z_score'] = np.abs((df_features['transaction_duration_filled'] - duration_mean) / duration_std)
        
        return df_features
    
    def _select_features(self, df_features):
        """특성 선택"""
        numeric_features = [
            'hour', 'minute', 'day_of_week', 'is_weekend', 'is_business_hours',
            'is_complete', 'is_success', 'transaction_duration_filled',
            'request_id_length', 'response_id_length', 'time_since_last',
            'hourly_transaction_count', 'duration_z_score'
        ]
        
        sp_columns = [col for col in df_features.columns if col.startswith('sp_')]
        selected_features = numeric_features + sp_columns
        available_features = [feat for feat in selected_features if feat in df_features.columns]
        
        df_selected = df_features[available_features].copy()
        
        # 데이터 타입 변환
        for col in df_selected.columns:
            if df_selected[col].dtype == 'object':
                df_selected[col] = pd.to_numeric(df_selected[col], errors='coerce')
        
        df_selected = df_selected.fillna(0).replace([np.inf, -np.inf], 0)
        
        # feature_names를 실제 DataFrame의 컬럼명으로 설정 (문자열로 강제 변환)
        self.feature_names = [str(col) for col in df_selected.columns]
        
        print(f"🔍 최종 선택된 특성들: {self.feature_names[:10]}...")  # 디버깅용
        print(f"🔍 df_selected.columns: {list(df_selected.columns)[:10]}...")  # 컬럼 확인
        print(f"🔍 df_selected.columns.dtype: {df_selected.columns.dtype}")  # 컬럼 타입 확인
        
        return df_selected
    
    def _preprocess_data(self, df_selected):
        """데이터 전처리"""
        df_scaled = pd.DataFrame(
            self.scaler.fit_transform(df_selected),
            columns=df_selected.columns,
            index=df_selected.index
        )
        return df_scaled
    
    def train_anomaly_model(self):
        """이상탐지 모델 훈련 (다중 모델 지원)"""
        model_name = SUPPORTED_MODELS[self.model_name]
        print(f"🤖 {model_name} 모델 훈련 중...")
        
        # 디버깅 정보
        print(f"🔍 df_scaled shape: {self.df_scaled.shape}")
        print(f"🔍 df_scaled columns: {list(self.df_scaled.columns)}")
        print(f"🔍 feature_names: {self.feature_names}")
        print(f"🔍 feature_names type: {type(self.feature_names[0]) if self.feature_names else 'empty'}")
        
        # 모델 인스턴스 생성
        self.anomaly_model = get_model_instance(self.model_name, **self.model_params)
        
        # 모델별 훈련 방식
        if self.model_name == 'local_outlier_factor':
            # LOF는 fit과 predict가 동시에 수행됨
            self.anomaly_labels = self.anomaly_model.fit_predict(self.df_scaled)
            # LOF의 이상치 점수 계산 (음수이므로 부호 반전)
            self.anomaly_scores = -self.anomaly_model.negative_outlier_factor_
        else:
            # 다른 모델들은 일반적인 fit-predict 패턴
            self.anomaly_model.fit(self.df_scaled)
            self.anomaly_labels = self.anomaly_model.predict(self.df_scaled)
            
            # One-Class SVM은 점수 반전 필요
            if self.model_name == 'one_class_svm':
                self.anomaly_scores = -self.anomaly_model.decision_function(self.df_scaled)
            else:
                self.anomaly_scores = self.anomaly_model.decision_function(self.df_scaled)
        
        n_anomalies = np.sum(self.anomaly_labels == -1)
        print(f"✅ 훈련 완료! 이상치 {n_anomalies}개 탐지")
        
    def calculate_statistical_importance(self):
        """통계적 특성 중요도 계산"""
        print("📊 통계적 특성 중요도 계산 중...")
        
        # 디버깅 정보 출력
        print(f"🔍 DataFrame 형태: {self.df_scaled.shape}")
        print(f"🔍 DataFrame 컬럼: {list(self.df_scaled.columns)[:10]}...")  # 첫 10개만
        print(f"🔍 feature_names: {self.feature_names[:10]}...")  # 첫 10개만
        print(f"🔍 anomaly_labels 형태: {self.anomaly_labels.shape if hasattr(self.anomaly_labels, 'shape') else len(self.anomaly_labels)}")
        
        importance_scores = []
        
        for i in range(len(self.df_scaled.columns)):
            try:
                # 인덱스 기반으로 안전하게 접근
                feature_name = self.df_scaled.columns[i]
                
                # 인덱스 정렬하여 안전하게 접근
                df_reset = self.df_scaled.reset_index(drop=True)
                labels_reset = pd.Series(self.anomaly_labels).reset_index(drop=True)
                
                # 정상과 이상치 그룹 분리
                normal_mask = labels_reset == 1
                anomaly_mask = labels_reset == -1
                
                # loc을 사용해서 boolean mask로 안전하게 접근
                normal_data = df_reset.loc[normal_mask, feature_name]
                anomaly_data = df_reset.loc[anomaly_mask, feature_name]
                
                if len(anomaly_data) > 0 and len(normal_data) > 0:
                    # 평균 차이
                    mean_diff = abs(normal_data.mean() - anomaly_data.mean())
                    
                    # 표준편차 비율
                    std_ratio = anomaly_data.std() / (normal_data.std() + 1e-8)
                    
                    # 분포 분리도 (Cohen's d)
                    pooled_std = np.sqrt(((len(normal_data) - 1) * normal_data.var() + 
                                         (len(anomaly_data) - 1) * anomaly_data.var()) / 
                                        (len(normal_data) + len(anomaly_data) - 2))
                    cohens_d = mean_diff / (pooled_std + 1e-8)
                    
                    # 종합 점수
                    importance = mean_diff * (1 + abs(1 - std_ratio)) * cohens_d
                else:
                    mean_diff = 0
                    std_ratio = 1
                    cohens_d = 0
                    importance = 0
                
                importance_scores.append({
                    'feature': feature_name,
                    'importance': importance,
                    'mean_diff': mean_diff if len(anomaly_data) > 0 else 0,
                    'std_ratio': std_ratio if len(anomaly_data) > 0 else 1,
                    'cohens_d': cohens_d if len(anomaly_data) > 0 else 0
                })
                
            except Exception as e:
                print(f"⚠️ Feature index {i} ({self.df_scaled.columns[i] if i < len(self.df_scaled.columns) else 'unknown'}) 처리 중 오류: {e}")
                continue
        
        print(f"🔍 importance_scores 개수: {len(importance_scores)}")
        
        if len(importance_scores) == 0:
            print("⚠️ 통계적 중요도 점수가 계산되지 않았습니다. 빈 DataFrame을 반환합니다.")
            return pd.DataFrame(columns=['feature', 'importance', 'mean_diff', 'std_ratio', 'cohens_d'])
        
        importance_df = pd.DataFrame(importance_scores)
        
        print(f"🔍 importance_df 형태: {importance_df.shape}")
        print(f"🔍 importance_df 컬럼: {importance_df.columns.tolist()}")
        if len(importance_df) > 0:
            print(f"🔍 importance_df 미리보기:\n{importance_df.head()}")
        
        importance_df = importance_df.sort_values('importance', ascending=False)
        
        print("✅ 통계적 중요도 계산 완료")
        return importance_df
    
    def calculate_permutation_importance(self):
        """Permutation Importance 계산 (모델별 지원)"""
        print(f"🔄 {SUPPORTED_MODELS[self.model_name]} Permutation Importance 계산 중...")
        
        # LOF는 permutation importance를 지원하지 않음 (fit_predict 방식)
        if self.model_name == 'local_outlier_factor':
            print("⚠️ LOF는 Permutation Importance를 지원하지 않습니다.")
            return None
        
        # 이상치 레이블을 이진 분류로 변환 (-1 -> 1, 1 -> 0)
        # self.df_scaled와 인덱스를 맞춤
        y_binary = (self.anomaly_labels == -1).astype(int)
        
        # 인덱스 정렬 및 길이 확인
        if len(y_binary) != len(self.df_scaled):
            print(f"⚠️ 길이 불일치: y_binary={len(y_binary)}, df_scaled={len(self.df_scaled)}")
            min_len = min(len(y_binary), len(self.df_scaled))
            y_binary = y_binary[:min_len]
            df_for_perm = self.df_scaled.iloc[:min_len].reset_index(drop=True)
        else:
            df_for_perm = self.df_scaled.reset_index(drop=True)
        
        # y_binary도 reset_index
        y_binary = pd.Series(y_binary).reset_index(drop=True)
        
        # 모델별 커스텀 스코어링 함수
        def anomaly_score_func(model, X, y):
            try:
                if hasattr(model, 'decision_function'):
                    scores = model.decision_function(X)
                    # 모델별 점수 해석 방식 조정
                    if self.model_name == 'one_class_svm':
                        # One-Class SVM: 높을수록 정상이므로 음수 취함
                        return -scores.mean()
                    else:
                        # Isolation Forest, Random Cut Forest: 낮을수록 이상
                        return -scores.mean()
                else:
                    # decision_function이 없는 경우 기본 점수 반환
                    return 0.5
            except Exception as e:
                print(f"⚠️ 스코어링 함수 오류: {e}")
                return 0.0
        
        try:
            # numpy array로 변환하여 인덱스 문제 해결
            X_array = df_for_perm.values
            y_array = y_binary.values
            
            perm_importance = permutation_importance(
                self.anomaly_model, 
                X_array,  # numpy array 사용
                y_array,  # numpy array 사용
                scoring=anomaly_score_func,
                n_repeats=5,  # 다중 모델 지원으로 반복 횟수 줄임
                random_state=42,
                n_jobs=-1
            )
            
            # 길이 확인 및 안전한 DataFrame 생성
            actual_feature_names = list(self.df_scaled.columns)
            n_features = len(actual_feature_names)
            n_importances = len(perm_importance.importances_mean)
            
            if n_features != n_importances:
                print(f"⚠️ 특성 개수 불일치: features={n_features}, importances={n_importances}")
                min_len = min(n_features, n_importances)
                feature_names_adj = actual_feature_names[:min_len]
                importances_mean_adj = perm_importance.importances_mean[:min_len]
                importances_std_adj = perm_importance.importances_std[:min_len]
            else:
                feature_names_adj = actual_feature_names
                importances_mean_adj = perm_importance.importances_mean
                importances_std_adj = perm_importance.importances_std
            
            perm_df = pd.DataFrame({
                'feature': feature_names_adj,
                'importance_mean': importances_mean_adj,
                'importance_std': importances_std_adj
            }).sort_values('importance_mean', ascending=False)
            
            print("✅ Permutation Importance 계산 완료")
            return perm_df
        
        except Exception as e:
            print(f"❌ Permutation Importance 계산 실패: {e}")
            return None
    
    def calculate_isolation_path_importance(self):
        """Isolation Path 기반 중요도 계산"""
        print("🌳 Isolation Path 중요도 계산 중...")
        
        # 각 특성에 대해 isolation path의 기여도 계산
        feature_contributions = []
        
        for i in range(len(self.df_scaled.columns)):
            try:
                # 인덱스 기반으로 안전하게 접근
                feature_name = self.df_scaled.columns[i]
                
                # 해당 특성의 값이 극단적인 경우들을 찾음
                feature_values = self.df_scaled.iloc[:, i]
                
                # 상위/하위 10%의 극단값들
                upper_threshold = feature_values.quantile(0.9)
                lower_threshold = feature_values.quantile(0.1)
                
                extreme_mask = (feature_values >= upper_threshold) | (feature_values <= lower_threshold)
                
                # 인덱스를 맞춰서 안전하게 접근
                labels_reset = pd.Series(self.anomaly_labels).reset_index(drop=True)
                if len(extreme_mask) == len(labels_reset):
                    extreme_anomaly_rate = (labels_reset[extreme_mask] == -1).mean() if extreme_mask.any() else 0
                else:
                    # 길이가 맞지 않으면 기본값 사용
                    extreme_anomaly_rate = 0
                
                # 전체 이상치 비율
                overall_anomaly_rate = (self.anomaly_labels == -1).mean()
                
                # 기여도 = 극단값에서의 이상치 비율 - 전체 이상치 비율
                contribution = extreme_anomaly_rate - overall_anomaly_rate
                
                feature_contributions.append({
                    'feature': feature_name,
                    'contribution': contribution,
                    'extreme_anomaly_rate': extreme_anomaly_rate,
                    'overall_anomaly_rate': overall_anomaly_rate
                })
                
            except Exception as e:
                print(f"⚠️ Feature index {i} ({self.df_scaled.columns[i] if i < len(self.df_scaled.columns) else 'unknown'}) path importance 계산 중 오류: {e}")
                continue
        
        contrib_df = pd.DataFrame(feature_contributions)
        contrib_df = contrib_df.sort_values('contribution', ascending=False)
        
        print("✅ Isolation Path 중요도 계산 완료")
        return contrib_df
    
    def create_importance_visualizations(self, stat_importance, perm_importance, path_importance, output_dir=None):
        """특성 중요도 시각화"""
        print("📊 특성 중요도 시각화 생성 중...")
        
        if not output_dir:
            # 모델별 구조화된 폴더에 저장
            data_dir = str(Path(self.log_directory).parent)  # DATA 폴더 경로
            output_dir = get_structured_output_path(data_dir, "feature_importance", self.model_name)
        
        # 공통 색상 스타일 적용
        setup_matplotlib_style()
        
        # 서브플롯 개수 결정
        n_plots = 3 if perm_importance is not None else 2
        fig, axes = plt.subplots(1, n_plots, figsize=(6*n_plots, 8))
        
        if n_plots == 2:
            axes = [axes[0], axes[1]]
        
        # 1. 통계적 중요도
        top_stat = stat_importance.head(15)
        
        # 데이터 검증 및 안전장치
        if len(top_stat) > 0 and 'importance' in top_stat.columns and 'feature' in top_stat.columns:
            # NaN 제거
            top_stat_clean = top_stat.dropna(subset=['importance', 'feature'])
            
            if len(top_stat_clean) > 0:
                y_pos = range(len(top_stat_clean))
                axes[0].barh(y_pos, top_stat_clean['importance'], color=COLORS['primary'])
                axes[0].set_yticks(y_pos)
                axes[0].set_yticklabels(top_stat_clean['feature'], fontsize=10)
                axes[0].set_xlabel('Statistical Importance')
                axes[0].set_title('Statistical Feature Importance\n(Mean Difference × Cohen\'s D)')
                axes[0].invert_yaxis()
            else:
                axes[0].text(0.5, 0.5, 'No Valid Data', transform=axes[0].transAxes, 
                           ha='center', va='center', fontsize=12)
                axes[0].set_title('Statistical Feature Importance\n(No Data)')
        else:
            axes[0].text(0.5, 0.5, 'No Statistical Data', transform=axes[0].transAxes, 
                       ha='center', va='center', fontsize=12)
            axes[0].set_title('Statistical Feature Importance\n(No Data)')
        
        # 2. Isolation Path 중요도
        top_path = path_importance.head(15)
        
        # 데이터 검증 및 안전장치
        if len(top_path) > 0 and 'contribution' in top_path.columns and 'feature' in top_path.columns:
            # NaN 제거
            top_path_clean = top_path.dropna(subset=['contribution', 'feature'])
            
            if len(top_path_clean) > 0:
                colors = [COLORS['anomaly'] if x > 0 else COLORS['normal'] for x in top_path_clean['contribution']]
                y_pos = range(len(top_path_clean))
                axes[1].barh(y_pos, top_path_clean['contribution'], color=colors)
                axes[1].set_yticks(y_pos)
                axes[1].set_yticklabels(top_path_clean['feature'], fontsize=10)
                axes[1].set_xlabel('Isolation Path Contribution')
                axes[1].set_title('Isolation Path Feature Importance\n(Extreme Value Anomaly Rate)')
                axes[1].invert_yaxis()
                axes[1].axvline(x=0, color='black', linestyle='--', alpha=0.5)
            else:
                axes[1].text(0.5, 0.5, 'No Valid Data', transform=axes[1].transAxes, 
                           ha='center', va='center', fontsize=12)
                axes[1].set_title('Isolation Path Feature Importance\n(No Data)')
        else:
            axes[1].text(0.5, 0.5, 'No Path Data', transform=axes[1].transAxes, 
                       ha='center', va='center', fontsize=12)
            axes[1].set_title('Isolation Path Feature Importance\n(No Data)')
        
        # 3. Permutation Importance (가능한 경우)
        if perm_importance is not None and n_plots == 3:
            top_perm = perm_importance.head(15)
            
            # 데이터 검증 및 안전장치
            if len(top_perm) > 0 and 'importance_mean' in top_perm.columns and 'feature' in top_perm.columns:
                # NaN 제거
                top_perm_clean = top_perm.dropna(subset=['importance_mean', 'feature'])
                
                if len(top_perm_clean) > 0:
                    y_pos = range(len(top_perm_clean))
                    xerr = top_perm_clean['importance_std'] if 'importance_std' in top_perm_clean.columns else None
                    axes[2].barh(y_pos, top_perm_clean['importance_mean'], 
                                xerr=xerr, color=COLORS['secondary'])
                    axes[2].set_yticks(y_pos)
                    axes[2].set_yticklabels(top_perm_clean['feature'], fontsize=10)
                    axes[2].set_xlabel('Permutation Importance')
                    axes[2].set_title('Permutation Feature Importance\n(with Standard Deviation)')
                    axes[2].invert_yaxis()
                else:
                    axes[2].text(0.5, 0.5, 'No Valid Data', transform=axes[2].transAxes, 
                               ha='center', va='center', fontsize=12)
                    axes[2].set_title('Permutation Feature Importance\n(No Data)')
            else:
                axes[2].text(0.5, 0.5, 'No Permutation Data', transform=axes[2].transAxes, 
                           ha='center', va='center', fontsize=12)
                axes[2].set_title('Permutation Feature Importance\n(No Data)')
        
        plt.tight_layout()
        viz_filename = 'feature_importance_analysis.png'
        output_path = Path(output_dir) / viz_filename
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"📈 시각화가 {output_dir}/{viz_filename}에 저장되었습니다.")
    
    def create_feature_distribution_plots(self, output_dir=None):
        """특성별 분포 비교 플롯"""
        print("📊 특성별 분포 비교 플롯 생성 중...")
        
        if not output_dir:
            # 모델별 구조화된 폴더에 저장
            data_dir = str(Path(self.log_directory).parent)  # DATA 폴더 경로
            output_dir = get_structured_output_path(data_dir, "feature_importance", self.model_name)
        
        # 상위 중요 특성들 선택
        stat_importance = self.calculate_statistical_importance()
        
        # 데이터 검증
        if len(stat_importance) == 0 or 'feature' not in stat_importance.columns:
            print("⚠️ 통계적 중요도 데이터가 없어 분포 플롯을 생성할 수 없습니다.")
            return
        
        top_features = stat_importance.head(9)['feature'].tolist()
        
        # 최소 1개의 특성이 있는지 확인
        if len(top_features) == 0:
            print("⚠️ 분석할 특성이 없어 분포 플롯을 생성할 수 없습니다.")
            return
        
        fig, axes = plt.subplots(3, 3, figsize=(15, 12))
        axes = axes.flatten()
        
        plot_count = 0
        for i, feature in enumerate(top_features):
            if i >= 9:
                break
                
            try:
                # 특성이 존재하는지 확인하고 인덱스 찾기
                if feature not in self.df_scaled.columns:
                    axes[i].text(0.5, 0.5, f'Feature\n{feature}\nNot Found', 
                               transform=axes[i].transAxes, ha='center', va='center')
                    axes[i].set_title(f'{feature} (Missing)', fontsize=10)
                    continue
                
                # 안전한 방식으로 데이터 분리
                df_reset = self.df_scaled.reset_index(drop=True)
                labels_reset = pd.Series(self.anomaly_labels).reset_index(drop=True)
                
                normal_mask = labels_reset == 1
                anomaly_mask = labels_reset == -1
                
                normal_data = df_reset.loc[normal_mask, feature].dropna()
                anomaly_data = df_reset.loc[anomaly_mask, feature].dropna()
                
                # 데이터가 있는지 확인
                if len(normal_data) == 0 and len(anomaly_data) == 0:
                    axes[i].text(0.5, 0.5, 'No Data', transform=axes[i].transAxes, 
                               ha='center', va='center')
                    axes[i].set_title(f'{feature} (No Data)', fontsize=10)
                    continue
                
                # 히스토그램
                if len(normal_data) > 0:
                    axes[i].hist(normal_data, alpha=0.7, label='Normal', bins=20, 
                               color=GRAPH_COLORS['normal_data'], density=True)
                if len(anomaly_data) > 0:
                    axes[i].hist(anomaly_data, alpha=0.7, label='Anomaly', bins=20, 
                               color=GRAPH_COLORS['anomaly_data'], density=True)
                
                axes[i].set_title(f'{feature}', fontsize=10)
                axes[i].set_xlabel('Normalized Value')
                axes[i].set_ylabel('Density')
                axes[i].legend()
                axes[i].grid(True, alpha=0.3)
                plot_count += 1
                
            except Exception as e:
                print(f"⚠️ 특성 {feature} 플롯 생성 실패: {e}")
                axes[i].text(0.5, 0.5, f'Error\n{feature}', transform=axes[i].transAxes, 
                           ha='center', va='center')
                axes[i].set_title(f'{feature} (Error)', fontsize=10)
        
        # 빈 서브플롯 숨기기
        for i in range(len(top_features), 9):
            axes[i].set_visible(False)
        
        plt.tight_layout()
        dist_filename = 'feature_importance_distributions.png'
        output_path = Path(output_dir) / dist_filename
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"📈 분포 비교 플롯이 {output_dir}/{dist_filename}에 저장되었습니다.")
    
    def export_importance_results(self, stat_importance, perm_importance, path_importance, output_dir=None):
        """중요도 분석 결과 저장"""
        print("💾 특성 중요도 결과 저장 중...")
        
        if not output_dir:
            # 모델별 구조화된 폴더에 저장
            data_dir = str(Path(self.log_directory).parent)  # DATA 폴더 경로
            output_dir = get_structured_output_path(data_dir, "feature_importance", self.model_name)
        
        # JSON 형태로 저장
        results = {
            "statistical_importance": stat_importance.to_dict('records'),
            "path_importance": path_importance.to_dict('records'),
            "analysis_summary": {
                "total_features": len(self.feature_names),
                "total_transactions": len(self.df_scaled),
                "anomaly_count": int((self.anomaly_labels == -1).sum()),
                "anomaly_rate": float((self.anomaly_labels == -1).mean()),
                "top_3_statistical": stat_importance.head(3)['feature'].tolist(),
                "top_3_path": path_importance.head(3)['feature'].tolist()
            }
        }
        
        if perm_importance is not None:
            results["permutation_importance"] = perm_importance.to_dict('records')
            results["analysis_summary"]["top_3_permutation"] = perm_importance.head(3)['feature'].tolist()
        
        # 간단한 파일명 (모델별 폴더로 구분되므로 파일명에서 모델명 제거)
        # JSON 저장
        json_filename = "feature_importance_results.json"
        output_path = Path(output_dir) / json_filename
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        # CSV 저장
        stat_filename = "feature_importance_statistical.csv"
        path_filename = "feature_importance_path.csv"
        
        stat_importance.to_csv(Path(output_dir) / stat_filename, index=False)
        path_importance.to_csv(Path(output_dir) / path_filename, index=False)
        
        if perm_importance is not None:
            perm_filename = "feature_importance_permutation.csv"
            perm_importance.to_csv(Path(output_dir) / perm_filename, index=False)
        
        print(f"✅ {SUPPORTED_MODELS[self.model_name]} 특성 중요도 결과 저장:")
        print(f"   📂 저장 경로: {output_dir}")
        print(f"   📊 종합 결과: {json_filename}")
        print(f"   📋 통계적 중요도: {stat_filename}")
        print(f"   🌳 Path 중요도: {path_filename}")
        if perm_importance is not None:
            print(f"   🔄 Permutation 중요도: {perm_filename}")
    
    def print_importance_summary(self, stat_importance, perm_importance, path_importance):
        """중요도 분석 요약 출력"""
        print("\n" + "="*80)
        print("🎯 특성 중요도 분석 요약")
        print("="*80)
        
        print(f"\n📊 통계적 중요도 Top 10:")
        print("-" * 50)
        for i, row in stat_importance.head(10).iterrows():
            print(f"{row['feature']:30s} | {row['importance']:8.4f} | Cohen's d: {row['cohens_d']:6.3f}")
        
        print(f"\n🌳 Isolation Path 중요도 Top 10:")
        print("-" * 50)
        for i, row in path_importance.head(10).iterrows():
            contribution = row['contribution']
            direction = "↑" if contribution > 0 else "↓"
            print(f"{row['feature']:30s} | {contribution:8.4f} {direction} | Rate: {row['extreme_anomaly_rate']:6.3f}")
        
        if perm_importance is not None:
            print(f"\n🔄 Permutation 중요도 Top 10:")
            print("-" * 50)
            for i, row in perm_importance.head(10).iterrows():
                print(f"{row['feature']:30s} | {row['importance_mean']:8.4f} ± {row['importance_std']:6.4f}")
        
        # 종합 순위
        print(f"\n🏆 종합 중요도 Top 5:")
        print("-" * 50)
        
        # 각 방법별 상위 특성들의 평균 순위 계산
        all_features = set(stat_importance['feature']) | set(path_importance['feature'])
        if perm_importance is not None:
            all_features |= set(perm_importance['feature'])
        
        feature_ranks = {}
        for feature in all_features:
            ranks = []
            
            # 통계적 중요도 순위
            stat_rank = stat_importance[stat_importance['feature'] == feature].index[0] + 1 if feature in stat_importance['feature'].values else len(stat_importance) + 1
            ranks.append(stat_rank)
            
            # Path 중요도 순위
            path_rank = path_importance[path_importance['feature'] == feature].index[0] + 1 if feature in path_importance['feature'].values else len(path_importance) + 1
            ranks.append(path_rank)
            
            # Permutation 중요도 순위 (있는 경우)
            if perm_importance is not None:
                perm_rank = perm_importance[perm_importance['feature'] == feature].index[0] + 1 if feature in perm_importance['feature'].values else len(perm_importance) + 1
                ranks.append(perm_rank)
            
            feature_ranks[feature] = np.mean(ranks)
        
        # 평균 순위로 정렬
        sorted_features = sorted(feature_ranks.items(), key=lambda x: x[1])
        
        for i, (feature, avg_rank) in enumerate(sorted_features[:5]):
            print(f"{i+1}. {feature:30s} | 평균 순위: {avg_rank:6.2f}")
    
    def run_full_analysis(self):
        """전체 특성 중요도 분석 실행"""
        print("🚀 SSO 특성 중요도 분석 시작")
        print("=" * 70)
        
        # 모델별 구조화된 출력 경로 설정
        data_dir = str(Path(self.log_directory).parent)  # DATA 폴더 경로
        output_dir = get_structured_output_path(data_dir, "feature_importance", self.model_name)
        
        # 1. 데이터 준비
        df_original, df_features, df_scaled = self.prepare_data_for_analysis()
        
        # 2. 이상탐지 모델 훈련
        self.train_anomaly_model()
        
        # 3. 통계적 중요도 계산
        stat_importance = self.calculate_statistical_importance()
        
        # 4. Permutation Importance 계산
        perm_importance = self.calculate_permutation_importance()
        
        # 5. Isolation Path 중요도 계산
        path_importance = self.calculate_isolation_path_importance()
        
        # 6. 시각화 생성
        self.create_importance_visualizations(stat_importance, perm_importance, path_importance, output_dir)
        self.create_feature_distribution_plots(output_dir)
        
        # 7. 결과 저장
        self.export_importance_results(stat_importance, perm_importance, path_importance, output_dir)
        
        # 8. 요약 출력
        self.print_importance_summary(stat_importance, perm_importance, path_importance)
        
        print("\n🎉 특성 중요도 분석 완료!")
        return stat_importance, perm_importance, path_importance


def run_all_models_analysis():
    """모든 모델에 대해 특성 중요도 분석 실행"""
    print("🎯 모든 모델 특성 중요도 분석")
    print("=" * 70)
    
    logs_dir = "/home/kongju/DEV/dream/DATA/LOGS"
    results = {}
    
    for model_name in SUPPORTED_MODELS.keys():
        print(f"\n🤖 {SUPPORTED_MODELS[model_name]} 특성 중요도 분석")
        print("-" * 50)
        
        try:
            analyzer = FeatureImportanceAnalyzer(logs_dir, model_name, contamination=0.1)
            stat_imp, perm_imp, path_imp = analyzer.run_full_analysis()
            
            results[model_name] = {
                'model': SUPPORTED_MODELS[model_name],
                'statistical': stat_imp,
                'permutation': perm_imp,
                'path': path_imp,
                'status': 'success'
            }
            
            if len(stat_imp) > 0:
                top_feature = stat_imp.iloc[0]['feature']
                top_score = stat_imp.iloc[0]['importance']
                print(f"   🥇 가장 중요한 특성: {top_feature} (점수: {top_score:.4f})")
            
        except Exception as e:
            print(f"   ❌ {SUPPORTED_MODELS[model_name]} 분석 실패: {e}")
            results[model_name] = {'status': 'failed', 'error': str(e)}
    
    return results


def main():
    """메인 실행 함수"""
    print("🎯 SSO 다중 모델 특성 중요도 분석")
    print("=" * 70)
    
    # 지원 모델 목록 출력
    print("🤖 지원하는 이상탐지 모델:")
    for key, name in SUPPORTED_MODELS.items():
        print(f"   - {name} ({key})")
    
    # 기본 모델(Isolation Forest)로 실행
    print(f"\n🚀 기본 모델(Isolation Forest) 특성 중요도 분석:")
    print("=" * 50)
    
    logs_dir = "/home/kongju/DEV/dream/DATA/LOGS"
    analyzer = FeatureImportanceAnalyzer(logs_dir, 'isolation_forest', contamination=0.1)
    stat_imp, perm_imp, path_imp = analyzer.run_full_analysis()
    
    print(f"\n💡 주요 인사이트:")
    if len(stat_imp) > 0:
        top_feature = stat_imp.iloc[0]['feature']
        top_score = stat_imp.iloc[0]['importance']
        print(f"   🥇 가장 중요한 특성: {top_feature} (점수: {top_score:.4f})")
        
        # 이상탐지에 도움이 되는 특성들 (안전한 접근)
        if 'importance' in stat_imp.columns and len(stat_imp) > 0 and not stat_imp['importance'].isna().all():
            median_importance = stat_imp['importance'].median()
            helpful_features = stat_imp[stat_imp['importance'] > median_importance]
            print(f"   📈 중요도가 높은 특성 수: {len(helpful_features)}개")
            if len(helpful_features) > 0:
                print(f"   📋 핵심 특성들: {', '.join(helpful_features.head(5)['feature'].tolist())}")
            else:
                print(f"   📋 핵심 특성들: 없음")
        else:
            print(f"   📈 중요도 계산 결과가 없습니다.")
            print(f"   📋 핵심 특성들: 없음")
    
    print(f"\n💡 전체 모델 비교를 실행하려면 run_all_models_analysis() 함수를 호출하세요.")


if __name__ == "__main__":
    import sys
    
    # 커맨드라인 인자 처리
    if len(sys.argv) > 1:
        if sys.argv[1] == 'all':
            # 모든 모델 분석
            run_all_models_analysis()
        elif sys.argv[1] in SUPPORTED_MODELS:
            # 특정 모델 분석
            model_name = sys.argv[1]
            logs_dir = "/home/kongju/DEV/dream/DATA/LOGS"
            analyzer = FeatureImportanceAnalyzer(logs_dir, model_name, contamination=0.1)
            stat_imp, perm_imp, path_imp = analyzer.run_full_analysis()
            
            print(f"\n💡 {SUPPORTED_MODELS[model_name]} 주요 인사이트:")
            if len(stat_imp) > 0:
                top_feature = stat_imp.iloc[0]['feature']
                top_score = stat_imp.iloc[0]['importance']
                print(f"   🥇 가장 중요한 특성: {top_feature} (점수: {top_score:.4f})")
        else:
            print(f"❌ 지원하지 않는 모델: {sys.argv[1]}")
            print(f"✅ 지원 모델: {list(SUPPORTED_MODELS.keys())}")
    else:
        main()
