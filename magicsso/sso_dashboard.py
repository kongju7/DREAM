#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSO Feature Analysis Dashboard
Streamlit을 활용한 SSO 이상탐지 피처 분석 대시보드

Author: Kong Ju
Date: 2025-09-01
"""

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import warnings
warnings.filterwarnings('ignore')

from sso_flow_analyzer import SSOFlowAnalyzer
from sklearn.preprocessing import StandardScaler
import json
from pathlib import Path


# 페이지 설정
st.set_page_config(
    page_title="MagicSSO Feature Analysis Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 공통 색상 설정 import
from color_config import COLORS, GRAPH_COLORS, PLOTLY_COLORS

# 모델 설정 import
from model_config import SUPPORTED_MODELS, get_model_info, get_file_suffix

# 폴더 관리 유틸리티 import
from folder_utils import get_structured_output_path

# 커스텀 CSS
st.markdown("""
<style>
    .main > div {
        padding-top: 2rem;
    }
    .stMetric {
        background-color: #f0f2f6;
        border: 1px solid #e6e9ef;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .feature-importance {
        background-color: #fff3cd;
        border-left: 4px solid #ffc107;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_data
def load_and_prepare_data(selected_model='isolation_forest'):
    """데이터 로드 및 전처리 (모델별)"""
    try:
        # 경로 설정
        logs_dir = "/home/kongju/DEV/dream/DATA/LOGS"
        data_dir = "/home/kongju/DEV/dream/DATA"
        
        # SSO 분석기로 데이터 로드
        analyzer = SSOFlowAnalyzer(logs_dir)
        analyzer.parse_log_files()
        df = analyzer.export_to_dataframe()
        
        # 특성 엔지니어링
        df_features = engineer_features(df)
        
        # 선택된 모델에 따른 이상탐지 결과 로드 (새로운 폴더 구조)
        anomaly_dir = get_structured_output_path(data_dir, "anomaly", selected_model)
        anomaly_results_path = Path(anomaly_dir) / "sso_anomaly_results.csv"
        
        if anomaly_results_path.exists():
            df_anomaly = pd.read_csv(anomaly_results_path)
            # 이상치 정보 병합
            df_features['is_anomaly'] = df_anomaly.get('is_anomaly', False)
            df_features['anomaly_score'] = df_anomaly.get('anomaly_score', 0)
            df_features['anomaly_label'] = df_anomaly.get('anomaly_label', 1)
            
            st.success(f"✅ {SUPPORTED_MODELS[selected_model]} 결과 로드 완료: {len(df_anomaly)}개 트랜잭션")
        else:
            df_features['is_anomaly'] = False
            df_features['anomaly_score'] = 0
            df_features['anomaly_label'] = 1
            
            st.warning(f"⚠️ {SUPPORTED_MODELS[selected_model]} 결과 파일이 없습니다. 먼저 이상탐지를 실행하세요.")
            st.info(f"📝 실행 명령: `python sso_anomaly_detector.py {selected_model}`")
        
        return df_features, analyzer
    
    except Exception as e:
        st.error(f"데이터 로드 중 오류 발생: {e}")
        return None, None


def engineer_features(df):
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


def get_numeric_features(df):
    """수치형 특성들 추출"""
    numeric_features = [
        'hour', 'minute', 'day_of_week', 'is_weekend', 'is_business_hours',
        'is_complete', 'is_success', 'transaction_duration_filled',
        'request_id_length', 'response_id_length', 'time_since_last',
        'hourly_transaction_count', 'duration_z_score'
    ]
    
    available_features = [feat for feat in numeric_features if feat in df.columns]
    return available_features


def create_overview_metrics(df):
    """개요 메트릭 생성"""
    st.markdown("## 📊 데이터 개요")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("총 트랜잭션", f"{len(df):,}")
    
    with col2:
        completed = df['is_complete'].sum()
        st.metric("완료된 트랜잭션", f"{completed:,}")
    
    with col3:
        success_rate = df['is_success'].mean() * 100
        st.metric("성공률", f"{success_rate:.1f}%")
    
    with col4:
        if 'is_anomaly' in df.columns:
            anomaly_count = df['is_anomaly'].sum()
            st.metric("이상치", f"{anomaly_count:,}")
        else:
            st.metric("이상치", "N/A")
    
    with col5:
        avg_duration = df['transaction_duration'].mean()
        if pd.notna(avg_duration):
            st.metric("평균 응답시간", f"{avg_duration:.2f}초")
        else:
            st.metric("평균 응답시간", "N/A")


def create_feature_statistics_table(df, selected_features):
    """특성 통계 테이블 생성"""
    st.markdown("## 📈 특성별 통계 요약")
    
    stats_data = []
    
    for feature in selected_features:
        if feature in df.columns:
            series = df[feature]
            
            stats = {
                '특성명': feature,
                '평균': f"{series.mean():.3f}",
                '표준편차': f"{series.std():.3f}",
                '최솟값': f"{series.min():.3f}",
                '25%': f"{series.quantile(0.25):.3f}",
                '중앙값': f"{series.median():.3f}",
                '75%': f"{series.quantile(0.75):.3f}",
                '최댓값': f"{series.max():.3f}",
                '결측값': f"{series.isna().sum()}",
                '유니크값': f"{series.nunique()}"
            }
            
            # 이상치가 있는 경우 정상/이상치별 통계 추가
            if 'is_anomaly' in df.columns and df['is_anomaly'].any():
                normal_data = series[~df['is_anomaly']]
                anomaly_data = series[df['is_anomaly']]
                
                if len(normal_data) > 0 and len(anomaly_data) > 0:
                    stats['정상_평균'] = f"{normal_data.mean():.3f}"
                    stats['이상_평균'] = f"{anomaly_data.mean():.3f}"
                    stats['평균_차이'] = f"{abs(normal_data.mean() - anomaly_data.mean()):.3f}"
            
            stats_data.append(stats)
    
    stats_df = pd.DataFrame(stats_data)
    st.dataframe(stats_df, use_container_width=True)


def create_distribution_plots(df, selected_features):
    """분포 시각화"""
    st.markdown("## 📊 특성별 분포 분석")
    
    # 특성 선택
    feature_to_plot = st.selectbox(
        "분석할 특성 선택:",
        selected_features,
        index=0
    )
    
    if feature_to_plot in df.columns:
        col1, col2 = st.columns(2)
        
        with col1:
            # 히스토그램
            fig_hist = px.histogram(
                df, 
                x=feature_to_plot,
                title=f"{feature_to_plot} 분포",
                nbins=30,
                marginal="box",
                color_discrete_sequence=[COLORS['primary']]
            )
            fig_hist.update_layout(height=400)
            st.plotly_chart(fig_hist, use_container_width=True)
        
        with col2:
            # 박스플롯
            fig_box = px.box(
                df,
                y=feature_to_plot,
                title=f"{feature_to_plot} 박스플롯",
                color_discrete_sequence=[COLORS['primary']]
            )
            fig_box.update_layout(height=400)
            st.plotly_chart(fig_box, use_container_width=True)
        
        # 이상치 구분 분포 (이상치 데이터가 있는 경우)
        if 'is_anomaly' in df.columns and df['is_anomaly'].any():
            st.markdown("### 정상 vs 이상치 분포 비교")
            
            col3, col4 = st.columns(2)
            
            with col3:
                # 겹친 히스토그램
                fig_overlay = go.Figure()
                
                normal_data = df[~df['is_anomaly']][feature_to_plot]
                anomaly_data = df[df['is_anomaly']][feature_to_plot]
                
                fig_overlay.add_trace(go.Histogram(
                    x=normal_data,
                    name='정상',
                    opacity=0.7,
                    nbinsx=20,
                    marker_color=COLORS['normal']
                ))
                
                if len(anomaly_data) > 0:
                    fig_overlay.add_trace(go.Histogram(
                        x=anomaly_data,
                        name='이상치',
                        opacity=0.7,
                        nbinsx=20,
                        marker_color=COLORS['anomaly']
                    ))
                
                fig_overlay.update_layout(
                    title=f"{feature_to_plot} - 정상 vs 이상치",
                    barmode='overlay',
                    height=400
                )
                st.plotly_chart(fig_overlay, use_container_width=True)
            
            with col4:
                # 그룹별 박스플롯
                df_melted = df.copy()
                df_melted['그룹'] = df_melted['is_anomaly'].map({False: '정상', True: '이상치'})
                
                fig_group_box = px.box(
                    df_melted,
                    x='그룹',
                    y=feature_to_plot,
                    title=f"{feature_to_plot} - 그룹별 박스플롯",
                    color='그룹',
                    color_discrete_map={'정상': COLORS['normal'], '이상치': COLORS['anomaly']}
                )
                fig_group_box.update_layout(height=400)
                st.plotly_chart(fig_group_box, use_container_width=True)


def create_correlation_analysis(df, selected_features):
    """상관관계 분석"""
    st.markdown("## 🔗 특성 간 상관관계 분석")
    
    # 상관관계 계산
    corr_features = [f for f in selected_features if f in df.columns]
    if len(corr_features) > 1:
        corr_matrix = df[corr_features].corr()
        
        # 히트맵
        fig_corr = px.imshow(
            corr_matrix,
            title="특성 간 상관관계 히트맵",
            color_continuous_scale=[[0, '#FFFFFF'], [0.5, COLORS['secondary']], [1, COLORS['primary']]],
            aspect="auto"
        )
        fig_corr.update_layout(height=600)
        st.plotly_chart(fig_corr, use_container_width=True)
        
        # 높은 상관관계 특성 쌍 찾기
        st.markdown("### 🔍 높은 상관관계 특성 쌍 (|r| > 0.7)")
        
        high_corr_pairs = []
        for i in range(len(corr_matrix.columns)):
            for j in range(i+1, len(corr_matrix.columns)):
                corr_val = corr_matrix.iloc[i, j]
                if abs(corr_val) > 0.7:
                    high_corr_pairs.append({
                        '특성1': corr_matrix.columns[i],
                        '특성2': corr_matrix.columns[j],
                        '상관계수': f"{corr_val:.3f}"
                    })
        
        if high_corr_pairs:
            high_corr_df = pd.DataFrame(high_corr_pairs)
            st.dataframe(high_corr_df, use_container_width=True)
        else:
            st.info("상관계수 0.7 이상인 특성 쌍이 없습니다.")


def create_time_series_analysis(df):
    """시계열 분석"""
    st.markdown("## ⏰ 시계열 분석")
    
    if 'request_timestamp' in df.columns and df['request_timestamp'].notna().any():
        # 시간별 트랜잭션 수
        df_time = df[df['request_timestamp'].notna()].copy()
        df_time['timestamp'] = pd.to_datetime(df_time['request_timestamp'])
        
        # 시간별 집계
        time_group = st.selectbox(
            "시간 집계 단위:",
            ["시간별", "일별", "요일별"],
            index=0
        )
        
        if time_group == "시간별":
            df_time['time_unit'] = df_time['timestamp'].dt.hour
            x_label = "시간"
        elif time_group == "일별":
            df_time['time_unit'] = df_time['timestamp'].dt.date
            x_label = "날짜"
        else:  # 요일별
            df_time['time_unit'] = df_time['timestamp'].dt.day_name()
            x_label = "요일"
        
        # 트랜잭션 수 집계
        time_counts = df_time.groupby('time_unit').size().reset_index(name='count')
        
        # 이상치 수 집계 (이상치 데이터가 있는 경우)
        if 'is_anomaly' in df.columns:
            anomaly_counts = df_time[df_time['is_anomaly']].groupby('time_unit').size().reset_index(name='anomaly_count')
            time_counts = time_counts.merge(anomaly_counts, on='time_unit', how='left')
            time_counts['anomaly_count'] = time_counts['anomaly_count'].fillna(0)
        
        # 시각화
        fig_time = go.Figure()
        
        fig_time.add_trace(go.Scatter(
            x=time_counts['time_unit'],
            y=time_counts['count'],
            mode='lines+markers',
            name='총 트랜잭션',
            line=dict(color=COLORS['primary'], width=3),
            marker=dict(color=COLORS['primary'], size=8)
        ))
        
        if 'anomaly_count' in time_counts.columns:
            fig_time.add_trace(go.Scatter(
                x=time_counts['time_unit'],
                y=time_counts['anomaly_count'],
                mode='lines+markers',
                name='이상치',
                line=dict(color=COLORS['anomaly'], width=3),
                marker=dict(color=COLORS['anomaly'], size=8)
            ))
        
        fig_time.update_layout(
            title=f"{time_group} 트랜잭션 분포",
            xaxis_title=x_label,
            yaxis_title="트랜잭션 수",
            height=400
        )
        
        st.plotly_chart(fig_time, use_container_width=True)


def create_anomaly_analysis(df):
    """이상치 분석"""
    if 'is_anomaly' in df.columns and df['is_anomaly'].any():
        st.markdown("## 🚨 이상치 분석")
        
        # 이상치 기본 통계
        col1, col2, col3 = st.columns(3)
        
        with col1:
            total_anomalies = df['is_anomaly'].sum()
            st.metric("총 이상치 수", f"{total_anomalies:,}")
        
        with col2:
            anomaly_rate = df['is_anomaly'].mean() * 100
            st.metric("이상치 비율", f"{anomaly_rate:.2f}%")
        
        with col3:
            if 'anomaly_score' in df.columns:
                avg_anomaly_score = df[df['is_anomaly']]['anomaly_score'].mean()
                st.metric("평균 이상치 점수", f"{avg_anomaly_score:.3f}")
        
        # SP별 이상치 분포
        if 'sp_provider' in df.columns:
            st.markdown("### SP별 이상치 분포")
            
            sp_anomaly = df.groupby('sp_provider').agg({
                'is_anomaly': ['sum', 'count', 'mean']
            }).round(3)
            sp_anomaly.columns = ['이상치_수', '총_트랜잭션', '이상치_비율']
            sp_anomaly['정상_수'] = sp_anomaly['총_트랜잭션'] - sp_anomaly['이상치_수']
            
            st.dataframe(sp_anomaly, use_container_width=True)
            
            # 막대 그래프
            fig_sp = px.bar(
                sp_anomaly.reset_index(),
                x='sp_provider',
                y=['정상_수', '이상치_수'],
                title="SP별 정상/이상치 분포",
                barmode='stack',
                color_discrete_map={'정상_수': COLORS['normal'], '이상치_수': COLORS['anomaly']}
            )
            st.plotly_chart(fig_sp, use_container_width=True)
        
        # 이상치 점수 분포
        if 'anomaly_score' in df.columns:
            st.markdown("### 이상치 점수 분포")
            
            fig_score = px.histogram(
                df,
                x='anomaly_score',
                color='is_anomaly',
                title="이상치 점수 분포",
                nbins=50,
                marginal="box",
                color_discrete_map={False: COLORS['normal'], True: COLORS['anomaly']}
            )
            st.plotly_chart(fig_score, use_container_width=True)


def create_model_comparison(available_models, selected_comparison_models=None):
    """모델 비교 분석"""
    st.subheader("🔍 모델 비교 분석")
    
    if not selected_comparison_models:
        selected_comparison_models = [SUPPORTED_MODELS[model] for model in available_models[:3]]
    
    # 비교할 모델들의 데이터 로드
    comparison_data = {}
    data_dir = Path("/home/kongju/DEV/dream/DATA")
    
    for model_display_name in selected_comparison_models:
        # 모델명 역매핑
        model_name = None
        for key, value in SUPPORTED_MODELS.items():
            if value == model_display_name:
                model_name = key
                break
        
        if model_name and model_name in available_models:
            # 새로운 폴더 구조에서 파일 찾기
            anomaly_dir = get_structured_output_path(str(data_dir), "anomaly", model_name)
            result_file = Path(anomaly_dir) / "sso_anomaly_results.csv"
            
            if result_file.exists():
                df_model = pd.read_csv(result_file)
                comparison_data[model_display_name] = {
                    'data': df_model,
                    'anomaly_count': int(df_model.get('is_anomaly', pd.Series(dtype=bool)).fillna(False).sum()),
                    'total_count': len(df_model),
                    'model_info': get_model_info(model_name)
                }
    
    if not comparison_data:
        st.warning("비교할 모델 데이터가 없습니다.")
        return
    
    # 모델별 성능 비교 테이블
    st.subheader("📊 모델별 성능 비교")
    
    comparison_summary = []
    for model_name, data in comparison_data.items():
        anomaly_rate = (data['anomaly_count'] / data['total_count'] * 100) if data['total_count'] > 0 else 0
        
        comparison_summary.append({
            '모델': model_name,
            '총 트랜잭션': data['total_count'],
            '이상치 개수': data['anomaly_count'],
            '이상치 비율 (%)': round(anomaly_rate, 2),
            '설명': data['model_info']['description'][:50] + "..." if len(data['model_info']['description']) > 50 else data['model_info']['description']
        })
    
    df_comparison = pd.DataFrame(comparison_summary)
    st.dataframe(df_comparison, use_container_width=True)
    
    # 모델별 이상치 비율 시각화
    st.subheader("📈 모델별 이상치 탐지율 비교")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # 막대 차트
        fig_bar = px.bar(
            df_comparison,
            x='모델',
            y='이상치 비율 (%)',
            title="모델별 이상치 탐지율",
            color='이상치 비율 (%)',
            color_continuous_scale=[COLORS['normal'], COLORS['primary'], COLORS['anomaly']]
        )
        st.plotly_chart(fig_bar, use_container_width=True)
    
    with col2:
        # 파이 차트 (이상치 개수)
        fig_pie = px.pie(
            df_comparison,
            values='이상치 개수',
            names='모델',
            title="모델별 이상치 개수 분포",
            color_discrete_sequence=[COLORS['primary'], COLORS['secondary'], COLORS['anomaly'], COLORS['accent']]
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    
    # 모델별 이상치 점수 분포 비교
    if len(comparison_data) >= 2:
        st.subheader("📊 모델별 이상치 점수 분포 비교")
        
        fig_scores = go.Figure()
        
        for model_name, data in comparison_data.items():
            if 'anomaly_score' in data['data'].columns:
                fig_scores.add_trace(go.Histogram(
                    x=data['data']['anomaly_score'],
                    name=model_name,
                    opacity=0.7,
                    nbinsx=30
                ))
        
        fig_scores.update_layout(
            title="모델별 이상치 점수 분포",
            xaxis_title="이상치 점수",
            yaxis_title="빈도",
            barmode='overlay',
            template="plotly_white"
        )
        
        st.plotly_chart(fig_scores, use_container_width=True)
    
    # 모델 특성 비교
    st.subheader("🔍 모델 특성 비교")
    
    for model_name, data in comparison_data.items():
        with st.expander(f"📋 {model_name} 상세 정보", expanded=False):
            info = data['model_info']
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**장점:**")
                for pro in info['pros']:
                    st.markdown(f"- ✅ {pro}")
            
            with col2:
                st.markdown("**단점:**")
                for con in info['cons']:
                    st.markdown(f"- ⚠️ {con}")
            
            st.markdown(f"**적합한 용도:** {info['best_for']}")


def main():
    """메인 함수"""
    # 제목
    st.title("🔐 SSO Feature Analysis Dashboard")
    st.markdown("---")
    
    # 사이드바 설정
    st.sidebar.title("🛠️ 분석 설정")
    
    # 모델 선택
    st.sidebar.subheader("🤖 이상탐지 모델 선택")
    
    # 사용 가능한 모델 파일 확인
    data_dir = Path("/home/kongju/DEV/dream/DATA")
    available_models = []
    
    for model_name in SUPPORTED_MODELS.keys():
        # 새로운 폴더 구조에서 파일 확인
        anomaly_dir = get_structured_output_path(str(data_dir), "anomaly", model_name)
        result_file = Path(anomaly_dir) / "sso_anomaly_results.csv"
        if result_file.exists():
            available_models.append(model_name)
    
    if not available_models:
        st.sidebar.error("🚨 이상탐지 결과 파일이 없습니다!")
        st.sidebar.info("먼저 다음 명령을 실행하세요:")
        st.sidebar.code("python sso_anomaly_detector.py compare")
        selected_model = 'isolation_forest'  # 기본값
    else:
        # 모델 선택 위젯
        model_options = {}
        for model in available_models:
            model_options[SUPPORTED_MODELS[model]] = model
        
        selected_model_name = st.sidebar.selectbox(
            "분석할 모델을 선택하세요:",
            options=list(model_options.keys()),
            index=0
        )
        selected_model = model_options[selected_model_name]
        
        # 선택된 모델 정보 표시
        model_info = get_model_info(selected_model)
        with st.sidebar.expander("📋 모델 정보", expanded=False):
            st.markdown(f"**설명**: {model_info['description']}")
            st.markdown(f"**장점**: {', '.join(model_info['pros'])}")
            st.markdown(f"**적합한 용도**: {model_info['best_for']}")
    
    # 데이터 로드
    with st.spinner(f"{SUPPORTED_MODELS.get(selected_model, '선택된 모델')} 데이터 로딩 중..."):
        df, analyzer = load_and_prepare_data(selected_model)
    
    if df is None:
        st.error("데이터를 로드할 수 없습니다.")
        return
    
    # 현재 선택된 모델 정보 표시
    if selected_model in SUPPORTED_MODELS:
        model_info = get_model_info(selected_model)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                label="🤖 현재 모델",
                value=SUPPORTED_MODELS[selected_model]
            )
        
        with col2:
            anomaly_count = int(df['is_anomaly'].fillna(False).sum()) if 'is_anomaly' in df.columns else 0
            total_count = len(df)
            anomaly_rate = (anomaly_count / total_count * 100) if total_count > 0 else 0
            
            st.metric(
                label="🚨 이상치 탐지율",
                value=f"{anomaly_rate:.1f}%",
                delta=f"{anomaly_count}/{total_count}"
            )
        
        with col3:
            st.metric(
                label="📊 총 트랜잭션",
                value=f"{total_count:,}개"
            )
        
        # 모델 설명
        st.info(f"📝 **모델 설명**: {model_info['description']}")
        st.markdown("---")
    
    # 수치형 특성들 가져오기
    numeric_features = get_numeric_features(df)
    
    # 특성 선택
    selected_features = st.sidebar.multiselect(
        "분석할 특성 선택:",
        numeric_features,
        default=numeric_features[:10] if len(numeric_features) > 10 else numeric_features
    )
    
    if not selected_features:
        st.warning("분석할 특성을 선택해주세요.")
        return
    
    # 분석 옵션
    analysis_options = st.sidebar.multiselect(
        "분석 유형 선택:",
        ["개요", "통계 요약", "분포 분석", "상관관계", "시계열", "이상치 분석", "모델 비교"],
        default=["개요", "통계 요약", "분포 분석"]
    )
    
    # 모델 비교 옵션
    if "모델 비교" in analysis_options and len(available_models) > 1:
        st.sidebar.subheader("🔍 모델 비교 설정")
        comparison_models = st.sidebar.multiselect(
            "비교할 모델들 선택:",
            [SUPPORTED_MODELS[model] for model in available_models],
            default=[SUPPORTED_MODELS[model] for model in available_models[:2]]
        )
    
    # 분석 실행
    if "개요" in analysis_options:
        create_overview_metrics(df)
        st.markdown("---")
    
    if "통계 요약" in analysis_options:
        create_feature_statistics_table(df, selected_features)
        st.markdown("---")
    
    if "분포 분석" in analysis_options:
        create_distribution_plots(df, selected_features)
        st.markdown("---")
    
    if "상관관계" in analysis_options:
        create_correlation_analysis(df, selected_features)
        st.markdown("---")
    
    if "시계열" in analysis_options:
        create_time_series_analysis(df)
        st.markdown("---")
    
    if "이상치 분석" in analysis_options:
        create_anomaly_analysis(df)
        st.markdown("---")
    
    if "모델 비교" in analysis_options and len(available_models) > 1:
        create_model_comparison(available_models, comparison_models if 'comparison_models' in locals() else None)
        st.markdown("---")
    
    # 데이터 다운로드
    st.sidebar.markdown("### 📥 데이터 다운로드")
    
    if st.sidebar.button("선택된 특성 데이터 다운로드"):
        csv = df[selected_features + ['is_anomaly'] if 'is_anomaly' in df.columns else selected_features].to_csv(index=False)
        st.sidebar.download_button(
            label="CSV 다운로드",
            data=csv,
            file_name="sso_features.csv",
            mime="text/csv"
        )


if __name__ == "__main__":
    main()
