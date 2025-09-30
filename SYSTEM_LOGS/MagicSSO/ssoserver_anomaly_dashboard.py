#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MagicSSO Log Analysis Dashboard
MagicSSO 프로젝트를 위한 로그 이상탐지 대시보드

Author: Kong Ju
Date: 2025-09-25
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import numpy as np
from datetime import datetime, timedelta
from collections import Counter
import seaborn as sns
import matplotlib.pyplot as plt
import sys
import os
import io
import base64

# color_config 모듈 import (없으면 기본값 사용)
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
    from color_config import (
        COLORS, COLOR_PALETTE, LEVEL_COLORS, GRAPH_COLORS,
        get_color, get_color_palette, get_level_colors, get_graph_color
    )
except ImportError:
    # 기본 색상 설정
    COLORS = {
        'primary': '#1f77b4',
        'secondary': '#ff7f0e',
        'success': '#2ca02c',
        'info': '#17a2b8',
        'warning': '#ffc107',
        'error': '#dc3545',
        'normal': '#6c757d'
    }
    
    def get_color(name):
        return COLORS.get(name, '#1f77b4')
    
    def get_color_palette(n=10):
        colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', 
                 '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']
        return colors[:n] if n <= len(colors) else colors * (n // len(colors) + 1)
    
    def get_level_colors(levels):
        level_color_map = {
            'TRACE': '#6c757d', 'DEBUG': '#17a2b8', 'INFO': '#28a745',
            'WARN': '#ffc107', 'ERROR': '#dc3545', 'FATAL': '#6f42c1'
        }
        return [level_color_map.get(level, '#1f77b4') for level in levels]
    
    def get_graph_color(chart_type):
        return 'Blues' if chart_type == 'heatmap' else '#1f77b4'

st.set_page_config(
    page_title="MagicSSO 로그 이상탐지 대시보드",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 한글 라벨 매핑
KOREAN_LABELS = {
    'timestamp': '시간',
    'level': '로그 레벨',
    'count': '개수',
    'severity_score': '심각도 점수',
    'processing_time_ms': '처리 시간 (밀리초)',
    'template_frequency': '템플릿 빈도',
    'message_len': '메시지 길이',
    'logger': '로거',
    'error_code': '에러 코드',
    'log_category': '로그 카테고리',
    'weekday': '요일',
    'hour': '시간',
    'x': '시간',
    'y': '개수',
    'saml_type': 'SAML 타입',
    'license_status': '라이센스 상태',
    'crypto_operation': '암호화 작업'
}

# 요일 한글 변환
WEEKDAY_KOREAN = {
    'Monday': '월요일',
    'Tuesday': '화요일', 
    'Wednesday': '수요일',
    'Thursday': '목요일',
    'Friday': '금요일',
    'Saturday': '토요일',
    'Sunday': '일요일'
}

# 로그 레벨 한글 변환
LEVEL_KOREAN = {
    'TRACE': '추적',
    'DEBUG': '디버그',
    'INFO': '정보',
    'WARN': '경고',
    'ERROR': '에러',
    'FATAL': '치명적'
}

# SSO 특화 한글 변환
SSO_CATEGORY_KOREAN = {
    'SAML': 'SAML',
    'LICENSE': '라이센스',
    'CRYPTO': '암호화',
    'REPOSITORY': '저장소',
    'OTHER': '기타'
}

SAML_TYPE_KOREAN = {
    'AuthnRequest': '인증요청',
    'Assertion': '인증응답',
    'Response': '응답',
    'LogoutRequest': '로그아웃요청',
    'LogoutResponse': '로그아웃응답'
}

LICENSE_STATUS_KOREAN = {
    'VALID': '유효',
    'EXPIRED': '만료',
    'INVALID': '무효',
    'WARNING': '경고'
}


def create_download_button(fig, filename, button_text="그래프 다운로드"):
    """Plotly 그래프를 PNG로 다운로드하는 버튼 생성"""
    
    # 커스텀 CSS로 버튼 색상 변경
    st.markdown("""
    <style>
    .stDownloadButton > button {
        background-color: #B1B1B2 !important;
        color: white !important;
        border: none !important;
        border-radius: 4px !important;
    }
    .stDownloadButton > button:hover {
        background-color: #9A9A9B !important;
        color: white !important;
    }
    </style>
    """, unsafe_allow_html=True)
    
    try:
        # Plotly 그래프를 PNG 바이트로 변환
        img_bytes = fig.to_image(format="png", width=1200, height=800, scale=2)
        
        st.download_button(
            label="그래프 다운로드",
            data=img_bytes,
            file_name=f"{filename}.png",
            mime="image/png",
            key=f"download_{filename}_{hash(str(fig))}",
            help="고해상도 PNG 이미지로 다운로드합니다"
        )
        return True
    except Exception as e:
        # Chrome이 없을 때는 HTML 다운로드로 대체
        html_str = fig.to_html()
        st.download_button(
            label="그래프 다운로드",
            data=html_str,
            file_name=f"{filename}.html",
            mime="text/html",
            key=f"download_{filename}_{hash(str(fig))}",
            help="인터랙티브 HTML 파일로 다운로드합니다"
        )
        
        # Chrome 자동 다운로드 시도 (한 번만, 조용히)
        if f"chrome_download_attempted_{filename}" not in st.session_state:
            try:
                import kaleido
                kaleido.get_chrome_sync()
                st.session_state[f"chrome_download_attempted_{filename}"] = True
            except:
                st.session_state[f"chrome_download_attempted_{filename}"] = True
        
        return False

@st.cache_data
def load_data(file_path):
    """NDJSON 파일 로드"""
    data = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    data.append(json.loads(line.strip()))
        df = pd.DataFrame(data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    except Exception as e:
        st.error(f"데이터 로드 중 오류 발생: {e}")
        return pd.DataFrame()

def convert_weekday_to_korean(df):
    """요일을 한글로 변환"""
    if 'weekday' in df.columns:
        df['weekday'] = df['weekday'].map(WEEKDAY_KOREAN).fillna(df['weekday'])
    return df

def convert_level_to_korean(df):
    """로그 레벨을 한글로 변환"""
    if 'level' in df.columns:
        df['level_kr'] = df['level'].map(LEVEL_KOREAN).fillna(df['level'])
    return df

def detect_sso_anomalies(df):
    """SSO 특화 이상 패턴 탐지"""
    anomalies = {}
    
    # 1. 높은 심각도 점수 (90 이상)
    high_severity = df[df['severity_score'] >= 90]
    anomalies['high_severity'] = high_severity
    
    # 2. 스택트레이스가 있는 로그
    with_stacktrace = df[df['has_stacktrace'] == True]
    anomalies['with_stacktrace'] = with_stacktrace
    
    # 3. ERROR/WARN 레벨 로그
    error_warn_logs = df[df['level'].isin(['ERROR', 'WARN'])]
    anomalies['error_warn'] = error_warn_logs
    
    # 4. 라이센스 만료/에러 로그
    if 'license_status' in df.columns:
        license_issues = df[df['license_status'].isin(['EXPIRED', 'INVALID'])]
        anomalies['license_issues'] = license_issues
    else:
        license_issues = df[df['log_category'] == 'LICENSE']
        anomalies['license_issues'] = license_issues
    
    # 5. SAML 관련 에러
    saml_errors = df[(df['log_category'] == 'SAML') & (df['level'].isin(['ERROR', 'WARN']))]
    anomalies['saml_errors'] = saml_errors
    
    # 6. 암호화 관련 에러
    crypto_errors = df[(df['log_category'] == 'CRYPTO') & (df['level'].isin(['ERROR', 'WARN']))]
    anomalies['crypto_errors'] = crypto_errors
    
    # 7. 비정상적인 템플릿 빈도 (매우 낮은 빈도)
    low_frequency = df[df['template_frequency'] < 10]
    anomalies['low_frequency'] = low_frequency
    
    # 8. 비정상적인 메시지 길이 (이상치)
    q75, q25 = np.percentile(df['message_len'], [75, 25])
    iqr = q75 - q25
    lower_bound = q25 - 1.5 * iqr
    upper_bound = q75 + 1.5 * iqr
    outlier_length = df[(df['message_len'] < lower_bound) | (df['message_len'] > upper_bound)]
    anomalies['outlier_length'] = outlier_length
    
    return anomalies

def main():
    st.title("MagicSSO 로그 이상탐지 대시보드")
    st.markdown("---")
    
    # 파일 경로
    file_path = "/home/kongju/DREAM/SYSTEM_LOGS/MagicSSO/output/ssoserver_structured.ndjson"
    
    st.sidebar.header("대시보드 설정")
    
    # 데이터 로드
    with st.spinner("데이터를 로드하는 중..."):
        df = load_data(file_path)
    
    if df.empty:
        st.error("데이터를 로드할 수 없습니다.")
        return
    
    # 기본 통계
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("총 로그 수", f"{len(df):,}")
    with col2:
        st.metric("고심각도 로그", f"{len(df[df['severity_score'] >= 90]):,}")
    with col3:
        st.metric("에러/경고 로그", f"{len(df[df['level'].isin(['ERROR', 'WARN'])]):,}")
    with col4:
        if 'license_status' in df.columns:
            license_issues = len(df[df['license_status'].isin(['EXPIRED', 'INVALID'])])
        else:
            license_issues = len(df[df['log_category'] == 'LICENSE'])
        st.metric("라이센스 이슈", f"{license_issues:,}")
    
    # 시간 범위 선택
    min_date = df['timestamp'].min().date()
    max_date = df['timestamp'].max().date()
    
    date_range = st.sidebar.date_input(
        "분석 기간 선택",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date
    )
    
    if len(date_range) == 2:
        start_date, end_date = date_range
        df_filtered = df[
            (df['timestamp'].dt.date >= start_date) & 
            (df['timestamp'].dt.date <= end_date)
        ]
    else:
        df_filtered = df
    
    # SSO 특화 이상 탐지
    anomalies = detect_sso_anomalies(df_filtered)
    
    # 탭 구성
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "이상탐지 결과  |", "시계열 분석  |", "로그 레벨 분석  |", 
        "SSO 특화 분석  |", "상세 분석  |", "로그 검색  |"
    ])
    
    with tab1:
        st.header("이상탐지 결과")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("이상 패턴 요약")
            anomaly_summary = pd.DataFrame([
                {"이상 유형": "고심각도 로그 (≥90)", "개수": len(anomalies['high_severity'])},
                {"이상 유형": "스택트레이스 포함", "개수": len(anomalies['with_stacktrace'])},
                {"이상 유형": "ERROR/WARN 레벨", "개수": len(anomalies['error_warn'])},
                {"이상 유형": "라이센스 이슈", "개수": len(anomalies['license_issues'])},
                {"이상 유형": "SAML 에러", "개수": len(anomalies['saml_errors'])},
                {"이상 유형": "암호화 에러", "개수": len(anomalies['crypto_errors'])},
                {"이상 유형": "낮은 템플릿 빈도", "개수": len(anomalies['low_frequency'])},
                {"이상 유형": "비정상적 메시지 길이", "개수": len(anomalies['outlier_length'])}
            ])
            st.dataframe(anomaly_summary, use_container_width=True)
        
        with col2:
            st.subheader("심각도 분포")
            fig = px.histogram(df_filtered, x='severity_score', 
                             title="심각도 점수 분포",
                             nbins=20,
                             labels={'severity_score': KOREAN_LABELS['severity_score'], 
                                    'count': KOREAN_LABELS['count']},
                             color_discrete_sequence=[get_color('primary')])
            fig.add_vline(x=90, line_dash="dash", line_color=get_color('error'), 
                         annotation_text="고심각도 임계점", 
                         annotation_font_color=get_color('error'))
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                xaxis_title=KOREAN_LABELS['severity_score'],
                yaxis_title=KOREAN_LABELS['count']
            )
            st.plotly_chart(fig, use_container_width=True)
            
            create_download_button(fig, "severity_distribution", "심각도 분포 그래프 다운로드")
        
        # 최근 이상 로그들
        st.subheader("최근 이상 로그 (상위 10개)")
        recent_anomalies = pd.concat([
            anomalies['high_severity'], 
            anomalies['with_stacktrace'], 
            anomalies['error_warn'],
            anomalies['license_issues'],
            anomalies['saml_errors'],
            anomalies['crypto_errors']
        ]).drop_duplicates().sort_values('timestamp', ascending=False).head(10)
        
        if not recent_anomalies.empty:
            display_cols = ['timestamp', 'level', 'severity_score', 'log_category', 'logger', 'message']
            st.dataframe(recent_anomalies[display_cols], use_container_width=True)
        else:
            st.info("이상 로그가 발견되지 않았습니다.")
    
    with tab2:
        st.header("시계열 분석")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # 시간당 로그 수
            df_hourly = df_filtered.set_index('timestamp').resample('H').size().reset_index()
            df_hourly.columns = ['날짜', '로그 수']
            
            fig = px.line(df_hourly, x='날짜', y='로그 수',
                         title="날짜별 로그 수 추이",
                         color_discrete_sequence=[get_color('primary')])
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                xaxis_title='날짜',
                yaxis_title='로그 수'
            )
            st.plotly_chart(fig, use_container_width=True)
            
            create_download_button(fig, "hourly_log_trend", "날짜별 로그 수 추이 다운로드")
        
        with col2:
            # 로그 레벨별 시계열
            level_time = df_filtered.groupby([
                df_filtered['timestamp'].dt.floor('H'), 'level'
            ]).size().reset_index()
            level_time.columns = ['날짜', '로그 레벨', '로그 수']
            
            # 로그 레벨을 한글로 변환
            level_time['로그 레벨'] = level_time['로그 레벨'].map(LEVEL_KOREAN).fillna(level_time['로그 레벨'])
            
            # 로그 레벨에 맞는 색상 적용
            unique_levels = level_time['로그 레벨'].unique()
            level_color_map = {}
            for kr_level in unique_levels:
                en_level = [k for k, v in LEVEL_KOREAN.items() if v == kr_level]
                if en_level:
                    level_color_map[kr_level] = get_level_colors([en_level[0]])[0]
                else:
                    level_color_map[kr_level] = get_color('normal')
            
            fig = px.line(level_time, x='날짜', y='로그 수', color='로그 레벨',
                         title="로그 레벨별 시계열 패턴",
                         color_discrete_map=level_color_map)
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                xaxis_title='날짜',
                yaxis_title='로그 수'
            )
            st.plotly_chart(fig, use_container_width=True)
            
            create_download_button(fig, "level_time_series", "로그 레벨별 시계열 다운로드")
        
        # 히트맵 - 요일별/시간별 패턴
        df_temp = df_filtered.copy()
        df_temp['hour'] = df_temp['timestamp'].dt.hour
        df_temp['weekday'] = df_temp['timestamp'].dt.day_name()
        df_temp = convert_weekday_to_korean(df_temp)
        
        heatmap_data = df_temp.groupby(['weekday', 'hour']).size().unstack(fill_value=0)
        
        fig = px.imshow(heatmap_data, 
                       title="요일별/시간별 로그 패턴 히트맵",
                       labels={'x': '시간', 'y': '요일', 'color': '로그 수'},
                       aspect='auto',
                       color_continuous_scale=get_graph_color('heatmap'))
        fig.update_layout(
            xaxis_title='시간',
            yaxis_title='요일'
        )
        st.plotly_chart(fig, use_container_width=True)
        
        create_download_button(fig, "weekday_hour_heatmap", "요일별/시간별 히트맵 다운로드")
    
    with tab3:
        st.header("로그 레벨 분석")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # 로그 레벨 분포
            level_counts = df_filtered['level'].value_counts()
            level_counts_kr = pd.Series(
                level_counts.values, 
                index=[LEVEL_KOREAN.get(level, level) for level in level_counts.index]
            )
            level_color_list = get_level_colors(level_counts.index.tolist())
            
            fig = px.pie(values=level_counts_kr.values, names=level_counts_kr.index,
                        title="로그 레벨 분포",
                        color_discrete_sequence=level_color_list)
            st.plotly_chart(fig, use_container_width=True)
            
            create_download_button(fig, "level_distribution_pie", "로그 레벨 분포 파이차트 다운로드")
        
        with col2:
            # 로그 카테고리 분포
            if 'log_category' in df_filtered.columns:
                category_counts = df_filtered['log_category'].value_counts()
                # 카테고리를 한글로 변환
                category_counts_kr = pd.Series(
                    category_counts.values,
                    index=[SSO_CATEGORY_KOREAN.get(cat, cat) for cat in category_counts.index]
                )
                fig = px.bar(x=category_counts_kr.values, y=category_counts_kr.index,
                            orientation='h',
                            title="로그 카테고리 분포",
                            labels={'x': '개수', 'y': '카테고리'},
                            color_discrete_sequence=get_color_palette(len(category_counts_kr)))
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    xaxis_title='개수',
                    yaxis_title='카테고리'
                )
                st.plotly_chart(fig, use_container_width=True)
                
                create_download_button(fig, "category_distribution", "로그 카테고리 분포 다운로드")
        
        # 심각도별 상세 분석
        severity_level = df_filtered.groupby(['level', pd.cut(df_filtered['severity_score'], 
                                                            bins=[0, 30, 60, 90, 100],
                                                            labels=['낮음', '보통', '높음', '매우높음'])]).size().reset_index()
        severity_level.columns = ['로그 레벨', '심각도 그룹', '개수']
        severity_level['로그 레벨'] = severity_level['로그 레벨'].map(LEVEL_KOREAN).fillna(severity_level['로그 레벨'])
        
        fig = px.sunburst(severity_level, path=['로그 레벨', '심각도 그룹'], 
                         values='개수',
                         title="로그 레벨별 심각도 분포",
                         color_discrete_sequence=get_color_palette())
        st.plotly_chart(fig, use_container_width=True)
        
        create_download_button(fig, "severity_level_sunburst", "심각도별 선버스트 차트 다운로드")
    
    with tab4:
        st.header("SSO 특화 분석")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("SAML 요청 타입 분포")
            if 'saml_type' in df_filtered.columns:
                saml_type_counts = df_filtered[df_filtered['saml_type'].notna()]['saml_type'].value_counts()
                if not saml_type_counts.empty:
                    # SAML 타입을 한글로 변환
                    saml_type_counts_kr = pd.Series(
                        saml_type_counts.values,
                        index=[SAML_TYPE_KOREAN.get(saml_type, saml_type) for saml_type in saml_type_counts.index]
                    )
                    fig = px.pie(values=saml_type_counts_kr.values, names=saml_type_counts_kr.index,
                                title="SAML 요청 타입 분포",
                                color_discrete_sequence=get_color_palette(len(saml_type_counts_kr)))
                    st.plotly_chart(fig, use_container_width=True)
                    
                    create_download_button(fig, "saml_type_distribution", "SAML 타입 분포 다운로드")
                else:
                    st.info("SAML 타입 데이터가 없습니다.")
            else:
                st.info("SAML 타입 필드가 없습니다.")
        
        with col2:
            st.subheader("라이센스 상태 분석")
            if 'license_status' in df_filtered.columns:
                license_status_counts = df_filtered[df_filtered['license_status'].notna()]['license_status'].value_counts()
                if not license_status_counts.empty:
                    # 라이센스 상태를 한글로 변환
                    license_status_counts_kr = pd.Series(
                        license_status_counts.values,
                        index=[LICENSE_STATUS_KOREAN.get(status, status) for status in license_status_counts.index]
                    )
                    
                    # 색상 매핑
                    license_colors = []
                    for status in license_status_counts.index:
                        if status == 'EXPIRED':
                            license_colors.append(get_color('error'))
                        elif status == 'INVALID':
                            license_colors.append(get_color('warning'))
                        else:
                            license_colors.append(get_color('success'))
                    
                    fig = px.bar(x=license_status_counts_kr.values, y=license_status_counts_kr.index,
                                orientation='h',
                                title="라이센스 상태 분포",
                                labels={'x': '개수', 'y': '라이센스 상태'},
                                color_discrete_sequence=license_colors)
                    fig.update_layout(
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)',
                        xaxis_title='개수',
                        yaxis_title='라이센스 상태'
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    create_download_button(fig, "license_status_distribution", "라이센스 상태 분포 다운로드")
                else:
                    st.info("라이센스 상태 데이터가 없습니다.")
            else:
                st.info("라이센스 상태 필드가 없습니다.")
        
        # 암호화 작업 분석
        if 'crypto_operation' in df_filtered.columns:
            st.subheader("암호화 작업 분석")
            crypto_ops = df_filtered[df_filtered['crypto_operation'].notna()]
            if not crypto_ops.empty:
                crypto_op_counts = crypto_ops['crypto_operation'].value_counts()
                
                col1, col2 = st.columns(2)
                
                with col1:
                    fig = px.bar(x=crypto_op_counts.values, y=crypto_op_counts.index,
                                orientation='h',
                                title="암호화 작업 종류별 분포",
                                labels={'x': '개수', 'y': '암호화 작업'},
                                color_discrete_sequence=get_color_palette(len(crypto_op_counts)))
                    fig.update_layout(
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)',
                        xaxis_title='개수',
                        yaxis_title='암호화 작업'
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    create_download_button(fig, "crypto_operation_distribution", "암호화 작업 분포 다운로드")
                
                with col2:
                    # 암호화 작업별 시계열
                    crypto_time = crypto_ops.groupby([
                        crypto_ops['timestamp'].dt.floor('H'), 'crypto_operation'
                    ]).size().reset_index()
                    crypto_time.columns = ['날짜', '암호화 작업', '로그 수']
                    
                    fig = px.line(crypto_time, x='날짜', y='로그 수', color='암호화 작업',
                                 title="암호화 작업별 시계열 패턴",
                                 color_discrete_sequence=get_color_palette(len(crypto_time['암호화 작업'].unique())))
                    fig.update_layout(
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)',
                        xaxis_title='날짜',
                        yaxis_title='로그 수'
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    create_download_button(fig, "crypto_operation_timeline", "암호화 작업 시계열 다운로드")
        
        # SAML 에러 상세 분석
        st.subheader("SAML 에러 상세 분석")
        saml_errors = df_filtered[(df_filtered['log_category'] == 'SAML') & (df_filtered['level'].isin(['ERROR', 'WARN']))]
        
        if not saml_errors.empty:
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**SAML 에러 수:** {len(saml_errors):,}개")
                
                # SAML 에러의 시간별 분포
                saml_error_hourly = saml_errors.set_index('timestamp').resample('H').size().reset_index()
                saml_error_hourly.columns = ['날짜', '에러 수']
                
                fig = px.line(saml_error_hourly, x='날짜', y='에러 수',
                             title="SAML 에러 시간별 분포",
                             color_discrete_sequence=[get_color('error')])
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    xaxis_title='날짜',
                    yaxis_title='에러 수'
                )
                st.plotly_chart(fig, use_container_width=True)
                
                create_download_button(fig, "saml_errors_timeline", "SAML 에러 시계열 다운로드")
            
            with col2:
                # 최근 SAML 에러 상위 5개
                st.write("**최근 SAML 에러 (상위 5개):**")
                recent_saml_errors = saml_errors.sort_values('timestamp', ascending=False).head(5)
                display_cols = ['timestamp', 'level', 'severity_score', 'message']
                st.dataframe(recent_saml_errors[display_cols], use_container_width=True)
        else:
            st.info("SAML 에러가 없습니다.")
        
        # 데이터베이스 연결 분석 (connection_time_ms 있는 경우)
        if 'connection_time_ms' in df_filtered.columns:
            st.subheader("데이터베이스 연결 성능 분석")
            db_conn_logs = df_filtered[df_filtered['connection_time_ms'].notna()]
            
            if not db_conn_logs.empty:
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric(
                        label="평균 연결 시간",
                        value=f"{db_conn_logs['connection_time_ms'].mean():.1f} ms"
                    )
                
                with col2:
                    st.metric(
                        label="최대 연결 시간",
                        value=f"{db_conn_logs['connection_time_ms'].max():.0f} ms"
                    )
                
                with col3:
                    st.metric(
                        label="최소 연결 시간",
                        value=f"{db_conn_logs['connection_time_ms'].min():.0f} ms"
                    )
                
                with col4:
                    st.metric(
                        label="연결 시도 횟수",
                        value=f"{len(db_conn_logs):,}회"
                    )
                
                # 연결 시간 분포 히스토그램
                fig = px.histogram(db_conn_logs, x='connection_time_ms',
                                 title="데이터베이스 연결 시간 분포",
                                 labels={'connection_time_ms': '연결 시간 (ms)', 'count': '빈도'},
                                 nbins=20,
                                 color_discrete_sequence=[get_color('info')])
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    xaxis_title='연결 시간 (ms)',
                    yaxis_title='빈도'
                )
                st.plotly_chart(fig, use_container_width=True)
                
                create_download_button(fig, "db_connection_time_distribution", "DB 연결 시간 분포 다운로드")
    
    with tab5:
        st.header("상세 분석")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("에러 코드 분석")
            if 'error_code' in df_filtered.columns:
                error_codes = df_filtered[df_filtered['error_code'].notna()]['error_code'].value_counts().head(10)
                if not error_codes.empty:
                    fig = px.bar(x=error_codes.values, y=error_codes.index,
                                orientation='h',
                                title="상위 에러 코드",
                                labels={'x': '개수', 'y': '에러 코드'},
                                color_discrete_sequence=[get_color('error')])
                    fig.update_layout(
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)',
                        xaxis_title='개수',
                        yaxis_title='에러 코드'
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    create_download_button(fig, "error_code_analysis", "에러 코드 분석 다운로드")
                else:
                    st.info("에러 코드가 없습니다.")
            else:
                st.subheader("템플릿 빈도 분석")
                template_freq = df_filtered['template_frequency'].describe()
                st.write(template_freq)
                
                fig = px.histogram(df_filtered, x='template_frequency',
                                 title="템플릿 빈도 분포",
                                 nbins=30,
                                 labels={'template_frequency': '템플릿 빈도', 'count': '개수'},
                                 color_discrete_sequence=[get_color('secondary')])
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    xaxis_title='템플릿 빈도',
                    yaxis_title='개수'
                )
                st.plotly_chart(fig, use_container_width=True)
                
                create_download_button(fig, "template_frequency_distribution", "템플릿 빈도 분포 다운로드")
        
        with col2:
            st.subheader("메시지 길이 분석")
            fig = px.histogram(df_filtered, x='message_len',
                             title="메시지 길이 분포",
                             nbins=20,
                             labels={'message_len': '메시지 길이', 'count': '빈도'},
                             color_discrete_sequence=[get_color('info')])
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                xaxis_title='메시지 길이',
                yaxis_title='빈도'
            )
            st.plotly_chart(fig, use_container_width=True)
            
            create_download_button(fig, "message_length_distribution", "메시지 길이 분포 다운로드")
            
            # 메시지 길이 통계
            st.subheader("메시지 길이 통계")
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric(
                    label="평균",
                    value=f"{df_filtered['message_len'].mean():.1f}",
                    help="전체 메시지 길이의 평균값"
                )
            
            with col2:
                st.metric(
                    label="중앙값",
                    value=f"{df_filtered['message_len'].median():.1f}",
                    help="전체 메시지 길이의 중앙값"
                )
            
            with col3:
                st.metric(
                    label="최댓값",
                    value=f"{df_filtered['message_len'].max():.0f}",
                    delta=f"+{(df_filtered['message_len'].max() - df_filtered['message_len'].mean()):.0f}",
                    delta_color="inverse",
                    help="가장 긴 메시지 길이"
                )
            
            with col4:
                st.metric(
                    label="최솟값",
                    value=f"{df_filtered['message_len'].min():.0f}",
                    delta=f"{(df_filtered['message_len'].min() - df_filtered['message_len'].mean()):.0f}",
                    delta_color="normal",
                    help="가장 짧은 메시지 길이"
                )
        
        # 로거별 분석
        st.subheader("상위 로거별 로그 수")
        logger_counts = df_filtered['logger'].value_counts().head(15)
        fig = px.bar(x=logger_counts.values, y=logger_counts.index,
                    orientation='h',
                    title="로거별 로그 수",
                    labels={'x': '로그 수', 'y': '로거'},
                    color_discrete_sequence=get_color_palette(len(logger_counts)))
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            xaxis_title='로그 수',
            yaxis_title='로거'
        )
        st.plotly_chart(fig, use_container_width=True)
        
        create_download_button(fig, "logger_distribution", "로거별 로그 수 다운로드")
        
        # 스레드별 분석
        if 'thread' in df_filtered.columns:
            st.subheader("상위 스레드별 로그 수")
            thread_counts = df_filtered['thread'].value_counts().head(10)
            fig = px.bar(x=thread_counts.values, y=thread_counts.index,
                        orientation='h',
                        title="스레드별 로그 수",
                        labels={'x': '로그 수', 'y': '스레드'},
                        color_discrete_sequence=get_color_palette(len(thread_counts)))
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                xaxis_title='로그 수',
                yaxis_title='스레드'
            )
            st.plotly_chart(fig, use_container_width=True)
            
            create_download_button(fig, "thread_distribution", "스레드별 로그 수 다운로드")
    
    with tab6:
        st.header("로그 검색 및 필터링")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            search_level = st.selectbox("로그 레벨", ['전체'] + list(df_filtered['level'].unique()))
        
        with col2:
            search_logger = st.selectbox("로거", ['전체'] + list(df_filtered['logger'].unique()))
        
        with col3:
            min_severity = st.slider("최소 심각도", 0, 100, 0)
        
        col4, col5 = st.columns(2)
        
        with col4:
            if 'log_category' in df_filtered.columns:
                search_category = st.selectbox("로그 카테고리", ['전체'] + list(df_filtered['log_category'].unique()))
            else:
                search_category = '전체'
        
        with col5:
            if 'saml_type' in df_filtered.columns:
                search_saml_type = st.selectbox("SAML 타입", ['전체'] + list(df_filtered[df_filtered['saml_type'].notna()]['saml_type'].unique()))
            else:
                search_saml_type = '전체'
        
        search_text = st.text_input("메시지 검색 (키워드)")
        
        # 필터 적용
        filtered_df = df_filtered.copy()
        
        if search_level != '전체':
            filtered_df = filtered_df[filtered_df['level'] == search_level]
        
        if search_logger != '전체':
            filtered_df = filtered_df[filtered_df['logger'] == search_logger]
        
        filtered_df = filtered_df[filtered_df['severity_score'] >= min_severity]
        
        if search_category != '전체' and 'log_category' in filtered_df.columns:
            filtered_df = filtered_df[filtered_df['log_category'] == search_category]
        
        if search_saml_type != '전체' and 'saml_type' in filtered_df.columns:
            filtered_df = filtered_df[filtered_df['saml_type'] == search_saml_type]
        
        if search_text:
            filtered_df = filtered_df[filtered_df['message'].str.contains(search_text, case=False, na=False)]
        
        st.subheader(f"검색 결과: {len(filtered_df):,}개 로그")
        
        if not filtered_df.empty:
            display_cols = ['timestamp', 'level', 'severity_score', 'log_category', 'logger', 'message']
            # 존재하는 컬럼만 선택
            available_cols = [col for col in display_cols if col in filtered_df.columns]
            st.dataframe(filtered_df[available_cols].sort_values('timestamp', ascending=False).head(100), 
                        use_container_width=True)
            
            # 검색 결과 다운로드
            csv = filtered_df[available_cols].sort_values('timestamp', ascending=False).to_csv(index=False, encoding='utf-8-sig')
            st.download_button(
                label="검색 결과 CSV 다운로드",
                data=csv,
                file_name=f"sso_log_search_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                help="검색 결과를 CSV 파일로 다운로드합니다"
            )
        else:
            st.info("검색 조건에 맞는 로그가 없습니다.")
    
    # 사이드바에 추가 정보
    st.sidebar.markdown("---")
    st.sidebar.subheader("데이터 정보")
    st.sidebar.write(f"총 로그 수: {len(df):,}")
    st.sidebar.write(f"분석 기간: {min_date} ~ {max_date}")
    st.sidebar.write(f"로그 레벨 종류: {len(df['level'].unique())}개")
    st.sidebar.write(f"로거 종류: {len(df['logger'].unique())}개")
    
    if 'log_category' in df.columns:
        st.sidebar.write(f"로그 카테고리: {len(df['log_category'].unique())}개")
    
    if 'saml_type' in df.columns:
        saml_count = len(df[df['saml_type'].notna()])
        st.sidebar.write(f"SAML 로그: {saml_count:,}개")

if __name__ == "__main__":
    main()
