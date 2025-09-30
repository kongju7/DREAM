#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Color Configuration for MagicIAM Log Analysis
MagicIAM 프로젝트에서 사용할 색상 팔레트 정의

Author: Kong Ju
Date: 2025-09-23
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

# 상위 디렉토리의 color_config 모듈 import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from color_config import (
    COLORS, COLOR_PALETTE, LEVEL_COLORS, GRAPH_COLORS,
    get_color, get_color_palette, get_level_colors, get_graph_color
)

st.set_page_config(
    page_title="MagicIAM 로그 이상탐지 대시보드 (일부 데이터)",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 한글 라벨 매핑
KOREAN_LABELS = {
    'timestamp': '시간',
    'level': '로그 레벨',
    'count': '개수',
    'severity_score': '심각도 점수',
    'template_frequency': '템플릿 빈도',
    'message_len': '메시지 길이',
    'logger': '로거',
    'error_code': '에러 코드',
    'log_category': '로그 카테고리',
    'weekday': '요일',
    'hour': '시간',
    'word_count': '단어 수',
    'char_count': '문자 수',
    'x': '시간',
    'y': '개수'
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
        # Chrome이 없을 때는 HTML 다운로드로 대체 (사용자에게는 동일하게 보임)
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
def load_data_simple(file_path):
    """간단한 데이터 로더 (기존 방식)"""
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

def detect_anomalies(df):
    """이상 패턴 탐지"""
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
    
    # 4. 비정상적인 템플릿 빈도 (매우 낮은 빈도)
    low_frequency = df[df['template_frequency'] < 10]
    anomalies['low_frequency'] = low_frequency
    
    # 5. 비정상적인 메시지 길이 (이상치)
    q75, q25 = np.percentile(df['message_len'], [75, 25])
    iqr = q75 - q25
    lower_bound = q25 - 1.5 * iqr
    upper_bound = q75 + 1.5 * iqr
    outlier_length = df[(df['message_len'] < lower_bound) | (df['message_len'] > upper_bound)]
    anomalies['outlier_length'] = outlier_length
    
    return anomalies

def main():
    st.title("MagicIAM 로그 이상탐지 대시보드 (일부 데이터)")
    st.markdown("---")
    
    # 파일 업로드 또는 기본 파일 사용
    # file_path = "/home/kongju/DREAM/MagicIAM/output/catalina_out_structured.ndjson" # 3 GB가 넘어서 사용하기 어려움 
    file_path = "/home/kongju/DREAM/MagicIAM/output/catalina_out_partial_structured.ndjson"
    
    st.sidebar.header("대시보드 설정")
    
    # 데이터 로드
    with st.spinner("IAM 로그 데이터를 로드하는 중..."):
        df = load_data_simple(file_path)
    
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
        st.metric("스택트레이스 포함", f"{len(df[df['has_stacktrace'] == True]):,}")
    
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
    
    # 이상 탐지
    anomalies = detect_anomalies(df_filtered)
    
    # 탭 구성
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "이상탐지 결과  |", "시계열 분석  |", "로그 레벨 분석  |", 
        "상세 분석  |", "로그 검색  |"
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
            
            # 다운로드 버튼 추가
            create_download_button(fig, "severity_distribution", "심각도 분포 그래프 다운로드")
        
        # 최근 이상 로그들
        st.subheader("최근 이상 로그 (상위 10개)")
        recent_anomalies = pd.concat([
            anomalies['high_severity'], 
            anomalies['with_stacktrace'], 
            anomalies['error_warn']
        ]).drop_duplicates().sort_values('timestamp', ascending=False).head(10)
        
        if not recent_anomalies.empty:
            display_cols = ['timestamp', 'level', 'severity_score', 'logger', 'message']
            st.dataframe(recent_anomalies[display_cols], use_container_width=True)
        else:
            st.info("이상 로그가 발견되지 않았습니다.")
    
    with tab2:
        st.header("시계열 분석")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # 날짜별 로그 수
            df_hourly = df_filtered.set_index('timestamp').resample('h').size().reset_index()
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
            
            # 다운로드 버튼 추가
            create_download_button(fig, "hourly_log_trend", "시간당 로그 수 추이 다운로드")
        
        with col2:
            # 로그 레벨별 시계열
            level_time = df_filtered.groupby([
                df_filtered['timestamp'].dt.floor('h'), 'level'
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
            
            # 다운로드 버튼 추가
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
        
        # 다운로드 버튼 추가
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
            
            # 다운로드 버튼 추가
            create_download_button(fig, "level_distribution_pie", "로그 레벨 분포 파이차트 다운로드")
        
        with col2:
            # 로그 카테고리 분포
            if 'log_category' in df_filtered.columns:
                category_counts = df_filtered['log_category'].value_counts()
                fig = px.bar(x=category_counts.values, y=category_counts.index,
                            orientation='h',
                            title="로그 카테고리 분포",
                            labels={'x': '개수', 'y': '카테고리'},
                            color_discrete_sequence=get_color_palette(len(category_counts)))
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    xaxis_title='개수',
                    yaxis_title='카테고리'
                )
                st.plotly_chart(fig, use_container_width=True)
                
                # 다운로드 버튼 추가
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
        
        # 다운로드 버튼 추가
        create_download_button(fig, "severity_level_sunburst", "심각도별 선버스트 차트 다운로드")
    
    with tab4:
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
                    
                    # 다운로드 버튼 추가
                    create_download_button(fig, "error_code_analysis", "에러 코드 분석 다운로드")
                else:
                    st.info("에러 코드가 없습니다.")
        
        with col2:
            st.subheader("메시지 분석")
            if 'word_count' in df_filtered.columns:
                word_counts = df_filtered[df_filtered['word_count'].notna()]['word_count']
                if not word_counts.empty:
                    fig = px.histogram(word_counts, 
                                     title="단어 수 분포",
                                     nbins=20,
                                     labels={'x': '단어 수', 'count': '빈도'},
                                     color_discrete_sequence=[get_color('info')])
                    fig.update_layout(
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)',
                        xaxis_title='단어 수',
                        yaxis_title='빈도'
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    # 다운로드 버튼 추가
                    create_download_button(fig, "word_count_distribution", "단어 수 분포 다운로드")
                    
                    # 단어 수 통계를 카드 형태로 표시
                    st.subheader("메시지 분석 통계")
                    
                    # 4개 컬럼으로 메트릭 카드 배치
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric(
                            label="평균 단어 수",
                            value=f"{word_counts.mean():.1f}",
                            help="메시지당 평균 단어 수"
                        )
                    
                    with col2:
                        if 'char_count' in df_filtered.columns:
                            char_counts = df_filtered[df_filtered['char_count'].notna()]['char_count']
                            st.metric(
                                label="평균 문자 수",
                                value=f"{char_counts.mean():.1f}",
                                help="메시지당 평균 문자 수"
                            )
                        else:
                            st.metric(
                                label="중앙값 단어 수",
                                value=f"{word_counts.median():.1f}",
                                help="메시지 단어 수의 중앙값"
                            )
                    
                    with col3:
                        st.metric(
                            label="최대 단어 수",
                            value=f"{word_counts.max():.0f}",
                            delta=f"+{(word_counts.max() - word_counts.mean()):.0f}",
                            delta_color="inverse",
                            help="가장 긴 메시지의 단어 수"
                        )
                    
                    with col4:
                        st.metric(
                            label="최소 단어 수",
                            value=f"{word_counts.min():.0f}",
                            delta=f"{(word_counts.min() - word_counts.mean()):.0f}",
                            delta_color="normal",
                            help="가장 짧은 메시지의 단어 수"
                        )
                else:
                    st.info("단어 수 데이터가 없습니다.")
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
                
                # 다운로드 버튼 추가
                create_download_button(fig, "template_frequency_distribution", "템플릿 빈도 분포 다운로드")
        
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
        
        # 다운로드 버튼 추가
        create_download_button(fig, "logger_distribution", "로거별 로그 수 다운로드")
    
    with tab5:
        st.header("로그 검색 및 필터링")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            search_level = st.selectbox("로그 레벨", ['전체'] + list(df_filtered['level'].unique()))
        
        with col2:
            search_logger = st.selectbox("로거", ['전체'] + list(df_filtered['logger'].unique()))
        
        with col3:
            min_severity = st.slider("최소 심각도", 0, 100, 0)
        
        search_text = st.text_input("메시지 검색 (키워드)")
        
        # 필터 적용
        filtered_df = df_filtered.copy()
        
        if search_level != '전체':
            filtered_df = filtered_df[filtered_df['level'] == search_level]
        
        if search_logger != '전체':
            filtered_df = filtered_df[filtered_df['logger'] == search_logger]
        
        filtered_df = filtered_df[filtered_df['severity_score'] >= min_severity]
        
        if search_text:
            filtered_df = filtered_df[filtered_df['message'].str.contains(search_text, case=False, na=False)]
        
        st.subheader(f"검색 결과: {len(filtered_df):,}개 로그")
        
        if not filtered_df.empty:
            display_cols = ['timestamp', 'level', 'severity_score', 'logger', 'message']
            st.dataframe(filtered_df[display_cols].sort_values('timestamp', ascending=False).head(100), 
                        use_container_width=True)
        else:
            st.info("검색 조건에 맞는 로그가 없습니다.")
    
    # 사이드바에 추가 정보
    st.sidebar.markdown("---")
    st.sidebar.subheader("데이터 정보")
    st.sidebar.write(f"총 로그 수: {len(df):,}")
    st.sidebar.write(f"분석 기간: {min_date} ~ {max_date}")
    st.sidebar.write(f"로그 레벨 종류: {len(df['level'].unique())}개")
    st.sidebar.write(f"로거 종류: {len(df['logger'].unique())}개")

if __name__ == "__main__":
    main()
