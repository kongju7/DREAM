#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
이상 탐지 데이터 EDA 대시보드
정제된 인증 로그 데이터에 대한 종합적인 탐색적 데이터 분석

Author: Kong Ju  
Date: 2025-09-29
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.figure_factory as ff
from datetime import datetime, timedelta
import sys
import os
from pathlib import Path
import ipaddress

# 색상 설정 import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from color_config import (
    COLORS, COLOR_PALETTE, LEVEL_COLORS, GRAPH_COLORS,
    get_color, get_color_palette, get_level_colors, get_graph_color
)

# 국가 매핑 import
from country_code_ko_mapper import alpha2_to_korean

# 페이지 설정
st.set_page_config(
    page_title="인증 로그 이상 탐지 EDA 대시보드",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 기본 색상 정의 (단순화)
PRIMARY_COLOR = get_color('primary')  # '#00599B'
SUCCESS_COLOR = get_color('success')  # 성공
ERROR_COLOR = get_color('error')      # 실패/에러
WARNING_COLOR = get_color('warning')  # 경고
NORMAL_COLOR = get_color('normal')    # 정상

# 한글 라벨 매핑
KOREAN_LABELS = {
    # 기본 필드
    'session_id': '세션 ID',
    'timestamp': '시간',
    'event': '이벤트',
    'status': '상태',
    'user_id': '사용자 ID',
    'source_ip': 'IP 주소',
    
    # 시간 관련
    'ts_hour': '시간',
    'ts_dayofweek': '요일',
    'ts_is_weekend': '주말 여부',
    'ts_is_business_hours': '업무시간 여부',
    
    # 세션 관련
    'duration_ms': '세션 지속시간(ms)',
    'n_events': '이벤트 수',
    'is_successful': '성공 여부',
    'n_failures': '실패 횟수',
    'avg_step_interval': '평균 단계 간격',
    
    # 이상 탐지 관련
    'anomaly_score_final': '이상 점수',
    'step_jump': '단계 점프',
    'step_reverse': '단계 역행',
    'delta_too_fast': '너무 빠른 요청',
    'delta_too_slow': '너무 느린 요청',
    'has_error_keyword': '오류 키워드 포함',
    
    # 기타
    'count': '개수',
    'frequency': '빈도'
}

# 요일 한글 변환
WEEKDAY_KOREAN = ['월요일', '화요일', '수요일', '목요일', '금요일', '토요일', '일요일']

def hex_to_rgba(hex_color, alpha=0.3):
    """헥스 색상을 rgba로 변환"""
    hex_color = hex_color.lstrip('#')
    rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
    return f'rgba({rgb[0]}, {rgb[1]}, {rgb[2]}, {alpha})'

def create_download_button(fig, filename, button_text="그래프 다운로드"):
    """Plotly 그래프 다운로드 버튼 생성"""
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
        img_bytes = fig.to_image(format="png", width=1200, height=800, scale=2)
        st.download_button(
            label=button_text,
            data=img_bytes,
            file_name=f"{filename}.png",
            mime="image/png",
            key=f"download_{filename}_{hash(str(fig))}",
            help="고해상도 PNG 이미지로 다운로드합니다"
        )
        return True
    except Exception as e:
        html_str = fig.to_html()
        st.download_button(
            label=button_text,
            data=html_str,
            file_name=f"{filename}.html",
            mime="text/html",
            key=f"download_{filename}_{hash(str(fig))}",
            help="인터랙티브 HTML 파일로 다운로드합니다"
        )
        return False

@st.cache_data
def load_processed_data():
    """전처리된 데이터 로드"""
    data_dir = Path(__file__).parent / "processed_data"
    
    try:
        events_df = pd.read_csv(data_dir / "events_processed.csv")
        sessions_df = pd.read_csv(data_dir / "sessions_aggregated.csv")
        
        # 타임스탬프 변환
        if 'timestamp' in events_df.columns:
            events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])
        if 'timestamp_min' in sessions_df.columns:
            sessions_df['timestamp_min'] = pd.to_datetime(sessions_df['timestamp_min'])
        if 'timestamp_max' in sessions_df.columns:
            sessions_df['timestamp_max'] = pd.to_datetime(sessions_df['timestamp_max'])
        
        return events_df, sessions_df
    
    except FileNotFoundError as e:
        st.error(f"데이터 파일을 찾을 수 없습니다: {e}")
        st.info("먼저 anomaly_detection_preprocessor.py를 실행하여 데이터를 전처리하세요.")
        return pd.DataFrame(), pd.DataFrame()
    except Exception as e:
        st.error(f"데이터 로드 중 오류 발생: {e}")
        return pd.DataFrame(), pd.DataFrame()

def get_country_from_ip(ip_list):
    """IP 주소를 국가명으로 변환"""
    # 간단한 IP-국가 매핑 (테스트 데이터용)
    # 실제 환경에서는 IP 데이터베이스를 사용해야 함
    country_map = {
        '203.0.113.1': 'KR',
        '203.0.113.2': 'KR', 
        '203.0.113.3': 'KR',
        '192.168.1.1': 'KR',
        '10.0.0.1': 'KR',
        '127.0.0.1': 'KR'
    }
    
    countries = []
    for ip in ip_list:
        if pd.isna(ip):
            countries.append('Unknown')
            continue
            
        # 테스트 네트워크는 한국으로 매핑
        try:
            ip_obj = ipaddress.ip_address(str(ip))
            if ip_obj.is_private or str(ip).startswith('203.0.113'):
                country_code = 'KR'
            else:
                country_code = country_map.get(str(ip), 'Unknown')
        except:
            country_code = 'Unknown'
        
        # 국가 코드를 한국어 국가명으로 변환
        if country_code == 'Unknown':
            countries.append('알 수 없음')
        else:
            country_name = alpha2_to_korean(country_code)
            countries.append(country_name if country_name else '알 수 없음')
    
    return countries

def get_basic_statistics(events_df, sessions_df):
    """기본 통계 정보 계산"""
    stats = {}
    
    if not events_df.empty and not sessions_df.empty:
        stats['total_events'] = len(events_df)
        stats['total_sessions'] = len(sessions_df)
        stats['success_rate'] = (sessions_df['is_successful'] == 1).mean() * 100
        stats['avg_events_per_session'] = len(events_df) / len(sessions_df)
        
        # 이상 탐지 관련 통계
        if 'anomaly_score_final' in sessions_df.columns:
            stats['high_anomaly_sessions'] = (sessions_df['anomaly_score_final'] > 1.0).sum()
            stats['avg_anomaly_score'] = sessions_df['anomaly_score_final'].mean()
        
        # 이상 패턴 통계
        anomaly_patterns = {}
        for col in ['step_jump', 'delta_too_fast', 'delta_too_slow', 'has_error_keyword']:
            if col in events_df.columns:
                anomaly_patterns[col] = (events_df[col] > 0).sum()
        stats['anomaly_patterns'] = anomaly_patterns
    
    return stats

def plot_overview_metrics(stats):
    """개요 메트릭 표시"""
    if not stats:
        st.warning("통계 데이터를 계산할 수 없습니다.")
        return
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "총 이벤트 수", 
            f"{stats.get('total_events', 0):,}"
        )
    
    with col2:
        st.metric(
            "총 세션 수", 
            f"{stats.get('total_sessions', 0):,}"
        )
    
    with col3:
        success_rate = stats.get('success_rate', 0)
        st.metric(
            "성공률", 
            f"{success_rate:.1f}%",
            delta=f"{success_rate - 80:.1f}%" if success_rate < 80 else None,
            delta_color="inverse" if success_rate < 80 else "normal"
        )
    
    with col4:
        high_anomaly = stats.get('high_anomaly_sessions', 0)
        st.metric(
            "고위험 세션", 
            f"{high_anomaly:,}개",
            delta=f"{high_anomaly / stats.get('total_sessions', 1) * 100:.1f}%"
        )

def plot_session_analysis(sessions_df):
    """세션 분석 시각화"""
    if sessions_df.empty:
        st.warning("세션 데이터가 없습니다.")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        # 성공/실패 분포 (도넛 차트로 변경)
        success_counts = sessions_df['is_successful'].value_counts()
        success_labels = ['실패', '성공']
        
        fig = go.Figure(data=[go.Pie(
            labels=success_labels,
            values=success_counts.values,
            hole=0.4,
            marker_colors=[ERROR_COLOR, SUCCESS_COLOR]
        )])
        fig.update_layout(
            title="세션 성공/실패 분포",
            showlegend=True,
            annotations=[dict(text='세션', x=0.5, y=0.5, font_size=20, showarrow=False)]
        )
        fig.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig, config={'displayModeBar': False})
        create_download_button(fig, "session_success_distribution", "성공/실패 분포 다운로드")
    
    with col2:
        # 이상 점수 분포 (히스토그램 -> 박스 플롯으로 변경)
        if 'anomaly_score_final' in sessions_df.columns:
            fig = go.Figure()
            
            fig.add_trace(go.Box(
                y=sessions_df['anomaly_score_final'],
                name='이상 점수',
                boxpoints='all',
                jitter=0.3,
                pointpos=-1.8,
                fillcolor=PRIMARY_COLOR,
                line=dict(color=PRIMARY_COLOR),
                marker=dict(color=PRIMARY_COLOR, size=4)
            ))
            
            # 임계값 라인 추가
            fig.add_hline(
                y=1.0,
                line_dash="dash",
                line_color=WARNING_COLOR,
                annotation_text="위험 임계점"
            )
            
            fig.update_layout(
                title="세션별 이상 점수 분포",
                yaxis_title="이상 점수",
                showlegend=False
            )
            st.plotly_chart(fig, config={'displayModeBar': False})
            create_download_button(fig, "anomaly_score_distribution", "이상 점수 분포 다운로드")

def plot_time_analysis(events_df, sessions_df):
    """시간 기반 분석"""
    if events_df.empty:
        st.warning("이벤트 데이터가 없습니다.")
        return
    
    # 시간별 패턴
    if 'ts_hour' in events_df.columns:
        col1, col2 = st.columns(2)
        
        with col1:
            # 시간별 이벤트 분포 (레이더 차트로 변경)
            hourly_counts = events_df['ts_hour'].value_counts().sort_index()
            
            # 24시간 전체를 포함하도록 보정
            full_hours = range(24)
            hourly_data = [hourly_counts.get(hour, 0) for hour in full_hours]
            
            fig = go.Figure()
            
            
            fig.add_trace(go.Scatterpolar(
                r=hourly_data,
                theta=[f"{hour}시" for hour in full_hours],
                fill='toself',
                fillcolor=hex_to_rgba(PRIMARY_COLOR, 0.3),
                line=dict(color=PRIMARY_COLOR, width=2),
                name='이벤트 수'
            ))
            
            fig.update_layout(
                polar=dict(
                    radialaxis=dict(
                        visible=True,
                        range=[0, max(hourly_data) * 1.1] if max(hourly_data) > 0 else [0, 1]
                    )),
                title="시간대별 이벤트 분포 (24시간)",
                showlegend=False
            )
            st.plotly_chart(fig, config={'displayModeBar': False})
            create_download_button(fig, "hourly_events", "시간별 이벤트 분포 다운로드")
        
        with col2:
            # 요일별 패턴 (방사형 막대 차트)
            if 'ts_dayofweek' in events_df.columns:
                weekday_counts = events_df['ts_dayofweek'].value_counts().sort_index()
                
                # 7일 전체를 포함하도록 보정
                full_weekdays = range(7)
                weekday_data = [weekday_counts.get(day, 0) for day in full_weekdays]
                weekday_labels = [WEEKDAY_KOREAN[i] for i in full_weekdays]
                
                fig = go.Figure()
                
                fig.add_trace(go.Scatterpolar(
                    r=weekday_data,
                    theta=weekday_labels,
                    fill='toself',
                    fillcolor=hex_to_rgba(SUCCESS_COLOR, 0.3),
                    line=dict(color=SUCCESS_COLOR, width=2),
                    name='이벤트 수'
                ))
                
                fig.update_layout(
                    polar=dict(
                        radialaxis=dict(
                            visible=True,
                            range=[0, max(weekday_data) * 1.1] if max(weekday_data) > 0 else [0, 1]
                        )),
                    title="요일별 이벤트 분포",
                    showlegend=False
                )
                st.plotly_chart(fig, config={'displayModeBar': False})
                create_download_button(fig, "weekday_events", "요일별 이벤트 분포 다운로드")
    
    # 세션 지속시간 분석 (표로 변경)
    if not sessions_df.empty and 'duration_ms' in sessions_df.columns:
        st.subheader("세션별 지속시간")
        
        # 세션 정보를 표 형태로 준비
        sessions_display = sessions_df.copy()
        sessions_display['세션 ID (마지막 8자리)'] = sessions_display['session_id'].str[-8:]
        sessions_display['지속시간(ms)'] = sessions_display['duration_ms'].apply(lambda x: f"{x:.0f}")
        sessions_display['상태'] = sessions_display['is_successful'].apply(lambda x: '성공' if x == 1 else '실패')
        sessions_display['이벤트 수'] = sessions_display['event_count'] if 'event_count' in sessions_display.columns else 'N/A'
        
        # 표에 표시할 컬럼 선택
        display_columns = ['세션 ID (마지막 8자리)', '지속시간(ms)', '상태', '이벤트 수']
        table_data = sessions_display[display_columns]
        
        # Streamlit 표로 표시
        st.dataframe(
            table_data,
            use_container_width=True,
            hide_index=True,
            column_config={
                '세션 ID (마지막 8자리)': st.column_config.TextColumn(
                    '세션 ID',
                    help='세션 ID의 마지막 8자리'
                ),
                '지속시간(ms)': st.column_config.TextColumn(
                    '지속시간(ms)',
                    help='세션 지속시간 (밀리초)'
                ),
                '상태': st.column_config.TextColumn(
                    '상태',
                    help='세션 성공/실패 상태'
                ),
                '이벤트 수': st.column_config.TextColumn(
                    '이벤트 수',
                    help='세션 내 이벤트 수'
                )
            }
        )
        
        # CSV 다운로드 버튼
        csv_data = table_data.to_csv(index=False, encoding='utf-8-sig')
        st.download_button(
            label="세션별 지속시간 표 다운로드 (CSV)",
            data=csv_data,
            file_name="session_duration_table.csv",
            mime="text/csv"
        )

def plot_authentication_flow(events_df):
    """인증 플로우 분석"""
    if events_df.empty:
        st.warning("이벤트 데이터가 없습니다.")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        # 이벤트 타입별 분포 (트리맵으로 변경)
        if 'event' in events_df.columns:
            event_counts = events_df['event'].value_counts()
            
            fig = go.Figure(go.Treemap(
                labels=event_counts.index,
                values=event_counts.values,
                parents=[""] * len(event_counts),
                textinfo="label+value+percent parent",
                marker_colorscale=[[0, PRIMARY_COLOR], [1, SUCCESS_COLOR]],
                textfont_size=12
            ))
            
            fig.update_layout(
                title="이벤트 타입별 분포",
                font_size=12
            )
            st.plotly_chart(fig, config={'displayModeBar': False})
            create_download_button(fig, "event_types", "이벤트 타입 분포 다운로드")
    
    with col2:
        # 단계별 분포 (막대 그래프로 변경)
        if 'step_id' in events_df.columns:
            step_counts = events_df['step_id'].value_counts().sort_index()
            
            fig = go.Figure()
            
            fig.add_trace(go.Bar(
                x=step_counts.index,
                y=step_counts.values,
                marker_color=PRIMARY_COLOR,
                name='이벤트 수',
                text=step_counts.values,
                textposition='outside'
            ))
            
            fig.update_layout(
                title="인증 단계별 분포",
                xaxis_title="단계 ID",
                yaxis_title="이벤트 수",
                showlegend=False,
                xaxis=dict(
                    type='category',  # x축을 카테고리(정수)로 설정
                    tickmode='array',
                    tickvals=list(step_counts.index),
                    ticktext=[str(x) for x in step_counts.index]
                ),
                yaxis=dict(range=[0, step_counts.values.max() * 1.1])  # y축 0부터 시작
            )
            st.plotly_chart(fig, config={'displayModeBar': False})
            create_download_button(fig, "auth_steps", "인증 단계 분포 다운로드")
    
    # 단계 이상 패턴 분석 (히트맵으로 변경)
    anomaly_cols = ['step_jump', 'step_reverse', 'step_event_mismatch']
    existing_cols = [col for col in anomaly_cols if col in events_df.columns]
    
    if existing_cols:
        anomaly_data = []
        anomaly_labels = []
        
        for col in existing_cols:
            count = (events_df[col] > 0).sum()
            if count > 0:
                anomaly_data.append([count])
                anomaly_labels.append(col.replace('_', ' ').title())
        
        if anomaly_data:
            fig = go.Figure(data=go.Heatmap(
                z=anomaly_data,
                y=anomaly_labels,
                x=['발생 횟수'],
                colorscale=[[0, 'white'], [1, WARNING_COLOR]],
                showscale=True,
                text=anomaly_data,
                texttemplate="%{text}",
                textfont={"size": 16}
            ))
            
            fig.update_layout(
                title="인증 플로우 이상 패턴",
                xaxis_title="",
                yaxis_title=""
            )
            st.plotly_chart(fig, config={'displayModeBar': False})
            create_download_button(fig, "auth_flow_anomalies", "인증 플로우 이상 패턴 다운로드")

def plot_detailed_anomalies(events_df):
    """상세 이상 패턴 분석"""
    if events_df.empty:
        st.warning("이벤트 데이터가 없습니다.")
        return
    
    # 이상 패턴별 분석
    anomaly_features = [
        'delta_too_fast', 'delta_too_slow', 'has_error_keyword', 
        'simultaneous_event', 'message_unusual_length'
    ]
    
    existing_features = [feat for feat in anomaly_features if feat in events_df.columns]
    
    if not existing_features:
        st.info("이상 패턴 특징이 없습니다.")
        return
    
    # 이상 패턴 요약
    anomaly_summary = {}
    for feature in existing_features:
        count = (events_df[feature] > 0).sum()
        if count > 0:
            anomaly_summary[feature.replace('_', ' ').title()] = count
    
    if anomaly_summary:
        col1, col2 = st.columns(2)
        
        with col1:
            # 이상 패턴 선버스트 차트
            labels = list(anomaly_summary.keys())
            values = list(anomaly_summary.values())
            
            fig = go.Figure()
            
            fig.add_trace(go.Bar(
                x=labels,
                y=values,
                marker_color=[WARNING_COLOR, ERROR_COLOR, PRIMARY_COLOR][:len(labels)],
                text=values,
                textposition='outside',
                opacity=0.8
            ))
            
            fig.update_layout(
                title="이상 패턴별 발생 현황",
                xaxis_title="이상 패턴 유형",
                yaxis_title="발생 건수",
                showlegend=False,
                yaxis=dict(range=[0, max(values) * 1.1]) if values else dict(range=[0, 1])
            )
            st.plotly_chart(fig, config={'displayModeBar': False})
            create_download_button(fig, "anomaly_patterns", "이상 패턴 발생 현황 다운로드")
        
        with col2:
            # 시간 간격 이상 분석 (히스토그램 -> 밀도 플롯으로 변경)
            if 'delta_ms' in events_df.columns:
                # 정상 범위 이외의 시간 간격 분석
                normal_deltas = events_df[
                    (events_df['delta_ms'] >= 10) & 
                    (events_df['delta_ms'] <= 30000)
                ]['delta_ms']
                
                if len(normal_deltas) > 0:
                    # 값 빈도 계산
                    value_counts = normal_deltas.value_counts().sort_index()
                    
                    # 막대 그래프로 표시
                    fig = go.Figure()
                    fig.add_trace(go.Bar(
                        x=[f"{idx:.0f}ms" for idx in value_counts.index],
                        y=value_counts.values,
                        marker_color=PRIMARY_COLOR,
                        opacity=0.8,
                        text=value_counts.values,
                        textposition='outside',
                        marker_line=dict(width=1, color='white')
                    ))
                    
                    fig.update_layout(
                        title="정상 범위 시간 간격 분포",
                        xaxis_title="시간 간격(ms)",
                        yaxis_title="빈도",
                        showlegend=False,
                        yaxis=dict(range=[0, value_counts.max() * 1.1]),
                        xaxis=dict(type='category')  # 카테고리형으로 설정
                    )
                    
                    st.plotly_chart(fig, config={'displayModeBar': False})
                    create_download_button(fig, "time_intervals", "시간 간격 분포 다운로드")

def plot_user_ip_analysis(events_df):
    """사용자 및 IP 분석"""
    if events_df.empty:
        st.warning("이벤트 데이터가 없습니다.")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        # 사용자별 이벤트 수 (일반 막대 그래프로 변경)
        if 'user_id' in events_df.columns:
            user_counts = events_df['user_id'].value_counts().head(10)
            
            fig = go.Figure()
            
            # #B1B1B2 기반 투명도 색상 생성
            base_color_hex = 'B1B1B2'
            base_r, base_g, base_b = int(base_color_hex[:2], 16), int(base_color_hex[2:4], 16), int(base_color_hex[4:], 16)
            
            # 사용자별로 다른 투명도 생성
            transparent_colors = []
            for i, user in enumerate(user_counts.index):
                alpha = 0.3 + (i * 0.6) / max(1, len(user_counts.index) - 1)  # 0.3~0.9 투명도
                transparent_colors.append(f'rgba({base_r},{base_g},{base_b},{alpha})')
            
            fig.add_trace(go.Bar(
                x=user_counts.index,
                y=user_counts.values,
                marker_color=transparent_colors,
                text=user_counts.values,
                textposition='outside'
            ))
            
            fig.update_layout(
                title="사용자별 이벤트 수",
                xaxis_title="사용자 ID",
                yaxis_title="이벤트 수",
                showlegend=False,
                yaxis=dict(range=[0, user_counts.values.max() * 1.1])  # y축 0부터 시작
            )
            st.plotly_chart(fig, config={'displayModeBar': False})
            create_download_button(fig, "user_events", "사용자별 이벤트 수 다운로드")
    
    with col2:
        # IP 국가별 분포 (새로 추가)
        if 'source_ip' in events_df.columns:
            # IP를 국가명으로 변환
            countries = get_country_from_ip(events_df['source_ip'].tolist())
            events_df_temp = events_df.copy()
            events_df_temp['country'] = countries
            
            country_counts = pd.Series(countries).value_counts()
            
            fig = go.Figure(data=[go.Pie(
                labels=country_counts.index,
                values=country_counts.values,
                hole=0.3,
                marker_colors=[PRIMARY_COLOR, SUCCESS_COLOR, WARNING_COLOR][:len(country_counts)]
            )])
            
            fig.update_layout(
                title="IP 국가별 분포",
                annotations=[dict(text='국가', x=0.5, y=0.5, font_size=16, showarrow=False)]
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, config={'displayModeBar': False})
            create_download_button(fig, "ip_countries", "IP 국가별 분포 다운로드")
    
    # IP별 이벤트 수 (전체 너비로 표시, 워드클라우드 스타일)
    if 'source_ip' in events_df.columns:
        ip_counts = events_df['source_ip'].value_counts().head(10)
        
        # 버블 차트로 표시
        fig = go.Figure()
        
        # 버블 크기에 따른 그라데이션 색상
        bubble_sizes = ip_counts.values * 50
        max_size = bubble_sizes.max()
        min_size = bubble_sizes.min()
        
        # 크기에 비례한 색상 그라데이션 (작은 버블: 연한 색, 큰 버블: 진한 색)
        bubble_colors = []
        text_colors = []  # 텍스트 색상 배열
        for size in bubble_sizes:
            intensity = (size - min_size) / max(1, max_size - min_size)  # 0~1 정규화
            # PRIMARY_COLOR 기반으로 투명도/밝기 조정
            r, g, b = 0, 89, 155  # PRIMARY_COLOR (#00599B) RGB 값
            alpha = 0.3 + (intensity * 0.7)  # 0.3~1.0 투명도
            bubble_colors.append(f'rgba({r},{g},{b},{alpha})')
            
            # 작은 버블은 검은색 텍스트, 큰 버블은 흰색 텍스트
            if intensity < 0.5:  # 작은 버블
                text_colors.append('black')
            else:  # 큰 버블
                text_colors.append('white')
        
        # 텍스트 색상별로 별도 trace 생성
        small_bubble_indices = [i for i, color in enumerate(text_colors) if color == 'black']
        large_bubble_indices = [i for i, color in enumerate(text_colors) if color == 'white']
        
        # 작은 버블 (검은색 텍스트)
        if small_bubble_indices:
            fig.add_trace(go.Scatter(
                x=[i for i in small_bubble_indices],
                y=[1] * len(small_bubble_indices),
                mode='markers+text',
                marker=dict(
                    size=[bubble_sizes[i] for i in small_bubble_indices],
                    color=[bubble_colors[i] for i in small_bubble_indices],
                    line=dict(width=2, color='rgba(0,89,155,0.8)')
                ),
                text=[ip_counts.index[i] for i in small_bubble_indices],
                textposition="middle center",
                textfont=dict(size=12, color='black'),
                name='작은 IP',
                showlegend=False
            ))
        
        # 큰 버블 (흰색 텍스트)
        if large_bubble_indices:
            fig.add_trace(go.Scatter(
                x=[i for i in large_bubble_indices],
                y=[1] * len(large_bubble_indices),
                mode='markers+text',
                marker=dict(
                    size=[bubble_sizes[i] for i in large_bubble_indices],
                    color=[bubble_colors[i] for i in large_bubble_indices],
                    line=dict(width=2, color='rgba(0,89,155,0.8)')
                ),
                text=[ip_counts.index[i] for i in large_bubble_indices],
                textposition="middle center",
                textfont=dict(size=12, color='white'),
                name='큰 IP',
                showlegend=False
            ))
        
        fig.update_layout(
            title="IP별 이벤트 수 (버블 크기 = 이벤트 수)",
            xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            yaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
            showlegend=False,
            height=300
        )
        st.plotly_chart(fig, config={'displayModeBar': False})
        create_download_button(fig, "ip_events_bubble", "IP별 이벤트 버블차트 다운로드")

def show_data_quality_report(events_df, sessions_df):
    """데이터 품질 리포트"""
    st.subheader("데이터 품질 리포트")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**이벤트 데이터**")
        if not events_df.empty:
            st.write(f"- 총 행 수: {len(events_df):,}")
            st.write(f"- 총 컬럼 수: {len(events_df.columns)}")
            
            # 결측값 분석
            missing_counts = events_df.isnull().sum()
            missing_pct = (missing_counts / len(events_df) * 100).round(2)
            missing_data = pd.DataFrame({
                '컬럼': missing_counts.index,
                '결측값 수': missing_counts.values,
                '결측값 비율(%)': missing_pct.values
            })
            missing_data = missing_data[missing_data['결측값 수'] > 0]
            
            if len(missing_data) > 0:
                st.write("**결측값이 있는 컬럼:**")
                st.dataframe(missing_data, width="stretch")
            else:
                st.write("- 결측값: 없음")
        else:
            st.write("데이터가 없습니다.")
    
    with col2:
        st.write("**세션 데이터**")
        if not sessions_df.empty:
            st.write(f"- 총 행 수: {len(sessions_df):,}")
            st.write(f"- 총 컬럼 수: {len(sessions_df.columns)}")
            
            # 결측값 분석
            missing_counts = sessions_df.isnull().sum()
            missing_pct = (missing_counts / len(sessions_df) * 100).round(2)
            missing_data = pd.DataFrame({
                '컬럼': missing_counts.index,
                '결측값 수': missing_counts.values,
                '결측값 비율(%)': missing_pct.values
            })
            missing_data = missing_data[missing_data['결측값 수'] > 0]
            
            if len(missing_data) > 0:
                st.write("**결측값이 있는 컬럼:**")
                st.dataframe(missing_data, width="stretch")
            else:
                st.write("- 결측값: 없음")
        else:
            st.write("데이터가 없습니다.")

def main():
    st.title("인증 로그 이상 탐지 EDA 대시보드")
    st.markdown("전처리된 인증 로그 데이터에 대한 종합적인 탐색적 데이터 분석")
    st.markdown("---")
    
    # 데이터 로드
    with st.spinner("데이터를 로드하는 중..."):
        events_df, sessions_df = load_processed_data()
    
    if events_df.empty and sessions_df.empty:
        st.error("데이터를 로드할 수 없습니다. 먼저 데이터 전처리를 수행하세요.")
        return
    
    # 기본 통계 계산
    stats = get_basic_statistics(events_df, sessions_df)
    
    # 사이드바 설정
    st.sidebar.header("대시보드 설정")
    st.sidebar.markdown("---")
    
    # 개요 메트릭
    plot_overview_metrics(stats)
    st.markdown("---")
    
    # 탭 구성
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "세션 분석", "시계열 분석", "인증 플로우", 
        "이상 패턴", "사용자/IP 분석", "데이터 품질"
    ])
    
    with tab1:
        st.header("세션 기반 분석")
        plot_session_analysis(sessions_df)
        
        # 세션 상세 통계
        if not sessions_df.empty:
            st.subheader("세션 상세 통계")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                avg_duration = sessions_df['duration_ms'].mean() if 'duration_ms' in sessions_df.columns else 0
                st.metric("평균 세션 시간", f"{avg_duration:.0f}ms")
            
            with col2:
                avg_events = sessions_df['n_events'].mean() if 'n_events' in sessions_df.columns else 0
                st.metric("평균 이벤트 수", f"{avg_events:.1f}개")
            
            with col3:
                failure_rate = (sessions_df['n_failures'].sum() / len(sessions_df)) if 'n_failures' in sessions_df.columns else 0
                st.metric("평균 실패 횟수", f"{failure_rate:.2f}회")
            
            with col4:
                if 'anomaly_score_final' in sessions_df.columns:
                    high_risk_pct = (sessions_df['anomaly_score_final'] > 1.0).mean() * 100
                    st.metric("고위험 세션 비율", f"{high_risk_pct:.1f}%")
    
    with tab2:
        st.header("시계열 분석")
        plot_time_analysis(events_df, sessions_df)
    
    with tab3:
        st.header("인증 플로우 분석")
        plot_authentication_flow(events_df)
    
    with tab4:
        st.header("이상 패턴 상세 분석")
        plot_detailed_anomalies(events_df)
    
    with tab5:
        st.header("사용자 및 IP 분석")
        plot_user_ip_analysis(events_df)
    
    with tab6:
        st.header("데이터 품질 리포트")
        show_data_quality_report(events_df, sessions_df)
    
    # 사이드바 데이터 정보
    st.sidebar.markdown("---")
    st.sidebar.subheader("데이터 정보")
    
    if stats:
        st.sidebar.write(f"총 이벤트: {stats.get('total_events', 0):,}개")
        st.sidebar.write(f"총 세션: {stats.get('total_sessions', 0):,}개")
        st.sidebar.write(f"성공률: {stats.get('success_rate', 0):.1f}%")
        
        if 'anomaly_patterns' in stats:
            st.sidebar.write("**이상 패턴 발생:**")
            for pattern, count in stats['anomaly_patterns'].items():
                if count > 0:
                    st.sidebar.write(f"- {pattern.replace('_', ' ')}: {count}개")

if __name__ == "__main__":
    main()