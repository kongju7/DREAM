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
import base64
import numpy as np

# 로고 위치 
logo_path = "/home/kongju/DATA/DREAM/IMG/digicap_logo.png"

# 전역 이상 패턴 매핑 (노란색 계열의 조화로운 색상)
GLOBAL_PATTERN_MAPPING = {
    'delta_too_fast': {'name': '너무 빠른 요청', 'color': '#FFD700'},      # 골드
    'delta_too_slow': {'name': '너무 느린 요청', 'color': '#FFA500'},       # 오렌지
    'has_error_keyword': {'name': '오류 키워드', 'color': '#FF8C00'},       # 다크 오렌지
    'simultaneous_event': {'name': '동시 이벤트', 'color': '#F0E68C'},      # 카키
    'message_unusual_length': {'name': '비정상 메시지 길이', 'color': '#FFFF00'}, # 옐로우
    'step_jump': {'name': '단계 점프', 'color': '#FFB347'},                 # 살구색
    'step_reverse': {'name': '단계 역행', 'color': '#DAA520'},              # 골든로드
    'high_anomaly_score': {'name': '높은 이상 점수', 'color': '#B8860B'}    # 다크 골든로드
}

def get_pattern_display_name(pattern_key):
    """이상 패턴 키를 한국어 표시명으로 변환"""
    return GLOBAL_PATTERN_MAPPING.get(pattern_key, {'name': pattern_key.replace('_', ' ').title()})['name']

def get_pattern_color(pattern_key):
    """이상 패턴 키의 색상 반환"""
    return GLOBAL_PATTERN_MAPPING.get(pattern_key, {'color': '#999999'})['color']

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

@st.cache_data(ttl=300, show_spinner="데이터 로딩 중...")  # 5분 캐시
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
        
        # 이상 패턴 통계 (전역 매핑 사용)
        anomaly_patterns = {}
        for col in GLOBAL_PATTERN_MAPPING.keys():
            if col in events_df.columns:
                anomaly_patterns[col] = (events_df[col] > 0).sum()
        stats['anomaly_patterns'] = anomaly_patterns
    
    return stats

@st.cache_data(ttl=300, hash_funcs={pd.DataFrame: lambda df: str(df.shape) + str(df.dtypes.to_dict())})
def calculate_basic_stats(events_df, sessions_df):
    """기본 통계 계산 (캐시됨)"""
    stats = {}
    
    if not events_df.empty:
        stats['total_events'] = len(events_df)
        stats['unique_sessions'] = events_df['session_id'].nunique()
        stats['unique_users'] = events_df['user_id'].nunique() if 'user_id' in events_df.columns else 0
        stats['unique_ips'] = events_df['source_ip'].nunique() if 'source_ip' in events_df.columns else 0
        
        if 'timestamp' in events_df.columns:
            stats['date_range'] = {
                'start': events_df['timestamp'].min(),
                'end': events_df['timestamp'].max()
            }
    
    if not sessions_df.empty:
        stats['successful_sessions'] = (sessions_df['is_successful'] == 1).sum() if 'is_successful' in sessions_df.columns else 0
        stats['total_sessions'] = len(sessions_df)
        
        if 'anomaly_score_final' in sessions_df.columns:
            stats['high_anomaly_sessions'] = (sessions_df['anomaly_score_final'] > 1.0).sum()
            stats['avg_anomaly_score'] = sessions_df['anomaly_score_final'].mean()
    
    return stats

@st.cache_data(ttl=300)  # 5분 캐시
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
        # 성공/실패 분포 (누적 막대 그래프)
        success_counts = sessions_df['is_successful'].value_counts().rename(index={0: '실패', 1: '성공'})
        success_df = success_counts.reset_index()
        success_df.columns = ['상태', '세션 수']

        fig = px.bar(
            success_df,
            x='세션 수',
            y='상태',
            orientation='h',
            color='상태',
            color_discrete_map={'성공': SUCCESS_COLOR, '실패': ERROR_COLOR},
            text='세션 수'
        )
        fig.update_layout(
            title="세션 성공/실패 분포",
            xaxis_title="세션 수",
            yaxis_title="상태",
            showlegend=False
        )
        fig.update_xaxes(tickformat="d", dtick=1)  # 정수 형태로 표시, 1 간격으로 눈금
        fig.update_traces(texttemplate='%{x:d}')  # 텍스트도 정수로 표시
        fig.update_traces(textposition='outside')
        st.plotly_chart(fig, config={'displayModeBar': False, 'responsive': True}, 
                       use_container_width=True)
        create_download_button(fig, "session_success_distribution", "성공/실패 분포 다운로드")

    with col2:
        # 이상 점수 분포 (박스 플롯 + 분포 요약)
        if 'anomaly_score_final' in sessions_df.columns:
            fig = go.Figure()

            fig.add_trace(go.Box(
                y=sessions_df['anomaly_score_final'],
                name='이상 점수',
                boxpoints='outliers',
                jitter=0.2,
                pointpos=-1.6,
                fillcolor=hex_to_rgba(PRIMARY_COLOR, 0.4),
                line=dict(color=PRIMARY_COLOR),
                marker=dict(color=PRIMARY_COLOR, size=6),
                hovertemplate="<b>이상 점수</b><br>중위값: %{median:.3f}<extra></extra>"
            ))

            fig.add_hline(
                y=1.0,
                line_dash="dash",
                line_color=WARNING_COLOR,
                annotation_text="위험 임계점",
                annotation_position="top right"
            )

            fig.update_layout(
                title="세션별 이상 점수 분포",
                yaxis_title="이상 점수",
                showlegend=False
            )
            st.plotly_chart(fig, config={'displayModeBar': False})
            create_download_button(fig, "anomaly_score_distribution", "이상 점수 분포 다운로드")

    # 세션 분포 추가 시각화
    addl_col1, addl_col2 = st.columns(2)

    if 'duration_ms' in sessions_df.columns:
        with addl_col1:
            # 성공 여부를 명확한 카테고리로 변환
            sessions_df_display = sessions_df.copy()
            sessions_df_display['성공여부'] = sessions_df_display['is_successful'].map({1: '성공', 0: '실패'})
            
            duration_fig = px.histogram(
                sessions_df_display,
                x='duration_ms',
                nbins=30,
                color='성공여부',
                color_discrete_map={'성공': SUCCESS_COLOR, '실패': ERROR_COLOR},
                labels={'duration_ms': '세션 지속시간(ms)', '성공여부': '성공 여부'}
            )
            duration_fig.update_layout(
                title="세션 지속시간 분포",
                bargap=0.05,
                legend_title="성공 여부",
                yaxis_title="세션 수"
            )
            duration_fig.update_yaxes(tickformat="d", dtick=1)  # y축을 정수 간격으로 설정
            st.plotly_chart(duration_fig, config={'displayModeBar': False})
            create_download_button(duration_fig, "session_duration_hist", "세션 지속시간 분포 다운로드")

    if 'n_events' in sessions_df.columns:
        with addl_col2:
            events_fig = px.box(
                sessions_df,
                x='is_successful',
                y='n_events',
                color='is_successful',
                points='outliers',
                color_discrete_map={1: SUCCESS_COLOR, 0: ERROR_COLOR},
                labels={'is_successful': '성공 여부', 'n_events': '이벤트 수'}
            )
            events_fig.update_xaxes(
                tickvals=[0, 1],
                ticktext=['실패', '성공']
            )
            events_fig.update_layout(
                title="세션 이벤트 수 분포",
                showlegend=False
            )
            events_fig.update_yaxes(tickformat="d", dtick=1)  # y축을 1 간격 정수로 설정
            st.plotly_chart(events_fig, config={'displayModeBar': False})
            create_download_button(events_fig, "session_events_box", "세션 이벤트 수 분포 다운로드")

    # 이상 점수와 지속시간 관계
    if {'duration_ms', 'anomaly_score_final'}.issubset(sessions_df.columns):
        # null 값이 없는 데이터만 필터링
        valid_data = sessions_df.dropna(subset=['duration_ms', 'anomaly_score_final'])
        
        # 데이터 개수 표시
        st.info(f"유효한 데이터 포인트: {len(valid_data)}개")
        
        if len(valid_data) > 0:
            # 겹치는 점들을 위해 작은 지터 추가
            import numpy as np
            jitter_x = np.random.normal(0, valid_data['duration_ms'].std() * 0.02, len(valid_data))
            jitter_y = np.random.normal(0, valid_data['anomaly_score_final'].std() * 0.02, len(valid_data))
            
            valid_data_jittered = valid_data.copy()
            valid_data_jittered['duration_ms_jittered'] = valid_data['duration_ms'] + jitter_x
            valid_data_jittered['anomaly_score_final_jittered'] = valid_data['anomaly_score_final'] + jitter_y
            
            # 성공 여부를 명확한 카테고리로 변환
            valid_data_jittered['성공여부'] = valid_data_jittered['is_successful'].map({1: '성공', 0: '실패'})
            
            scatter_fig = px.scatter(
                valid_data_jittered,
                x='duration_ms_jittered',
                y='anomaly_score_final_jittered',
                color='성공여부',
                color_discrete_map={'성공': SUCCESS_COLOR, '실패': ERROR_COLOR},
                labels={
                    'duration_ms_jittered': '세션 지속시간(ms)',
                    'anomaly_score_final_jittered': '이상 점수',
                    '성공여부': '성공 여부'
                },
                hover_data={'session_id': True, 'duration_ms': True, 'anomaly_score_final': True},
                opacity=0.8
            )
            scatter_fig.add_hline(y=1.0, line_dash='dot', line_color=WARNING_COLOR)
            scatter_fig.update_layout(
                title="세션 지속시간 대비 이상 점수",
                legend_title="성공 여부",
                xaxis_title="세션 지속시간(ms)",
                yaxis_title="이상 점수"
            )
            scatter_fig.update_traces(marker=dict(size=10, line=dict(width=1, color='white')))  # 점 크기와 테두리 추가
            st.plotly_chart(scatter_fig, config={'displayModeBar': False})
            create_download_button(scatter_fig, "duration_vs_anomaly", "지속시간-이상점수 산점도 다운로드")
        else:
            st.warning("유효한 데이터가 없습니다. duration_ms 또는 anomaly_score_final 값이 누락되었을 수 있습니다.")

def plot_time_analysis(events_df, sessions_df):
    """시간 기반 분석"""
    if events_df.empty:
        st.warning("이벤트 데이터가 없습니다.")
        return
    
    # 시간별 패턴
    if 'ts_hour' in events_df.columns:
        col1, col2 = st.columns(2)

        with col1:
            hourly_counts = (
                events_df['ts_hour']
                .value_counts()
                .reindex(range(24), fill_value=0)
                .sort_index()
                .reset_index()
            )
            hourly_counts.columns = ['시간', '이벤트 수']

            fig = px.line(
                hourly_counts,
                x='시간',
                y='이벤트 수',
                markers=True,
                title="시간대별 이벤트 추이"
            )
            fig.update_traces(line_color=PRIMARY_COLOR)
            fig.update_layout(xaxis=dict(dtick=1, range=[0, 24]))
            fig.update_yaxes(tickformat="d", dtick=1)  # y축을 1 간격 정수로 설정
            st.plotly_chart(fig, config={'displayModeBar': False})
            create_download_button(fig, "hourly_events", "시간별 이벤트 추이 다운로드")

        with col2:
            if 'ts_dayofweek' in events_df.columns:
                pivot_df = (
                    events_df.groupby(['ts_dayofweek', 'ts_hour'])
                    .size()
                    .reset_index(name='count')
                )
                pivot_table = pivot_df.pivot(
                    index='ts_dayofweek',
                    columns='ts_hour',
                    values='count'
                ).reindex(range(7)).fillna(0)

                heatmap = go.Figure(data=go.Heatmap(
                    z=pivot_table.values,
                    x=[f"{hour}시" for hour in pivot_table.columns],
                    y=[WEEKDAY_KOREAN[idx] for idx in pivot_table.index],
                    colorscale='Blues'
                ))
                heatmap.update_layout(
                    title="요일·시간별 이벤트 히트맵",
                    xaxis_title="시간",
                    yaxis_title="요일"
                )
                st.plotly_chart(heatmap, config={'displayModeBar': False})
                create_download_button(heatmap, "weekday_hour_heatmap", "요일·시간 히트맵 다운로드")

    if {'ts_is_business_hours', 'ts_is_weekend'}.issubset(events_df.columns):
        business_col, weekend_col = st.columns(2)

        with business_col:
            biz_counts = (
                events_df['ts_is_business_hours']
                .map({1: '업무시간', 0: '비업무시간'})
                .value_counts()
                .reset_index()
            )
            biz_counts.columns = ['시간 구분', '이벤트 수']
            biz_fig = px.bar(
                biz_counts,
                x='시간 구분',
                y='이벤트 수',
                color='시간 구분',
                color_discrete_map={'업무시간': PRIMARY_COLOR, '비업무시간': WARNING_COLOR}
            )
            biz_fig.update_layout(
                title="업무시간 vs 비업무시간 이벤트 비교",
                showlegend=False
            )
            biz_fig.update_yaxes(tickformat="d", dtick=1)  # y축을 1 간격 정수로 설정
            st.plotly_chart(biz_fig, config={'displayModeBar': False})
            create_download_button(biz_fig, "business_hours_bar", "업무시간 이벤트 비교 다운로드")

        with weekend_col:
            weekend_counts = (
                events_df['ts_is_weekend']
                .map({1: '주말', 0: '평일'})
                .value_counts()
                .reset_index()
            )
            weekend_counts.columns = ['요일 구분', '이벤트 수']
            weekend_fig = px.pie(
                weekend_counts,
                names='요일 구분',
                values='이벤트 수',
                color='요일 구분',
                color_discrete_map={'주말': SUCCESS_COLOR, '평일': PRIMARY_COLOR}
            )
            weekend_fig.update_layout(title="주말 vs 평일 이벤트 비중")
            st.plotly_chart(weekend_fig, config={'displayModeBar': False})
            create_download_button(weekend_fig, "weekend_pie", "주말/평일 이벤트 다운로드")
    
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

    # 이벤트별 조화로운 색상 매핑 준비 (빨간색, 노란색 제외)
    harmonious_colors = [
        '#2E86AB',  # 파란색 (신뢰감)
        '#A23B72',  # 마젠타 (주의)
        '#4A90E2',  # 스카이 블루 (활동)
        '#6B46C1',  # 인디고 (중요)
        '#6A994E',  # 초록색 (성공)
        '#7209B7',  # 보라색 (특별)
        '#577590',  # 청회색 (중성)
        '#8B5A3C',  # 브라운 (안정)
        '#81B29A',  # 세이지 그린 (차분)
        '#5C6B73',  # 슬레이트 그레이 (온화)
        '#3D5A80',  # 네이비 (안정)
        '#98C1D9'   # 라이트 블루 (부드러움)
    ]
    
    unique_events = []
    if 'event' in events_df.columns:
        unique_events = sorted(events_df['event'].dropna().astype(str).unique().tolist())
    
    event_color_map = {
        event_name: harmonious_colors[idx % len(harmonious_colors)]
        for idx, event_name in enumerate(unique_events)
    }

    with col1:
        # 단계와 이벤트를 결합한 흐름 막대 그래프
        if {'event', 'step_id'}.issubset(events_df.columns):
            filtered_events = events_df.dropna(subset=['event', 'step_id']).copy()
            filtered_events['step_id'] = pd.to_numeric(filtered_events['step_id'], errors='coerce')
            filtered_events['event'] = filtered_events['event'].astype(str)
            filtered_events = filtered_events.dropna(subset=['step_id'])

            combined_counts = (
                filtered_events.groupby(['step_id', 'event'])
                .size()
                .reset_index(name='이벤트 수')
            )

            if not combined_counts.empty:
                combined_counts['step_id'] = combined_counts['step_id'].astype(int)
                combined_counts = combined_counts.sort_values(
                    ['step_id', '이벤트 수'], ascending=[True, False]
                )
                combined_counts['단계 정보'] = combined_counts.apply(
                    lambda row: f"단계 {row['step_id']}: {row['event']}", axis=1
                )

                category_order = combined_counts['단계 정보'].drop_duplicates().tolist()
                fig = px.bar(
                    combined_counts,
                    x='이벤트 수',
                    y='단계 정보',
                    color='event',
                    orientation='h',
                    color_discrete_map=event_color_map,
                    labels={'event': '이벤트 유형'}
                )
                fig.update_layout(
                    title="이벤트 단계별 발생 현황",
                    showlegend=True,
                    yaxis=dict(
                        autorange='reversed',
                        categoryorder='array',
                        categoryarray=category_order
                    ),
                    legend_title="이벤트 유형"
                )
                fig.update_xaxes(tickformat="d", dtick=1)  # x축을 1 간격 정수로 설정 (horizontal bar)
                st.plotly_chart(fig, config={'displayModeBar': False})
                create_download_button(fig, "event_step_distribution", "이벤트 단계별 그래프 다운로드")

    with col2:
        # 단계별 분포 (막대 그래프로 변경) - 단계별 투명도 적용
        if 'step_id' in events_df.columns:
            step_counts = events_df['step_id'].value_counts().sort_index()
            
            fig = go.Figure()
            
            # 단계별 투명도 생성 (0.3부터 1.0까지 점진적 증가)
            steps = list(step_counts.index)
            num_steps = len(steps)
            opacities = [0.3 + (0.7 * i / max(1, num_steps - 1)) for i in range(num_steps)]
            
            # 각 단계마다 개별 막대 추가
            for i, (step, count) in enumerate(step_counts.items()):
                fig.add_trace(go.Bar(
                    x=[step],
                    y=[count],
                    marker_color=hex_to_rgba(PRIMARY_COLOR, opacities[i]),
                    name=f'단계 {step}',
                    text=[count],
                    textposition='outside',
                    showlegend=False
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
            fig.update_yaxes(tickformat="d", dtick=1)  # y축을 1 간격 정수로 설정
            st.plotly_chart(fig, config={'displayModeBar': False})
            create_download_button(fig, "auth_steps", "인증 단계 분포 다운로드")
    
    # 단계 이상 패턴 분석 (히트맵) - 전역 매핑 사용
    existing_cols = [col for col in GLOBAL_PATTERN_MAPPING.keys() if col in events_df.columns]

    if existing_cols:
        anomaly_data = []
        anomaly_labels = []
        
        for col in existing_cols:
            count = (events_df[col] > 0).sum()
            if count > 0:
                anomaly_data.append([count])
                anomaly_labels.append(get_pattern_display_name(col))
        
        if anomaly_data:
            # 패턴별 일관된 색상을 위해 막대 그래프로 변경
            pattern_data = []
            pattern_colors = []
            pattern_names = []
            
            for col in existing_cols:
                count = (events_df[col] > 0).sum()
                if count > 0:
                    pattern_data.append(count)
                    pattern_colors.append(get_pattern_color(col))
                    pattern_names.append(get_pattern_display_name(col))
            
            fig = go.Figure()
            
            # 각 패턴별로 개별 색상 적용
            for i, (name, count, color) in enumerate(zip(pattern_names, pattern_data, pattern_colors)):
                fig.add_trace(go.Bar(
                    x=[count],
                    y=[name],
                    orientation='h',
                    marker_color=color,
                    text=[count],
                    textposition='outside',
                    name=name,
                    showlegend=False
                ))            


    # 세션 진행 흐름 (Sankey)
    if {'session_id', 'event', 'timestamp'}.issubset(events_df.columns):
        sorted_events = events_df.sort_values(['session_id', 'timestamp', 'step_id'])
        sorted_events['next_event'] = sorted_events.groupby('session_id')['event'].shift(-1)
        transitions = (
            sorted_events.dropna(subset=['next_event'])
            .groupby(['event', 'next_event'])
            .size()
            .reset_index(name='count')
        )

        if not transitions.empty:
            labels = pd.unique(transitions[['event', 'next_event']].astype(str).values.ravel('K')).tolist()
            label_to_index = {label: idx for idx, label in enumerate(labels)}

            node_colors = [
                event_color_map.get(label, harmonious_colors[idx % len(harmonious_colors)])
                for idx, label in enumerate(labels)
            ]

            sankey_fig = go.Figure(data=[go.Sankey(
                arrangement="snap",
                node=dict(
                    pad=15,
                    thickness=20,
                    line=dict(color="black", width=0.3),
                    label=labels,
                    color=node_colors
                ),
                link=dict(
                    source=[label_to_index[str(src)] for src in transitions['event']],
                    target=[label_to_index[str(tgt)] for tgt in transitions['next_event']],
                    value=transitions['count'],
                    color=[
                        hex_to_rgba(event_color_map.get(str(src), harmonious_colors[i % len(harmonious_colors)]), 0.4)
                        for i, src in enumerate(transitions['event'])
                    ]
                ),
                textfont=dict(color='black', size=12)
            )])

            sankey_fig.update_layout(title="세션 단계 전이 흐름")
            st.plotly_chart(sankey_fig, config={'displayModeBar': False})
            create_download_button(sankey_fig, "auth_flow_sankey", "세션 단계 흐름 다운로드")

def plot_detailed_anomalies(events_df):
    """상세 이상 패턴 분석"""
    if events_df.empty:
        st.warning("이벤트 데이터가 없습니다.")
        return
    
    # 이상 패턴별 분석 (전역 매핑 사용)
    anomaly_features = list(GLOBAL_PATTERN_MAPPING.keys())
    
    existing_features = [feat for feat in anomaly_features if feat in events_df.columns]
    
    if not existing_features:
        st.info("이상 패턴 특징이 없습니다.")
        return
    
    total_events = len(events_df)

    # 이상 패턴 요약 (일관된 명칭과 색상 사용)
    summary_records = []
    for feature in existing_features:
        if feature in events_df.columns:
            count = int((events_df[feature] > 0).sum())
            if count > 0:
                summary_records.append({
                    'pattern': feature,
                    'pattern_name': get_pattern_display_name(feature),
                    'color': get_pattern_color(feature),
                    'count': count,
                    'ratio': round((count / total_events) * 100, 2)
                })

    if summary_records:
        summary_df = pd.DataFrame(summary_records)
        col1, col2 = st.columns(2)

        with col1:
            fig = go.Figure()
            fig.add_trace(go.Bar(
                x=summary_df['pattern_name'],  # 한국어 명칭 사용
                y=summary_df['count'],
                marker_color=summary_df['color'],  # 개별 색상 사용
                name='발생 건수',
                text=summary_df['count'],
                textposition='outside'
            ))
            fig.update_layout(
                title="이상 패턴별 발생 현황",
                xaxis_title="이상 패턴 유형",
                yaxis_title="발생 건수",
                showlegend=False
            )
            fig.update_yaxes(tickformat="d", dtick=1)  # y축을 1 간격 정수로 설정
            st.plotly_chart(fig, config={'displayModeBar': False})
            create_download_button(fig, "anomaly_patterns", "이상 패턴 현황 다운로드")

        with col2:
            if 'delta_ms' in events_df.columns:
                delta_series = events_df['delta_ms'].dropna()
                delta_series = delta_series[delta_series > 0]

                if not delta_series.empty:
                    import numpy as np
                    
                    # 값이 모두 같은 경우 처리
                    if delta_series.min() == delta_series.max():
                        # 단일 값에 대한 포인트 차트
                        single_value = delta_series.iloc[0]
                        delta_fig = go.Figure()
                        delta_fig.add_trace(go.Scatter(
                            x=[single_value],
                            y=[len(delta_series)],
                            mode='markers',
                            marker=dict(
                                color=PRIMARY_COLOR,
                                size=20,
                                line=dict(width=2, color='white')
                            ),
                            name='빈도',
                            text=[f'{single_value}ms: {len(delta_series)}회'],
                            textposition='top center',
                            hovertemplate='시간 간격: %{x}ms<br>발생 횟수: %{y}회<extra></extra>'
                        ))
                        
                        delta_fig.update_layout(
                            title="요청 간 시간 간격 분포",
                            xaxis_title="시간 간격(ms)",
                            yaxis_title="빈도",
                            xaxis=dict(range=[single_value * 0.5, single_value * 1.5]),
                            yaxis=dict(range=[0, len(delta_series) * 1.2])
                        )
                    else:
                        # 로그 스케일 bins 생성
                        log_min = np.log10(delta_series.min())
                        log_max = np.log10(delta_series.max())
                        log_bins = np.logspace(log_min, log_max, 40)
                        
                        # numpy로 히스토그램 계산
                        counts, bin_edges = np.histogram(delta_series, bins=log_bins)
                        
                        # bin 중심점 계산
                        bin_centers = (bin_edges[:-1] + bin_edges[1:]) / 2
                        
                        delta_fig = go.Figure()
                        delta_fig.add_trace(go.Bar(
                            x=bin_centers,
                            y=counts,
                            marker_color=PRIMARY_COLOR,
                            opacity=0.7,
                            name='빈도'
                        ))
                        
                        delta_fig.update_layout(
                            title="요청 간 시간 간격 분포",
                            xaxis_title="시간 간격(ms) [log scale]",
                            yaxis_title="빈도",
                            xaxis_type="log",
                            bargap=0.1
                        )
                    
                    st.plotly_chart(delta_fig, config={'displayModeBar': False})
                    create_download_button(delta_fig, "delta_ms_hist", "시간 간격 분포 다운로드")
                else:
                    st.info("시간 간격 데이터가 없습니다.")
            else:
                st.info("시간 간격 분석을 위한 데이터가 준비되지 않았습니다.")

    if 'timestamp' in events_df.columns:
        # 전역 패턴 매핑에서 정의된 패턴들 사용
        flagged_cols = []
        
        for col in GLOBAL_PATTERN_MAPPING.keys():
            if col in events_df.columns:
                try:
                    # 숫자형 컬럼이고 양수 값이 있는지 확인
                    if pd.api.types.is_numeric_dtype(events_df[col]) and events_df[col].sum() > 0:
                        flagged_cols.append(col)
                    # 이진 플래그 컬럼인 경우
                    elif events_df[col].dtype == bool and events_df[col].any():
                        flagged_cols.append(col)
                except:
                    continue
        
        # 이상 점수가 있다면 임계값 기반으로 이상 패턴 생성
        if not flagged_cols and 'anomaly_score_final' in events_df.columns:
            events_df_temp = events_df.copy()
            threshold = 1.0  # 임계값 설정
            events_df_temp['high_anomaly_score'] = (events_df_temp['anomaly_score_final'] > threshold).astype(int)
            if events_df_temp['high_anomaly_score'].sum() > 0:
                flagged_cols = ['high_anomaly_score']
                events_df = events_df_temp
        
        if flagged_cols:
            trend_df = events_df[['timestamp'] + flagged_cols].copy()
            trend_df['timestamp_hour'] = trend_df['timestamp'].dt.floor('H')
            
            melted = trend_df.melt(
                id_vars='timestamp_hour',
                value_vars=flagged_cols,
                var_name='pattern',
                value_name='flag'
            )
            melted = melted[melted['flag'] > 0]

            if not melted.empty:
                time_counts = melted.groupby(['timestamp_hour', 'pattern']).size().reset_index(name='count')
                
                # 패턴명을 일관된 한국어로 변경하고 색상 매핑
                time_counts['pattern_name'] = time_counts['pattern'].map(get_pattern_display_name)
                
                # 패턴별 색상 매핑 생성
                pattern_color_map = {}
                for pattern in time_counts['pattern'].unique():
                    pattern_name = get_pattern_display_name(pattern)
                    pattern_color_map[pattern_name] = get_pattern_color(pattern)
                
                # 시간 범위 계산 (실제 데이터 범위 + 여유)
                min_time = time_counts['timestamp_hour'].min()
                max_time = time_counts['timestamp_hour'].max()
                time_range = [min_time - pd.Timedelta(hours=1), max_time + pd.Timedelta(hours=1)]
                
                # 버블 차트로 변경하여 더 직관적인 시각화
                time_fig = px.scatter(
                    time_counts,
                    x='timestamp_hour',
                    y='pattern_name',  # y축을 패턴으로 변경
                    size='count',  # 버블 크기를 발생 건수로 설정
                    color='pattern_name',  # 한국어 패턴명 사용
                    title='시간대별 이상 패턴 발생 추이',
                    labels={'timestamp_hour': '시간', 'count': '발생 건수', 'pattern_name': '패턴'},
                    color_discrete_map=pattern_color_map,  # 일관된 색상 사용
                    size_max=60,  # 최대 버블 크기 설정
                    hover_data={'count': True}  # 호버에 발생 건수 표시
                )
                
                time_fig.update_layout(
                    xaxis_title='시간',
                    yaxis_title='패턴',  # y축이 패턴명으로 변경
                    xaxis=dict(
                        range=time_range,
                        tickformat='%H:%M',  # 시간:분 형식
                        dtick=3600000  # 1시간 간격 (밀리초)
                    ),
                    showlegend=False,  # 범례 숨기기 (y축 레이블과 중복)
                    height=400  # 버블 차트에 적절한 높이 설정
                )
                
                st.plotly_chart(time_fig, config={'displayModeBar': False})
                create_download_button(time_fig, "anomaly_trend", "이상 패턴 추이 다운로드")
            else:
                st.info("해당 기간 동안 이상 패턴이 발생하지 않았습니다.")
        else:
            st.info("이상 패턴 분석을 위한 데이터가 준비되지 않았습니다.")

def plot_user_ip_analysis(events_df):
    """사용자 및 IP 분석"""
    if events_df.empty:
        st.warning("이벤트 데이터가 없습니다.")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        if 'user_id' in events_df.columns:
            anomaly_cols = [
                col for col in ['delta_too_fast', 'delta_too_slow', 'has_error_keyword',
                                 'simultaneous_event', 'message_unusual_length', 'step_jump', 'step_reverse']
                if col in events_df.columns
            ]

            temp_df = events_df.copy()
            if anomaly_cols:
                temp_df['has_any_anomaly'] = temp_df[anomaly_cols].gt(0).any(axis=1).astype(int)
            else:
                temp_df['has_any_anomaly'] = 0

            user_agg = temp_df.groupby('user_id').agg(
                total_events=('user_id', 'size'),
                anomaly_events=('has_any_anomaly', 'sum')
            ).reset_index()

            top_users = user_agg.sort_values('total_events', ascending=False).head(10)
            if not top_users.empty:
                # 메인 색상에 점진적 투명도 적용 (이벤트 수가 많을수록 진한 색상)
                num_users = len(top_users)
                opacities = [1.0 - (0.7 * i / max(1, num_users - 1)) for i in range(num_users)]
                
                user_fig = go.Figure()
                
                # 각 사용자마다 개별 막대 추가 (투명도별)
                for i, (_, user_data) in enumerate(top_users.iterrows()):
                    user_fig.add_trace(go.Bar(
                        x=[user_data['total_events']],
                        y=[user_data['user_id']],
                        marker_color=hex_to_rgba(PRIMARY_COLOR, opacities[i]),
                        name=f'사용자 {i+1}',
                        orientation='h',
                        text=[user_data['total_events']],
                        textposition='outside',
                        showlegend=False
                    ))
                
                user_fig.update_layout(
                    title="상위 사용자 이벤트 수",
                    xaxis_title="이벤트 수",
                    yaxis_title="사용자 ID",
                    yaxis=dict(autorange='reversed')
                )
                user_fig.update_xaxes(tickformat="d", dtick=1)  # x축을 1 간격 정수로 설정
                st.plotly_chart(user_fig, config={'displayModeBar': False})
                create_download_button(user_fig, "user_events_ratio", "사용자 이벤트/이상 비율 다운로드")

    with col2:
        # IP 국가 및 내부/외부 분포
        if 'source_ip' in events_df.columns:
            # IP를 국가명으로 변환
            countries = get_country_from_ip(events_df['source_ip'].tolist())
            events_df_temp = events_df.copy()
            events_df_temp['country'] = countries

            country_counts = pd.Series(countries).value_counts()

            if not country_counts.empty:
                country_df = country_counts.reset_index(name='이벤트 수')
                country_df.rename(columns={'index': '국가'}, inplace=True)
                
                # 버블 차트를 위한 좌표 생성 (원형 배치)
                import numpy as np
                n_countries = len(country_df)
                angles = np.linspace(0, 2*np.pi, n_countries, endpoint=False)
                radius_base = 10
                
                # 이벤트 수에 따라 반지름 조정 (많은 이벤트일수록 중심에서 멀리)
                max_events = country_df['이벤트 수'].max()
                radius_factor = country_df['이벤트 수'] / max_events * 5 + radius_base
                
                country_df['x'] = radius_factor * np.cos(angles)
                country_df['y'] = radius_factor * np.sin(angles)
                
                # 조화로운 색상 팔레트 (국가별 다른 색상)
                harmonious_country_colors = [
                    '#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8',
                    '#F7DC6F', '#BB8FCE', '#85C1E9', '#F8C471', '#82E0AA',
                    '#F1948A', '#7FB3D3', '#D7BDE2', '#A9DFBF', '#F9E79F'
                ]
                
                # 국가별 색상 매핑
                country_color_map = {
                    country: harmonious_country_colors[i % len(harmonious_country_colors)]
                    for i, country in enumerate(country_df['국가'])
                }
                
                country_df['색상'] = country_df['국가'].map(country_color_map)
                
                # 버블 차트 생성 (국가명 표기 포함)
                country_fig = px.scatter(
                    country_df,
                    x='x',
                    y='y',
                    size='이벤트 수',
                    color='국가',
                    color_discrete_map=country_color_map,
                    size_max=80,
                    text='국가',  # 버블 안에 국가명 표시
                    labels={'x': '', 'y': '', '이벤트 수': '이벤트 수', '국가': '국가'},
                    hover_data={'이벤트 수': True, 'x': False, 'y': False}
                )
                
                # 텍스트 스타일 설정
                country_fig.update_traces(
                    textposition="middle center",
                    textfont=dict(size=10, color="white", family="Arial Black")
                )
                
                country_fig.update_layout(
                    title="IP 국가별 이벤트 분포",
                    xaxis=dict(showgrid=False, showticklabels=False, zeroline=False),
                    yaxis=dict(showgrid=False, showticklabels=False, zeroline=False),
                    plot_bgcolor='rgba(0,0,0,0)',
                    showlegend=True,
                    legend_title="국가",
                    height=500
                )
                
                st.plotly_chart(country_fig, config={'displayModeBar': False})
                create_download_button(country_fig, "ip_countries_bubble", "IP 국가 분포 다운로드")

    # 내부/외부 IP 비교 및 상위 IP 하이라이트
    if {'source_ip', 'source_ip_is_internal'}.issubset(events_df.columns):
        col3, col4 = st.columns(2)

        with col3:
            internal_counts = (
                events_df.groupby('source_ip_is_internal')['source_ip']
                .count()
                .reset_index(name='이벤트 수')
            )
            internal_counts['IP 유형'] = internal_counts['source_ip_is_internal'].map({1: '내부', 0: '외부'})
            internal_counts = internal_counts.drop(columns=['source_ip_is_internal'])

            if not internal_counts.empty:
                internal_fig = px.pie(
                    internal_counts,
                    names='IP 유형',
                    values='이벤트 수',
                    color='IP 유형',
                    color_discrete_map={'내부': SUCCESS_COLOR, '외부': ERROR_COLOR}
                )
                internal_fig.update_layout(title="내부 vs 외부 IP 비중")
                st.plotly_chart(internal_fig, config={'displayModeBar': False})
                create_download_button(internal_fig, "internal_external_ip", "내부외부 IP 비중 다운로드")

        with col4:
            ip_counts = (
                events_df.groupby(['source_ip', 'source_ip_is_internal'])
                .size()
                .reset_index(name='이벤트 수')
            )
            top_ips = ip_counts.sort_values('이벤트 수', ascending=False).head(12)

            if not top_ips.empty:
                # 메인 색상에 점진적 투명도 적용 (이벤트 수가 많을수록 진한 색상)
                num_ips = len(top_ips)
                opacities = [1.0 - (0.7 * i / max(1, num_ips - 1)) for i in range(num_ips)]
                
                ip_fig = go.Figure()
                
                # 각 IP마다 개별 막대 추가 (투명도별)
                for i, (_, ip_data) in enumerate(top_ips.iterrows()):
                    ip_fig.add_trace(go.Bar(
                        x=[ip_data['이벤트 수']],
                        y=[ip_data['source_ip']],
                        marker_color=hex_to_rgba(PRIMARY_COLOR, opacities[i]),
                        name=f'IP {i+1}',
                        orientation='h',
                        text=[ip_data['이벤트 수']],
                        textposition='outside',
                        showlegend=False
                    ))
                
                ip_fig.update_layout(
                    title="상위 IP 이벤트 수",
                    xaxis_title="이벤트 수",
                    yaxis_title="IP 주소",
                    yaxis=dict(autorange='reversed')
                )
                ip_fig.update_xaxes(tickformat="d", dtick=1)  # x축을 1 간격 정수로 설정 (horizontal bar)
                st.plotly_chart(ip_fig, config={'displayModeBar': False})
                create_download_button(ip_fig, "top_ip_events", "상위 IP 이벤트 다운로드")

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
    
    # 개요 메트릭
    plot_overview_metrics(stats)
    st.markdown("---")
    
    # 성능 최적화: 탭별 지연 로딩
    if 'active_tab' not in st.session_state:
        st.session_state.active_tab = '세션 분석'
    
    # 탭 구성
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "세션 분석  |", "시계열 분석  |", "인증 플로우  |", 
        "이상 패턴  |", "사용자/IP 분석  |", "데이터 품질  |"
    ])
    
    # 탭 클릭 감지를 위한 간단한 방법 (실제 탭 변경은 자동으로 처리됨)
    
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
                      st.sidebar.write(f"- {get_pattern_display_name(pattern)}: {count}개")

    # 로고
    st.sidebar.markdown("---")                      
    st.sidebar.image(logo_path, width=120)

if __name__ == "__main__":
    main()
