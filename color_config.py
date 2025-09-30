#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Color Configuration for Magic Product Log Analysis
MagicLine 프로젝트에서 사용할 색상 팔레트 정의

Author: Kong Ju
Date: 2025-09-23
"""

# 기본 색상 정의
COLORS = {
    'primary': '#00599B',      # 기본 그래프 색상 (파란색)
    'secondary': '#91B7D4',    # 보조 색상 (연한 파란색)
    'normal': '#B1B1B2',       # 정상 데이터 색상 (회색)
    'anomaly': '#FC8D59',      # 이상치 데이터 색상 (주황색)
    'accent': '#FFC107',       # 강조 색상 (노란색)
    'success': '#2ECC71',      # 성공 색상 (초록색)
    'error': '#E74C3C',        # 에러 색상 (빨간색)
    'warning': '#F39C12',      # 경고 색상 (주황색)
    'info': '#3498DB',         # 정보 색상 (파란색)
    'dark': '#34495E'          # 어두운 색상
}

# 색상 팔레트 (순서대로 사용)
COLOR_PALETTE = [
    COLORS['primary'],     # 파란색
    COLORS['anomaly'],     # 주황색  
    COLORS['success'],     # 초록색
    COLORS['secondary'],   # 연한 파란색
    COLORS['warning'],     # 노란색
    COLORS['error'],       # 빨간색
    COLORS['normal'],      # 회색
    '#9B59B6',            # 보라색
    '#1ABC9C',            # 청록색
    COLORS['dark']         # 어두운 회색
]

# 로그 레벨별 색상 매핑
LEVEL_COLORS = {
    'INFO': COLORS['info'],
    'WARN': COLORS['warning'], 
    'ERROR': COLORS['error'],
    'DEBUG': COLORS['normal'],
    'TRACE': COLORS['secondary']
}

# 그래프별 색상 매핑
GRAPH_COLORS = {
    'histogram': COLORS['primary'],
    'line': COLORS['primary'],
    'bar': COLORS['primary'],
    'scatter': COLORS['primary'],
    'pie': COLOR_PALETTE,
    'heatmap': [[0, 'white'], [0.5, COLORS['secondary']], [1, COLORS['primary']]]
}

def get_color(color_type='primary'):
    """색상 타입에 따른 색상 코드 반환"""
    return COLORS.get(color_type, COLORS['primary'])

def get_color_palette(n_colors=None):
    """지정된 개수만큼의 색상 팔레트 반환"""
    if n_colors is None:
        return COLOR_PALETTE
    
    colors = []
    for i in range(n_colors):
        colors.append(COLOR_PALETTE[i % len(COLOR_PALETTE)])
    return colors

def get_level_colors(levels):
    """로그 레벨에 맞는 색상 리스트 반환"""
    return [LEVEL_COLORS.get(level, COLORS['normal']) for level in levels]

def get_graph_color(graph_type='primary'):
    """그래프 타입에 따른 색상 반환"""
    return GRAPH_COLORS.get(graph_type, COLORS['primary'])
