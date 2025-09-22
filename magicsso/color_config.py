#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Color Configuration for MagicSSO Analysis
프로젝트 전체에서 사용할 색상 팔레트 정의

Author: Kong Ju
Date: 2025-09-01
"""

# 🎨 MagicSSO 색상 팔레트
COLORS = {
    'primary': '#00599B',      # 기본 그래프 색상 (파란색)
    'secondary': '#91B7D4',    # 보조 색상 (연한 파란색)
    'normal': '#B1B1B2',       # 정상 데이터 색상 (회색)
    'anomaly': '#FC8D59',      # 이상치 데이터 색상 (주황색)
    'accent': '#FFC107'        # 강조 색상 (노란색)
}

# 📊 그래프별 색상 매핑
GRAPH_COLORS = {
    # 기본 차트 색상
    'default': COLORS['primary'],
    'histogram': COLORS['primary'],
    'line': COLORS['primary'],
    'bar': COLORS['primary'],
    'scatter': COLORS['primary'],
    
    # 정상/이상치 구분
    'normal_data': COLORS['normal'],
    'anomaly_data': COLORS['anomaly'],
    
    # 성공/실패 구분
    'success': COLORS['normal'],
    'failure': COLORS['anomaly'],
    
    # 완료/미완료 구분
    'completed': COLORS['normal'],
    'incomplete': COLORS['anomaly'],
    
    # 특수 용도
    'highlight': COLORS['accent'],
    'background': COLORS['secondary'],
    'text': '#2C3E50',
    'grid': '#ECF0F1'
}

# 🌈 색상 팔레트 (순서대로 사용)
COLOR_PALETTE = [
    COLORS['primary'],     # 파란색
    COLORS['anomaly'],     # 주황색  
    COLORS['normal'],      # 회색
    COLORS['secondary'],   # 연한 파란색
    '#2ECC71',            # 초록색
    '#E74C3C',            # 빨간색
    '#F39C12',            # 노란색
    '#9B59B6',            # 보라색
    '#1ABC9C',            # 청록색
    '#34495E'             # 어두운 회색
]

# 📈 matplotlib 스타일 설정
MATPLOTLIB_STYLE = {
    'figure.facecolor': 'white',
    'axes.facecolor': 'white',
    'axes.edgecolor': GRAPH_COLORS['grid'],
    'axes.linewidth': 0.8,
    'axes.grid': True,
    'grid.color': GRAPH_COLORS['grid'],
    'grid.alpha': 0.3,
    'xtick.color': GRAPH_COLORS['text'],
    'ytick.color': GRAPH_COLORS['text'],
    'axes.labelcolor': GRAPH_COLORS['text'],
    'axes.titlecolor': GRAPH_COLORS['text'],
    'legend.frameon': True,
    'legend.facecolor': 'white',
    'legend.edgecolor': GRAPH_COLORS['grid']
}

# 🎯 plotly 색상 설정
PLOTLY_COLORS = {
    'discrete_sequence': COLOR_PALETTE,
    'continuous_scale': [
        [0, 'white'], 
        [0.5, COLORS['secondary']], 
        [1, COLORS['primary']]
    ],
    'normal_anomaly_map': {
        'Normal': COLORS['normal'],
        'Anomaly': COLORS['anomaly'],
        '정상': COLORS['normal'],
        '이상치': COLORS['anomaly'],
        False: COLORS['normal'],
        True: COLORS['anomaly']
    }
}


def get_color(color_type='primary'):
    """
    색상 타입에 따른 색상 코드 반환
    
    Args:
        color_type (str): 색상 타입
        
    Returns:
        str: 색상 코드
    """
    return COLORS.get(color_type, COLORS['primary'])


def get_graph_color(graph_type='default'):
    """
    그래프 타입에 따른 색상 코드 반환
    
    Args:
        graph_type (str): 그래프 타입
        
    Returns:
        str: 색상 코드
    """
    return GRAPH_COLORS.get(graph_type, GRAPH_COLORS['default'])


def get_palette(n_colors=None):
    """
    지정된 개수만큼의 색상 팔레트 반환
    
    Args:
        n_colors (int): 필요한 색상 개수 (None이면 전체 팔레트 반환)
        
    Returns:
        list: 색상 코드 리스트
    """
    if n_colors is None:
        return COLOR_PALETTE
    
    # 필요한 개수만큼 색상 반복
    colors = []
    for i in range(n_colors):
        colors.append(COLOR_PALETTE[i % len(COLOR_PALETTE)])
    
    return colors


def setup_matplotlib_style():
    """matplotlib 스타일 설정 적용"""
    import matplotlib.pyplot as plt
    import matplotlib.font_manager as fm
    
    # 한글 폰트 설정
    korean_fonts = ['Noto Sans CJK JP', 'Noto Sans CJK KR', 'DejaVu Sans', 'Arial Unicode MS']
    
    for font in korean_fonts:
        try:
            plt.rcParams['font.family'] = font
            # 테스트용 한글 텍스트로 폰트 확인
            fig, ax = plt.subplots(figsize=(1, 1))
            ax.text(0.5, 0.5, '한글', fontsize=10)
            plt.close(fig)
            print(f"✅ 한글 폰트 설정 완료: {font}")
            break
        except:
            continue
    else:
        print("⚠️ 한글 폰트를 찾을 수 없습니다. 기본 폰트를 사용합니다.")
    
    # minus 기호 깨짐 방지
    plt.rcParams['axes.unicode_minus'] = False
    
    # 기본 스타일 적용
    plt.rcParams.update(MATPLOTLIB_STYLE)
    print("✅ matplotlib 스타일 설정 적용됨")


def get_plotly_colors():
    """plotly용 색상 설정 반환"""
    return PLOTLY_COLORS


def print_color_palette():
    """색상 팔레트 출력 (디버깅용)"""
    print("🎨 MagicSSO 색상 팔레트:")
    print("=" * 50)
    
    for name, color in COLORS.items():
        print(f"  {name:12s}: {color}")
    
    print(f"\n📊 사용 가능한 그래프 색상:")
    for name, color in GRAPH_COLORS.items():
        print(f"  {name:12s}: {color}")



if __name__ == "__main__":
    print_color_palette()
