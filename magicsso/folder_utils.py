#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Folder Management Utilities
SSO 분석 프로젝트의 폴더 구조 관리 도구

Author: Kong Ju
Date: 2025-09-01
"""

from pathlib import Path
import logging
import pandas as pd

# 로깅 설정
logger = logging.getLogger(__name__)


def ensure_output_directory(base_dir: str, category: str, model_name: str = None) -> str:
    """
    출력 디렉토리 생성 및 경로 반환
    
    Args:
        base_dir: 기본 데이터 디렉토리 (예: "/home/kongju/DEV/dream/DATA")
        category: 카테고리 ("FLOW_ANALYSIS", "ANOMALY_DETECTION", "FEATURE_IMPORTANCE")
        model_name: 모델명 (선택사항, 모델별 하위 폴더가 필요한 경우)
    
    Returns:
        str: 생성된 출력 디렉토리 경로
    """
    # 기본 경로 생성
    output_path = Path(base_dir) / category
    
    # 모델별 하위 폴더 생성
    if model_name:
        try:
            from model_config import get_file_suffix
            model_folder = get_file_suffix(model_name)
            output_path = output_path / model_folder
        except ImportError:
            # model_config를 import할 수 없는 경우 모델명 그대로 사용
            output_path = output_path / model_name
    
    # 디렉토리 생성
    output_path.mkdir(parents=True, exist_ok=True)
    print(f"📁 출력 디렉토리 확인/생성: {output_path}")
    
    return str(output_path)


def get_structured_output_path(base_dir: str, analysis_type: str, model_name: str = None, filename: str = None) -> str:
    """
    구조화된 출력 파일 경로 생성
    
    Args:
        base_dir: 기본 데이터 디렉토리
        analysis_type: 분석 유형 ("flow", "anomaly", "feature_importance") 
        model_name: 모델명 (선택사항)
        filename: 파일명 (선택사항)
    
    Returns:
        str: 구조화된 파일 경로
    """
    # 분석 유형에 따른 카테고리 매핑
    category_mapping = {
        "flow": "FLOW_ANALYSIS",
        "anomaly": "ANOMALY_DETECTION", 
        "feature_importance": "FEATURE_IMPORTANCE"
    }
    
    category = category_mapping.get(analysis_type, analysis_type.upper())
    
    # 디렉토리 생성
    output_dir = ensure_output_directory(base_dir, category, model_name)
    
    # 파일명이 제공된 경우 전체 경로 반환
    if filename:
        return str(Path(output_dir) / filename)
    else:
        return output_dir


def create_project_structure(base_dir: str) -> dict:
    """
    전체 프로젝트 폴더 구조 생성
    
    Args:
        base_dir: 기본 데이터 디렉토리
        
    Returns:
        dict: 생성된 폴더 정보
    """
    base_path = Path(base_dir)
    
    # 기본 폴더 구조
    folders = {
        'LOGS': base_path / 'LOGS',
        'RAW_LOGS': base_path / 'RAW_LOGS', 
        'FLOW_ANALYSIS': base_path / 'FLOW_ANALYSIS',
        'ANOMALY_DETECTION': base_path / 'ANOMALY_DETECTION',
        'FEATURE_IMPORTANCE': base_path / 'FEATURE_IMPORTANCE',
        'REPORTS': base_path / 'REPORTS',
        'ARCHIVE': base_path / 'ARCHIVE'
    }
    
    # 모델별 하위 폴더
    model_categories = ['ANOMALY_DETECTION', 'FEATURE_IMPORTANCE']
    
    try:
        from model_config import SUPPORTED_MODELS, get_file_suffix
        
        for category in model_categories:
            for model_name in SUPPORTED_MODELS.keys():
                model_folder = get_file_suffix(model_name)
                folders[f'{category}_{model_folder}'] = folders[category] / model_folder
                
    except ImportError:
        logger.warning("model_config를 import할 수 없습니다. 기본 모델 폴더만 생성합니다.")
        default_models = ['isolation_forest', 'lof', 'one_class_svm', 'random_cut_forest']
        
        for category in model_categories:
            for model in default_models:
                folders[f'{category}_{model}'] = folders[category] / model
    
    # 모든 폴더 생성
    created_folders = []
    for name, path in folders.items():
        try:
            path.mkdir(parents=True, exist_ok=True)
            created_folders.append(str(path))
            print(f"✅ 폴더 생성: {path}")
        except Exception as e:
            logger.error(f"폴더 생성 실패 {path}: {e}")
    
    return {
        'created': created_folders,
        'structure': {name: str(path) for name, path in folders.items()}
    }


def validate_output_path(file_path: str, create_if_missing: bool = True) -> bool:
    """
    출력 파일 경로 유효성 검사
    
    Args:
        file_path: 검사할 파일 경로
        create_if_missing: 누락된 디렉토리 생성 여부
        
    Returns:
        bool: 경로가 유효한지 여부
    """
    try:
        path = Path(file_path)
        
        # 디렉토리가 존재하지 않는 경우
        if not path.parent.exists():
            if create_if_missing:
                path.parent.mkdir(parents=True, exist_ok=True)
                print(f"📁 누락된 디렉토리 생성: {path.parent}")
                return True
            else:
                return False
        
        return True
        
    except Exception as e:
        logger.error(f"경로 유효성 검사 실패: {e}")
        return False


def safe_int_conversion(value, default=0):
    """
    안전한 정수 변환 (NaN 처리)
    
    Args:
        value: 변환할 값
        default: 기본값 (변환 실패 시)
    
    Returns:
        int: 변환된 정수 값
    """
    try:
        if pd.isna(value):
            return default
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_sum(series, fillna_value=False):
    """
    안전한 합계 계산 (NaN 처리)
    
    Args:
        series: pandas Series
        fillna_value: NaN을 채울 값
    
    Returns:
        int: 안전한 합계
    """
    try:
        if series is None or len(series) == 0:
            return 0
        return int(series.fillna(fillna_value).sum())
    except (ValueError, TypeError):
        return 0


def get_analysis_summary(base_dir: str) -> dict:
    """
    분석 결과 파일 요약 정보 반환
    
    Args:
        base_dir: 기본 데이터 디렉토리
        
    Returns:
        dict: 분석 결과 요약
    """
    base_path = Path(base_dir)
    summary = {
        'flow_analysis': {},
        'anomaly_detection': {},
        'feature_importance': {},
        'total_files': 0
    }
    
    # 흐름 분석 파일 확인
    flow_dir = base_path / 'FLOW_ANALYSIS'
    if flow_dir.exists():
        flow_files = list(flow_dir.glob('*'))
        summary['flow_analysis'] = {
            'count': len(flow_files),
            'files': [f.name for f in flow_files if f.is_file()]
        }
        summary['total_files'] += len(flow_files)
    
    # 이상탐지 결과 확인 (모델별)
    anomaly_dir = base_path / 'ANOMALY_DETECTION'
    if anomaly_dir.exists():
        for model_dir in anomaly_dir.iterdir():
            if model_dir.is_dir():
                model_files = list(model_dir.glob('*'))
                summary['anomaly_detection'][model_dir.name] = {
                    'count': len(model_files),
                    'files': [f.name for f in model_files if f.is_file()]
                }
                summary['total_files'] += len(model_files)
    
    # 특성 중요도 결과 확인 (모델별)
    importance_dir = base_path / 'FEATURE_IMPORTANCE'
    if importance_dir.exists():
        for model_dir in importance_dir.iterdir():
            if model_dir.is_dir():
                model_files = list(model_dir.glob('*'))
                summary['feature_importance'][model_dir.name] = {
                    'count': len(model_files),
                    'files': [f.name for f in model_files if f.is_file()]
                }
                summary['total_files'] += len(model_files)
    
    return summary


# 테스트 및 예시
if __name__ == "__main__":
    import sys
    
    # 테스트용 베이스 디렉토리
    test_base_dir = "/home/kongju/DEV/dream/DATA"
    
    print("🗂️ 폴더 관리 유틸리티 테스트")
    print("=" * 50)
    
    # 전체 구조 생성 테스트
    if len(sys.argv) > 1 and sys.argv[1] == "create":
        print("📁 전체 폴더 구조 생성...")
        result = create_project_structure(test_base_dir)
        print(f"✅ {len(result['created'])}개 폴더 생성 완료")
    
    # 경로 생성 테스트
    elif len(sys.argv) > 1 and sys.argv[1] == "test":
        print("🧪 경로 생성 테스트...")
        
        # 흐름 분석 경로
        flow_path = get_structured_output_path(test_base_dir, "flow", filename="test_flow.json")
        print(f"흐름 분석: {flow_path}")
        
        # 이상탐지 경로 (모델별)
        anomaly_path = get_structured_output_path(test_base_dir, "anomaly", "isolation_forest", "test_anomaly.csv")
        print(f"이상탐지: {anomaly_path}")
        
        # 특성 중요도 경로 (모델별)
        importance_path = get_structured_output_path(test_base_dir, "feature_importance", "lof", "test_importance.json")
        print(f"특성 중요도: {importance_path}")
    
    # 요약 정보
    else:
        print("📊 현재 분석 결과 요약...")
        summary = get_analysis_summary(test_base_dir)
        
        print(f"📁 총 파일 수: {summary['total_files']}개")
        print(f"📊 흐름 분석: {summary['flow_analysis'].get('count', 0)}개")
        print(f"🚨 이상탐지: {sum(info['count'] for info in summary['anomaly_detection'].values())}개")
        print(f"🎯 특성 중요도: {sum(info['count'] for info in summary['feature_importance'].values())}개")
        
        # 사용법 안내
        print("\n📝 사용법:")
        print("  python folder_utils.py create  # 전체 폴더 구조 생성")
        print("  python folder_utils.py test    # 경로 생성 테스트")
        print("  python folder_utils.py         # 현재 상태 요약")
