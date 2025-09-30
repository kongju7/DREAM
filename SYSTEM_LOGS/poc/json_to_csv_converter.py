#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JSON 로그 파일을 CSV 형태로 변환하는 스크립트
중첩된 JSON 객체들을 플래튼화하여 CSV 컬럼으로 변환합니다.
"""

import json
import pandas as pd
import sys
from pathlib import Path
from typing import Dict, Any, List


def flatten_json(nested_json: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
    """
    중첩된 JSON 객체를 플래튼화합니다.
    
    Args:
        nested_json: 플래튼화할 JSON 객체
        parent_key: 부모 키 (재귀 호출용)
        sep: 키 구분자
    
    Returns:
        플래튼화된 딕셔너리
    """
    items = []
    
    for k, v in nested_json.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        
        if isinstance(v, dict):
            # 중첩된 딕셔너리인 경우 재귀적으로 플래튼화
            items.extend(flatten_json(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            # 리스트인 경우 문자열로 변환
            items.append((new_key, str(v)))
        else:
            items.append((new_key, v))
    
    return dict(items)


def convert_json_log_to_csv(input_file: str, output_file: str = None) -> str:
    """
    JSON 라인 형태의 로그 파일을 CSV로 변환합니다.
    
    Args:
        input_file: 입력 JSON 로그 파일 경로
        output_file: 출력 CSV 파일 경로 (기본값: 입력파일명_converted.csv)
    
    Returns:
        출력 파일 경로
    """
    input_path = Path(input_file)
    
    if not input_path.exists():
        raise FileNotFoundError(f"입력 파일을 찾을 수 없습니다: {input_file}")
    
    # 출력 파일명 설정
    if output_file is None:
        output_file = input_path.parent / f"{input_path.stem}_converted.csv"
    else:
        output_file = Path(output_file)
    
    print(f"입력 파일: {input_file}")
    print(f"출력 파일: {output_file}")
    
    # JSON 라인들을 읽어서 플래튼화
    flattened_records = []
    
    with open(input_path, 'r', encoding='utf-8') as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:  # 빈 라인 스킵
                continue
                
            try:
                # JSON 파싱
                json_obj = json.loads(line)
                
                # 플래튼화
                flattened = flatten_json(json_obj)
                flattened_records.append(flattened)
                
            except json.JSONDecodeError as e:
                print(f"경고: {line_no}번째 라인 JSON 파싱 오류: {e}")
                continue
    
    if not flattened_records:
        raise ValueError("변환할 수 있는 JSON 레코드가 없습니다.")
    
    # DataFrame 생성
    df = pd.DataFrame(flattened_records)
    
    # 컬럼 순서 정렬 (주요 필드들을 앞으로)
    primary_columns = ['timestamp', 'level', 'session_id', 'event', 'step_id', 
                      'user_id', 'status', 'message', 'source_ip', 'target']
    
    # 존재하는 주요 컬럼들을 앞으로 배치
    columns = [col for col in primary_columns if col in df.columns]
    # 나머지 컬럼들 추가
    remaining_columns = [col for col in df.columns if col not in columns]
    columns.extend(sorted(remaining_columns))
    
    df = df[columns]
    
    # CSV로 저장
    df.to_csv(output_file, index=False, encoding='utf-8-sig')
    
    print(f"\n변환 완료!")
    print(f"- 총 레코드 수: {len(df)}")
    print(f"- 총 컬럼 수: {len(df.columns)}")
    print(f"- 컬럼 목록:")
    for i, col in enumerate(df.columns, 1):
        print(f"  {i:2d}. {col}")
    
    return str(output_file)


def main():
    """메인 함수"""
    if len(sys.argv) < 2:
        print("사용법: python json_to_csv_converter.py <입력파일> [출력파일]")
        print("예시: python json_to_csv_converter.py ml_message_exchange_2025-01-15.log")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    try:
        result_file = convert_json_log_to_csv(input_file, output_file)
        print(f"\n✅ 변환이 성공적으로 완료되었습니다: {result_file}")
        
    except Exception as e:
        print(f"❌ 오류 발생: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
