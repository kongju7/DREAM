#!/usr/bin/env python3
"""
CSV 파일의 국가 코드를 한국어 국가명으로 변환하는 스크립트

기능:
- IP 데이터베이스 CSV 파일의 country 컬럼을 한국어로 변환
- 대용량 파일 처리 최적화 (청크 단위 처리)
- 변환 통계 및 진행률 표시
- 백업 파일 생성 옵션
"""

import os
import pandas as pd
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Tuple
import shutil

# 기존 매핑 유틸리티 import
from country_code_ko_mapper import alpha2_to_korean, build_full_mapping

class CSVCountryConverter:
    def __init__(self, csv_path: str, output_path: Optional[str] = None, backup: bool = True):
        self.csv_path = Path(csv_path)
        self.output_path = Path(output_path) if output_path else self.csv_path.with_suffix('.korean.csv')
        self.backup = backup
        self.country_mapping = build_full_mapping()
        self.stats = {
            'total_rows': 0,
            'converted_count': 0,
            'unknown_codes': set(),
            'processing_time': 0
        }
    
    def create_backup(self):
        """원본 파일 백업 생성"""
        if not self.backup:
            return
        
        backup_path = self.csv_path.with_suffix(f'.backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv')
        print(f"백업 파일 생성 중: {backup_path}")
        shutil.copy2(self.csv_path, backup_path)
        print(f"✓ 백업 완료: {backup_path}")
    
    def analyze_country_codes(self, sample_size: int = 10000) -> Dict[str, int]:
        """CSV 파일의 국가 코드 분포 분석"""
        print(f"\n=== 국가 코드 분석 중 (샘플: {sample_size:,}개) ===")
        
        try:
            # 샘플 데이터로 빠른 분석
            df_sample = pd.read_csv(
                self.csv_path, 
                names=['ip_start', 'ip_end', 'country'],
                nrows=sample_size
            )
            
            country_dist = df_sample['country'].value_counts().to_dict()
            
            print(f"발견된 고유 국가 코드: {len(country_dist)}개")
            print(f"상위 10개 국가 코드:")
            
            for i, (code, count) in enumerate(list(country_dist.items())[:10], 1):
                korean_name = self.country_mapping.get(code, '알 수 없음')
                percentage = count / len(df_sample) * 100
                print(f"  {i:2d}. {code} ({korean_name}): {count:,}개 ({percentage:.1f}%)")
            
            # 매핑되지 않는 코드 확인
            unmapped = set(country_dist.keys()) - set(self.country_mapping.keys())
            if unmapped:
                print(f"\n매핑되지 않는 코드: {sorted(unmapped)}")
            
            return country_dist
            
        except Exception as e:
            print(f"분석 실패: {str(e)}")
            return {}
    
    def convert_country_chunk(self, chunk: pd.DataFrame) -> pd.DataFrame:
        """데이터 청크의 country 컬럼을 한국어로 변환"""
        original_countries = chunk['country'].copy()
        
        # 국가 코드를 한국어로 매핑
        chunk['country_korean'] = chunk['country'].map(
            lambda x: self.country_mapping.get(str(x).upper().strip(), f"알 수 없음({x})") if pd.notna(x) else "정보 없음"
        )
        
        # 통계 업데이트
        for code in original_countries.dropna():
            code_upper = str(code).upper().strip()
            if code_upper in self.country_mapping:
                self.stats['converted_count'] += 1
            else:
                self.stats['unknown_codes'].add(code_upper)
        
        # 기존 country 컬럼을 한국어로 교체
        chunk['country'] = chunk['country_korean']
        chunk.drop('country_korean', axis=1, inplace=True)
        
        return chunk
    
    def process_csv(self, chunk_size: int = 50000):
        """CSV 파일 전체 처리"""
        print(f"\n=== CSV 파일 변환 시작 ===")
        print(f"입력 파일: {self.csv_path}")
        print(f"출력 파일: {self.output_path}")
        print(f"청크 크기: {chunk_size:,}개")
        
        start_time = time.time()
        
        try:
            # 백업 생성
            self.create_backup()
            
            # 전체 행 수 확인
            print(f"\n전체 행 수 확인 중...")
            total_rows = sum(1 for _ in open(self.csv_path, 'r', encoding='utf-8'))
            self.stats['total_rows'] = total_rows
            print(f"전체 행 수: {total_rows:,}개")
            
            # 청크 단위로 처리
            processed_rows = 0
            chunk_count = 0
            
            # CSV 리더 초기화
            csv_reader = pd.read_csv(
                self.csv_path,
                names=['ip_start', 'ip_end', 'country'],
                chunksize=chunk_size,
                dtype=str
            )
            
            # 출력 파일 초기화
            first_chunk = True
            
            for chunk in csv_reader:
                chunk_count += 1
                current_chunk_size = len(chunk)
                
                # 국가 코드 변환
                converted_chunk = self.convert_country_chunk(chunk)
                
                # 파일에 저장 (첫 번째 청크는 새 파일, 나머지는 append)
                converted_chunk.to_csv(
                    self.output_path,
                    mode='w' if first_chunk else 'a',
                    header=False,
                    index=False
                )
                first_chunk = False
                
                # 진행률 표시
                processed_rows += current_chunk_size
                progress = processed_rows / total_rows * 100
                
                print(f"\r청크 {chunk_count} 처리 완료 - 진행률: {progress:.1f}% ({processed_rows:,}/{total_rows:,})", end='')
            
            self.stats['processing_time'] = time.time() - start_time
            
            print(f"\n\n✓ 변환 완료!")
            self.print_conversion_summary()
            
            return True
            
        except Exception as e:
            print(f"\n❌ 변환 실패: {str(e)}")
            return False
    
    def print_conversion_summary(self):
        """변환 결과 요약 출력"""
        print(f"\n=== 변환 결과 요약 ===")
        print(f"총 처리 행수: {self.stats['total_rows']:,}개")
        print(f"성공적 변환: {self.stats['converted_count']:,}개")
        print(f"처리 시간: {self.stats['processing_time']:.1f}초")
        
        if self.stats['unknown_codes']:
            print(f"\n매핑되지 않은 코드 ({len(self.stats['unknown_codes'])}개):")
            for code in sorted(self.stats['unknown_codes']):
                print(f"  - {code}")
        
        print(f"\n출력 파일: {self.output_path}")
        if self.output_path.exists():
            size_mb = self.output_path.stat().st_size / 1024 / 1024
            print(f"출력 파일 크기: {size_mb:.2f} MB")
    
    def verify_conversion(self, sample_size: int = 10):
        """변환 결과 검증 (샘플 확인)"""
        if not self.output_path.exists():
            print("출력 파일이 존재하지 않습니다.")
            return False
        
        print(f"\n=== 변환 결과 검증 (샘플 {sample_size}개) ===")
        
        try:
            # 변환된 파일에서 샘플 읽기
            df_converted = pd.read_csv(
                self.output_path,
                names=['ip_start', 'ip_end', 'country'],
                nrows=sample_size
            )
            
            print("변환된 샘플 데이터:")
            for i, row in df_converted.iterrows():
                print(f"  {row['ip_start']} - {row['ip_end']} → {row['country']}")
            
            return True
            
        except Exception as e:
            print(f"검증 실패: {str(e)}")
            return False

def main():
    """메인 함수"""
    print("CSV 국가 코드 → 한국어 변환기")
    print("=" * 50)
    
    # 기본 설정
    default_csv = "/home/kongju/DATA/DREAM/DB-IP/dbip-country-lite-2025-09.csv"
    
    # CSV 파일 존재 확인
    if not os.path.exists(default_csv):
        print(f"CSV 파일을 찾을 수 없습니다: {default_csv}")
        return 1
    
    # 컨버터 초기화
    converter = CSVCountryConverter(
        csv_path=default_csv,
        output_path="/home/kongju/DATA/DREAM/DB-IP/dbip-country-lite-2025-09-korean.csv",
        backup=True
    )
    
    try:
        # 1. 국가 코드 분석
        converter.analyze_country_codes(sample_size=10000)
        
        # 2. 변환 실행
        success = converter.process_csv(chunk_size=100000)
        
        if success:
            # 3. 결과 검증
            converter.verify_conversion(sample_size=10)
            print(f"\n모든 작업이 성공적으로 완료되었습니다!")
            return 0
        else:
            print(f"\n변환 작업 중 오류가 발생했습니다.")
            return 1
            
    except KeyboardInterrupt:
        print(f"\n사용자에 의해 중단되었습니다.")
        return 1
    except Exception as e:
        print(f"\n예상치 못한 오류: {str(e)}")
        return 1

if __name__ == "__main__":
    exit(main())
