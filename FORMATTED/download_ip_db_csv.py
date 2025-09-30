#!/usr/bin/env python3
"""
DB-IP Country Lite CSV 데이터베이스 자동 다운로드 및 분석 스크립트
최신 IP 데이터베이스를 다운로드하고 구조를 검증합니다.
"""

import os
import requests
import gzip
import pandas as pd
import ipaddress
from datetime import datetime
from pathlib import Path
import time

# 설정
OUTPUT_PATH = "/home/kongju/DATA/DREAM/DB-IP/"
BASE_URL = "https://download.db-ip.com/free/"
DB_NAME_TEMPLATE = "dbip-country-lite-{year}-{month:02d}.csv.gz"

class IPDatabaseDownloader:
    def __init__(self, output_path=OUTPUT_PATH):
        self.output_path = Path(output_path)
        self.output_path.mkdir(parents=True, exist_ok=True)
        
    def get_current_db_version(self):
        """현재 날짜 기준으로 최신 데이터베이스 버전 정보 반환"""
        now = datetime.now()
        current_year = now.year
        current_month = now.month
        
        # 현재 월과 이전 월 모두 확인 (업데이트 지연 고려)
        versions_to_try = [
            (current_year, current_month),
            (current_year, current_month - 1) if current_month > 1 else (current_year - 1, 12)
        ]
        
        return versions_to_try
    
    def check_url_availability(self, url):
        """URL 접근 가능성 확인"""
        try:
            response = requests.head(url, timeout=10)
            return response.status_code == 200
        except:
            return False
    
    def get_latest_available_version(self):
        """사용 가능한 최신 버전 찾기"""
        print("=== 최신 IP 데이터베이스 버전 확인 중... ===")
        
        versions_to_try = self.get_current_db_version()
        
        for year, month in versions_to_try:
            filename = DB_NAME_TEMPLATE.format(year=year, month=month)
            url = BASE_URL + filename
            
            print(f"확인 중: {filename}")
            if self.check_url_availability(url):
                print(f"사용 가능한 최신 버전 발견: {filename}")
                return url, filename
            else:
                print(f"{filename} - 사용 불가")
        
        print("최신 버전을 찾을 수 없습니다. 기본 버전을 시도합니다.")
        # 기본값으로 현재 년도-월 사용
        year, month = datetime.now().year, datetime.now().month
        filename = DB_NAME_TEMPLATE.format(year=year, month=month)
        url = BASE_URL + filename
        return url, filename
    
    def download_file(self, url, filename):
        """파일 다운로드"""
        filepath = self.output_path / filename
        
        print(f"\n=== 파일 다운로드 중... ===")
        print(f"URL: {url}")
        print(f"저장 경로: {filepath}")
        
        try:
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0
            
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        
                        if total_size > 0:
                            progress = (downloaded_size / total_size) * 100
                            print(f"\r진행률: {progress:.1f}% ({downloaded_size:,}/{total_size:,} 바이트)", end='')
            
            print(f"\n다운로드 완료: {filepath}")
            print(f"파일 크기: {os.path.getsize(filepath):,} 바이트")
            return filepath
            
        except Exception as e:
            print(f"다운로드 실패: {str(e)}")
            return None
    
    def extract_gz_file(self, gz_filepath):
        """gzip 파일 압축 해제"""
        csv_filepath = gz_filepath.with_suffix('')  # .gz 확장자 제거
        
        print(f"\n=== 압축 파일 해제 중... ===")
        print(f"압축 파일: {gz_filepath}")
        print(f"출력 파일: {csv_filepath}")
        
        try:
            with gzip.open(gz_filepath, 'rb') as f_in:
                with open(csv_filepath, 'wb') as f_out:
                    # 청크 단위로 읽어서 메모리 사용량 최적화
                    chunk_size = 64 * 1024  # 64KB
                    while True:
                        chunk = f_in.read(chunk_size)
                        if not chunk:
                            break
                        f_out.write(chunk)
            
            print(f"압축 해제 완료: {csv_filepath}")
            print(f"해제된 파일 크기: {os.path.getsize(csv_filepath):,} 바이트")
            
            # 압축 파일 삭제 (선택사항)
            # gz_filepath.unlink()
            
            return csv_filepath
            
        except Exception as e:
            print(f"압축 해제 실패: {str(e)}")
            return None
    
    def analyze_csv_data(self, csv_filepath):
        """CSV 데이터 구조 및 품질 분석"""
        print(f"\n=== CSV 데이터 분석 중... ===")
        print(f"분석 파일: {csv_filepath}")
        
        try:
            # CSV 파일 읽기
            print("데이터 로딩 중...")
            df = pd.read_csv(csv_filepath, names=['ip_start', 'ip_end', 'country'])
            
            print(f"\n 기본 정보:")
            print(f"  - 총 레코드 수: {len(df):,}개")
            print(f"  - 컬럼 수: {len(df.columns)}개")
            print(f"  - 컬럼명: {list(df.columns)}")
            print(f"  - 메모리 사용량: {df.memory_usage(deep=True).sum():,} 바이트")
            
            print(f"\n 컬럼별 상세 정보:")
            for col in df.columns:
                null_count = df[col].isnull().sum()
                unique_count = df[col].nunique()
                data_type = df[col].dtype
                print(f"  {col}:")
                print(f"    - 데이터 타입: {data_type}")
                print(f"    - 결측값: {null_count:,}개 ({null_count/len(df)*100:.2f}%)")
                print(f"    - 고유값: {unique_count:,}개")
            
            print(f"\n 상위 5행:")
            print(df.head().to_string(index=False))
            
            print(f"\n 하위 5행:")
            print(df.tail().to_string(index=False))
            
            # 국가별 통계
            print(f"\n 국가별 IP 블록 수 (상위 10개):")
            country_counts = df['country'].value_counts().head(10)
            for i, (country, count) in enumerate(country_counts.items(), 1):
                percentage = count / len(df) * 100
                print(f"  {i:2d}. {country}: {count:,}개 ({percentage:.1f}%)")
            
            print(f"\n총 국가 수: {df['country'].nunique()}개")
            
            # IP 버전 분석 (샘플링)
            print(f"\n IP 주소 버전 분석 (샘플 1000개):")
            sample_size = min(1000, len(df))
            sample_df = df.sample(n=sample_size, random_state=42)
            
            ipv4_count = 0
            ipv6_count = 0
            invalid_count = 0
            
            for _, row in sample_df.iterrows():
                try:
                    start_ip = ipaddress.ip_address(row['ip_start'])
                    if isinstance(start_ip, ipaddress.IPv4Address):
                        ipv4_count += 1
                    elif isinstance(start_ip, ipaddress.IPv6Address):
                        ipv6_count += 1
                except:
                    invalid_count += 1
            
            total_sample = ipv4_count + ipv6_count + invalid_count
            if total_sample > 0:
                print(f"  - IPv4 블록: {ipv4_count}개 ({ipv4_count/total_sample*100:.1f}%)")
                print(f"  - IPv6 블록: {ipv6_count}개 ({ipv6_count/total_sample*100:.1f}%)")
                if invalid_count > 0:
                    print(f"  - 유효하지 않은 IP: {invalid_count}개 ({invalid_count/total_sample*100:.1f}%)")
            
            # 데이터 품질 검증
            self.validate_data_quality(df)
            
            return df
            
        except Exception as e:
            print(f" CSV 분석 실패: {str(e)}")
            return None
    
    def validate_data_quality(self, df):
        """데이터 품질 검증"""
        print(f"\n 데이터 품질 검증:")
        
        validations = []
        
        # 1. 컬럼 수 확인
        if len(df.columns) == 3:
            validations.append("컬럼 수: 3개 (ip_start, ip_end, country)")
        else:
            validations.append(f"컬럼 수: {len(df.columns)}개 (3개 필요)")
        
        # 2. 컬럼명 확인
        expected_columns = ['ip_start', 'ip_end', 'country']
        if list(df.columns) == expected_columns:
            validations.append("컬럼명: 요구사항과 정확히 일치")
        else:
            validations.append(f"컬럼명: {list(df.columns)} (헤더 없음)")
        
        # 3. 데이터 완결성
        total_nulls = df.isnull().sum().sum()
        completeness = (len(df) * len(df.columns) - total_nulls) / (len(df) * len(df.columns)) * 100
        validations.append(f"데이터 완결성: {completeness:.2f}% ({total_nulls:,}개 결측값)")
        
        # 4. 국가 코드 형식 확인
        country_lengths = df['country'].dropna().str.len()
        if len(country_lengths) > 0:
            if country_lengths.min() == country_lengths.max() == 2:
                validations.append("국가 코드: ISO 3166-1 alpha-2 형식 (2글자)")
            else:
                validations.append(f"국가 코드: 길이 불일치 ({country_lengths.min()}-{country_lengths.max()}글자)")
        
        # 5. 중복 레코드 확인
        duplicates = df.duplicated().sum()
        if duplicates == 0:
            validations.append("중복 레코드: 없음")
        else:
            validations.append(f"중복 레코드: {duplicates:,}개")
        
        for validation in validations:
            print(f"  {validation}")
    
    def run(self):
        """전체 프로세스 실행"""
        print("DB-IP Country Lite CSV 자동 다운로드 및 분석 시스템")
        print("=" * 60)
        print(f"시작 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"출력 디렉토리: {self.output_path}")
        
        start_time = time.time()
        
        try:
            # 1. 최신 버전 확인
            url, filename = self.get_latest_available_version()
            
            # 2. 파일 다운로드
            gz_filepath = self.download_file(url, filename)
            if not gz_filepath:
                return False
            
            # 3. 압축 해제
            csv_filepath = self.extract_gz_file(gz_filepath)
            if not csv_filepath:
                return False
            
            # 4. 데이터 분석
            df = self.analyze_csv_data(csv_filepath)
            if df is None:
                return False
            
            # 완료 메시지
            elapsed_time = time.time() - start_time
            print(f"\n 모든 작업 완료!")
            print(f"소요 시간: {elapsed_time:.1f}초")
            print(f"최종 CSV 파일: {csv_filepath}")
            print(f"총 IP 블록: {len(df):,}개")
            print(f"총 국가: {df['country'].nunique()}개")
            
            return True
            
        except Exception as e:
            print(f"\n 프로세스 실행 중 오류 발생: {str(e)}")
            return False

def main():
    """메인 함수"""
    downloader = IPDatabaseDownloader()
    success = downloader.run()
    
    if success:
        print(f"\n 프로그램이 성공적으로 완료되었습니다.")
        return 0
    else:
        print(f"\n 프로그램 실행 중 오류가 발생했습니다.")
        return 1

if __name__ == "__main__":
    exit(main())
