#!/usr/bin/env python3
"""
IP 데이터베이스 다운로드 및 조회 스크립트
DB-IP Country Lite 데이터베이스를 다운로드하고 샘플 데이터를 조회합니다.
"""

import os
import maxminddb
import socket
import struct

# 설정
OUTPUT_PATH = "/home/kongju/DATA/DREAM/DB-IP/"
DB_FILE = os.path.join(OUTPUT_PATH, "dbip-country-lite-2025-09.mmdb")

def ip_to_int(ip):
    """IP 주소를 정수로 변환"""
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def int_to_ip(ip_int):
    """정수를 IP 주소로 변환"""
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def analyze_data_structure(reader, sample_ips):
    """데이터베이스 구조 상세 분석"""
    print("\n=== 데이터베이스 구조 분석 ===")
    
    # 첫 번째 샘플 IP로 전체 데이터 구조 확인
    test_ip = sample_ips[0]
    print(f"테스트 IP: {test_ip}")
    
    try:
        result = reader.get(test_ip)
        if result:
            print("\n전체 데이터 구조:")
            import json
            print(json.dumps(result, indent=2, ensure_ascii=False))
            
            print("\n=== 사용자 요청 정보 확인 ===")
            available_fields = []
            missing_fields = []
            
            # 각 필드 확인
            fields_to_check = [
                ("First IP address", "first_ip", None),
                ("Last IP address", "last_ip", None), 
                ("Continent code", "continent.code", "continent"),
                ("Continent name", "continent.names.en", "continent"),
                ("Country ISO-3166-alpha2 code", "country.iso_code", "country"),
                ("Country EU membership", "country.is_in_european_union", "country"),
                ("Country name", "country.names.en", "country")
            ]
            
            for field_desc, field_path, parent_key in fields_to_check:
                if parent_key and parent_key in result:
                    parent_data = result[parent_key]
                    if "." in field_path:
                        # 중첩된 필드 확인
                        nested_keys = field_path.split('.')[1:]  # parent_key 이후 키들
                        value = parent_data
                        found = True
                        for key in nested_keys:
                            if isinstance(value, dict) and key in value:
                                value = value[key]
                            else:
                                found = False
                                break
                        if found:
                            available_fields.append((field_desc, value))
                        else:
                            missing_fields.append(field_desc)
                    else:
                        # 단일 필드 확인
                        key = field_path.split('.')[-1]
                        if key in parent_data:
                            available_fields.append((field_desc, parent_data[key]))
                        else:
                            missing_fields.append(field_desc)
                else:
                    missing_fields.append(field_desc)
            
            print("\n✅ 사용 가능한 정보:")
            for field, value in available_fields:
                print(f"  - {field}: {value}")
            
            print("\n❌ 사용 불가능한 정보:")
            for field in missing_fields:
                print(f"  - {field}")
                
        else:
            print("데이터를 찾을 수 없습니다.")
            
    except Exception as e:
        print(f"오류 발생: {str(e)}")

def sample_ip_lookup(reader, sample_ips):
    """샘플 IP 주소들로 데이터베이스 조회"""
    print("\n=== 샘플 IP 주소 조회 결과 (상위 5개) ===")
    print(f"{'IP 주소':<15} {'국가 코드':<8} {'국가명':<20} {'대륙 코드':<8} {'대륙명'}")
    print("-" * 70)
    
    for i, ip in enumerate(sample_ips[:5]):
        try:
            result = reader.get(ip)
            if result:
                # 국가 정보
                country_code = result.get('country', {}).get('iso_code', 'N/A')
                country_name = result.get('country', {}).get('names', {}).get('en', 'N/A')
                
                # 대륙 정보 (있다면)
                continent_code = result.get('continent', {}).get('code', 'N/A')
                continent_name = result.get('continent', {}).get('names', {}).get('en', 'N/A')
                
                print(f"{ip:<15} {country_code:<8} {country_name:<20} {continent_code:<8} {continent_name}")
            else:
                print(f"{ip:<15} {'N/A':<8} {'Not Found':<20} {'N/A':<8} {'N/A'}")
        except Exception as e:
            print(f"{ip:<15} {'ERROR':<8} {str(e):<20} {'N/A':<8} {'N/A'}")

def main():
    """메인 함수"""
    print("DB-IP Country Lite 데이터베이스 조회 프로그램")
    print("=" * 50)
    
    # 데이터베이스 파일 존재 확인
    if not os.path.exists(DB_FILE):
        print(f"오류: 데이터베이스 파일을 찾을 수 없습니다: {DB_FILE}")
        return
    
    try:
        # 데이터베이스 열기
        with maxminddb.open_database(DB_FILE) as reader:
            
            # 데이터베이스 메타데이터 출력
            print("\n=== 데이터베이스 정보 ===")
            print(f"데이터베이스 파일: {DB_FILE}")
            print(f"파일 크기: {os.path.getsize(DB_FILE):,} 바이트")
            metadata = reader.metadata()
            print(f"데이터베이스 타입: {getattr(metadata, 'database_type', 'Unknown')}")
            print(f"빌드 시간: {getattr(metadata, 'build_epoch', 'Unknown')}")
            print(f"IP 버전: {getattr(metadata, 'ip_version', 'Unknown')}")
            print(f"레코드 크기: {getattr(metadata, 'record_size', 'Unknown')}")
            print(f"노드 개수: {getattr(metadata, 'node_count', 'Unknown')}")
            if hasattr(metadata, 'description'):
                print(f"설명: {metadata.description}")
            
            # 샘플 IP 주소들 (다양한 국가)
            sample_ips = [
                "8.8.8.8",      # Google DNS (미국)
                "1.1.1.1",      # Cloudflare DNS (미국)
                "114.114.114.114", # 중국
                "168.126.63.1", # KT DNS (한국)
                "208.67.222.222", # OpenDNS (미국)
            ]
            
            # 데이터 구조 분석 실행
            analyze_data_structure(reader, sample_ips)
            
            # 샘플 IP 조회 실행
            sample_ip_lookup(reader, sample_ips)
            
            print("\n=== 프로그램 실행 완료 ===")
            
    except Exception as e:
        print(f"오류 발생: {str(e)}")

if __name__ == "__main__":
    main()
