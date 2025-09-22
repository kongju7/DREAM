#!/usr/bin/env python3
"""XML 캐시 관리 CLI 도구"""

import argparse
import sys
from pathlib import Path

from utils.xml_cache_manager import get_xml_cache_manager
from config.log_paths import LOG_PATHS


def main():
    parser = argparse.ArgumentParser(description="XML 블록 병합 캐시 관리 도구")
    subparsers = parser.add_subparsers(dest='command', help='사용 가능한 명령어')
    
    # 캐시 생성 명령어
    create_parser = subparsers.add_parser('create', help='XML 병합 캐시 생성')
    create_parser.add_argument('files', nargs='*', help='처리할 로그 파일 경로 (생략시 모든 로그 파일)')
    create_parser.add_argument('--force', action='store_true', help='기존 캐시 강제 재생성')
    
    # 캐시 상태 확인
    status_parser = subparsers.add_parser('status', help='캐시 상태 확인')
    
    # 캐시 삭제
    clear_parser = subparsers.add_parser('clear', help='캐시 삭제')
    clear_parser.add_argument('files', nargs='*', help='삭제할 파일의 캐시 (생략시 모든 캐시 삭제)')
    
    # 캐시 검증
    verify_parser = subparsers.add_parser('verify', help='캐시 유효성 검증')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    cache_manager = get_xml_cache_manager()
    
    if args.command == 'create':
        create_cache(cache_manager, args.files, args.force)
    elif args.command == 'status':
        cache_manager.print_cache_status()
    elif args.command == 'clear':
        clear_cache(cache_manager, args.files)
    elif args.command == 'verify':
        verify_cache(cache_manager)


def create_cache(cache_manager, files, force):
    """캐시 생성"""
    if not files:
        # 모든 로그 파일 처리
        files = LOG_PATHS
        print(f"모든 로그 파일({len(files)}개) 캐시 생성 중...")
    
    success_count = 0
    for file_path in files:
        if not Path(file_path).exists():
            print(f"[ERROR] 파일을 찾을 수 없음: {file_path}")
            continue
            
        try:
            cache_manager.create_cached_file(file_path, force_rebuild=force)
            success_count += 1
        except Exception as e:
            print(f"[ERROR] {file_path} 캐시 생성 실패: {e}")
    
    print(f"\n[INFO] 캐시 생성 완료: {success_count}/{len(files)}개")


def clear_cache(cache_manager, files):
    """캐시 삭제"""
    if not files:
        # 모든 캐시 삭제
        response = input("모든 캐시를 삭제하시겠습니까? (y/N): ")
        if response.lower() == 'y':
            cache_manager.clear_cache()
        else:
            print("취소되었습니다.")
    else:
        # 특정 파일 캐시 삭제
        for file_path in files:
            cache_manager.clear_cache(file_path)


def verify_cache(cache_manager):
    """캐시 유효성 검증"""
    cached_files = cache_manager.list_cached_files()
    
    if not cached_files:
        print("검증할 캐시 파일이 없습니다.")
        return
    
    print(f"총 {len(cached_files)}개 캐시 파일 검증 중...")
    
    valid_count = 0
    invalid_count = 0
    
    for info in cached_files:
        original_file = info['original_file']
        
        if not Path(original_file).exists():
            print(f"❌ {Path(original_file).name}: 원본 파일 없음")
            invalid_count += 1
            continue
            
        if not info['cache_exists']:
            print(f"❌ {Path(original_file).name}: 캐시 파일 없음")
            invalid_count += 1
            continue
            
        if cache_manager.is_cache_valid(original_file):
            print(f"✅ {Path(original_file).name}: 유효")
            valid_count += 1
        else:
            print(f"⚠️  {Path(original_file).name}: 무효 (원본 파일 변경됨)")
            invalid_count += 1
    
    print(f"\n검증 결과: 유효 {valid_count}개, 무효 {invalid_count}개")
    
    if invalid_count > 0:
        response = input("무효한 캐시를 재생성하시겠습니까? (y/N): ")
        if response.lower() == 'y':
            for info in cached_files:
                original_file = info['original_file']
                if Path(original_file).exists() and not cache_manager.is_cache_valid(original_file):
                    try:
                        cache_manager.create_cached_file(original_file, force_rebuild=True)
                        print(f"✅ {Path(original_file).name}: 캐시 재생성 완료")
                    except Exception as e:
                        print(f"❌ {Path(original_file).name}: 캐시 재생성 실패: {e}")


if __name__ == "__main__":
    main()







