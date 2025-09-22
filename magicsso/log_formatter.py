#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Log File Formatter
RAW_LOGS 폴더의 파일들을 LOGS 폴더의 표준 형식으로 변환하는 도구

변환 형식: RAW_LOGS/{폴더명}/{파일명} → LOGS/{폴더명}__{파일명}

Author: Kong Ju
Date: 2025-01-21
"""

import os
import shutil
from pathlib import Path
import logging
from datetime import datetime

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/kongju/DEV/dream/DATA/log_formatter.log'),
        logging.StreamHandler()
    ]
)

class LogFormatter:
    """로그 파일 형식 변환기"""
    
    def __init__(self, raw_logs_dir: str, target_logs_dir: str):
        """
        초기화
        
        Args:
            raw_logs_dir: 원본 로그 디렉토리 (RAW_LOGS)
            target_logs_dir: 대상 로그 디렉토리 (LOGS)
        """
        self.raw_logs_dir = Path(raw_logs_dir)
        self.target_logs_dir = Path(target_logs_dir)
        
        # 대상 디렉토리 생성
        self.target_logs_dir.mkdir(parents=True, exist_ok=True)
        
        logging.info(f"원본 디렉토리: {self.raw_logs_dir}")
        logging.info(f"대상 디렉토리: {self.target_logs_dir}")
    
    def scan_raw_logs(self) -> dict:
        """
        RAW_LOGS 디렉토리 스캔하여 폴더별 파일 목록 반환
        
        Returns:
            dict: {폴더명: [파일목록]}
        """
        folder_files = {}
        
        if not self.raw_logs_dir.exists():
            logging.error(f"RAW_LOGS 디렉토리가 존재하지 않습니다: {self.raw_logs_dir}")
            return folder_files
        
        logging.info("RAW_LOGS 디렉토리 스캔 시작...")
        
        # 모든 하위 폴더 스캔
        for folder_path in self.raw_logs_dir.iterdir():
            if folder_path.is_dir():
                folder_name = folder_path.name
                files = []
                
                # 폴더 내 모든 파일 스캔
                for file_path in folder_path.iterdir():
                    if file_path.is_file():
                        files.append(file_path)
                        logging.info(f"발견된 파일: {folder_name}/{file_path.name}")
                
                if files:
                    folder_files[folder_name] = files
                    logging.info(f"폴더 '{folder_name}'에서 {len(files)}개 파일 발견")
                else:
                    logging.warning(f"폴더 '{folder_name}'에 파일이 없습니다.")
        
        logging.info(f"총 {len(folder_files)}개 폴더에서 파일 발견")
        return folder_files
    
    def format_filename(self, folder_name: str, original_filename: str) -> str:
        """
        파일명을 표준 형식으로 변환
        
        Args:
            folder_name: 폴더명
            original_filename: 원본 파일명
            
        Returns:
            str: 변환된 파일명 (폴더명__원본파일명)
        """
        return f"{folder_name}__{original_filename}"
    
    def copy_and_format_files(self, folder_files: dict, copy_mode: str = 'copy') -> dict:
        """
        파일들을 표준 형식으로 복사/이동
        
        Args:
            folder_files: 폴더별 파일 딕셔너리
            copy_mode: 'copy' 또는 'move'
            
        Returns:
            dict: 변환 결과 정보
        """
        results = {
            'success': [],
            'failed': [],
            'skipped': []
        }
        
        total_files = sum(len(files) for files in folder_files.values())
        processed = 0
        
        logging.info(f"총 {total_files}개 파일 처리 시작 (모드: {copy_mode})")
        
        for folder_name, files in folder_files.items():
            logging.info(f"폴더 '{folder_name}' 처리 중...")
            
            for source_file in files:
                try:
                    processed += 1
                    
                    # 새 파일명 생성
                    new_filename = self.format_filename(folder_name, source_file.name)
                    target_file = self.target_logs_dir / new_filename
                    
                    # 파일이 이미 존재하는지 확인
                    if target_file.exists():
                        logging.warning(f"파일이 이미 존재합니다: {new_filename}")
                        
                        # 파일 크기 및 수정시간 비교
                        if self._files_are_identical(source_file, target_file):
                            logging.info(f"동일한 파일이므로 건너뜁니다: {new_filename}")
                            results['skipped'].append({
                                'source': str(source_file),
                                'target': str(target_file),
                                'reason': '동일한 파일'
                            })
                            continue
                        else:
                            # 백업 파일명 생성
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            backup_name = f"{folder_name}__{source_file.stem}_{timestamp}{source_file.suffix}"
                            target_file = self.target_logs_dir / backup_name
                            logging.info(f"기존 파일과 다름. 백업 파일명 사용: {backup_name}")
                    
                    # 파일 복사 또는 이동
                    if copy_mode == 'copy':
                        shutil.copy2(source_file, target_file)
                        logging.info(f"복사 완료: {source_file.name} → {target_file.name}")
                    elif copy_mode == 'move':
                        shutil.move(str(source_file), str(target_file))
                        logging.info(f"이동 완료: {source_file.name} → {target_file.name}")
                    
                    results['success'].append({
                        'source': str(source_file),
                        'target': str(target_file),
                        'operation': copy_mode
                    })
                    
                    logging.info(f"진행률: {processed}/{total_files} ({processed/total_files*100:.1f}%)")
                    
                except Exception as e:
                    logging.error(f"파일 처리 실패: {source_file} → {e}")
                    results['failed'].append({
                        'source': str(source_file),
                        'error': str(e)
                    })
        
        return results
    
    def _files_are_identical(self, file1: Path, file2: Path) -> bool:
        """두 파일이 동일한지 확인 (크기와 수정시간 비교)"""
        try:
            stat1 = file1.stat()
            stat2 = file2.stat()
            
            return (stat1.st_size == stat2.st_size and 
                   abs(stat1.st_mtime - stat2.st_mtime) < 1)  # 1초 차이 허용
        except:
            return False
    
    def create_summary_report(self, results: dict) -> str:
        """변환 결과 요약 보고서 생성"""
        report = []
        report.append("=" * 60)
        report.append("📋 로그 파일 형식 변환 결과 보고서")
        report.append("=" * 60)
        report.append(f"📅 실행 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # 성공 파일들
        report.append(f"✅ 성공: {len(results['success'])}개")
        for item in results['success']:
            source_name = Path(item['source']).name
            target_name = Path(item['target']).name
            report.append(f"   {source_name} → {target_name}")
        report.append("")
        
        # 건너뛴 파일들
        if results['skipped']:
            report.append(f"⏭️ 건너뜀: {len(results['skipped'])}개")
            for item in results['skipped']:
                source_name = Path(item['source']).name
                target_name = Path(item['target']).name
                report.append(f"   {source_name} → {target_name} ({item['reason']})")
            report.append("")
        
        # 실패 파일들
        if results['failed']:
            report.append(f"❌ 실패: {len(results['failed'])}개")
            for item in results['failed']:
                source_name = Path(item['source']).name
                report.append(f"   {source_name}: {item['error']}")
            report.append("")
        
        # 요약
        total = len(results['success']) + len(results['skipped']) + len(results['failed'])
        success_rate = (len(results['success']) / total * 100) if total > 0 else 0
        
        report.append("📊 요약")
        report.append(f"   총 파일: {total}개")
        report.append(f"   성공률: {success_rate:.1f}%")
        report.append("=" * 60)
        
        return "\n".join(report)
    
    def run_conversion(self, copy_mode: str = 'copy', create_report: bool = True):
        """
        전체 변환 프로세스 실행
        
        Args:
            copy_mode: 'copy' (복사) 또는 'move' (이동)
            create_report: 보고서 생성 여부
        """
        try:
            logging.info("🚀 로그 파일 형식 변환 시작")
            
            # 1. RAW_LOGS 스캔
            folder_files = self.scan_raw_logs()
            
            if not folder_files:
                logging.warning("처리할 파일이 없습니다.")
                return
            
            # 2. 파일 변환 실행
            results = self.copy_and_format_files(folder_files, copy_mode)
            
            # 3. 결과 보고서 생성
            if create_report:
                report = self.create_summary_report(results)
                print(report)
                
                # 보고서 파일 저장
                report_file = self.target_logs_dir.parent / f"log_conversion_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(report_file, 'w', encoding='utf-8') as f:
                    f.write(report)
                logging.info(f"📄 보고서 저장: {report_file}")
            
            logging.info("✅ 로그 파일 형식 변환 완료")
            
        except Exception as e:
            logging.error(f"❌ 변환 중 오류 발생: {e}")
            raise


def main():
    """메인 함수"""
    # 경로 설정
    raw_logs_dir = "/home/kongju/DEV/dream/DATA/RAW_LOGS"
    target_logs_dir = "/home/kongju/DEV/dream/DATA/LOGS"
    
    print("🔄 SSO 로그 파일 형식 변환 도구")
    print("=" * 50)
    print(f"📂 원본: {raw_logs_dir}")
    print(f"📁 대상: {target_logs_dir}")
    print()
    
    # 사용자 입력 받기
    print("변환 모드를 선택하세요:")
    print("1. copy   - 파일 복사 (원본 파일 유지)")
    print("2. move   - 파일 이동 (원본 파일 삭제)")
    print("3. preview - 미리보기만 (실제 변환하지 않음)")
    
    choice = input("선택 (1/2/3, 기본값: 1): ").strip()
    
    if choice == "2":
        copy_mode = "move"
        print("⚠️  이동 모드: 원본 파일이 삭제됩니다!")
        confirm = input("계속하시겠습니까? (y/N): ").strip().lower()
        if confirm != 'y':
            print("작업이 취소되었습니다.")
            return
    elif choice == "3":
        copy_mode = "preview"
    else:
        copy_mode = "copy"
        print("✅ 복사 모드: 원본 파일이 유지됩니다.")
    
    # 변환 실행
    formatter = LogFormatter(raw_logs_dir, target_logs_dir)
    
    if copy_mode == "preview":
        # 미리보기만
        folder_files = formatter.scan_raw_logs()
        print("\n📋 변환 예정 파일 목록:")
        print("-" * 50)
        for folder_name, files in folder_files.items():
            print(f"📁 {folder_name}/")
            for file_path in files:
                new_name = formatter.format_filename(folder_name, file_path.name)
                print(f"   {file_path.name} → {new_name}")
        print("-" * 50)
        print(f"총 {sum(len(files) for files in folder_files.values())}개 파일이 변환 예정입니다.")
    else:
        formatter.run_conversion(copy_mode)


if __name__ == "__main__":
    main()
