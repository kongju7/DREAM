#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Data Folder Organizer
DATA 폴더의 파일들을 체계적으로 정리하는 도구

Author: Kong Ju
Date: 2025-01-21
"""

import os
import shutil
from pathlib import Path
import logging
from datetime import datetime
import json

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class DataOrganizer:
    """데이터 폴더 정리 도구"""
    
    def __init__(self, data_dir: str):
        """
        초기화
        
        Args:
            data_dir: 정리할 데이터 디렉토리
        """
        self.data_dir = Path(data_dir)
        self.backup_dir = self.data_dir / "ARCHIVE" / f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # 새로운 폴더 구조 정의
        self.folder_structure = {
            'FLOW_ANALYSIS': self.data_dir / "FLOW_ANALYSIS",
            'ANOMALY_DETECTION': self.data_dir / "ANOMALY_DETECTION",
            'FEATURE_IMPORTANCE': self.data_dir / "FEATURE_IMPORTANCE", 
            'REPORTS': self.data_dir / "REPORTS",
            'ARCHIVE': self.data_dir / "ARCHIVE"
        }
        
        # 모델별 하위 폴더
        self.model_folders = [
            'isolation_forest',
            'lof', 
            'one_class_svm',
            'random_cut_forest'
        ]
        
        # 파일 분류 규칙
        self.file_patterns = {
            # SSO 흐름 분석
            'FLOW_ANALYSIS': [
                'sso_analysis_result.json',
                'sso_flow_analysis.png', 
                'sso_transactions.csv'
            ],
            
            # 이상탐지 결과 (모델별)
            'ANOMALY_DETECTION': {
                'isolation_forest': ['sso_anomaly_iforest_'],
                'lof': ['sso_anomaly_lof_'],
                'one_class_svm': ['sso_anomaly_ocsvm_'],
                'random_cut_forest': ['sso_anomaly_rcf_']
            },
            
            # 특성 중요도 (모델별)
            'FEATURE_IMPORTANCE': {
                'isolation_forest': ['feature_importance_iforest_'],
                'lof': ['feature_importance_lof_'],
                'one_class_svm': ['feature_importance_ocsvm_'],
                'random_cut_forest': ['feature_importance_rcf_']
            },
            
            # 리포트 및 로그
            'REPORTS': [
                'log_conversion_report_',
                'log_formatter.log',
                'data_organization_report_'
            ]
        }
    
    def create_folder_structure(self):
        """새로운 폴더 구조 생성"""
        logging.info("📁 폴더 구조 생성 중...")
        
        # 메인 폴더 생성
        for folder_name, folder_path in self.folder_structure.items():
            folder_path.mkdir(parents=True, exist_ok=True)
            logging.info(f"✅ 폴더 생성: {folder_name}")
        
        # 모델별 하위 폴더 생성
        for category in ['ANOMALY_DETECTION', 'FEATURE_IMPORTANCE']:
            category_path = self.folder_structure[category]
            
            for model in self.model_folders:
                model_path = category_path / model
                model_path.mkdir(parents=True, exist_ok=True)
                logging.info(f"✅ 하위 폴더 생성: {category}/{model}")
        
        # 백업 폴더 생성
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        logging.info(f"✅ 백업 폴더 생성: {self.backup_dir}")
    
    def scan_files(self) -> dict:
        """현재 DATA 폴더의 파일들 스캔"""
        files_info = {
            'FLOW_ANALYSIS': [],
            'ANOMALY_DETECTION': {model: [] for model in self.model_folders},
            'FEATURE_IMPORTANCE': {model: [] for model in self.model_folders},
            'REPORTS': [],
            'UNCLASSIFIED': []
        }
        
        logging.info("🔍 파일 스캔 중...")
        
        # DATA 폴더의 모든 파일 스캔 (하위 폴더 제외)
        for file_path in self.data_dir.iterdir():
            if file_path.is_file():
                file_name = file_path.name
                classified = False
                
                # 흐름 분석 파일
                if file_name in self.file_patterns['FLOW_ANALYSIS']:
                    files_info['FLOW_ANALYSIS'].append(file_path)
                    classified = True
                    logging.info(f"📊 흐름분석: {file_name}")
                
                # 이상탐지 결과 파일 (모델별)
                elif not classified:
                    for model, patterns in self.file_patterns['ANOMALY_DETECTION'].items():
                        if any(file_name.startswith(pattern) for pattern in patterns):
                            files_info['ANOMALY_DETECTION'][model].append(file_path)
                            classified = True
                            logging.info(f"🚨 이상탐지({model}): {file_name}")
                            break
                
                # 특성 중요도 파일 (모델별)
                elif not classified:
                    for model, patterns in self.file_patterns['FEATURE_IMPORTANCE'].items():
                        if any(file_name.startswith(pattern) for pattern in patterns):
                            files_info['FEATURE_IMPORTANCE'][model].append(file_path)
                            classified = True
                            logging.info(f"🎯 특성중요도({model}): {file_name}")
                            break
                
                # 리포트 파일
                elif not classified:
                    if any(file_name.startswith(pattern) for pattern in self.file_patterns['REPORTS']):
                        files_info['REPORTS'].append(file_path)
                        classified = True
                        logging.info(f"📋 리포트: {file_name}")
                
                # 분류되지 않은 파일
                if not classified:
                    files_info['UNCLASSIFIED'].append(file_path)
                    logging.warning(f"❓ 미분류: {file_name}")
        
        return files_info
    
    def move_files(self, files_info: dict, create_backup: bool = True) -> dict:
        """파일들을 새로운 위치로 이동"""
        results = {
            'moved': [],
            'failed': [],
            'backed_up': []
        }
        
        logging.info("📦 파일 이동 시작...")
        
        # 백업 생성 (선택사항)
        if create_backup:
            logging.info("💾 백업 생성 중...")
            for category, files in files_info.items():
                if isinstance(files, list):
                    for file_path in files:
                        try:
                            backup_path = self.backup_dir / file_path.name
                            shutil.copy2(file_path, backup_path)
                            results['backed_up'].append(str(file_path))
                        except Exception as e:
                            logging.error(f"백업 실패: {file_path} → {e}")
                elif isinstance(files, dict):
                    for model, model_files in files.items():
                        for file_path in model_files:
                            try:
                                backup_path = self.backup_dir / file_path.name
                                shutil.copy2(file_path, backup_path)
                                results['backed_up'].append(str(file_path))
                            except Exception as e:
                                logging.error(f"백업 실패: {file_path} → {e}")
        
        # 흐름 분석 파일 이동
        for file_path in files_info['FLOW_ANALYSIS']:
            try:
                target_path = self.folder_structure['FLOW_ANALYSIS'] / file_path.name
                shutil.move(str(file_path), str(target_path))
                results['moved'].append(f"{file_path.name} → FLOW_ANALYSIS/")
                logging.info(f"✅ 이동: {file_path.name} → FLOW_ANALYSIS/")
            except Exception as e:
                results['failed'].append(f"{file_path.name}: {e}")
                logging.error(f"이동 실패: {file_path.name} → {e}")
        
        # 이상탐지 결과 이동 (모델별)
        for model, model_files in files_info['ANOMALY_DETECTION'].items():
            target_dir = self.folder_structure['ANOMALY_DETECTION'] / model
            for file_path in model_files:
                try:
                    target_path = target_dir / file_path.name
                    shutil.move(str(file_path), str(target_path))
                    results['moved'].append(f"{file_path.name} → ANOMALY_DETECTION/{model}/")
                    logging.info(f"✅ 이동: {file_path.name} → ANOMALY_DETECTION/{model}/")
                except Exception as e:
                    results['failed'].append(f"{file_path.name}: {e}")
                    logging.error(f"이동 실패: {file_path.name} → {e}")
        
        # 특성 중요도 결과 이동 (모델별)
        for model, model_files in files_info['FEATURE_IMPORTANCE'].items():
            target_dir = self.folder_structure['FEATURE_IMPORTANCE'] / model
            for file_path in model_files:
                try:
                    target_path = target_dir / file_path.name
                    shutil.move(str(file_path), str(target_path))
                    results['moved'].append(f"{file_path.name} → FEATURE_IMPORTANCE/{model}/")
                    logging.info(f"✅ 이동: {file_path.name} → FEATURE_IMPORTANCE/{model}/")
                except Exception as e:
                    results['failed'].append(f"{file_path.name}: {e}")
                    logging.error(f"이동 실패: {file_path.name} → {e}")
        
        # 리포트 파일 이동
        for file_path in files_info['REPORTS']:
            try:
                target_path = self.folder_structure['REPORTS'] / file_path.name
                shutil.move(str(file_path), str(target_path))
                results['moved'].append(f"{file_path.name} → REPORTS/")
                logging.info(f"✅ 이동: {file_path.name} → REPORTS/")
            except Exception as e:
                results['failed'].append(f"{file_path.name}: {e}")
                logging.error(f"이동 실패: {file_path.name} → {e}")
        
        # 미분류 파일은 ARCHIVE로 이동
        for file_path in files_info['UNCLASSIFIED']:
            try:
                target_path = self.folder_structure['ARCHIVE'] / file_path.name
                shutil.move(str(file_path), str(target_path))
                results['moved'].append(f"{file_path.name} → ARCHIVE/ (미분류)")
                logging.info(f"✅ 이동: {file_path.name} → ARCHIVE/ (미분류)")
            except Exception as e:
                results['failed'].append(f"{file_path.name}: {e}")
                logging.error(f"이동 실패: {file_path.name} → {e}")
        
        return results
    
    def create_organization_report(self, files_info: dict, results: dict):
        """정리 결과 보고서 생성"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_files_processed': sum(
                    len(files) if isinstance(files, list) 
                    else sum(len(model_files) for model_files in files.values()) 
                    for files in files_info.values()
                ),
                'successfully_moved': len(results['moved']),
                'failed_moves': len(results['failed']),
                'backed_up': len(results['backed_up'])
            },
            'file_distribution': {
                'flow_analysis': len(files_info['FLOW_ANALYSIS']),
                'anomaly_detection': {
                    model: len(model_files) 
                    for model, model_files in files_info['ANOMALY_DETECTION'].items()
                },
                'feature_importance': {
                    model: len(model_files) 
                    for model, model_files in files_info['FEATURE_IMPORTANCE'].items()
                },
                'reports': len(files_info['REPORTS']),
                'unclassified': len(files_info['UNCLASSIFIED'])
            },
            'moved_files': results['moved'],
            'failed_files': results['failed']
        }
        
        # JSON 보고서 저장
        report_file = self.folder_structure['REPORTS'] / f"data_organization_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        # 텍스트 보고서 생성
        text_report = []
        text_report.append("=" * 60)
        text_report.append("📁 DATA 폴더 정리 결과 보고서")
        text_report.append("=" * 60)
        text_report.append(f"📅 실행 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        text_report.append("")
        
        text_report.append("📊 요약")
        text_report.append(f"   총 처리 파일: {report['summary']['total_files_processed']}개")
        text_report.append(f"   성공적으로 이동: {report['summary']['successfully_moved']}개")
        text_report.append(f"   이동 실패: {report['summary']['failed_moves']}개")
        text_report.append(f"   백업된 파일: {report['summary']['backed_up']}개")
        text_report.append("")
        
        text_report.append("📁 새로운 폴더 구조:")
        text_report.append("DATA/")
        text_report.append("├── LOGS/                  # 처리된 로그 파일")
        text_report.append("├── RAW_LOGS/             # 원본 로그 파일")
        text_report.append(f"├── FLOW_ANALYSIS/        # SSO 흐름 분석 ({report['file_distribution']['flow_analysis']}개)")
        text_report.append("├── ANOMALY_DETECTION/    # 이상탐지 결과")
        for model, count in report['file_distribution']['anomaly_detection'].items():
            text_report.append(f"│   ├── {model}/ ({count}개)")
        text_report.append("├── FEATURE_IMPORTANCE/   # 특성 중요도 분석")
        for model, count in report['file_distribution']['feature_importance'].items():
            text_report.append(f"│   ├── {model}/ ({count}개)")
        text_report.append(f"├── REPORTS/              # 리포트 파일 ({report['file_distribution']['reports']}개)")
        text_report.append(f"└── ARCHIVE/              # 백업 및 미분류 ({report['file_distribution']['unclassified']}개)")
        text_report.append("")
        
        if results['failed']:
            text_report.append("❌ 이동 실패 파일:")
            for failed in results['failed']:
                text_report.append(f"   {failed}")
        
        text_report.append("=" * 60)
        
        # 텍스트 보고서 출력 및 저장
        text_content = "\n".join(text_report)
        print(text_content)
        
        text_file = self.folder_structure['REPORTS'] / f"data_organization_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write(text_content)
        
        logging.info(f"📄 보고서 저장: {report_file}")
        logging.info(f"📄 요약 저장: {text_file}")
    
    def organize(self, create_backup: bool = True):
        """전체 정리 프로세스 실행"""
        try:
            logging.info("🚀 DATA 폴더 정리 시작")
            
            # 1. 폴더 구조 생성
            self.create_folder_structure()
            
            # 2. 파일 스캔
            files_info = self.scan_files()
            
            # 3. 파일 이동
            results = self.move_files(files_info, create_backup)
            
            # 4. 보고서 생성
            self.create_organization_report(files_info, results)
            
            logging.info("✅ DATA 폴더 정리 완료")
            
        except Exception as e:
            logging.error(f"❌ 정리 중 오류 발생: {e}")
            raise


def main():
    """메인 함수"""
    data_dir = "/home/kongju/DEV/dream/DATA"
    
    print("🗂️ SSO 데이터 폴더 정리 도구")
    print("=" * 50)
    print(f"📁 대상 폴더: {data_dir}")
    print()
    
    print("📋 정리될 내용:")
    print("   • SSO 흐름 분석 → FLOW_ANALYSIS/")
    print("   • 이상탐지 결과 → ANOMALY_DETECTION/{모델명}/")
    print("   • 특성 중요도 → FEATURE_IMPORTANCE/{모델명}/")
    print("   • 리포트/로그 → REPORTS/")
    print("   • 미분류 파일 → ARCHIVE/")
    print()
    
    # 백업 옵션
    backup_choice = input("백업을 생성하시겠습니까? (Y/n): ").strip().lower()
    create_backup = backup_choice != 'n'
    
    if create_backup:
        print("💾 백업이 ARCHIVE/backup_* 폴더에 생성됩니다.")
    else:
        print("⚠️ 백업 없이 진행됩니다!")
    
    confirm = input("\n계속 진행하시겠습니까? (Y/n): ").strip().lower()
    if confirm == 'n':
        print("작업이 취소되었습니다.")
        return
    
    # 정리 실행
    organizer = DataOrganizer(data_dir)
    organizer.organize(create_backup)
    
    print("\n🎉 정리가 완료되었습니다!")
    print(f"📁 새로운 구조를 확인하세요: {data_dir}")


if __name__ == "__main__":
    main()
