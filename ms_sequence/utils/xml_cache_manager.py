#!/usr/bin/env python3
"""XML 블록 병합 결과 캐시 관리자"""

import os
import hashlib
import pickle
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

from utils.multiline_xml_processor import MultilineXmlProcessor


class XmlCacheManager:
    """XML 병합 결과를 캐시하고 관리하는 클래스"""
    
    def __init__(self, cache_dir: str = "XML_CACHE"):
        """
        캐시 관리자 초기화
        
        Args:
            cache_dir: 캐시 디렉토리 경로
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
        # 메타데이터 파일
        self.metadata_file = self.cache_dir / "cache_metadata.pkl"
        self.metadata = self._load_metadata()
    
    def _load_metadata(self) -> Dict:
        """캐시 메타데이터 로드"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                print(f"[WARN] 캐시 메타데이터 로드 실패: {e}")
        return {}
    
    def _save_metadata(self):
        """캐시 메타데이터 저장"""
        try:
            with open(self.metadata_file, 'wb') as f:
                pickle.dump(self.metadata, f)
        except Exception as e:
            print(f"[WARN] 캐시 메타데이터 저장 실패: {e}")
    
    def _get_file_hash(self, file_path: str) -> str:
        """파일의 해시값 계산 (내용 기반)"""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                # 큰 파일도 처리할 수 있도록 청크 단위로 읽기
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            print(f"[WARN] 파일 해시 계산 실패 {file_path}: {e}")
            return ""
    
    def _get_cache_filename(self, original_file: str) -> str:
        """원본 파일에 대한 캐시 파일명 생성"""
        file_name = os.path.basename(original_file)
        name, ext = os.path.splitext(file_name)
        return f"{name}_xml_merged{ext}"
    
    def _get_cache_path(self, original_file: str) -> Path:
        """캐시 파일 전체 경로 생성"""
        cache_filename = self._get_cache_filename(original_file)
        return self.cache_dir / cache_filename
    
    def is_cache_valid(self, original_file: str) -> bool:
        """캐시가 유효한지 확인"""
        if not os.path.exists(original_file):
            return False
            
        cache_path = self._get_cache_path(original_file)
        if not cache_path.exists():
            return False
        
        # 메타데이터에서 원본 파일 정보 확인
        original_file_key = os.path.abspath(original_file)
        if original_file_key not in self.metadata:
            return False
        
        # 파일 해시 비교
        current_hash = self._get_file_hash(original_file)
        cached_hash = self.metadata[original_file_key].get('file_hash', '')
        
        return current_hash == cached_hash and current_hash != ""
    
    def get_cached_file_path(self, original_file: str) -> Optional[str]:
        """캐시된 파일 경로 반환 (유효한 경우만)"""
        if self.is_cache_valid(original_file):
            cache_path = self._get_cache_path(original_file)
            return str(cache_path)
        return None
    
    def create_cached_file(self, original_file: str, force_rebuild: bool = False) -> str:
        """
        XML 병합 처리된 캐시 파일 생성
        
        Args:
            original_file: 원본 로그 파일 경로
            force_rebuild: 강제 재생성 여부
            
        Returns:
            캐시된 파일 경로
        """
        cache_path = self._get_cache_path(original_file)
        
        # 캐시가 유효하고 강제 재생성이 아닌 경우 기존 파일 반환
        if not force_rebuild and self.is_cache_valid(original_file):
            print(f"[INFO] 캐시 파일 사용: {cache_path}")
            return str(cache_path)
        
        print(f"[INFO] XML 블록 병합 처리 중: {os.path.basename(original_file)}")
        
        # 원본 파일 읽기
        try:
            with open(original_file, 'r', encoding='utf-8', errors='ignore') as f:
                original_lines = f.readlines()
        except Exception as e:
            raise Exception(f"원본 파일 읽기 실패 {original_file}: {e}")
        
        # XML 블록 병합 처리
        processed_lines = MultilineXmlProcessor.process_lines(original_lines)
        
        # 처리 통계
        stats = MultilineXmlProcessor.get_processing_stats(original_lines, processed_lines)
        
        # 캐시 파일 저장
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                f.writelines(processed_lines)
        except Exception as e:
            raise Exception(f"캐시 파일 저장 실패 {cache_path}: {e}")
        
        # 메타데이터 업데이트
        original_file_key = os.path.abspath(original_file)
        self.metadata[original_file_key] = {
            'file_hash': self._get_file_hash(original_file),
            'cache_file': str(cache_path),
            'created_at': datetime.now().isoformat(),
            'original_size': len(original_lines),
            'processed_size': len(processed_lines),
            'compression_ratio': stats['compression_ratio'],
            'xml_blocks_merged': stats['xml_blocks_merged']
        }
        self._save_metadata()
        
        print(f"[INFO] XML 병합 완료: {len(original_lines):,} → {len(processed_lines):,} lines "
              f"(병합: {stats['xml_blocks_merged']:,}, 압축: {stats['compression_ratio']:.1%})")
        print(f"[INFO] 캐시 파일 저장: {cache_path}")
        
        return str(cache_path)
    
    def get_or_create_cached_file(self, original_file: str, force_rebuild: bool = False) -> str:
        """캐시된 파일을 가져오거나 없으면 생성"""
        cached_file = self.get_cached_file_path(original_file)
        
        if cached_file and not force_rebuild:
            print(f"[INFO] 기존 캐시 사용: {os.path.basename(cached_file)}")
            return cached_file
        else:
            return self.create_cached_file(original_file, force_rebuild)
    
    def get_cache_info(self, original_file: str) -> Optional[Dict]:
        """캐시 정보 반환"""
        original_file_key = os.path.abspath(original_file)
        return self.metadata.get(original_file_key)
    
    def clear_cache(self, original_file: str = None):
        """캐시 삭제 (특정 파일 또는 전체)"""
        if original_file:
            # 특정 파일의 캐시만 삭제
            original_file_key = os.path.abspath(original_file)
            if original_file_key in self.metadata:
                cache_path = Path(self.metadata[original_file_key]['cache_file'])
                if cache_path.exists():
                    cache_path.unlink()
                    print(f"[INFO] 캐시 파일 삭제: {cache_path}")
                del self.metadata[original_file_key]
                self._save_metadata()
        else:
            # 전체 캐시 삭제
            for cache_info in self.metadata.values():
                cache_path = Path(cache_info['cache_file'])
                if cache_path.exists():
                    cache_path.unlink()
            
            self.metadata.clear()
            self._save_metadata()
            print(f"[INFO] 전체 캐시 삭제 완료")
    
    def list_cached_files(self) -> List[Dict]:
        """캐시된 파일 목록 반환"""
        result = []
        for original_file, info in self.metadata.items():
            cache_path = Path(info['cache_file'])
            result.append({
                'original_file': original_file,
                'cache_file': info['cache_file'],
                'cache_exists': cache_path.exists(),
                'created_at': info['created_at'],
                'compression_ratio': info['compression_ratio'],
                'xml_blocks_merged': info['xml_blocks_merged'],
                'original_size': info['original_size'],
                'processed_size': info['processed_size']
            })
        return result
    
    def print_cache_status(self):
        """캐시 상태 출력"""
        cached_files = self.list_cached_files()
        
        print(f"\n=== XML 캐시 상태 ===")
        print(f"캐시 디렉토리: {self.cache_dir}")
        print(f"총 캐시 파일: {len(cached_files)}개")
        
        if cached_files:
            print(f"\n캐시된 파일 목록:")
            for info in cached_files:
                status = "✅" if info['cache_exists'] else "❌"
                print(f"{status} {os.path.basename(info['original_file'])} → {os.path.basename(info['cache_file'])}")
                print(f"   압축률: {info['compression_ratio']:.1%}, 병합: {info['xml_blocks_merged']:,}개, 생성: {info['created_at'][:19]}")
        else:
            print("캐시된 파일이 없습니다.")


# 전역 캐시 매니저 인스턴스
_xml_cache_manager = None

def get_xml_cache_manager() -> XmlCacheManager:
    """XML 캐시 매니저 싱글톤 인스턴스 반환"""
    global _xml_cache_manager
    if _xml_cache_manager is None:
        _xml_cache_manager = XmlCacheManager()
    return _xml_cache_manager







