"""Template mining using Drain3 with source grouping support."""
import os
from pathlib import Path
from typing import List, Dict
import pandas as pd

from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence

from config.drain_config import DrainConfig
from config.log_paths import pick_source_by_path
from utils.session_extractor import extract_session_id, extract_timestamp, preprocess_line_for_oidc
from utils.template_extractor import get_cluster_template
from utils.multiline_xml_processor import MultilineXmlProcessor
from utils.xml_cache_manager import get_xml_cache_manager


class SourceGroupedTemplateMiningService:
    """소스별로 구분된 Drain3 템플릿 마이닝 서비스"""
    
    def __init__(self, sources: List[str] = None, use_xml_cache: bool = True):
        self.sources = sources or ["idp", "sp1", "sp2"]
        self.miners = {}
        self.use_xml_cache = use_xml_cache
        self.xml_cache_manager = get_xml_cache_manager() if use_xml_cache else None
        self._build_miners()
    
    def _build_miners(self) -> None:
        """소스별 TemplateMiner 객체 생성"""
        for source in self.sources:
            config = DrainConfig.build_config_for_source(source)
            persistence_file = f"drain3_state_{source}.bin"
            
            self.miners[source] = TemplateMiner(
                persistence_handler=FilePersistence(persistence_file),
                config=config
            )
    
    def process_log_files(self, file_paths: List[str]) -> pd.DataFrame:
        """
        로그 파일들을 소스별로 그룹화하여 처리
        
        Args:
            file_paths: 로그 파일 경로 리스트
            
        Returns:
            소스 정보가 포함된 이벤트 데이터프레임
        """
        events = []
        
        for idx, path in enumerate(file_paths, 1):
            print(f"[INFO] Processing file {idx}/{len(file_paths)}: {os.path.basename(path)}")
            
            if not Path(path).exists():
                print(f"[WARN] File not found: {path}")
                continue
            
            events.extend(self._process_single_file(path))
            print(f"[INFO] {os.path.basename(path)} completed")
        
        print("[INFO] Source-grouped template mining completed")
        return pd.DataFrame(events)
    
    def _process_single_file(self, file_path: str) -> List[dict]:
        """단일 로그 파일 처리 (XML 블록 병합 포함)"""
        events = []
        filename = os.path.basename(file_path)
        source = pick_source_by_path(file_path)
        miner = self.miners[source]
        
        # XML 캐시 사용 여부에 따라 처리 방식 결정
        if self.use_xml_cache and self.xml_cache_manager:
            # 캐시된 파일 사용 또는 생성
            try:
                cached_file_path = self.xml_cache_manager.get_or_create_cached_file(file_path)
                
                # 캐시된 파일에서 라인 읽기
                with open(cached_file_path, "r", encoding="utf-8", errors="ignore") as f:
                    processed_lines = f.readlines()
                
                # 캐시 정보에서 통계 가져오기
                cache_info = self.xml_cache_manager.get_cache_info(file_path)
                if cache_info:
                    print(f"[INFO] {filename} [{source}]: {cache_info['original_size']} → {cache_info['processed_size']} lines "
                          f"(XML blocks merged: {cache_info['xml_blocks_merged']}, compression: {cache_info['compression_ratio']:.1%}) [캐시 사용]")
                else:
                    print(f"[INFO] {filename} [{source}]: XML 병합 처리됨 [캐시 생성]")
                    
            except Exception as e:
                print(f"[WARN] XML 캐시 사용 실패, 직접 처리: {e}")
                # 캐시 실패 시 직접 처리
                processed_lines = self._process_file_directly(file_path, filename, source)
        else:
            # 캐시 사용 안 함, 직접 처리
            processed_lines = self._process_file_directly(file_path, filename, source)
        
        total_lines = len(processed_lines)
        for line_no, raw_line in enumerate(processed_lines, 1):
            # 진행률 표시 (큰 파일만)
            if total_lines >= 5000 and line_no % 5000 == 0:
                print(f"[INFO] {line_no}/{total_lines} ({line_no/total_lines*100:.0f}%)")
            
            raw_message = raw_line.rstrip("\n")
            if not raw_message.strip():
                continue
            
            # OIDC 전처리 (idp__ssoserver.log 전용)
            preprocessed_message = preprocess_line_for_oidc(file_path, raw_message)
            
            # Drain3 처리
            result = miner.add_log_message(preprocessed_message)
            template = get_cluster_template(miner, result)
            
            # 소스별 클러스터 ID 생성
            cluster_id = result.get("cluster_id") if isinstance(result, dict) else None
            source_cluster_id = f"{source}#{cluster_id}" if cluster_id is not None else None
            
            events.append({
                "source": source,
                "file": filename,
                "line_no": line_no,
                "raw": raw_message,
                "raw_preprocessed": preprocessed_message,
                "session_id": extract_session_id(raw_message),
                "timestamp_raw": extract_timestamp(raw_message),
                "cluster_id": source_cluster_id,
                "cluster_size": result.get("cluster_size") if isinstance(result, dict) else None,
                "change_type": result.get("change_type") if isinstance(result, dict) else None,
                "template": template,
            })
        
        return events
    
    def _process_file_directly(self, file_path: str, filename: str, source: str) -> List[str]:
        """파일을 직접 처리 (캐시 사용 없이)"""
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            original_lines = f.readlines()
            
        # XML 블록 전처리 (멀티라인 XML을 하나의 메시지로 병합)
        processed_lines = MultilineXmlProcessor.process_lines(original_lines)
        
        # 처리 통계 출력
        stats = MultilineXmlProcessor.get_processing_stats(original_lines, processed_lines)
        print(f"[INFO] {filename} [{source}]: {stats['original_line_count']} → {stats['processed_line_count']} lines "
              f"(XML blocks merged: {stats['xml_blocks_merged']}, compression: {stats['compression_ratio']:.1%})")
        
        return processed_lines


# 기존 호환성을 위한 래퍼
class TemplateMiningService:
    """기존 인터페이스와의 호환성을 위한 래퍼"""
    
    def __init__(self, persistence_file: str = "drain3_state.bin", use_xml_cache: bool = True):
        self.grouped_service = SourceGroupedTemplateMiningService(use_xml_cache=use_xml_cache)
    
    def process_log_files(self, file_paths: List[str]) -> pd.DataFrame:
        return self.grouped_service.process_log_files(file_paths)