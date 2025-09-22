"""Cache management for source-grouped Drain3 results."""
import os
import json
from pathlib import Path
from typing import Tuple, Dict
import pandas as pd

from config.drain_config import DrainConfig


class SourceGroupedCacheManager:
    """소스별 Drain3 결과 캐시 관리자"""
    
    @staticmethod
    def get_cache_dir() -> str:
        """캐시 디렉토리 경로 반환"""
        # 전체 설정의 해시를 사용
        config_hash = DrainConfig.get_config_hash("all")
        return f"./DRAIN_CACHE/grouped_drain_{config_hash}"
    
    @staticmethod
    def should_reprocess(log_paths: list) -> bool:
        """재처리 필요 여부 판단"""
        cache_dir = SourceGroupedCacheManager.get_cache_dir()
        events_csv = os.path.join(cache_dir, "grouped_drain_parsed_events.csv")
        vectors_csv = os.path.join(cache_dir, "grouped_drain_session_vectors.csv")
        
        # 캐시 파일이 없으면 재처리 필요
        if not (Path(events_csv).exists() and Path(vectors_csv).exists()):
            return True
        
        # 로그 파일이 캐시보다 새로우면 재처리 필요
        cache_mtime = min(
            Path(events_csv).stat().st_mtime,
            Path(vectors_csv).stat().st_mtime
        )
        
        for log_path in log_paths:
            if Path(log_path).exists():
                if Path(log_path).stat().st_mtime > cache_mtime:
                    return True
        
        return False
    
    @staticmethod
    def save_cache(events_df: pd.DataFrame, session_vectors_by_source: Dict[str, pd.DataFrame]) -> None:
        """캐시에 결과 저장"""
        cache_dir = SourceGroupedCacheManager.get_cache_dir()
        Path(cache_dir).mkdir(parents=True, exist_ok=True)
        
        # 통합 이벤트 데이터 저장
        events_csv = os.path.join(cache_dir, "grouped_drain_parsed_events.csv")
        events_df.to_csv(events_csv, index=False, encoding="utf-8")
        
        # 소스별 세션 벡터 저장
        for source, vectors in session_vectors_by_source.items():
            vectors_csv = os.path.join(cache_dir, f"session_vectors_{source}.csv")
            vectors.to_csv(vectors_csv, encoding="utf-8")
        
        # 설정 정보 저장
        config_json = os.path.join(cache_dir, "grouped_drain_config.json")
        config_info = {
            "similarity_threshold": DrainConfig.SIMILARITY_THRESHOLD,
            "depth": DrainConfig.DEPTH,
            "max_children": DrainConfig.MAX_CHILDREN,
            "max_clusters": DrainConfig.MAX_CLUSTERS,
            "sources": list(session_vectors_by_source.keys()),
            "config_hash": DrainConfig.get_config_hash("all"),
            "created_at": pd.Timestamp.now().isoformat()
        }
        
        with open(config_json, "w", encoding="utf-8") as f:
            json.dump(config_info, f, ensure_ascii=False, indent=2)
        
        print(f"[INFO] Source-grouped cache saved to {cache_dir}")
    
    @staticmethod
    def load_cache() -> Tuple[pd.DataFrame, Dict[str, pd.DataFrame]]:
        """캐시에서 결과 로드"""
        cache_dir = SourceGroupedCacheManager.get_cache_dir()
        
        # 이벤트 데이터 로드
        events_csv = os.path.join(cache_dir, "grouped_drain_parsed_events.csv")
        events_df = pd.read_csv(events_csv)
        
        # 소스별 세션 벡터 로드
        session_vectors_by_source = {}
        for source in ["idp", "sp1", "sp2"]:
            vectors_csv = os.path.join(cache_dir, f"session_vectors_{source}.csv")
            if Path(vectors_csv).exists():
                session_vectors_by_source[source] = pd.read_csv(vectors_csv, index_col=0)
        
        print(f"[INFO] Loading source-grouped cache from {cache_dir}")
        return events_df, session_vectors_by_source


# 기존 호환성을 위한 래퍼
class CacheManager:
    """기존 인터페이스와의 호환성을 위한 래퍼"""
    
    @staticmethod
    def should_reprocess(log_paths: list) -> bool:
        return SourceGroupedCacheManager.should_reprocess(log_paths)
    
    @staticmethod
    def save_cache(events_df: pd.DataFrame, session_vectors: pd.DataFrame) -> None:
        # 소스별로 분할하여 저장
        session_vectors_by_source = {}
        for source in ["idp", "sp1", "sp2"]:
            source_events = events_df[events_df["source"] == source]
            if not source_events.empty:
                # 간단한 세션 벡터 생성 (실제로는 vectorizer 사용)
                session_vectors_by_source[source] = pd.DataFrame()
        
        SourceGroupedCacheManager.save_cache(events_df, session_vectors_by_source)
    
    @staticmethod
    def load_cache() -> Tuple[pd.DataFrame, pd.DataFrame]:
        events_df, session_vectors_by_source = SourceGroupedCacheManager.load_cache()
        # 통합 세션 벡터 반환 (기존 호환성)
        combined_vectors = pd.concat(session_vectors_by_source.values(), ignore_index=True) if session_vectors_by_source else pd.DataFrame()
        return events_df, combined_vectors