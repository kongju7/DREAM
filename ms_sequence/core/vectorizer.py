"""Session vectorization utilities with source grouping support."""
import pandas as pd
from typing import Dict


class SourceGroupedSessionVectorizer:
    """소스별 세션 벡터화 서비스"""
    
    @staticmethod
    def build_session_vectors_by_source(events_df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
        """
        소스별로 이벤트 데이터프레임에서 세션 벡터 생성
        
        Args:
            events_df: 소스 정보가 포함된 이벤트 데이터프레임
            
        Returns:
            소스별 세션 벡터 딕셔너리
        """
        session_vectors_by_source = {}
        
        for source in events_df["source"].unique():
            source_events = events_df[events_df["source"] == source].copy()
            
            # session_id가 없는 라인 제외
            valid_events = source_events.dropna(subset=["session_id"]).copy()
            
            if valid_events.empty:
                print(f"[WARN] No valid sessions found for source: {source}")
                session_vectors_by_source[source] = pd.DataFrame()
                continue
            
            # pivot table로 세션별 클러스터 카운트 생성
            session_vectors = pd.pivot_table(
                valid_events,
                index="session_id",
                columns="cluster_id",
                values="line_no",
                aggfunc="count",
                fill_value=0
            )
            
            # 안정성을 위한 정렬
            session_vectors = session_vectors.sort_index(axis=0).sort_index(axis=1)
            session_vectors_by_source[source] = session_vectors
            
            print(f"[INFO] {source}: {session_vectors.shape[0]} sessions, {session_vectors.shape[1]} features")
        
        return session_vectors_by_source


# 기존 호환성을 위한 래퍼
class SessionVectorizer:
    """기존 인터페이스와의 호환성을 위한 래퍼"""
    
    @staticmethod
    def build_session_vectors(events_df: pd.DataFrame) -> pd.DataFrame:
        """소스 구분 없이 전체 세션 벡터 생성 (기존 호환성)"""
        grouped_vectorizer = SourceGroupedSessionVectorizer()
        vectors_by_source = grouped_vectorizer.build_session_vectors_by_source(events_df)
        
        # 모든 소스의 벡터를 결합
        if not vectors_by_source:
            return pd.DataFrame()
        
        # 소스별 세션 ID에 prefix 추가하여 구분
        combined_vectors = []
        for source, vectors in vectors_by_source.items():
            if not vectors.empty:
                # 세션 ID에 소스 prefix 추가
                vectors_copy = vectors.copy()
                vectors_copy.index = [f"{source}#{session_id}" for session_id in vectors_copy.index]
                combined_vectors.append(vectors_copy)
        
        if combined_vectors:
            result = pd.concat(combined_vectors, sort=False).fillna(0)
            return result.sort_index(axis=0).sort_index(axis=1)
        else:
            return pd.DataFrame()