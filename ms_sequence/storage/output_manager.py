"""Output file management with source grouping support."""
import os
import json
from pathlib import Path
import pandas as pd
import numpy as np
from typing import Dict

from config.drain_config import DrainConfig


class NumpyEncoder(json.JSONEncoder):
    """Numpy 타입을 JSON으로 직렬화하기 위한 커스텀 인코더"""
    def default(self, obj):
        if isinstance(obj, pd.Series):
            return obj.tolist()
        elif hasattr(obj, 'item'):  # numpy scalar
            return obj.item()
        elif hasattr(obj, 'tolist'):  # numpy array
            return obj.tolist()
        return super().default(obj)


class SourceGroupedOutputManager:
    """소스별 결과 파일 저장 관리자"""
    
    @staticmethod
    def save_results_by_source(events_df: pd.DataFrame,
                              session_vectors_by_source: Dict[str, pd.DataFrame],
                              anomaly_scores_by_source: Dict[str, pd.DataFrame],
                              model_name: str,
                              output_base_dir: str = "./OUTPUTS") -> None:
        """소스별 최종 결과를 저장"""
        config_hash = DrainConfig.get_config_hash("all")
        
        for source in session_vectors_by_source.keys():
            output_dir = os.path.join(output_base_dir, f"grouped_drain_{config_hash}", f"{source}_{model_name.lower()}")
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            
            # 해당 소스의 이벤트만 필터링
            source_events = events_df[events_df["source"] == source]
            source_vectors = session_vectors_by_source[source]
            source_scores = anomaly_scores_by_source.get(source, pd.DataFrame())
            
            # 파일 경로
            events_csv = os.path.join(output_dir, f"{source}_drain_parsed_events.csv")
            vectors_csv = os.path.join(output_dir, f"{source}_drain_session_vectors.csv")
            scores_csv = os.path.join(output_dir, f"{source}_pyod_anomaly_scores.csv")
            summary_json = os.path.join(output_dir, f"{source}_summary.json")
            
            # 데이터 저장
            source_events.to_csv(events_csv, index=False, encoding="utf-8")
            source_vectors.to_csv(vectors_csv, encoding="utf-8")
            if not source_scores.empty:
                source_scores.to_csv(scores_csv, index=False, encoding="utf-8")
            
            # 요약 정보 생성
            if not source_events.empty:
                template_freq = source_events["cluster_id"].value_counts()
                rare_threshold = max(1, int(len(template_freq) * 0.05))
                rare_templates = template_freq.tail(rare_threshold).index.tolist()
                
                summary = {
                    "source": source,
                    "total_lines": len(source_events),
                    "total_sessions": source_events["session_id"].notna().sum(),
                    "unique_templates": source_events["cluster_id"].nunique(),
                    "rare_templates_count": len(rare_templates),
                    "rare_template_ids": rare_templates,
                    "top_anomalous_sessions": source_scores.head(10)["session_id"].tolist() if not source_scores.empty else [],
                    "drain_config_hash": config_hash,
                    "model_used": model_name
                }
                
                with open(summary_json, "w", encoding="utf-8") as f:
                    json.dump(summary, f, ensure_ascii=False, indent=2, cls=NumpyEncoder)
            
            print(f"[INFO] {source.upper()} results saved to {output_dir}")
            print(f"  - {events_csv}")
            print(f"  - {vectors_csv}")
            if not source_scores.empty:
                print(f"  - {scores_csv}")
            print(f"  - {summary_json}")


# 기존 호환성을 위한 래퍼
class OutputManager:
    """기존 인터페이스와의 호환성을 위한 래퍼"""
    
    @staticmethod
    def save_results(events_df: pd.DataFrame,
                    session_vectors: pd.DataFrame,
                    anomaly_scores: pd.DataFrame,
                    model_name: str,
                    output_base_dir: str = "./OUTPUTS") -> None:
        """기존 인터페이스 호환을 위한 래퍼 함수"""
        
        # 소스별로 데이터 분할
        session_vectors_by_source = {}
        anomaly_scores_by_source = {}
        
        for source in events_df["source"].unique():
            # 세션 벡터 분할 (session_id에서 소스 prefix 확인)
            source_sessions = [idx for idx in session_vectors.index if idx.startswith(f"{source}#")]
            if source_sessions:
                source_vectors = session_vectors.loc[source_sessions].copy()
                # 인덱스에서 소스 prefix 제거
                source_vectors.index = [idx.split("#", 1)[1] for idx in source_vectors.index]
                session_vectors_by_source[source] = source_vectors
                
                # 이상탐지 점수도 마찬가지로 분할
                source_scores = anomaly_scores[anomaly_scores["session_id"].isin(source_sessions)].copy()
                source_scores["session_id"] = source_scores["session_id"].str.split("#", 1).str[1]
                anomaly_scores_by_source[source] = source_scores
        
        # 소스별 저장
        SourceGroupedOutputManager.save_results_by_source(
            events_df, session_vectors_by_source, anomaly_scores_by_source, model_name, output_base_dir
        )