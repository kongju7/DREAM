"""Anomaly detection using PYOD models."""
import pandas as pd
from models.pyod_factory import PyodModelFactory


class AnomalyDetector:
    """PYOD를 사용한 이상탐지 서비스."""
    
    @staticmethod
    def detect_anomalies(session_vectors: pd.DataFrame, model_name: str, **model_params) -> pd.DataFrame:
        """
        세션 벡터에서 이상탐지 수행.
        
        Args:
            session_vectors: 세션별 특성 벡터
            model_name: PYOD 모델 이름
            **model_params: 모델 파라미터
            
        Returns:
            이상탐지 결과 데이터프레임
        """
        if session_vectors.empty:
            raise ValueError("Session vectors are empty")
        
        # 데이터 준비
        X = session_vectors.values.astype(float)
        
        # 모델 생성 및 학습
        model = PyodModelFactory.create_model(model_name, **model_params)
        model.fit(X)
        
        # 결과 정리
        return pd.DataFrame({
            "session_id": session_vectors.index,
            "pyod_label": model.labels_,      # 1: outlier, 0: inlier
            "pyod_score": model.decision_scores_  # 높을수록 이상
        }).sort_values("pyod_score", ascending=False)