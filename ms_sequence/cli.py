"""Command line interface."""
import argparse


def create_parser() -> argparse.ArgumentParser:
    """CLI 파서 생성."""
    parser = argparse.ArgumentParser(
        description="Drain3 + PYOD 기반 로그 이상탐지 파이프라인"
    )
    
    parser.add_argument(
        "--model", type=str, default="IForest",
        choices=["IForest", "COPOD", "ECOD", "LOF", "AutoEncoder"],
        help="PYOD 모델 선택"
    )
    
    parser.add_argument(
        "--contamination", type=float, default=0.05,
        help="이상치 비율 추정값 (0~0.5)"
    )
    
    parser.add_argument(
        "--n_estimators", type=int, default=400,
        help="IForest 트리 개수"
    )
    
    parser.add_argument(
        "--n_neighbors", type=int, default=20,
        help="LOF 이웃 개수"
    )
    
    parser.add_argument(
        "--epochs", type=int, default=15,
        help="AutoEncoder 학습 에포크"
    )
    
    parser.add_argument(
        "--batch_size", type=int, default=64,
        help="AutoEncoder 배치 크기"
    )
    
    parser.add_argument(
        "--random_state", type=int, default=42,
        help="랜덤 시드"
    )
    
    parser.add_argument(
        "--force-reprocess", action="store_true",
        help="Drain3 캐시 무시하고 강제 재처리"
    )
    
    # Drain3 설정 파라미터 추가
    parser.add_argument("--drain-similarity", type=float, default=0.4,
                       help="Drain3 유사도 임계값")
    parser.add_argument("--drain-depth", type=int, default=6,
                       help="Drain3 파싱 트리 깊이")
    parser.add_argument("--drain-max-children", type=int, default=100,
                       help="Drain3 최대 자식 노드 수")
    parser.add_argument("--drain-max-clusters", type=int, default=4096,
                       help="Drain3 최대 클러스터 수")
    
    return parser