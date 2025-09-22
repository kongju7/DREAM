"""Main execution script for source-grouped log anomaly detection pipeline."""
from cli import create_parser
from config.log_paths import LOG_PATHS
from config.drain_config import DrainConfig
from core.template_miner import SourceGroupedTemplateMiningService
from core.vectorizer import SourceGroupedSessionVectorizer
from core.anomaly_detector import AnomalyDetector
from storage.cache_manager import SourceGroupedCacheManager
from storage.output_manager import SourceGroupedOutputManager


def main():
    """메인 실행 함수"""
    # CLI 파싱
    parser = create_parser()
    args = parser.parse_args()
    
    # CLI에서 받은 Drain3 설정을 적용
    DrainConfig.update_config(
        similarity=getattr(args, 'drain_similarity', None),
        depth=getattr(args, 'drain_depth', None),
        max_children=getattr(args, 'drain_max_children', None),
        max_clusters=getattr(args, 'drain_max_clusters', None)
    )
    
    # 설정 정보 출력
    config_hash = DrainConfig.get_config_hash("all")
    print(f"[INFO] Grouped Drain config hash: {config_hash}")
    print(f"[INFO] Drain settings: similarity={DrainConfig.SIMILARITY_THRESHOLD}, "
          f"depth={DrainConfig.DEPTH}, max_clusters={DrainConfig.MAX_CLUSTERS}")
    print(f"[INFO] Model: {args.model}, contamination: {args.contamination}")
    
    # 1) 소스별 Drain3 템플릿 마이닝 (캐시 활용)
    if args.force_reprocess or SourceGroupedCacheManager.should_reprocess(LOG_PATHS):
        print("[INFO] Starting source-grouped template mining...")
        
        mining_service = SourceGroupedTemplateMiningService()
        events_df = mining_service.process_log_files(LOG_PATHS)
        
        if events_df.empty:
            raise RuntimeError("No events parsed. Check log paths or file encodings.")
        
        print("[INFO] Building source-grouped session vectors...")
        vectorizer = SourceGroupedSessionVectorizer()
        session_vectors_by_source = vectorizer.build_session_vectors_by_source(events_df)
        
        # 캐시에 저장
        SourceGroupedCacheManager.save_cache(events_df, session_vectors_by_source)
    else:
        print("[INFO] Using cached source-grouped Drain3 results...")
        events_df, session_vectors_by_source = SourceGroupedCacheManager.load_cache()
    
    # 2) 소스별 PYOD 이상탐지
    print(f"[INFO] Running {args.model} anomaly detection for each source...")
    
    model_params = {
        'contamination': args.contamination,
        'n_estimators': args.n_estimators,
        'n_neighbors': args.n_neighbors,
        'epochs': args.epochs,
        'batch_size': args.batch_size,
        'random_state': args.random_state
    }
    
    anomaly_scores_by_source = {}
    
    for source, session_vectors in session_vectors_by_source.items():
        if session_vectors.empty:
            print(f"[WARN] No session vectors for source: {source}")
            continue
        
        if session_vectors.shape[0] < 5:
            print(f"[WARN] Low number of sessions for {source}: {session_vectors.shape[0]}")
        
        print(f"[INFO] Running {args.model} for {source.upper()}...")
        anomaly_scores = AnomalyDetector.detect_anomalies(
            session_vectors, args.model, **model_params
        )
        anomaly_scores_by_source[source] = anomaly_scores
        
        print(f"[INFO] {source.upper()} - Top 5 anomalous sessions:")
        print(anomaly_scores.head(5).to_string(index=False))
    
    # 3) 소스별 결과 저장
    print("[INFO] Saving source-grouped results...")
    SourceGroupedOutputManager.save_results_by_source(
        events_df, session_vectors_by_source, anomaly_scores_by_source, args.model
    )
    
    print("[INFO] Source-grouped anomaly detection completed!")


if __name__ == "__main__":
    main()