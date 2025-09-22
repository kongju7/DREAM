"""Template extraction utilities for Drain3."""
from typing import Optional, Any, Dict


def get_cluster_template(miner: Any, result: Dict[str, Any]) -> Optional[str]:
    """
    Drain3 버전에 관계없이 템플릿 문자열을 추출.
    
    Args:
        miner: TemplateMiner 객체
        result: add_log_message 결과
        
    Returns:
        템플릿 문자열 또는 None
    """
    # 1) result dict에서 직접 추출
    if isinstance(result, dict):
        for key in ("template", "log_template", "template_mined"):
            if result.get(key):
                return result[key]
        
        # cluster 객체에서 추출
        cluster = result.get("cluster")
        if cluster is not None:
            template = _extract_from_cluster(cluster)
            if template:
                return template
    
    # 2) cluster_id를 통해 miner에서 추출
    cluster_id = result.get("cluster_id") if isinstance(result, dict) else None
    if cluster_id is not None:
        template = _extract_from_miner(miner, cluster_id)
        if template:
            return template
    
    return None


def _extract_from_cluster(cluster: Any) -> Optional[str]:
    """클러스터 객체에서 템플릿 추출."""
    if hasattr(cluster, "get_template"):
        try:
            return cluster.get_template()
        except Exception:
            pass
    
    if hasattr(cluster, "template"):
        return cluster.template
    
    return None


def _extract_from_miner(miner: Any, cluster_id: Any) -> Optional[str]:
    """마이너 객체에서 cluster_id로 템플릿 추출."""
    # id→cluster 맵에서 찾기
    for attr in ("id_to_cluster", "cluster_id_to_cluster"):
        if hasattr(miner, attr):
            mapping = getattr(miner, attr)
            if isinstance(mapping, dict) and cluster_id in mapping:
                cluster = mapping[cluster_id]
                template = _extract_from_cluster(cluster)
                if template:
                    return template
    
    # clusters 컨테이너에서 찾기
    if hasattr(miner, "clusters"):
        clusters = getattr(miner, "clusters")
        
        # 리스트 형태
        if isinstance(clusters, list):
            for cluster in clusters:
                if getattr(cluster, "cluster_id", None) == cluster_id:
                    return _extract_from_cluster(cluster)
        
        # 매니저 객체 형태
        for method_name in ("get_by_id", "get_cluster_by_id", "get_cluster"):
            if hasattr(clusters, method_name):
                try:
                    cluster = getattr(clusters, method_name)(cluster_id)
                    if cluster is not None:
                        template = _extract_from_cluster(cluster)
                        if template:
                            return template
                except Exception:
                    pass
    
    return None