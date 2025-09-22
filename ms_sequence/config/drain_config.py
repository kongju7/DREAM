"""Drain3 configuration settings with source-specific support."""
import json
import hashlib
from typing import List, Dict, Any

from drain3.template_miner_config import TemplateMinerConfig


class DrainConfig:
    """Drain3 configuration manager with source-specific settings."""
    
    # 기본 설정
    SIMILARITY_THRESHOLD = 0.4
    DEPTH = 6
    MAX_CHILDREN = 100
    MAX_CLUSTERS = 4096
    
    # 소스별 특화 마스킹 규칙
    BASE_MASK_PATTERNS = [
        {"regex_pattern": r"SP-[0-9a-fA-F]{8,}", "mask_with": "<:SPID:>"},
        {"regex_pattern": r"IDP-[0-9a-fA-F]{8,}", "mask_with": "<:IDPID:>"},
        {"regex_pattern": r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", "mask_with": "<:ISO_TS:>"},
        {"regex_pattern": r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", "mask_with": "<:DATETIME:>"},
        {"regex_pattern": r"\b\d{2}:\d{2}:\d{2}\b", "mask_with": "<:TIME:>"},
        {"regex_pattern": r"https?://[^\s\">]+", "mask_with": "<:URL:>"},
        {"regex_pattern": r"\b[a-zA-Z0-9.-]+\.(com|net|org|dev|io|co)\b", "mask_with": "<:DOMAIN:>"},
        {"regex_pattern": r":\d{2,5}\b", "mask_with": "<:PORT:>"},
        {"regex_pattern": r"\b\d{1,3}(\.\d{1,3}){3}\b", "mask_with": "<:IP:>"},
        {"regex_pattern": r"\b\d{6,}\b", "mask_with": "<:NUM6P:>"},
        {"regex_pattern": r"\b\d{3,5}\b", "mask_with": "<:NUM:>"},
    ]
    
    # IDP 전용 추가 마스킹 (OIDC 관련)
    IDP_ADDITIONAL_PATTERNS = [
        {"regex_pattern": r"/(?:oidc|oauth2|openid|well-known)[^\s\"]*", "mask_with": "<:OIDC_PATH:>"},
        {"regex_pattern": r"[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+(?:\.[A-Za-z0-9\-_]+)?", "mask_with": "<:JWT:>"},
        {"regex_pattern": r"([?&])code=[A-Za-z0-9\-_]{8,}", "mask_with": r"\1code=<:CODE:>"},
        {"regex_pattern": r"([?&])access_token=[A-Za-z0-9\-_]{8,}", "mask_with": r"\1access_token=<:AT:>"},
        {"regex_pattern": r"([?&])refresh_token=[A-Za-z0-9\-_]{8,}", "mask_with": r"\1refresh_token=<:RT:>"},
        {"regex_pattern": r"([?&])id_token=[A-Za-z0-9\-_\.]+", "mask_with": r"\1id_token=<:JWT:>"},
        {"regex_pattern": r"([?&])client_id=[^&\s]+", "mask_with": r"\1client_id=<:CLIENT_ID:>"},
        {"regex_pattern": r"([?&])redirect_uri=[^&\s]+", "mask_with": r"\1redirect_uri=<:URL:>"},
        {"regex_pattern": r"([?&])scope=[^&\s]+", "mask_with": r"\1scope=<:SCOPE:>"},
        {"regex_pattern": r"([?&])code_verifier=[^&\s]+", "mask_with": r"\1code_verifier=<:PKCE:>"},
        {"regex_pattern": r"([?&])code_challenge=[^&\s]+", "mask_with": r"\1code_challenge=<:PKCE:>"},
        {"regex_pattern": r"([?&])grant_type=[^&\s]+", "mask_with": r"\1grant_type=<:GRANT:>"},
        {"regex_pattern": r"([?&])response_type=[^&\s]+", "mask_with": r"\1response_type=<:RESP_TYPE:>"},
    ]

    @classmethod
    def update_config(cls, similarity=None, depth=None, max_children=None, max_clusters=None):
        """설정값을 동적으로 업데이트"""
        if similarity is not None:
            cls.SIMILARITY_THRESHOLD = similarity
        if depth is not None:
            cls.DEPTH = depth
        if max_children is not None:
            cls.MAX_CHILDREN = max_children
        if max_clusters is not None:
            cls.MAX_CLUSTERS = max_clusters

    @classmethod
    def get_mask_patterns_for_source(cls, source: str) -> List[Dict[str, str]]:
        """소스별 마스킹 패턴 반환"""
        patterns = cls.BASE_MASK_PATTERNS.copy()
        if source == "idp":
            patterns.extend(cls.IDP_ADDITIONAL_PATTERNS)
        return patterns
    
    @classmethod
    def get_config_hash(cls, source: str = "all") -> str:
        """소스별 설정 해시값 생성"""
        config_dict = {
            "similarity_threshold": cls.SIMILARITY_THRESHOLD,
            "depth": cls.DEPTH,
            "max_children": cls.MAX_CHILDREN,
            "max_clusters": cls.MAX_CLUSTERS,
            "source": source,
            "masks": cls.get_mask_patterns_for_source(source),
        }
        config_str = json.dumps(config_dict, sort_keys=True, ensure_ascii=False)
        return hashlib.md5(config_str.encode('utf-8')).hexdigest()[:8]
    
    @classmethod
    def build_config_for_source(cls, source: str) -> TemplateMinerConfig:
        """소스별 TemplateMinerConfig 객체 생성"""
        config = TemplateMinerConfig()
        
        # 드레인 파라미터 설정
        cls._safe_set_drain(config,
                           sim_th=cls.SIMILARITY_THRESHOLD,
                           depth=cls.DEPTH,
                           max_children=cls.MAX_CHILDREN,
                           max_clusters=cls.MAX_CLUSTERS)
        
        # 소스별 마스킹 설정
        patterns = cls.get_mask_patterns_for_source(source)
        cls._safe_set_masking(config, patterns)
        
        # 기타 설정
        for k, v in {"snapshot_interval_minutes": 0, "compress_state": False}.items():
            if hasattr(config, k):
                setattr(config, k, v)
        
        return config
    
    @staticmethod
    def _safe_set_drain(config, sim_th=None, depth=None, max_children=None, max_clusters=None):
        """드레인 설정을 안전하게 적용"""
        if hasattr(config, "drain"):
            if sim_th is not None: config.drain.similarity_threshold = sim_th
            if depth is not None: config.drain.depth = depth
            if max_children is not None: config.drain.max_children = max_children
            if max_clusters is not None: config.drain.max_clusters = max_clusters
        else:
            # 구버전 호환
            if sim_th is not None: setattr(config, "drain_sim_th", sim_th)
            if depth is not None: setattr(config, "drain_depth", depth)
            if max_children is not None: setattr(config, "drain_max_children", max_children)
            if max_clusters is not None: setattr(config, "drain_max_clusters", max_clusters)
    
    @staticmethod
    def _safe_set_masking(config, mask_list):
        """마스킹 설정을 안전하게 적용"""
        if hasattr(config, "masking") and hasattr(config.masking, "mask_list"):
            config.masking.mask_prefix = "<:"
            config.masking.mask_suffix = ":>"
            config.masking.mask_list = mask_list
        else:
            # 구버전 호환
            setattr(config, "masking", json.dumps(mask_list, ensure_ascii=False))