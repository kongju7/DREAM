"""Log file paths and source mapping configuration."""
import os

LOG_PATHS = [
    "/home/kongju/DEV/dream/DATA/LOGS/idp__ssoserver.log",
    "/home/kongju/DEV/dream/DATA/LOGS/idp_log__ssoserver.log",
    "/home/kongju/DEV/dream/DATA/LOGS/idp_log__ssoserver_20250820.log",
    "/home/kongju/DEV/dream/DATA/LOGS/sp_log__ssoagent_20250820.log",
    "/home/kongju/DEV/dream/DATA/LOGS/sp_log__ssoagent_20250821.log",
    "/home/kongju/DEV/dream/DATA/LOGS/sp1__ssoagent_20250821.log",
    "/home/kongju/DEV/dream/DATA/LOGS/sp2__ssoagent_20250821.log",
]

# 파일→소스 매핑
SOURCE_BY_FILE = {
    "sp_log__ssoagent_20250821.log": "sp1",
    "sp1__ssoagent_20250821.log": "sp1",
    "sp2__ssoagent_20250821.log": "sp2",
    "idp__ssoserver.log": "idp",
    "idp_log__ssoserver.log": "idp",
    "idp_log__ssoserver_20250820.log": "idp",
    "sp_log__ssoagent_20250820.log": "sp1",  # 추가
}

def pick_source_by_path(path: str) -> str:
    """파일 경로에서 로그 소스를 결정"""
    base = os.path.basename(path)
    if base in SOURCE_BY_FILE:
        return SOURCE_BY_FILE[base]
    
    # 파일명 기반 추론
    b = base.lower()
    if b.startswith("sp1") or ("ssoagent" in b and "40004" in b):
        return "sp1"
    if b.startswith("sp2") or ("ssoagent" in b and "40007" in b):
        return "sp2"
    return "idp"  # 기본값