"""Session ID, timestamp extraction and OIDC preprocessing utilities."""
import re
import os
from typing import Optional

# 컴파일된 정규식 패턴
RE_SID = re.compile(r'(?:ID="(SP-[0-9a-fA-F]{8,})"|InResponseTo="(SP-[0-9a-fA-F]{8,})")')
RE_TS = re.compile(r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|\b\d{2}:\d{2}:\d{2}\b)')
JWT_RE = re.compile(r"[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+(?:\.[A-Za-z0-9\-_]+)?")


def extract_session_id(line: str) -> Optional[str]:
    """로그 라인에서 세션 ID 추출"""
    match = RE_SID.search(line)
    if not match:
        return None
    return match.group(1) or match.group(2)


def extract_timestamp(line: str) -> Optional[str]:
    """로그 라인에서 타임스탬프 추출"""
    match = RE_TS.search(line)
    return match.group(1) if match else None


def preprocess_line_for_oidc(filepath: str, line: str) -> str:
    """
    OIDC 전처리: idp__ssoserver.log 전용
    토큰/코드/JWT/파라미터/경로 등 OIDC 흔적을 정규화
    """
    filename = os.path.basename(filepath)
    if filename != "idp__ssoserver.log":
        return line
    
    s = line

    # 1) 명시적 OIDC 경로/엔드포인트 → 플레이스홀더
    s = re.sub(r"/(?:oidc|oauth2|openid|well-known)[^\s\"]*", "<:OIDC_PATH:>", s, flags=re.IGNORECASE)

    # 2) 토큰/코드/클라이언트/스코프 파라미터 정규화
    # JWT(id_token 등)
    s = JWT_RE.sub("<:JWT:>", s)
    
    # 쿼리/폼 파라미터들
    oidc_params = [
        (r"([?&])code=[A-Za-z0-9\-_]{8,}", r"\1code=<:CODE:>"),
        (r"([?&])access_token=[A-Za-z0-9\-_]{8,}", r"\1access_token=<:AT:>"),
        (r"([?&])refresh_token=[A-Za-z0-9\-_]{8,}", r"\1refresh_token=<:RT:>"),
        (r"([?&])id_token=[A-Za-z0-9\-_\.]+", r"\1id_token=<:JWT:>"),
        (r"([?&])client_id=[^&\s]+", r"\1client_id=<:CLIENT_ID:>"),
        (r"([?&])redirect_uri=[^&\s]+", r"\1redirect_uri=<:URL:>"),
        (r"([?&])scope=[^&\s]+", r"\1scope=<:SCOPE:>"),
        (r"([?&])code_verifier=[^&\s]+", r"\1code_verifier=<:PKCE:>"),
        (r"([?&])code_challenge=[^&\s]+", r"\1code_challenge=<:PKCE:>"),
        (r"([?&])grant_type=[^&\s]+", r"\1grant_type=<:GRANT:>"),
        (r"([?&])response_type=[^&\s]+", r"\1response_type=<:RESP_TYPE:>"),
    ]
    
    for pattern, replacement in oidc_params:
        s = re.sub(pattern, replacement, s, flags=re.IGNORECASE)

    return s