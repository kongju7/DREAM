#!/usr/bin/env python3
"""OIDC 로그 시퀀스 이상탐지를 위한 전처리"""

import re

class OidcPreprocessor:
    """OIDC Parameter 로그의 시퀀스 분석을 위한 전처리기"""
    
    # OIDC Parameter 패턴
    OIDC_PARAM_PATTERN = re.compile(
        r'OidcController Parameter key: ([^,]+), value: (.+)$'
    )
    
    # OIDC Endpoint 기반 parameter 그룹화 (실제 로그 분석 반영)
    OIDC_PARAM_GROUPS = {
        # /oidc/auth - Authorization Request (OAuth 2.0 인증 요청)
        'AUTH_REQUEST': {
            'scope', 'response_type', 'state', 'client_id', 'redirect_uri',
            'logout_uri', 'code_challenge', 'code_challenge_method', 'nonce'
        },
        
        # /oidc/token - Token Exchange (Authorization Code → Access Token)
        'TOKEN_REQUEST': {
            'code', 'grant_type', 'client_secret', 'code_verifier',
            'client_id', 'redirect_uri'  # AUTH와 같은 key이지만 다른 endpoint
        },
        
        # /oidc/logout - Logout Request (세션 종료)
        'LOGOUT_REQUEST': {
            'ClientId', 'RelayState'  # 대문자 ClientId = 로그아웃 전용
        },
        
        # User Authentication (실제 사용자 인증)
        'USER_AUTH': {
            'uid', 'upw', 'SubAuthSessionId'
        }
    }
    
    @classmethod
    def preprocess_oidc_parameter(cls, message: str, url_context: str = None) -> str:
        """
        OIDC Parameter 로그를 시퀀스 분석에 적합하게 전처리
        
        전략: Endpoint 컨텍스트 기반 그룹화 + 값 일반화
        - URL context를 이용해 정확한 그룹 분류
        - 같은 parameter라도 endpoint에 따라 다른 의미
        
        Args:
            message: OIDC Parameter 로그 메시지
            url_context: 이전 로그의 URL 정보 (/oidc/auth, /oidc/token 등)
        """
        match = cls.OIDC_PARAM_PATTERN.search(message)
        
        if not match:
            return message
            
        param_key = match.group(1).strip()
        param_value = match.group(2).strip()
        
        # 1. URL context 기반으로 정확한 그룹 분류
        param_group = cls._get_parameter_group_with_context(param_key, url_context)
        
        # 2. 값을 의미있게 일반화
        generalized_value = cls._generalize_parameter_value(param_key, param_value)
        
        # 3. Context-aware 템플릿 생성
        if param_group:
            processed_message = message.replace(
                f"key: {param_key}, value: {param_value}",
                f"key: [{param_group}]{param_key}, value: {generalized_value}"
            )
        else:
            # URL context가 없으면 기존 방식 사용
            param_group = cls._get_parameter_group(param_key)
            processed_message = message.replace(
                f"key: {param_key}, value: {param_value}",
                f"key: [{param_group}]{param_key}, value: {generalized_value}"
            )
        
        return processed_message
    
    @classmethod
    def _get_parameter_group_with_context(cls, param_key: str, url_context: str = None) -> str:
        """URL context를 고려한 정확한 파라미터 그룹 분류"""
        if not url_context:
            # URL context가 없는 경우 스마트 추론
            return cls._infer_parameter_group(param_key)
            
        # URL 기반 endpoint 분류
        if '/oidc/auth' in url_context:
            return 'AUTH_REQUEST' if param_key in cls.OIDC_PARAM_GROUPS['AUTH_REQUEST'] else 'UNKNOWN'
        elif '/oidc/token' in url_context:
            return 'TOKEN_REQUEST' if param_key in cls.OIDC_PARAM_GROUPS['TOKEN_REQUEST'] else 'UNKNOWN'
        elif '/oidc/logout' in url_context:
            return 'LOGOUT_REQUEST' if param_key in cls.OIDC_PARAM_GROUPS['LOGOUT_REQUEST'] else 'UNKNOWN'
        else:
            # 기타 endpoint
            return cls._get_parameter_group(param_key)
    
    @classmethod
    def _infer_parameter_group(cls, param_key: str) -> str:
        """URL context가 없을 때 파라미터 특성으로 그룹 추론"""
        
        # 1. 고유 파라미터 기반 추론 (확실한 경우들)
        unique_params = {
            # 로그아웃 전용 (대문자 + SAML 스타일)
            'ClientId': 'LOGOUT_REQUEST',
            'RelayState': 'LOGOUT_REQUEST',
            
            # 토큰 교환 전용 
            'code': 'TOKEN_REQUEST',
            'grant_type': 'TOKEN_REQUEST', 
            'client_secret': 'TOKEN_REQUEST',
            'code_verifier': 'TOKEN_REQUEST',
            
            # 인증 요청 전용
            'scope': 'AUTH_REQUEST',
            'response_type': 'AUTH_REQUEST',
            'code_challenge': 'AUTH_REQUEST',
            'code_challenge_method': 'AUTH_REQUEST',
            'nonce': 'AUTH_REQUEST',
            'logout_uri': 'AUTH_REQUEST',
            
            # 사용자 인증
            'uid': 'USER_AUTH',
            'upw': 'USER_AUTH', 
            'SubAuthSessionId': 'USER_AUTH'
        }
        
        if param_key in unique_params:
            return unique_params[param_key]
        
        # 2. 애매한 파라미터 (client_id, redirect_uri)
        # 이런 경우는 UNKNOWN으로 두고 추가 로직이 필요할 수 있음
        ambiguous_params = {'client_id', 'redirect_uri', 'state'}
        if param_key in ambiguous_params:
            return 'AMBIGUOUS'  # 나중에 context로 재분류 필요
            
        return 'UNKNOWN'
    
    @classmethod
    def _get_parameter_group(cls, param_key: str) -> str:
        """파라미터를 OIDC 플로우 그룹으로 분류 (fallback)"""
        for group_name, param_set in cls.OIDC_PARAM_GROUPS.items():
            if param_key in param_set:
                return group_name
        return 'UNKNOWN'  # 새로운 파라미터 발견 시
    
    @classmethod
    def _generalize_parameter_value(cls, param_key: str, param_value: str) -> str:
        """파라미터 값을 의미있게 일반화"""
        
        # 고정 값들 (변경되지 않는 값들)
        fixed_values = {
            'response_type': 'code',
            'code_challenge_method': 'S256',
            'grant_type': 'authorization_code'
        }
        
        if param_key in fixed_values and param_value == fixed_values[param_key]:
            return param_value  # 고정값은 그대로 유지
        
        # URL 패턴 감지
        if param_value.startswith('http://') or param_value.startswith('https://'):
            return '<URL>'
            
        # UUID/GUID 패턴 감지
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        if re.match(uuid_pattern, param_value, re.IGNORECASE):
            return '<UUID>'
            
        # Base64 패턴 감지 (길고 특수문자가 많은 경우)
        if len(param_value) > 20 and re.search(r'[A-Za-z0-9+/=]{10,}', param_value):
            return '<BASE64>'
            
        # 스코프 패턴 (공백으로 구분된 권한들)
        if param_key == 'scope' and '+' in param_value:
            return '<SCOPE_LIST>'
            
        # 사용자 식별자 패턴
        if param_key in ['uid', 'username', 'user_id'] and len(param_value) < 20:
            return '<USER_ID>'
            
        # 클라이언트 식별자 패턴  
        if param_key == 'client_id' and param_value.startswith('TEST_'):
            return '<CLIENT_ID>'
            
        # 기타 긴 문자열은 일반화
        if len(param_value) > 30:
            return '<LONG_STRING>'
            
        # 짧은 문자열은 그대로 유지 (디버깅에 유용)
        return param_value


def preprocess_line_for_oidc_sequence(file_path: str, raw_message: str) -> str:
    """
    OIDC 시퀀스 분석을 위한 라인 전처리
    기존 preprocess_line_for_oidc와 함께 사용
    """
    # 기존 OIDC 전처리 적용
    from utils.session_extractor import preprocess_line_for_oidc
    preprocessed = preprocess_line_for_oidc(file_path, raw_message)
    
    # OIDC Parameter 추가 전처리
    if "OidcController Parameter key:" in preprocessed:
        preprocessed = OidcPreprocessor.preprocess_oidc_parameter(preprocessed)
    
    return preprocessed


if __name__ == "__main__":
    # 테스트 - URL context 있는 경우와 없는 경우
    test_cases = [
        # Case 1: URL context가 있는 경우
        {
            "url_context": "/oidc/auth",
            "logs": [
                "OidcController Parameter key: scope, value: address+email+openid+profile",
                "OidcController Parameter key: client_id, value: TEST_SP2",
                "OidcController Parameter key: state, value: d989fdfe-b265-4fe2-8b0c-f957355b1b56"
            ]
        },
        # Case 2: URL context가 없는 경우 (사용자 예시)
        {
            "url_context": None,
            "logs": [
                "OidcController Parameter key: ClientId, value: TEST_SP1",
                "OidcController Parameter key: RelayState, value: http://sp1.dev.com:40004/portal/oidcLoginSample.jsp",
                "OidcController Parameter key: code, value: abc123def456",
                "OidcController Parameter key: client_id, value: TEST_SP2"  # 애매한 경우
            ]
        }
    ]
    
    print("🔧 **OIDC Context-Aware 전처리 테스트**")
    print("=" * 60)
    
    for case_idx, test_case in enumerate(test_cases, 1):
        url_context = test_case["url_context"]
        logs = test_case["logs"]
        
        print(f"\n📋 **Case {case_idx}: URL Context = {url_context or 'None'}**")
        print("-" * 40)
        
        for i, log in enumerate(logs, 1):
            processed = OidcPreprocessor.preprocess_oidc_parameter(log, url_context)
            print(f"\n{i}. 원본:")
            print(f"   {log}")
            print(f"   처리:")
            print(f"   {processed}")
    
    print(f"\n💡 **핵심 개선사항:**")
    print("✅ URL context 있으면 → 정확한 endpoint 분류")
    print("✅ URL context 없으면 → 스마트 추론으로 분류")
    print("✅ ClientId/RelayState → 자동으로 LOGOUT_REQUEST")
    print("✅ client_id 같은 애매한 파라미터 → AMBIGUOUS 표시")
    print("✅ 시퀀스 패턴 보존 + 템플릿 최적화")
