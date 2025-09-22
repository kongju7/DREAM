"""Multiline XML block processor for SAML messages."""
import re
from typing import List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class XmlBlock:
    """XML 블록 정보."""
    header_line: str
    xml_content: List[str]
    start_line_num: int
    end_line_num: int
    block_type: str


class MultilineXmlProcessor:
    """멀티라인 XML 블록을 하나의 메시지로 병합하는 전처리기."""
    
    # XML 블록 시작을 나타내는 헤더 패턴들
    XML_HEADER_PATTERNS = {
        "AUTHN_REQUEST": re.compile(r"### AuthnRequest:.*$", re.IGNORECASE),
        "ASSERTION": re.compile(r"### Assertion XML:.*$", re.IGNORECASE),
        "SAML_RESPONSE": re.compile(r"### samlResponse XML:.*$", re.IGNORECASE),
        "RESPONSE": re.compile(r"### Response XML:.*$", re.IGNORECASE),
        "LOGOUT_REQUEST": re.compile(r"### LogoutRequest:.*$", re.IGNORECASE),
        "LOGOUT_RESPONSE": re.compile(r"### LogoutResponse:.*$", re.IGNORECASE),
    }
    
    # XML 블록 종료 패턴들
    XML_END_PATTERNS = {
        "AUTHN_REQUEST": re.compile(r"</saml2?p?:AuthnRequest>\s*$", re.IGNORECASE),
        "ASSERTION": re.compile(r"</saml2?:Assertion>\s*$", re.IGNORECASE), 
        "SAML_RESPONSE": re.compile(r"</saml2?p?:Response>\s*$", re.IGNORECASE),
        "RESPONSE": re.compile(r"</saml2?p?:Response>\s*$", re.IGNORECASE),
        "LOGOUT_REQUEST": re.compile(r"</saml2?p?:LogoutRequest>\s*$", re.IGNORECASE),
        "LOGOUT_RESPONSE": re.compile(r"</saml2?p?:LogoutResponse>\s*$", re.IGNORECASE),
    }
    
    # XML 시작 패턴 (<?xml 또는 <saml)
    XML_START_PATTERN = re.compile(r"^\s*(?:<?xml|<saml)", re.IGNORECASE)
    
    @classmethod
    def process_lines(cls, lines: List[str]) -> List[str]:
        """
        멀티라인 XML 블록을 처리하여 병합된 라인들을 반환.
        
        Args:
            lines: 원본 로그 라인들
            
        Returns:
            XML 블록이 병합된 라인들
        """
        result_lines = []
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            
            # XML 헤더 패턴 확인
            block_type = cls._detect_xml_header(line)
            
            if block_type:
                # XML 블록 추출
                xml_block = cls._extract_xml_block(lines, i, block_type)
                
                if xml_block:
                    # 헤더와 XML 블록을 병합한 라인 생성
                    merged_line = cls._merge_header_and_xml(xml_block)
                    result_lines.append(merged_line)
                    
                    # XML 블록 종료 위치로 점프
                    i = xml_block.end_line_num + 1
                else:
                    # XML 블록을 찾지 못한 경우 원본 라인 유지
                    result_lines.append(lines[i])
                    i += 1
            else:
                # 일반 라인은 그대로 유지
                result_lines.append(lines[i])
                i += 1
                
        return result_lines
    
    @classmethod
    def _detect_xml_header(cls, line: str) -> Optional[str]:
        """XML 헤더 패턴을 감지하여 블록 타입 반환."""
        for block_type, pattern in cls.XML_HEADER_PATTERNS.items():
            if pattern.search(line):
                return block_type
        return None
    
    @classmethod 
    def _extract_xml_block(cls, lines: List[str], header_idx: int, block_type: str) -> Optional[XmlBlock]:
        """
        XML 블록을 추출.
        
        Args:
            lines: 전체 라인들
            header_idx: 헤더 라인 인덱스
            block_type: XML 블록 타입
            
        Returns:
            추출된 XML 블록 정보
        """
        header_line = lines[header_idx]
        xml_content = []
        start_idx = header_idx + 1
        end_idx = None
        
        # 헤더 다음 라인부터 XML 종료 패턴을 찾을 때까지 수집
        end_pattern = cls.XML_END_PATTERNS.get(block_type)
        if not end_pattern:
            return None
            
        for i in range(start_idx, len(lines)):
            line = lines[i]
            
            # XML 라인인지 확인 (공백 라인 제외)
            if line.strip() == "":
                continue
                
            # XML이 아닌 일반 로그 라인이 나오면 중단 
            if not cls._is_xml_line(line) and not end_pattern.search(line):
                break
                
            xml_content.append(line)
            
            # 종료 패턴 확인
            if end_pattern.search(line):
                end_idx = i
                break
                
        # XML 블록을 찾았으면 반환
        if xml_content and end_idx is not None:
            return XmlBlock(
                header_line=header_line,
                xml_content=xml_content,
                start_line_num=start_idx,
                end_line_num=end_idx,
                block_type=block_type
            )
            
        return None
    
    @classmethod
    def _is_xml_line(cls, line: str) -> bool:
        """라인이 XML 형식인지 확인."""
        stripped = line.strip()
        
        # 빈 라인
        if not stripped:
            return True
            
        # XML 선언이나 태그로 시작
        if cls.XML_START_PATTERN.match(stripped):
            return True
            
        # XML 태그 (시작/종료)
        if stripped.startswith('<') and stripped.endswith('>'):
            return True
            
        # 들여쓰기된 XML 태그
        if re.match(r'^\s*<[^>]+>\s*$', stripped):
            return True
            
        # XML 내용 (태그 사이의 텍스트)
        if re.match(r'^\s*[^<>]*</[^>]+>\s*$', stripped):
            return True
            
        # XML 태그로 시작하는 라인 (태그 안에 내용이 있는 경우)
        if re.match(r'^\s*<[^>]+>[^<]*$', stripped):
            return True
            
        # Base64나 긴 문자열이 포함된 라인 (X509Certificate 등)
        # 영숫자, +, /, = 로만 구성된 긴 문자열
        if re.match(r'^\s*[A-Za-z0-9+/=]+\s*$', stripped) and len(stripped) > 20:
            return True
            
        # 들여쓰기된 긴 문자열 (인증서 내용 등)
        if re.match(r'^\s+[A-Za-z0-9+/=]+\s*$', stripped) and len(stripped.strip()) > 10:
            return True
            
        return False
    
    @classmethod
    def _merge_header_and_xml(cls, xml_block: XmlBlock) -> str:
        """헤더 라인과 XML 블록을 병합."""
        # XML 내용을 요약된 플레이스홀더로 대체
        xml_placeholder = cls._create_xml_placeholder(xml_block)
        
        # 헤더 라인에서 ### 이후 부분을 플레이스홀더로 교체
        header_parts = xml_block.header_line.split('###', 1)
        if len(header_parts) == 2:
            timestamp_and_logger = header_parts[0] + '###'
            merged_line = f"{timestamp_and_logger} {xml_placeholder}"
        else:
            # ### 패턴이 없는 경우 그대로 추가
            merged_line = f"{xml_block.header_line} {xml_placeholder}"
            
        return merged_line
    
    @classmethod
    def _create_xml_placeholder(cls, xml_block: XmlBlock) -> str:
        """XML 블록의 특성을 반영한 포괄적 플레이스홀더 생성."""
        block_type = xml_block.block_type
        
        # XML에서 주요 속성들 추출
        xml_text = '\n'.join(xml_block.xml_content)
        
        # 기본 식별자 정보
        id_match = re.search(r'ID="([^"]+)"', xml_text, re.IGNORECASE)
        session_id = id_match.group(1) if id_match else "UNKNOWN_ID"
        
        # InResponseTo 추출 (요청-응답 매핑)
        in_response_to_match = re.search(r'InResponseTo="([^"]+)"', xml_text, re.IGNORECASE)
        in_response_to = in_response_to_match.group(1) if in_response_to_match else None
        
        # 시간 정보 추출 (여러 패턴)
        instant_match = re.search(r'IssueInstant="([^"]+)"', xml_text, re.IGNORECASE)
        timestamp = instant_match.group(1) if instant_match else "UNKNOWN_TIME"
        
        # 발행자 정보
        issuer_match = re.search(r'<saml2?:Issuer[^>]*>([^<]+)</saml2?:Issuer>', xml_text, re.IGNORECASE)
        issuer = issuer_match.group(1) if issuer_match else "UNKNOWN_ISSUER"
        
        # Status 정보 (성공/실패)
        status_match = re.search(r'<saml2?p?:StatusCode Value="[^"]*:([^"]+)"', xml_text, re.IGNORECASE)
        status = status_match.group(1) if status_match else None
        
        # === 추가 상세 정보 추출 ===
        
        # URL 정보 추출
        destination_match = re.search(r'Destination="([^"]+)"', xml_text, re.IGNORECASE)
        destination = destination_match.group(1) if destination_match else None
        
        consumer_url_match = re.search(r'AssertionConsumerServiceURL="([^"]+)"', xml_text, re.IGNORECASE)
        consumer_url = consumer_url_match.group(1) if consumer_url_match else None
        
        # Provider 정보
        provider_match = re.search(r'ProviderName="([^"]+)"', xml_text, re.IGNORECASE)
        provider = provider_match.group(1) if provider_match else None
        
        # NameID 정보 (사용자 식별)
        name_id_match = re.search(r'<saml2?:NameID[^>]*>([^<]+)</saml2?:NameID>', xml_text, re.IGNORECASE)
        name_id = name_id_match.group(1) if name_id_match else None
        
        # NameID Format 정보
        name_id_format_match = re.search(r'<saml2?:NameID[^>]*Format="([^"]+)"', xml_text, re.IGNORECASE)
        name_id_format = name_id_format_match.group(1) if name_id_format_match else None
        if name_id_format:
            name_id_format = name_id_format.split(':')[-1]  # 마지막 부분만 (예: entity)
        
        # Subject Confirmation Method
        subject_confirm_match = re.search(r'<saml2?:SubjectConfirmation Method="([^"]+)"', xml_text, re.IGNORECASE)
        subject_method = subject_confirm_match.group(1) if subject_confirm_match else None
        if subject_method:
            subject_method = subject_method.split(':')[-1]  # 마지막 부분만
            
        # Conditions (NotBefore, NotOnOrAfter)
        not_before_match = re.search(r'NotBefore="([^"]+)"', xml_text, re.IGNORECASE)
        not_before = not_before_match.group(1) if not_before_match else None
        
        not_on_or_after_match = re.search(r'NotOnOrAfter="([^"]+)"', xml_text, re.IGNORECASE)
        not_on_or_after = not_on_or_after_match.group(1) if not_on_or_after_match else None
        
        # AuthnContext 정보
        authn_context_match = re.search(r'<saml2?:AuthnContextClassRef[^>]*>([^<]+)</saml2?:AuthnContextClassRef>', xml_text, re.IGNORECASE)
        authn_context = authn_context_match.group(1) if authn_context_match else None
        if authn_context:
            authn_context = authn_context.split(':')[-1]  # 마지막 부분만 (예: Password)
        
        # 플레이스홀더 생성 (중요도 순으로 정렬)
        components = [f"ID={session_id}"]
        
        # InResponseTo (요청-응답 매핑에 중요!)
        if in_response_to:
            components.append(f"InResponseTo={in_response_to}")
            
        components.append(f"TIME={timestamp}")
        components.append(f"ISSUER={issuer}")
        
        # Status 정보
        if status:
            components.append(f"STATUS={status}")
            
        # Provider 정보
        if provider:
            components.append(f"PROVIDER={provider}")
            
        # URL 정보
        if destination:
            # URL을 간단히 표현 (도메인:포트만)
            try:
                from urllib.parse import urlparse
                parsed = urlparse(destination)
                dest_short = f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname
                components.append(f"DEST={dest_short}")
            except:
                components.append(f"DEST={destination}")
                
        if consumer_url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(consumer_url)
                consumer_short = f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname
                components.append(f"CONSUMER={consumer_short}")
            except:
                components.append(f"CONSUMER={consumer_url}")
        
        # 사용자 정보
        if name_id and name_id != "null" and len(name_id.strip()) > 0:
            components.append(f"USER={name_id}")
            if name_id_format:
                components.append(f"USER_FORMAT={name_id_format}")
        
        # Subject Confirmation
        if subject_method:
            components.append(f"SUBJECT_METHOD={subject_method}")
            
        # 유효 기간
        if not_before:
            components.append(f"NOT_BEFORE={not_before}")
        if not_on_or_after:
            components.append(f"NOT_AFTER={not_on_or_after}")
            
        # 인증 컨텍스트
        if authn_context:
            components.append(f"AUTHN_CONTEXT={authn_context}")
        
        placeholder = f"<SAML_{block_type}:{':'.join(components)}>"
        
        return placeholder
    
    @classmethod
    def get_processing_stats(cls, original_lines: List[str], processed_lines: List[str]) -> dict:
        """XML 블록 처리 통계 반환."""
        xml_blocks_merged = len(original_lines) - len(processed_lines)
        
        # 원본에서 XML 관련 라인 수 계산
        xml_line_count = sum(1 for line in original_lines if cls._is_xml_line(line))
        
        return {
            "original_line_count": len(original_lines),
            "processed_line_count": len(processed_lines),
            "xml_blocks_merged": xml_blocks_merged,
            "xml_line_count": xml_line_count,
            "compression_ratio": xml_blocks_merged / len(original_lines) if original_lines else 0
        }
