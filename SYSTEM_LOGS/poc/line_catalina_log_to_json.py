# ml_catalina_log_to_json.py
# -*- coding: utf-8 -*-
"""
MagicLine (Server) Catalina.out → NDJSON 정제 스크립트
- 멀티라인 예외 병합
- 헤더 파싱(여러 패턴 지원: Tomcat, Spring)
- 필드 표준화 및 템플릿화
- 파생 피처 생성
- NDJSON + JSON Schema 출력
"""

import re
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

# ====== 경로 설정 ======

data_origin = "poc"
service = "Magicline_Server"

INPUT_PATH = f"/home/kongju/DATA/dream/{data_origin}/{service}/catalina.out"


OUT_NDJSON = f"/home/kongju/DEV/{data_origin}/output/{service}/catalina_out_structured.ndjson"
OUT_SCHEMA = f"/home/kongju/DEV/{data_origin}/output/{service}/catalina_out_schema.json"

# ====== 로그 헤더 패턴들 ======
# 1) Tomcat 기본: 18-Mar-2025 10:51:51.333 정보 [main] org.apache.catalina... 메시지
P_TOMCAT = re.compile(
    r"^(?P<ts>\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<level>SEVERE|WARNING|정보|경고|오류|디버그|TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"\[(?P<thr>[^\]]+)\]\s+(?P<cls>[\w\.\$]+)\s+(?P<msg>.*)$"
)

# 2) Spring/일반: 2025-04-24 10:09:19.752 ERROR 121679 --- [           main] o.s.boot.SpringApplication : 메시지
P_SPRING = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\.\d{3,6})\s+"
    r"(?P<level>SEVERE|WARNING|TRACE|DEBUG|INFO|WARN|ERROR|FATAL|정보|경고|오류|디버그)\s+"
    r"(?P<pid>\d+)?\s*(?:---)?\s*\[\s*(?P<thr>[^\]]+)\]\s+"
    r"(?P<cls>[\w\.\$\-]+)\s*[:\-]\s*(?P<msg>.*)$"
)

# 3) 심플 포맷: 2025-04-24 10:09:19,752 ERROR [main] com.example.Foo - 메시지
P_SIMPLE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[.,]\d{3,6})\s+"
    r"(?P<level>SEVERE|WARNING|TRACE|DEBUG|INFO|WARN|ERROR|FATAL|정보|경고|오류|디버그)\s+"
    r"\[(?P<thr>[^\]]+)\]\s+(?P<cls>[\w\.\$]+)\s*[:\-]\s*(?P<msg>.*)$"
)

# 4) 시간만 있는 포맷: 10:55:15.606 [http-nio-8080-exec-8] DEBUG com.example.Foo -- 메시지
P_TIME_ONLY = re.compile(
    r"^(?P<ts>\d{2}:\d{2}:\d{2}\.\d{3,6})\s+"
    r"\[(?P<thr>[^\]]+)\]\s+"
    r"(?P<level>SEVERE|WARNING|TRACE|DEBUG|INFO|WARN|ERROR|FATAL|정보|경고|오류|디버그)\s+"
    r"(?P<cls>[\w\.\$\-]+)\s*(?:--|\-\-|:)\s*(?P<msg>.*)$"
)

HEADER_PATTERNS = [P_TOMCAT, P_SPRING, P_SIMPLE, P_TIME_ONLY]

# ====== 레벨 정규화(KR → EN) ======
LEVEL_MAP = {
    "정보": "INFO", "경고": "WARN", "오류": "ERROR", "디버그": "DEBUG",
    "INFO": "INFO", 
    "WARN": "WARN", "WARNING": "WARN",
    "ERROR": "ERROR", "SEVERE": "ERROR",
    "DEBUG": "DEBUG", 
    "TRACE": "TRACE", 
    "FATAL": "FATAL"
}

# ====== 예외/스택트레이스 라인 감지 ======
RE_STACK_LINE = re.compile(r"^\s*at\s+[\w\.$]+\(.*\)$")
RE_CAUSED_BY  = re.compile(r"^\s*Caused by: .+$")

# ====== 노이즈 라인 감지 ======
RE_NOISE_LINES = [
    re.compile(r"^NOTE:\s+Picked up JDK_JAVA_OPTIONS:"),
    re.compile(r"^INFO:\s+Picked up JDK_JAVA_OPTIONS:"),
    re.compile(r"^\s*$"),  # 빈 라인
    re.compile(r"^---+.*---+$"),  # 구분선
]

# ====== 디버그/불필요 로그 패턴 ======
DEBUG_PATTERNS = [
    "Command line argument:",
    "At least one JAR was scanned for TLDs",
    "Skipping unneeded JARs during scanning",
    "Enable debug logging for this logger",
]

# ====== 가변값(토큰화) 정규식 ======
RE_IP        = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
RE_UUID      = re.compile(r"\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\b")
RE_HEX_LONG  = re.compile(r"\b[0-9a-fA-F]{16,}\b")
RE_NUM       = re.compile(r"\b\d+\b")
RE_PATH      = re.compile(r"(/[^ \t\n\r\f\v:]+)+")
RE_EMAIL     = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
RE_COOKIE    = re.compile(r"JSESSIONID=[A-Z0-9]+")
RE_QUOTED    = re.compile(r"\"[^\"]+\"|'[^']+'")

# ====== 유틸 ======
def to_iso8601(ts: str, base_date: Optional[str] = None) -> Optional[str]:
    """
    다양한 ts 포맷 → ISO8601(밀리초)로 변환.
    시간만 있는 경우 base_date를 사용.
    """
    ts = ts.replace(",", ".")
    
    # 시간만 있는 경우 (HH:MM:SS.mmm)
    if re.match(r"^\d{2}:\d{2}:\d{2}\.\d{3,6}$", ts) and base_date:
        try:
            # base_date에서 날짜 부분 추출
            base_dt = datetime.fromisoformat(base_date.replace("Z", "+00:00"))
            time_part = datetime.strptime(ts, "%H:%M:%S.%f").time()
            combined = datetime.combine(base_dt.date(), time_part)
            return combined.isoformat(timespec="milliseconds")
        except Exception:
            pass
    
    # 전체 날짜+시간
    fmts = [
        "%d-%b-%Y %H:%M:%S.%f",     # 18-Mar-2025 10:51:51.333
        "%Y-%m-%d %H:%M:%S.%f",     # 2025-04-24 10:09:19.752
        "%Y-%m-%dT%H:%M:%S.%f"      # 2025-04-24T10:09:19.752
    ]
    for f in fmts:
        try:
            dt = datetime.strptime(ts, f)
            return dt.isoformat(timespec="milliseconds")
        except Exception:
            continue
    return None

def normalize_level(lv: str) -> str:
    return LEVEL_MAP.get(lv, lv.upper())

def template_message(msg: str) -> str:
    """
    메시지 텍스트에서 가변 요소를 토큰화해 템플릿 생성.
    """
    s = msg
    s = RE_COOKIE.sub("JSESSIONID=<ID>", s)
    s = RE_EMAIL.sub("<EMAIL>", s)
    s = RE_UUID.sub("<UUID>", s)
    s = RE_IP.sub("<IP>", s)
    s = RE_HEX_LONG.sub("<HEX>", s)
    s = RE_PATH.sub("<PATH>", s)
    # 큰따옴표/작은따옴표 내부는 한 번에 일반화 (선택적)
    s = RE_QUOTED.sub("<QUOTE>", s)
    s = RE_NUM.sub("<NUM>", s)
    return " ".join(s.split())

def first_exception_type(stack: List[str]) -> Optional[str]:
    """
    스택트레이스 첫 라인(또는 Caused by)에서 예외 타입 추출.
    """
    if not stack:
        return None
    # "java.lang.IllegalStateException: ..." 형태
    for line in stack:
        line = line.strip()
        if line.startswith("Caused by: "):
            return line.split("Caused by: ", 1)[1].split(":", 1)[0].strip()
        if ":" in line and "(" not in line and line.lower().endswith("exception"):
            return line.split(":", 1)[0].strip()
        if line.endswith("Exception") or line.endswith("Error"):
            # ex) java.lang.IllegalArgumentException
            return line.split(":")[0].strip()
    # fallback
    head = stack[0].strip()
    return head.split(":")[0] if ":" in head else head[:200]

def severity_score(level: str, has_exc: bool) -> int:
    """
    간단 severity score: DEBUG=10, INFO=20, WARN=40, ERROR=80(+20 if stack)
    """
    base = {"TRACE": 5, "DEBUG": 10, "INFO": 20, "WARN": 40, "ERROR": 80, "FATAL": 90}.get(level, 20)
    return base + (20 if has_exc and base >= 40 else 0)

def categorize_log_type(logger: str, message: str) -> str:
    """로그 타입 카테고리화"""
    if not logger:
        return "UNKNOWN"
    
    logger_lower = logger.lower()
    msg_lower = message.lower()
    
    # 시스템 관련
    if any(x in logger_lower for x in ["catalina", "tomcat", "bootstrap"]):
        return "SYSTEM"
    
    # 보안 관련
    if any(x in logger_lower for x in ["security", "auth", "ssl", "cert"]):
        return "SECURITY"
    
    # 네트워크 관련
    if any(x in logger_lower for x in ["http", "nio", "coyote", "connector"]):
        return "NETWORK"
    
    # 애플리케이션 관련
    if any(x in logger_lower for x in ["servlet", "jsp", "filter", "valve"]):
        return "APPLICATION"
    
    # 데이터베이스 관련
    if any(x in logger_lower for x in ["sql", "jdbc", "database", "datasource"]):
        return "DATABASE"
    
    # 컴파일러 관련
    if any(x in logger_lower for x in ["compiler", "jasper", "jdt"]):
        return "COMPILER"
    
    return "OTHER"

def extract_error_code(message: str) -> Optional[str]:
    """에러 코드 추출 (HTTP 상태 코드, 예외 코드 등)"""
    # HTTP 상태 코드
    http_match = re.search(r'\b[4-5]\d{2}\b', message)
    if http_match:
        return f"HTTP_{http_match.group()}"
    
    # 일반적인 에러 코드 패턴
    error_match = re.search(r'\b[A-Z]{2,}-\d{3,}\b', message)
    if error_match:
        return error_match.group()
    
    return None

def calculate_message_complexity(message: str) -> Dict[str, int]:
    """메시지 복잡도 계산"""
    words = message.split()
    return {
        "word_count": len(words),
        "char_count": len(message),
        "unique_words": len(set(w.lower() for w in words)),
        "punctuation_count": sum(1 for c in message if c in ".,;:!?"),
        "number_count": len(re.findall(r'\d+', message))
    }

def extract_signature_info(message: str, logger: str) -> Dict[str, Any]:
    """전자서명 관련 로그에서 이상탐지용 정보 추출"""
    info = {}
    
    if "SignedDataVerifier" not in logger and "CertificateVerifier" not in logger:
        return info
    
    # === 기본 응답 정보 ===
    # responseCode 추출
    response_match = re.search(r"responseCode=(\d+)", message)
    if response_match:
        info["signature_response_code"] = int(response_match.group(1))
        info["signature_success"] = int(response_match.group(1)) == 0
    
    # msg 필드 추출 (OK, ERROR 등)
    msg_match = re.search(r"msg=([^,]+)", message)
    if msg_match:
        info["signature_msg"] = msg_match.group(1).strip()
    
    # === 사용자 인증서 정보 ===
    # 사용자 DN (Distinguished Name) 추출 
    dn_match = re.search(r"dn=([^,]+,[^,]+.*?),\s*signOrgData", message)
    if not dn_match:
        # signOrgData가 없으면 다른 필드까지 매칭
        dn_match = re.search(r"dn=([^,]+,[^,]+.*?),\s*signerInfos", message)
    if dn_match:
        dn = dn_match.group(1)
        info["user_dn"] = dn
        
        # 사용자 이름 추출 (cn=홍길동() 패턴)
        name_match = re.search(r"cn=([^()]+)", dn)
        if name_match:
            info["user_name"] = name_match.group(1)
        
        # 조직 정보 추출 (ou=KFTC 등)
        ou_matches = re.findall(r"ou=([^,]+)", dn)
        if ou_matches:
            info["user_organization"] = ",".join(ou_matches)
        
        # 국가 코드 추출
        country_match = re.search(r"c=([^,]+)", dn)
        if country_match:
            info["user_country"] = country_match.group(1)
    
    # 주 인증서 해시 추출
    cert_match = re.search(r"userCert=.*@([a-fA-F0-9]+)", message)
    if cert_match:
        info["primary_cert_hash"] = cert_match.group(1)
    
    # 인증서 체인 길이 (userCerts 배열 크기)
    user_certs_match = re.search(r"userCerts=\[(.*?)\]", message)
    if user_certs_match:
        certs_content = user_certs_match.group(1)
        # X509Certificate@ 패턴 개수로 인증서 개수 계산
        cert_count = len(re.findall(r"X509Certificate@[a-fA-F0-9]+", certs_content))
        info["cert_chain_length"] = cert_count
        
        # 인증서 체인의 모든 해시값 추출
        cert_hashes = re.findall(r"X509Certificate@([a-fA-F0-9]+)", certs_content)
        if cert_hashes:
            info["cert_chain_hashes"] = cert_hashes
    
    # === 서명 데이터 정보 ===
    # 서명 원본 데이터 길이 (signOrgData 배열 크기)
    org_data_match = re.search(r"signOrgData=\[([^\]]+)\]", message)
    if org_data_match:
        data_elements = org_data_match.group(1).split(", ")
        info["sign_data_length"] = len(data_elements)
        
        # 서명 데이터의 패턴 분석 (모두 숫자인지, ASCII 범위인지)
        try:
            data_values = [int(x.strip()) for x in data_elements]
            info["sign_data_avg"] = sum(data_values) / len(data_values)
            info["sign_data_min"] = min(data_values)
            info["sign_data_max"] = max(data_values)
            info["sign_data_ascii_range"] = all(32 <= x <= 126 for x in data_values)
        except (ValueError, ZeroDivisionError):
            pass
    
    # === 서명자 정보 ===
    # signerInfos 해시값들 추출
    signer_infos_match = re.search(r"signerInfos=\[(.*?)\]", message)
    if signer_infos_match:
        signer_content = signer_infos_match.group(1)
        signer_hashes = re.findall(r"SignerInfo@([a-fA-F0-9]+)", signer_content)
        if signer_hashes:
            info["signer_info_hashes"] = signer_hashes
            info["signer_count"] = len(signer_hashes)
    
    # 서명 시간 추출
    signing_time_match = re.search(r"signingTime=([^,)]+)", message)
    if signing_time_match:
        signing_time = signing_time_match.group(1).strip()
        info["signing_time"] = signing_time
        
        # 서명 시간 파싱하여 시간대 분석
        try:
            if "KST" in signing_time:
                time_parts = signing_time.replace(" KST", "").split()
                if len(time_parts) >= 4:
                    hour_min = time_parts[3].split(":")
                    if len(hour_min) >= 2:
                        hour = int(hour_min[0])
                        info["signing_hour"] = hour
                        info["signing_time_period"] = (
                            "night" if hour < 6 or hour >= 22 else
                            "morning" if hour < 12 else
                            "afternoon" if hour < 18 else
                            "evening"
                        )
        except (ValueError, IndexError):
            pass
    
    # === 전체 SignedData 객체 해시 ===
    signed_data_match = re.search(r"signedData=.*@([a-fA-F0-9]+)", message)
    if signed_data_match:
        info["signed_data_hash"] = signed_data_match.group(1)
    
    # === 전체 데이터 복잡도 ===
    if "SignedDataVO(" in message:
        info["signature_data_complexity"] = len(message)
        info["signature_field_count"] = len(re.findall(r"\w+=", message))
    
    return info

def detect_security_anomalies(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """보안 이상패턴 탐지를 위한 필드 추가"""
    
    # 사용자별 서명 시간 추적
    user_signatures = {}
    
    for i, event in enumerate(events):
        if event.get("signature_response_code") is not None:
            user_name = event.get("user_name")
            timestamp = event.get("timestamp")
            
            if user_name and timestamp:
                if user_name not in user_signatures:
                    user_signatures[user_name] = []
                user_signatures[user_name].append(timestamp)
                
                # 이전 서명과의 시간 간격 계산
                if len(user_signatures[user_name]) > 1:
                    try:
                        prev_time = datetime.fromisoformat(user_signatures[user_name][-2])
                        curr_time = datetime.fromisoformat(timestamp)
                        interval_seconds = (curr_time - prev_time).total_seconds()
                        event["signature_interval_seconds"] = interval_seconds
                        
                        # 이상패턴 플래그
                        event["rapid_signature"] = interval_seconds < 30  # 30초 이내 연속 서명
                        event["delayed_signature"] = interval_seconds > 3600  # 1시간 이상 간격
                    except Exception:
                        pass
                
                # 사용자별 서명 횟수
                event["user_signature_count"] = len(user_signatures[user_name])
    
    return events

# ====== 파서 ======
def parse_header(line: str, base_date: Optional[str] = None) -> Optional[Dict[str, Any]]:
    for p in HEADER_PATTERNS:
        m = p.match(line)
        if m:
            d = m.groupdict()
            ts = to_iso8601(d.get("ts", ""), base_date)
            if not ts:
                return None
            return {
                "timestamp": ts,
                "level": normalize_level(d.get("level", "INFO")),
                "thread": d.get("thr"),
                "logger": d.get("cls"),
                "pid": d.get("pid"),
                "message": d.get("msg", "").strip()
            }
    return None

def is_noise_line(line: str) -> bool:
    """노이즈 라인인지 확인"""
    line_stripped = line.strip()
    
    # 노이즈 패턴 확인
    for pattern in RE_NOISE_LINES:
        if pattern.match(line):
            return True
    
    # 디버그 패턴 확인
    for debug_pattern in DEBUG_PATTERNS:
        if debug_pattern in line:
            return True
    
    return False

def is_stack_line(line: str) -> bool:
    """스택트레이스 라인인지 확인 (탭 문자 처리 개선)"""
    l = line.rstrip()
    return bool(
        RE_STACK_LINE.match(l) or 
        RE_CAUSED_BY.match(l) or 
        l.startswith("\t") or 
        l.startswith("    ") or  # 4칸 들여쓰기도 포함
        (line.startswith(" ") and ("at " in line or "..." in line))
    )

def is_debug_log(level: str, message: str, logger: str = "") -> bool:
    """디버그성 로그인지 판단 (보안 관련 로그는 예외)"""
    
    # 전자서명 관련 로그는 보안상 중요하므로 DEBUG 레벨이어도 포함
    if "SignedDataVerifier" in logger or "CertificateVerifier" in logger:
        return False
    
    if level in ["TRACE", "DEBUG"]:
        return True
    
    # INFO 레벨이지만 디버그성 메시지
    debug_keywords = [
        "starting", "stopping", "initialized", "loaded", "deployed",
        "deployment", "version", "build", "home", "argument", "configuration"
    ]
    
    msg_lower = message.lower()
    for keyword in debug_keywords:
        if keyword in msg_lower:
            return True
    
    return False

def read_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()

def transform(path: str) -> List[Dict[str, Any]]:
    raw = read_lines(path)
    events: List[Dict[str, Any]] = []
    template_counts: Dict[str, int] = {}  # 템플릿 빈도 추적

    current: Optional[Dict[str, Any]] = None
    stack_buf: List[str] = []
    skipped_noise = 0
    skipped_debug = 0
    last_full_timestamp: Optional[str] = None  # 마지막 완전한 타임스탬프

    def finalize_event(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """이벤트 최종 처리"""
        if not event:
            return None
            
        # 디버그 로그 필터링 (선택적, 보안 관련 로그는 예외)
        if is_debug_log(event.get("level", ""), event.get("message", ""), event.get("logger", "")):
            nonlocal skipped_debug
            skipped_debug += 1
            return None
        
        # 스택트레이스 처리
        if stack_buf:
            event["stacktrace"] = "\n".join(stack_buf)
            event["exception_type"] = first_exception_type(stack_buf)
        
        # 기본 템플릿 및 피처
        message = event.get("message", "")
        tmpl = template_message(message)
        event["message_template"] = tmpl
        event["message_len"] = len(message)
        event["template_len"] = len(tmpl)
        event["has_stacktrace"] = "stacktrace" in event
        event["severity_score"] = severity_score(event["level"], event["has_stacktrace"])
        
        # 새로운 피처들
        event["log_category"] = categorize_log_type(event.get("logger", ""), message)
        event["error_code"] = extract_error_code(message)
        
        # 메시지 복잡도
        complexity = calculate_message_complexity(message)
        event.update(complexity)
        
        # 전자서명 관련 정보 추출
        signature_info = extract_signature_info(message, event.get("logger", ""))
        event.update(signature_info)
        
        # 템플릿 빈도 추적
        template_counts[tmpl] = template_counts.get(tmpl, 0) + 1
        event["template_frequency"] = template_counts[tmpl]
        
        return event

    for rawline in raw:
        line = rawline.rstrip("\n")
        
        # 노이즈 라인 필터링
        if is_noise_line(line):
            skipped_noise += 1
            continue

        header = parse_header(line, last_full_timestamp)
        if header:
            # 이전 이벤트 flush
            if current:
                processed_event = finalize_event(current)
                if processed_event:
                    events.append(processed_event)

            # 새 이벤트 시작
            current = header
            stack_buf = []
            
            # 완전한 타임스탬프인 경우 기록 (날짜 포함)
            if "-" in header["timestamp"] or "T" in header["timestamp"]:
                last_full_timestamp = header["timestamp"]
            
            continue

        # 멀티라인(스택/원인) 누적
        if current and is_stack_line(line):
            stack_buf.append(line)
            continue

        # 헤더도 스택도 아닌 추가 텍스트는 메시지에 이어붙임(필요 시)
        if current and line.strip():
            current["message"] = (current.get("message", "") + " " + line.strip()).strip()

    # 마지막 이벤트 flush
    if current:
        processed_event = finalize_event(current)
        if processed_event:
            events.append(processed_event)

    # 템플릿 빈도 업데이트 (2차 패스)
    for event in events:
        tmpl = event.get("message_template", "")
        event["template_frequency"] = template_counts.get(tmpl, 1)
        event["is_frequent_template"] = template_counts.get(tmpl, 1) > 1

    # 보안 이상패턴 탐지
    events = detect_security_anomalies(events)

    print(f"[정제] 노이즈 라인 제거: {skipped_noise}개")
    print(f"[정제] 디버그 로그 제거: {skipped_debug}개")
    print(f"[정제] 유니크 템플릿: {len(template_counts)}개")
    
    # 전자서명 관련 통계
    signature_events = [e for e in events if e.get("signature_response_code") is not None]
    if signature_events:
        success_count = sum(1 for e in signature_events if e.get("signature_success"))
        print(f"[보안] 전자서명 이벤트: {len(signature_events)}개 (성공: {success_count}개)")

    return events

# ====== JSON Schema(draft-07) ======
SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Catalina Out Structured Log",
    "type": "object",
    "properties": {
        "timestamp": {"type": "string", "format": "date-time"},
        "level": {"type": "string", "enum": ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"]},
        "thread": {"type": ["string", "null"]},
        "logger": {"type": ["string", "null"]},
        "pid": {"type": ["string", "null"]},
        "message": {"type": ["string", "null"]},
        "message_template": {"type": ["string", "null"]},
        "message_len": {"type": ["integer", "null"]},
        "template_len": {"type": ["integer", "null"]},
        "stacktrace": {"type": ["string", "null"]},
        "exception_type": {"type": ["string", "null"]},
        "has_stacktrace": {"type": ["boolean", "null"]},
        "severity_score": {"type": ["integer", "null"]},
        "log_category": {
            "type": ["string", "null"], 
            "enum": ["SYSTEM", "SECURITY", "NETWORK", "APPLICATION", "DATABASE", "COMPILER", "OTHER", "UNKNOWN", None]
        },
        "error_code": {"type": ["string", "null"]},
        "word_count": {"type": ["integer", "null"]},
        "char_count": {"type": ["integer", "null"]},
        "unique_words": {"type": ["integer", "null"]},
        "punctuation_count": {"type": ["integer", "null"]},
        "number_count": {"type": ["integer", "null"]},
        "template_frequency": {"type": ["integer", "null"]},
        "is_frequent_template": {"type": ["boolean", "null"]},
        "signature_response_code": {"type": ["integer", "null"]},
        "signature_success": {"type": ["boolean", "null"]},
        "signature_msg": {"type": ["string", "null"]},
        "user_dn": {"type": ["string", "null"]},
        "user_name": {"type": ["string", "null"]},
        "user_organization": {"type": ["string", "null"]},
        "user_country": {"type": ["string", "null"]},
        "primary_cert_hash": {"type": ["string", "null"]},
        "cert_chain_length": {"type": ["integer", "null"]},
        "cert_chain_hashes": {"type": ["array", "null"], "items": {"type": "string"}},
        "signing_time": {"type": ["string", "null"]},
        "signing_hour": {"type": ["integer", "null"]},
        "signing_time_period": {
            "type": ["string", "null"],
            "enum": ["night", "morning", "afternoon", "evening", None]
        },
        "sign_data_length": {"type": ["integer", "null"]},
        "sign_data_avg": {"type": ["number", "null"]},
        "sign_data_min": {"type": ["integer", "null"]},
        "sign_data_max": {"type": ["integer", "null"]},
        "sign_data_ascii_range": {"type": ["boolean", "null"]},
        "signer_info_hashes": {"type": ["array", "null"], "items": {"type": "string"}},
        "signer_count": {"type": ["integer", "null"]},
        "signed_data_hash": {"type": ["string", "null"]},
        "signature_data_complexity": {"type": ["integer", "null"]},
        "signature_field_count": {"type": ["integer", "null"]},
        "signature_interval_seconds": {"type": ["number", "null"]},
        "rapid_signature": {"type": ["boolean", "null"]},
        "delayed_signature": {"type": ["boolean", "null"]},
        "user_signature_count": {"type": ["integer", "null"]}
    },
    "required": ["timestamp", "level", "message"]
}

def main():
    if not os.path.exists(INPUT_PATH):
        raise FileNotFoundError(f"입력 파일을 찾을 수 없습니다: {INPUT_PATH}")

    # 출력 디렉토리 생성
    os.makedirs(os.path.dirname(OUT_NDJSON), exist_ok=True)
    os.makedirs(os.path.dirname(OUT_SCHEMA), exist_ok=True)

    print(f"[시작] 로그 파일 정제: {INPUT_PATH}")
    events = transform(INPUT_PATH)

    if not events:
        print("[경고] 처리된 이벤트가 없습니다.")
        return

    # NDJSON 저장
    with open(OUT_NDJSON, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    # Schema 저장
    with open(OUT_SCHEMA, "w", encoding="utf-8") as f:
        json.dump(SCHEMA, f, ensure_ascii=False, indent=2)

    # 통계 정보 출력
    print(f"\n[완료] 총 이벤트: {len(events)}개")
    
    # 레벨별 통계
    level_stats = {}
    category_stats = {}
    for event in events:
        level = event.get("level", "UNKNOWN")
        category = event.get("log_category", "UNKNOWN")
        level_stats[level] = level_stats.get(level, 0) + 1
        category_stats[category] = category_stats.get(category, 0) + 1
    
    print("\n[레벨별 통계]")
    for level, count in sorted(level_stats.items()):
        print(f"  {level}: {count}개")
    
    print("\n[카테고리별 통계]")
    for category, count in sorted(category_stats.items()):
        print(f"  {category}: {count}개")
    
    # 예외가 있는 이벤트 통계
    exception_count = sum(1 for ev in events if ev.get("has_stacktrace"))
    print(f"\n[예외 포함 이벤트]: {exception_count}개")
    
    print(f"\n[출력 파일]")
    print(f"NDJSON: {OUT_NDJSON}")
    print(f"SCHEMA: {OUT_SCHEMA}")

if __name__ == "__main__":
    main()
