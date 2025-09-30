# iam_catalina_log_to_json.py
# -*- coding: utf-8 -*-
"""
MagicIAM Catalina.out → NDJSON 정제 스크립트
- 멀티라인 예외 병합
- 헤더 파싱(여러 패턴 지원: Tomcat, Spring/Logback)
- 필드 표준화 및 템플릿화
- 파생 피처 생성
- NDJSON + JSON Schema 출력
"""

import re
import os
import json
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

# ====== 경로 설정 ======

service = "MagicIAM"

INPUT_PATH = f"/home/kongju/DATA/DREAM/{service}/catalina.out"
# INPUT_PATH = f"/home/kongju/DATA/DREAM/{service}/catalina_partial.out"  # 테스트트

OUT_NDJSON = f"/home/kongju/DREAM/{service}/output/catalina_out_structured.ndjson"
OUT_SCHEMA = f"/home/kongju/DREAM/{service}/output/catalina_out_schema.json"

# ====== 로그 헤더 패턴들 ======
# 1) Tomcat 기본: 18-Mar-2025 10:51:51.333 정보 [main] org.apache.catalina... 메시지
P_TOMCAT = re.compile(
    r"^(?P<ts>\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<level>SEVERE|WARNING|정보|경고|오류|심각|TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"\[(?P<thr>[^\]]+)\]\s+(?P<cls>[\w\.\$]+)\s+(?P<msg>.*)$"
)

# 2) Spring/일반: 2025-04-24 10:09:19.752 ERROR 121679 --- [           main] o.s.boot.SpringApplication : 메시지
P_SPRING = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\.\d{3,6})\s+"
    r"(?P<level>SEVERE|WARNING|TRACE|DEBUG|INFO|WARN|ERROR|FATAL|정보|경고|오류|심각)\s+"
    r"(?P<pid>\d+)?\s*(?:---)?\s*\[\s*(?P<thr>[^\]]+)\]\s+"
    r"(?P<cls>[\w\.\$\-]+)\s*[:\-]\s*(?P<msg>.*)$"
)

# 3) Spring/Logback 단축 형식: DEBUG 25-03-21 03:34:06[HikariPool-1 connection adder] [HikariPool:729] - 메시지
P_LOGBACK = re.compile(
    r"^(?P<level>SEVERE|WARNING|TRACE|DEBUG|INFO|WARN|ERROR|FATAL|정보|경고|오류|심각)\s+"
    r"(?P<ts>\d{2}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\[(?P<thr>[^\]]+)\]\s+"
    r"\[(?P<cls>[^\]]+)\]\s*[:\-]\s*(?P<msg>.*)$"
)

# 4) 심플 포맷: 2025-04-24 10:09:19,752 ERROR [main] com.example.Foo - 메시지
P_SIMPLE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[.,]\d{3,6})\s+"
    r"(?P<level>SEVERE|WARNING|TRACE|DEBUG|INFO|WARN|ERROR|FATAL|정보|경고|오류|심각)\s+"
    r"\[(?P<thr>[^\]]+)\]\s+(?P<cls>[\w\.\$]+)\s*[:\-]\s*(?P<msg>.*)$"
)

# 5) 시간만 있는 포맷: 10:55:15.606 [http-nio-8080-exec-8] DEBUG com.example.Foo -- 메시지
P_TIME_ONLY = re.compile(
    r"^(?P<ts>\d{2}:\d{2}:\d{2}\.\d{3,6})\s+"
    r"\[(?P<thr>[^\]]+)\]\s+"
    r"(?P<level>SEVERE|WARNING|TRACE|DEBUG|INFO|WARN|ERROR|FATAL|정보|경고|오류|심각)\s+"
    r"(?P<cls>[\w\.\$\-]+)\s*(?:--|\-\-|:)\s*(?P<msg>.*)$"
)

HEADER_PATTERNS = [P_TOMCAT, P_SPRING, P_LOGBACK, P_SIMPLE, P_TIME_ONLY]

# ====== 레벨 정규화(KR → EN) ======
LEVEL_MAP = {
    "정보": "INFO", "경고": "WARN", "오류": "ERROR", "심각": "ERROR", "디버그": "DEBUG",
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
    re.compile(r"^Logging system failed to initialize"),
    re.compile(r"^\s*$"),  # 빈 라인
    re.compile(r"^---+.*---+$"),  # 구분선
]

# ====== 디버그/불필요 로그 패턴 ======
DEBUG_PATTERNS = [
    "Command line argument:",
    "At least one JAR was scanned for TLDs",
    "Skipping unneeded JARs during scanning",
    "Enable debug logging for this logger",
    "Pool stats",
    "Fill pool skipped",
    "batch acquisition of 0 triggers",
    "connection closer",
    "connection adder",
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
RE_CONN_HASH = re.compile(r"@[a-fA-F0-9]+")  # 커넥션 해시값

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
    
    # 2자리 연도 형식 (YY-MM-DD HH:MM:SS) -> 20YY-MM-DD HH:MM:SS
    if re.match(r"^\d{2}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$", ts):
        try:
            # 2025년대로 가정
            year_prefix = "20"
            ts = year_prefix + ts
            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            return dt.isoformat(timespec="milliseconds")
        except Exception:
            pass
    
    # 전체 날짜+시간
    fmts = [
        "%d-%b-%Y %H:%M:%S.%f",     # 18-Mar-2025 10:51:51.333
        "%Y-%m-%d %H:%M:%S.%f",     # 2025-04-24 10:09:19.752
        "%Y-%m-%dT%H:%M:%S.%f",     # 2025-04-24T10:09:19.752
        "%Y-%m-%d %H:%M:%S"         # 2025-04-24 10:09:19
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
    s = RE_CONN_HASH.sub("@<HASH>", s)  # 커넥션 해시
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
    """MagicIAM 로그 타입 카테고리화"""
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
    
    # 데이터베이스/커넥션 풀 관련
    if any(x in logger_lower for x in ["sql", "jdbc", "database", "datasource", "hikari", "connection"]):
        return "DATABASE"
    
    # 스케줄러 관련
    if any(x in logger_lower for x in ["quartz", "scheduler", "job"]):
        return "SCHEDULER"
    
    # 컴파일러 관련
    if any(x in logger_lower for x in ["compiler", "jasper", "jdt"]):
        return "COMPILER"
    
    # Spring 관련
    if any(x in logger_lower for x in ["spring", "boot", "context"]):
        return "FRAMEWORK"
    
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

def extract_database_info(message: str, logger: str) -> Dict[str, Any]:
    """데이터베이스 관련 로그에서 정보 추출"""
    info = {}
    
    if "hikari" not in logger.lower():
        return info
    
    # 커넥션 풀 통계
    pool_stats_match = re.search(r"Pool stats \(total=(\d+), active=(\d+), idle=(\d+), waiting=(\d+)\)", message)
    if pool_stats_match:
        info["pool_total"] = int(pool_stats_match.group(1))
        info["pool_active"] = int(pool_stats_match.group(2))
        info["pool_idle"] = int(pool_stats_match.group(3))
        info["pool_waiting"] = int(pool_stats_match.group(4))
        info["pool_utilization"] = info["pool_active"] / info["pool_total"] if info["pool_total"] > 0 else 0
    
    # 커넥션 생성/제거
    if "Added connection" in message:
        info["connection_action"] = "ADDED"
    elif "Closing connection" in message:
        info["connection_action"] = "CLOSED"
        # maxLifetime 체크
        if "maxLifetime" in message:
            info["close_reason"] = "MAX_LIFETIME"
    
    return info

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
    """디버그성 로그인지 판단 (이상탐지 중요 DEBUG는 보존)"""
    
    # DEBUG 레벨에서 중요한 이상탐지 정보 확인
    if level == "DEBUG":
        msg_lower = message.lower()
        logger_lower = logger.lower()
        
        # 중요한 DEBUG 정보들 (이상탐지에 필수)
        important_debug_patterns = [
            # 데이터베이스 연결 문제
            "failed", "cannot", "error", "exception", "timeout", "connection attempt failed",
            "cannot acquire connection", "psqlexception",
            
            # 보안 및 인증 관련
            "account", "auth", "login", "security", "permission", "denied", "jndi",
            "namingexception", "binding", 
            
            # 시스템 컴포넌트 (IAM 핵심)
            "accountmapper", "admnmapper", "apiusermapper", "apirolemapper", "mapper",
            
            # 설정 문제
            "configuration", "hikariconfig", "connectiontimeout", "validationtimeout",
            "initializationfailtimeout",
            
            # 네트워크 및 연결
            "yugabyte", "hikaripool", "poolbase"
        ]
        
        # 중요 패턴이 있으면 보존 (제외하지 않음)
        for pattern in important_debug_patterns:
            if pattern in msg_lower or pattern in logger_lower:
                return False  # 중요하므로 제외하지 않음
        
        # 일반적인 불필요한 DEBUG 패턴들
        trivial_debug_patterns = [
            "creating new restarter", "pool stats", "batch acquisition of 0 triggers",
            "fill pool skipped", "adding type registration"
        ]
        
        for pattern in trivial_debug_patterns:
            if pattern in msg_lower:
                return True  # 불필요하므로 제외
        
        # 기본적으로 DEBUG는 제외하되, 위 중요 패턴은 예외
        return True
    
    # TRACE는 여전히 제외
    if level == "TRACE":
        return True
    
    # INFO 레벨이지만 디버그성 메시지
    debug_keywords = [
        "starting", "stopping", "initialized", "loaded", "deployed",
        "deployment", "version", "build", "home", "argument"
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
    print(f"[시작] 로그 파일 읽기: {path}")
    start_time = time.time()
    
    # 파일 크기 확인
    file_size = os.path.getsize(path)
    print(f"[파일정보] 크기: {file_size / (1024**2):.1f} MB")
    
    raw = read_lines(path)
    total_lines = len(raw)
    print(f"[파일정보] 총 라인 수: {total_lines:,}개")
    print(f"[정제시작] 로그 변환 시작...")
    
    events: List[Dict[str, Any]] = []
    template_counts: Dict[str, int] = {}  # 템플릿 빈도 추적

    current: Optional[Dict[str, Any]] = None
    stack_buf: List[str] = []
    skipped_noise = 0
    skipped_debug = 0
    last_full_timestamp: Optional[str] = None  # 마지막 완전한 타임스탬프
    
    # 진행 상황 추적 변수들
    processed_lines = 0
    last_update_time = start_time
    update_interval = max(1000, total_lines // 100)  # 최소 1000라인 또는 전체의 1%마다 업데이트

    def finalize_event(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """이벤트 최종 처리"""
        if not event:
            return None
            
        # 디버그 로그 필터링
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
        
        # 데이터베이스 관련 정보 추출
        db_info = extract_database_info(message, event.get("logger", ""))
        event.update(db_info)
        
        # 템플릿 빈도 추적
        template_counts[tmpl] = template_counts.get(tmpl, 0) + 1
        event["template_frequency"] = template_counts[tmpl]
        
        return event

    def show_progress(current_line: int, force: bool = False):
        """진행 상황 표시"""
        nonlocal last_update_time
        current_time = time.time()
        
        if not force and current_line % update_interval != 0:
            return
            
        elapsed = current_time - start_time
        if elapsed > 0:
            lines_per_sec = current_line / elapsed
            remaining_lines = total_lines - current_line
            eta_seconds = remaining_lines / lines_per_sec if lines_per_sec > 0 else 0
            eta_minutes = eta_seconds / 60
            
            progress_pct = (current_line / total_lines) * 100
            
            print(f"\r[진행] {current_line:,}/{total_lines:,} ({progress_pct:.1f}%) | "
                  f"속도: {lines_per_sec:.0f} 라인/초 | "
                  f"이벤트: {len(events):,}개 | "
                  f"예상완료: {eta_minutes:.1f}분", end="", flush=True)
        
        last_update_time = current_time

    for i, rawline in enumerate(raw, 1):
        line = rawline.rstrip("\n")
        processed_lines = i
        
        # 진행 상황 표시
        show_progress(processed_lines)
        
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

    # 최종 진행률 표시
    show_progress(total_lines, force=True)
    print()  # 새 줄로 이동
    
    # 템플릿 빈도 업데이트 (2차 패스)
    print("[후처리] 템플릿 빈도 계산 중...")
    for event in events:
        tmpl = event.get("message_template", "")
        event["template_frequency"] = template_counts.get(tmpl, 1)
        event["is_frequent_template"] = template_counts.get(tmpl, 1) > 1

    # 처리 완료 통계
    end_time = time.time()
    total_time = end_time - start_time
    
    print(f"\n[완료] 로그 정제 완료!")
    print(f"[통계] 전체 처리 시간: {total_time:.1f}초")
    print(f"[통계] 평균 처리 속도: {total_lines / total_time:.0f} 라인/초")
    print(f"[정제] 처리된 라인: {total_lines:,}개")
    print(f"[정제] 생성된 이벤트: {len(events):,}개")
    print(f"[정제] 노이즈 라인 제거: {skipped_noise:,}개")
    print(f"[정제] 디버그 로그 제거: {skipped_debug:,}개")
    print(f"[정제] 유니크 템플릿: {len(template_counts):,}개")
    print(f"[효율] 이벤트 추출률: {len(events) / total_lines * 100:.1f}%")

    return events

# ====== JSON Schema(draft-07) ======
SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "MagicIAM Catalina Out Structured Log",
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
            "enum": ["SYSTEM", "SECURITY", "NETWORK", "APPLICATION", "DATABASE", "SCHEDULER", "COMPILER", "FRAMEWORK", "OTHER", "UNKNOWN", None]
        },
        "error_code": {"type": ["string", "null"]},
        "word_count": {"type": ["integer", "null"]},
        "char_count": {"type": ["integer", "null"]},
        "unique_words": {"type": ["integer", "null"]},
        "punctuation_count": {"type": ["integer", "null"]},
        "number_count": {"type": ["integer", "null"]},
        "template_frequency": {"type": ["integer", "null"]},
        "is_frequent_template": {"type": ["boolean", "null"]},
        "pool_total": {"type": ["integer", "null"]},
        "pool_active": {"type": ["integer", "null"]},
        "pool_idle": {"type": ["integer", "null"]},
        "pool_waiting": {"type": ["integer", "null"]},
        "pool_utilization": {"type": ["number", "null"]},
        "connection_action": {"type": ["string", "null"], "enum": ["ADDED", "CLOSED", None]},
        "close_reason": {"type": ["string", "null"]}
    },
    "required": ["timestamp", "level", "message"]
}

def main():
    if not os.path.exists(INPUT_PATH):
        raise FileNotFoundError(f"입력 파일을 찾을 수 없습니다: {INPUT_PATH}")

    # 출력 디렉토리 생성
    os.makedirs(os.path.dirname(OUT_NDJSON), exist_ok=True)
    os.makedirs(os.path.dirname(OUT_SCHEMA), exist_ok=True)

    print(f"[시작] {service} 로그 파일 정제: {INPUT_PATH}")
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
    
    # 데이터베이스 관련 통계
    db_events = [e for e in events if e.get("log_category") == "DATABASE"]
    if db_events:
        print(f"[데이터베이스 관련 이벤트]: {len(db_events)}개")
    
    print(f"\n[출력 파일]")
    print(f"NDJSON: {OUT_NDJSON}")
    print(f"SCHEMA: {OUT_SCHEMA}")

if __name__ == "__main__":
    main()