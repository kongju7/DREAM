#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MagicLine Web 로그 파일을 JSON 형태로 변환하는 스크립트
"""

import json
import re
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Union

# 한글 → 표준 필드 매핑
KOR_KEY_MAP = {
    "추출한 서명 원문": "signature_plaintext",
    "서명 검증 성공": "signature_verify_success",   # bool
    "인증서 검증 성공": "cert_verify_success",       # bool
    "사용자 DN": "user_dn",
    "발급자 DN": "issuer_dn",
    "인증서 SN": "cert_sn",
    "인증서 정책": "cert_policy",
    "본인확인 식별값": "pid_hash",
}

def parse_timestamp(timestamp_str: str) -> Optional[str]:
    """타임스탬프 문자열을 파싱"""
    try:
        # [2025-09-09T15:36:25.377491] 형태에서 대괄호 제거
        clean_timestamp = timestamp_str.strip('[]')
        return clean_timestamp
    except:
        return None

def parse_log_header(line: str) -> Optional[Dict[str, str]]:
    """로그 헤더 라인을 파싱 (타임스탬프, 방향, 액션)"""
    # 패턴: [timestamp] [direction] action
    pattern = r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)$'
    match = re.match(pattern, line.strip())
    
    if match:
        timestamp, direction, action = match.groups()
        return {
            'timestamp': parse_timestamp(f'[{timestamp}]'),
            'direction': direction,
            'action': action
        }
    return None

def parse_set_cookie(cookie_str: str) -> Dict[str, Any]:
    """Set-Cookie 헤더를 파싱해서 구조화된 객체로 변환"""
    if not cookie_str:
        return {"raw": cookie_str}
    
    try:
        parts = cookie_str.split(';')
        if not parts:
            return {"raw": cookie_str}
        
        # 첫 번째 부분: name=value
        name_value = parts[0].strip()
        if '=' in name_value:
            name, value = name_value.split('=', 1)
            result = {
                "name": name.strip(),
                "value": value.strip(),
                "attributes": {},
                "raw": cookie_str
            }
        else:
            return {"raw": cookie_str}
        
        # 나머지 부분: 속성들
        for part in parts[1:]:
            part = part.strip()
            if '=' in part:
                attr_name, attr_value = part.split('=', 1)
                result["attributes"][attr_name.strip()] = attr_value.strip()
            else:
                # HttpOnly, Secure 같은 플래그
                result["attributes"][part] = True
        
        return result
    except:
        return {"raw": cookie_str}

def parse_content_type(content_type_str: str) -> Dict[str, Any]:
    """Content-Type 헤더를 파싱"""
    if not content_type_str:
        return {"raw": content_type_str}
    
    try:
        parts = content_type_str.split(';')
        result = {
            "type": parts[0].strip(),
            "raw": content_type_str
        }
        
        # charset, boundary 등 추가 속성 파싱
        for part in parts[1:]:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                result[key.strip()] = value.strip()
        
        return result
    except:
        return {"raw": content_type_str}

def parse_keep_alive(keep_alive_str: str) -> Dict[str, Any]:
    """Keep-Alive 헤더를 파싱"""
    if not keep_alive_str:
        return {"raw": keep_alive_str}
    
    try:
        result = {"raw": keep_alive_str}
        
        # timeout=20, max=100 같은 형태 파싱
        parts = keep_alive_str.split(',')
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                result[key.strip()] = value.strip()
        
        return result
    except:
        return {"raw": keep_alive_str}

def parse_headers(headers_str: str) -> Dict[str, Any]:
    """headers 문자열을 파싱해서 딕셔너리로 변환"""
    if not headers_str:
        return {}
    
    try:
        # Python dict 형태를 JSON으로 변환 시도
        if headers_str.startswith('{') and headers_str.endswith('}'):
            # 작은따옴표를 큰따옴표로 변경
            json_text = headers_str.replace("'", '"')
            headers_dict = json.loads(json_text)
            
            # 특별한 헤더들 파싱
            if 'Set-Cookie' in headers_dict:
                headers_dict['Set-Cookie'] = parse_set_cookie(headers_dict['Set-Cookie'])
            
            if 'Content-Type' in headers_dict:
                headers_dict['Content-Type'] = parse_content_type(headers_dict['Content-Type'])
            
            if 'Keep-Alive' in headers_dict:
                headers_dict['Keep-Alive'] = parse_keep_alive(headers_dict['Keep-Alive'])
            
            return headers_dict
    except:
        pass
    
    # 파싱 실패시 원본 문자열 반환을 위한 딕셔너리
    return {"raw": headers_str}

def parse_dn(dn_string: str) -> Dict[str, Union[str, List[str]]]:
    """DN(Distinguished Name) 문자열을 파싱해서 구조화된 객체로 변환"""
    if not dn_string:
        return {}
    
    result = {
        "raw": dn_string,
        "components": {}
    }
    
    # DN 형식: cn=값,ou=값,ou=값2,o=값,c=값
    parts = dn_string.split(',')
    
    for part in parts:
        part = part.strip()
        if '=' in part:
            key, value = part.split('=', 1)
            key = key.strip().lower()
            value = value.strip()
            
            # 같은 키가 여러 개 있는 경우 (예: ou=KFTC,ou=personal4IB)
            if key in result["components"]:
                if isinstance(result["components"][key], list):
                    result["components"][key].append(value)
                else:
                    result["components"][key] = [result["components"][key], value]
            else:
                result["components"][key] = value
    
    # ou는 보통 여러 개가 있으므로 리스트로 정규화
    if 'ou' in result["components"] and not isinstance(result["components"]['ou'], list):
        result["components"]['ou'] = [result["components"]['ou']]
    
    return result

def parse_korean_fields(text: str) -> Dict[str, Any]:
    """한글 필드를 포함한 텍스트를 파싱"""
    result = {}
    
    # HTML 태그 제거
    text = re.sub(r'<br\s*/?>', '\n', text)
    text = re.sub(r'<[^>]+>', '', text)
    
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # "- 키" 형태 처리
        if line.startswith('- '):
            key_part = line[2:].strip()
            
            # "- 키 [값]" 패턴
            bracket_match = re.match(r'^(.+?)\s*\[(.+)\]$', key_part)
            if bracket_match:
                key, value = bracket_match.groups()
                key = key.strip()
                value = value.strip()
                
                # 한글 키를 영어 키로 변환
                if key in KOR_KEY_MAP:
                    english_key = KOR_KEY_MAP[key]
                    # 불린 값 처리
                    if english_key in ['signature_verify_success', 'cert_verify_success']:
                        result[english_key] = True
                    # DN 값 처리
                    elif english_key in ['user_dn', 'issuer_dn']:
                        result[english_key] = parse_dn(value)
                    else:
                        result[english_key] = value
                else:
                    # 알려지지 않은 키는 그대로 저장
                    result[key] = value
            
            # "- 키" 형태 (다음 줄에 [값]이 있거나 불린 값)
            else:
                key = key_part.strip()
                
                # 다음 줄이 [값] 형태인지 확인
                if i + 1 < len(lines) and lines[i + 1].startswith('[') and lines[i + 1].endswith(']'):
                    value = lines[i + 1][1:-1]  # 대괄호 제거
                    i += 1  # 다음 줄도 처리했으므로 인덱스 증가
                    
                    # 한글 키를 영어 키로 변환
                    if key in KOR_KEY_MAP:
                        english_key = KOR_KEY_MAP[key]
                        # DN 값 처리
                        if english_key in ['user_dn', 'issuer_dn']:
                            result[english_key] = parse_dn(value)
                        else:
                            result[english_key] = value
                    else:
                        result[key] = value
                
                # 값이 없는 경우 (불린 값)
                else:
                    if key in KOR_KEY_MAP:
                        english_key = KOR_KEY_MAP[key]
                        if english_key in ['signature_verify_success', 'cert_verify_success']:
                            result[english_key] = True
                        else:
                            result[english_key] = True  # 기본값
                    else:
                        result[key] = True
        
        i += 1
    
    return result

def parse_metadata_line(line: str) -> Optional[tuple]:
    """메타데이터 라인을 파싱 (- key: value 형태)"""
    if line.startswith('- '):
        parts = line[2:].split(': ', 1)
        if len(parts) == 2:
            key, value = parts
            key = key.strip()
            value = value.strip()
            
            # headers 필드는 특별히 파싱
            if key == 'headers':
                return key, parse_headers(value)
            else:
                return key, value
    return None

def parse_anomaly_input(input_str: str) -> Dict[str, Any]:
    """이상탐지 input JSON 문자열을 파싱하고 구조화"""
    try:
        # JSON 문자열을 파싱
        input_data = json.loads(input_str)
        
        # user_dn이 있으면 구조화
        if 'user_dn' in input_data and input_data['user_dn']:
            # Unicode 이스케이프 디코딩
            user_dn_str = input_data['user_dn']
            if '\\u' in user_dn_str:
                try:
                    user_dn_str = user_dn_str.encode().decode('unicode_escape')
                except:
                    pass
            
            # DN 구조화
            input_data['user_dn'] = parse_dn(user_dn_str)
        
        return input_data
    except:
        return {"raw": input_str}

def parse_payload_data(payload_lines: List[str], action: str = None) -> Union[Dict, List, str]:
    """payload 데이터를 파싱"""
    payload_text = '\n'.join(payload_lines).strip()
    
    if not payload_text:
        return ""
    
    # JSON/dict 형태 데이터 시도
    try:
        # Python dict 형태를 JSON으로 변환 시도
        if payload_text.startswith('{') and payload_text.endswith('}'):
            # 작은따옴표를 큰따옴표로 변경
            json_text = payload_text.replace("'", '"')
            parsed_data = json.loads(json_text)
            
            # 이상탐지 관련 액션의 경우 input 필드를 추가 파싱
            if (action in ['opa_anomaly_check', 'direct_anomaly_check'] and 
                'input' in parsed_data and isinstance(parsed_data['input'], str)):
                parsed_data['input'] = parse_anomaly_input(parsed_data['input'])
            
            return parsed_data
    except Exception as e:
        pass
    
    # key=value 형태 데이터 처리 (한글 키가 없는 경우만)
    if '=' in payload_text and not any(kor_key in payload_text for kor_key in KOR_KEY_MAP.keys()):
        result = {}
        for line in payload_lines:
            line = line.strip()
            if '=' in line:
                parts = line.split('=', 1)
                if len(parts) == 2:
                    key, value = parts
                    result[key.strip()] = value.strip()
        
        # 이상탐지 관련 액션의 경우 input 필드를 추가 파싱
        if (action in ['opa_anomaly_check', 'direct_anomaly_check'] and 
            'input' in result and isinstance(result['input'], str)):
            result['input'] = parse_anomaly_input(result['input'])
        
        # user_dn, issuer_dn 필드가 있으면 구조화
        if 'user_dn' in result and isinstance(result['user_dn'], str):
            result['user_dn'] = parse_dn(result['user_dn'])
        
        if 'issuer_dn' in result and isinstance(result['issuer_dn'], str):
            result['issuer_dn'] = parse_dn(result['issuer_dn'])
        
        if result:
            return result
    
    # 한글 필드가 포함된 경우 또는 "- " 패턴이 있는 경우
    if any(kor_key in payload_text for kor_key in KOR_KEY_MAP.keys()) or '- ' in payload_text:
        return parse_korean_fields(payload_text)
    
    # 일반 텍스트
    return payload_text

def parse_log_file(file_path: str) -> List[Dict[str, Any]]:
    """로그 파일 전체를 파싱"""
    entries = []
    current_entry = None
    current_payload_lines = []
    in_payload = False
    
    with open(file_path, 'r', encoding='utf-8') as file:
        for line_num, line in enumerate(file, 1):
            line = line.rstrip('\n\r')
            
            # 새로운 로그 엔트리 시작
            if line.startswith('[') and '] [' in line:
                # 이전 엔트리 완료
                if current_entry is not None:
                    if in_payload:
                        action = current_entry.get('action', '')
                        current_entry['payload'] = parse_payload_data(current_payload_lines, action)
                    entries.append(current_entry)
                
                # 새 엔트리 시작
                header = parse_log_header(line)
                if header:
                    current_entry = {
                        'line_number': line_num,
                        **header,
                        'metadata': {},
                        'payload': None
                    }
                    current_payload_lines = []
                    in_payload = False
                else:
                    current_entry = None
            
            # payload 시작
            elif line.strip() == '-- payload begin --':
                in_payload = True
                current_payload_lines = []
            
            # payload 종료
            elif line.strip() == '-- payload end --':
                if current_entry is not None:
                    action = current_entry.get('action', '')
                    current_entry['payload'] = parse_payload_data(current_payload_lines, action)
                in_payload = False
                current_payload_lines = []
            
            # payload 내용
            elif in_payload:
                current_payload_lines.append(line)
            
            # 메타데이터 라인
            elif current_entry is not None and line.startswith('- '):
                metadata = parse_metadata_line(line)
                if metadata:
                    key, value = metadata
                    current_entry['metadata'][key] = value
        
        # 마지막 엔트리 처리
        if current_entry is not None:
            if in_payload:
                action = current_entry.get('action', '')
                current_entry['payload'] = parse_payload_data(current_payload_lines, action)
            entries.append(current_entry)
    
    return entries

def main():
    """메인 함수"""
    # 파일 경로 설정
    log_file_path = "/home/kongju/workspace/ANOMALY_DATA/dream/poc/magicline_web/transcripts-2025-09-16.log"
    output_dir = "/home/kongju/DEV/poc/output"
    
    # 출력 디렉토리 생성
    os.makedirs(output_dir, exist_ok=True)
    
    # 출력 파일 경로
    output_file = os.path.join(output_dir, "transcripts-2025-09-16.json")
    
    print(f"로그 파일 파싱 시작: {log_file_path}")
    
    try:
        # 로그 파일 파싱
        entries = parse_log_file(log_file_path)
        
        print(f"총 {len(entries)}개의 로그 엔트리를 파싱했습니다.")
        
        # JSON 파일로 저장
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(entries, f, ensure_ascii=False, indent=2)
        
        print(f"JSON 파일이 생성되었습니다: {output_file}")
        
        # 통계 정보 출력
        actions = {}
        directions = {'IN': 0, 'OUT': 0}
        
        for entry in entries:
            action = entry.get('action', 'unknown')
            direction = entry.get('direction', 'unknown')
            
            actions[action] = actions.get(action, 0) + 1
            if direction in directions:
                directions[direction] += 1
        
        print("\n=== 파싱 통계 ===")
        print(f"총 엔트리 수: {len(entries)}")
        print(f"IN 방향: {directions['IN']}")
        print(f"OUT 방향: {directions['OUT']}")
        print("\n액션별 통계:")
        for action, count in sorted(actions.items()):
            print(f"  {action}: {count}")
    
    except Exception as e:
        print(f"오류 발생: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
