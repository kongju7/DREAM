# iso_alpha2_to_korean.py
# -*- coding: utf-8 -*-

"""
ISO 3166-1 alpha-2 -> 한국어 국가명 매핑 유틸

의존성:
  - babel (로캘 지역명)
  - pycountry (공식 ISO 국가 코드 목록)

설명:
  - Babel Locale('ko').territories 를 통해 거의 모든 ISO2 코드를 한국어로 매핑
  - 실무에서 자주 필요한 별칭/비표준 코드 보강:
      * UK -> GB (영국 표준 코드는 GB)
      * EU (유럽 연합, ISO 정식 국가는 아니나 실무에서 빈번)
      * XK (코소보, ISO 미정식 코드로 사용 사례 다수)
  - 출력 포맷: 개별 조회 함수 + 전체 딕셔너리 생성/내보내기
"""

from __future__ import annotations
from typing import Dict, Iterable, Optional
from babel import Locale
import pycountry

# 1) 한국어 로캘의 영토(국가/지역) 명칭 테이블
_LOCALE_KO = Locale('ko')
_TERRITORIES_KO: Dict[str, str] = _LOCALE_KO.territories

# 2) 실무 보강(비표준/별칭/표기 선호) 매핑
#    - 필요 시 여기서 표기를 바꾸면 전체 결과가 반영됩니다.
OVERRIDES: Dict[str, str] = {
    "UK": "영국",      # ISO 공식 코드는 GB, 하지만 UK 코드가 자주 들어옴 → 영국
    "EU": "유럽 연합",  # European Union (ISO 국가코드 아님)
    "XK": "코소보",     # Kosovo (비공식 코드)
    "ZZ": "미할당",     # 미할당 또는 사용자 할당 코드
    "XX": "알 수 없음", # 알 수 없는 국가
    # 아래는 표기 선호(있다면 활성화)
    # "KR": "대한민국",
    # "KP": "조선민주주의인민공화국",
    # "TW": "대만",
    # "VN": "베트남",
}

# 3) 알파벳 대소문자·공백 등 정규화
def _normalize_code(code: str) -> str:
    return (code or "").strip().upper()

def alpha2_to_korean(code: str) -> Optional[str]:
    """
    단일 ISO 3166-1 alpha-2 코드 -> 한국어 국가/지역명 (없으면 None)
    - 우선 OVERRIDES 적용
    - 없으면 Babel ko 로캘 데이터를 조회
    - 그래도 없으면 None
    """
    c = _normalize_code(code)
    if not c:
        return None
    if c in OVERRIDES:
        return OVERRIDES[c]
    # Babel 로캘 테이블 조회 (예: 'US' -> '미국', 'KR' -> '대한민국', 'JP' -> '일본')
    name = _TERRITORIES_KO.get(c)
    if name:
        return name
    # 비표준 코드이거나 누락 시, GB/UK 같은 매핑 보강
    if c == "UK":
        return _TERRITORIES_KO.get("GB")
    return None

def build_full_mapping(include_non_iso_common: bool = True) -> Dict[str, str]:
    """
    전체 매핑 딕셔너리 생성:
      - pycountry.countries 로부터 공식 ISO alpha-2 수집
      - Babel ko 로캘에 존재하는 경우 한글명 채우기
      - OVERRIDES 반영
      - include_non_iso_common=True 면 EU/XK/UK 등 자주 쓰는 비표준 코드 포함
    """
    mapping: Dict[str, str] = {}

    # 공식 ISO 3166-1 alpha-2 목록
    for c in pycountry.countries:
        alpha2 = getattr(c, "alpha_2", None)
        if not alpha2:
            continue
        name_ko = alpha2_to_korean(alpha2)
        # Babel이 없더라도 최소 영문명을 fallback으로 넣고 싶다면 아래처럼:
        if not name_ko:
            # name_ko = getattr(c, "name", None)  # (원문 영문명; 한국어가 꼭 필요하다면 None 유지 권장)
            name_ko = None
        if name_ko:
            mapping[alpha2.upper()] = name_ko

    # 자주 쓰는 비표준 코드 추가
    if include_non_iso_common:
        for k, v in OVERRIDES.items():
            mapping[k] = v
        # UK 별칭(GB) 보강
        if "GB" in mapping and "UK" not in mapping:
            mapping["UK"] = mapping["GB"]
        # EU/XK가 overrides에 없다면 명시적으로 추가
        mapping.setdefault("EU", "유럽 연합")
        mapping.setdefault("XK", "코소보")

    return dict(sorted(mapping.items()))

# ------------------------------
# 예시 사용
# ------------------------------
if __name__ == "__main__":
    samples = ["KR", "US", "JP", "CN", "DE", "FR", "GB", "UK", "EU", "XK", "TW", "HK", "MO"]
    print("[단일 조회 예시]")
    for s in samples:
        print(f"{s} -> {alpha2_to_korean(s)}")

    print("\n[전체 매핑 개수 & 상위 20개 미리보기]")
    m = build_full_mapping()
    print(f"총 개수: {len(m)}")
    for i, (k, v) in enumerate(m.items()):
        if i >= 20: break
        print(f"{k}: {v}")

    # 파일로 내보내기 (원하면 주석 해제)
    # import json, csv
    # with open("iso2_ko.json", "w", encoding="utf-8") as f:
    #     json.dump(m, f, ensure_ascii=False, indent=2)
    # with open("iso2_ko.csv", "w", encoding="utf-8", newline="") as f:
    #     w = csv.writer(f)
    #     w.writerow(["alpha2", "name_ko"])
    #     for k, v in m.items():
    #         w.writerow([k, v])
