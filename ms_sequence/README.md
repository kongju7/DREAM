# MAGIC Series Log Anomaly Detection Pipeline

Drain3 템플릿 마이닝과 PYOD 모델을 결합한 소스별 구분 로그 이상탐지 파이프라인입니다.

## 주요 특징

- **소스별 구분 분석**: IDP, SP1, SP2 로그를 독립적으로 분석하여 더 정확한 템플릿 생성
- **OIDC 전처리**: IDP 로그의 OIDC 토큰/코드를 정규화하여 템플릿 품질 향상
- **모듈화된 아키텍처**: 기능별로 명확히 분리된 코드 구조
- **지능형 캐싱**: Drain3 결과를 소스별/파라미터별로 캐시하여 재처리 시간 단축
- **다양한 PYOD 모델**: IForest, COPOD, ECOD, LOF, AutoEncoder 지원
- **자동 파라미터 관리**: Drain3 설정 변경 시 자동으로 새로운 캐시 생성
- **CLI 기반 설정**: 명령행에서 Drain3 및 PYOD 파라미터 동적 조정

## 프로젝트 구조

```
sequence/
├── main.py                    # 메인 실행 파일 (소스별 구분 분석)
├── cli.py                     # CLI 인터페이스
├── config/                    # 설정 관리
│   ├── __init__.py
│   ├── drain_config.py       # 소스별 Drain3 설정 및 OIDC 마스킹
│   └── log_paths.py          # 로그 파일 경로 및 소스 매핑
├── core/                      # 핵심 비즈니스 로직
│   ├── __init__.py
│   ├── template_miner.py     # 소스별 Drain3 템플릿 마이닝
│   ├── vectorizer.py         # 소스별 세션 벡터화
│   └── anomaly_detector.py   # 이상탐지
├── models/                    # 모델 팩토리
│   ├── __init__.py
│   └── pyod_factory.py       # PYOD 모델 생성
├── utils/                     # 유틸리티 함수
│   ├── __init__.py
│   ├── session_extractor.py  # 세션 ID/타임스탬프 추출 + OIDC 전처리
│   └── template_extractor.py # 템플릿 추출
├── storage/                   # 저장소 관리
│   ├── __init__.py
│   ├── cache_manager.py      # 소스별 캐시 관리
│   └── output_manager.py     # 소스별 결과 저장
├── DRAIN_CACHE/              # 소스별 Drain3 캐시 (자동 생성)
├── OUTPUTS/                  # 소스별 결과 파일 (자동 생성)
└── requirements.txt
```

## 로그 소스 구분

### 자동 소스 분류
시스템은 파일명을 기반으로 자동으로 로그 소스를 분류합니다:

- **IDP**: `idp__ssoserver.log`, `idp_log__*.log` → OIDC 전처리 적용
- **SP1**: `sp1__*.log`, `sp_log__ssoagent_*.log` → 표준 마스킹
- **SP2**: `sp2__*.log` → 표준 마스킹

### 소스별 특화 기능

#### IDP 로그 (OIDC 전처리)
- JWT 토큰 정규화: `eyJ0eXAi...` → `<:JWT:>`
- OAuth2 파라미터 정규화: `code=abc123` → `code=<:CODE:>`
- OIDC 경로 정규화: `/oidc/auth` → `<:OIDC_PATH:>`
- 클라이언트 정보 정규화: `client_id=myapp` → `client_id=<:CLIENT_ID:>`

#### SP1/SP2 로그
- 표준 SAML 마스킹 적용
- 세션 ID, 타임스탬프, URL 등 정규화

## 설치 및 설정

### 1. 환경 설정
```bash
conda create -n ad_sequence python=3.9
conda activate ad_sequence
pip install -r requirements.txt
```

### 2. 로그 파일 경로 설정
`config/log_paths.py`에서 분석할 로그 파일 경로를 설정하세요:

```python
LOG_PATHS = [
    "/path/to/idp__ssoserver.log",      # IDP 로그 (OIDC 전처리)
    "/path/to/sp1__ssoagent.log",       # SP1 로그
    "/path/to/sp2__ssoagent.log",       # SP2 로그
    # ... 추가 로그 파일들
]

# 커스텀 소스 매핑도 가능
SOURCE_BY_FILE = {
    "custom_idp.log": "idp",
    "custom_sp.log": "sp1",
    # ...
}
```

## 기본 사용법

### 1. 소스별 구분 분석 (기본)
```bash
python main.py --model IForest --contamination 0.02
```

### 2. Drain3 세부 설정과 함께 실행
```bash
python main.py --model IForest \
  --drain-similarity 0.6 \
  --drain-depth 8 \
  --drain-max-clusters 8192 \
  --contamination 0.02
```

### 3. 다른 이상탐지 모델로 실행 (캐시 재사용)
```bash
python main.py --model COPOD
python main.py --model LOF --n_neighbors 30
```

### 4. 강제 재처리 (캐시 무시)
```bash
python main.py --model ECOD --force-reprocess
```

## 지원하는 PYOD 모델

### IForest (Isolation Forest)
```bash
python main.py --model IForest --contamination 0.08 --n_estimators 400
```
- **특징**: 트리 기반, 빠른 처리 속도
- **파라미터**: `--n_estimators` (트리 개수)
- **소스별 적용**: 각 소스마다 독립적으로 모델 학습

### COPOD (Copula-based Outlier Detection)
```bash
python main.py --model COPOD --contamination 0.05
```
- **특징**: 파라미터가 거의 없음, 안정적 성능
- **파라미터**: contamination만 설정
- **권장**: SP 로그처럼 패턴이 단순한 경우

### ECOD (Empirical Cumulative Distribution)
```bash
python main.py --model ECOD --contamination 0.05
```
- **특징**: 파라미터 프리, 경험적 분포 기반
- **파라미터**: contamination만 설정
- **권장**: 모든 소스에 안정적으로 적용 가능

### LOF (Local Outlier Factor)
```bash
python main.py --model LOF --contamination 0.05 --n_neighbors 25
```
- **특징**: 근접도 기반, 지역적 이상치 탐지
- **파라미터**: `--n_neighbors` (이웃 개수)
- **권장**: IDP 로그처럼 복잡한 패턴의 경우

### AutoEncoder (신경망 기반)
```bash
python main.py --model AutoEncoder --contamination 0.05 --epochs 20 --batch_size 128
```
- **특징**: 딥러닝 기반, 복잡한 패턴 학습 가능
- **파라미터**: `--epochs`, `--batch_size`
- **요구사항**: PyTorch 필요
- **권장**: IDP 로그의 복잡한 OIDC 패턴 분석

## Drain3 설정 파라미터

### CLI에서 동적 설정 (권장)
```bash
python main.py --model IForest \
  --drain-similarity 0.6 \
  --drain-depth 8 \
  --drain-max-children 200 \
  --drain-max-clusters 8192
```

### 소스별 최적 설정 예시

#### IDP 로그 (복잡한 OIDC 패턴)
```bash
python main.py --model LOF \
  --drain-similarity 0.3 \
  --drain-max-clusters 10000 \
  --contamination 0.03
```

#### SP 로그 (단순한 SAML 패턴)
```bash
python main.py --model COPOD \
  --drain-similarity 0.7 \
  --drain-max-clusters 2000 \
  --contamination 0.05
```

### Drain3 파라미터별 의미

| 파라미터 | CLI 옵션 | 범위 | 설명 | 소스별 권장값 |
|---------|----------|------|------|-------------|
| **similarity_threshold** | `--drain-similarity` | 0.1~0.9 | 낮을수록 세밀한 템플릿 | IDP: 0.3-0.4, SP: 0.6-0.7 |
| **depth** | `--drain-depth` | 4~10 | 파싱 트리 깊이 | IDP: 8-10, SP: 6-8 |
| **max_children** | `--drain-max-children` | 50~500 | 각 노드의 최대 자식 수 | 모든 소스: 100-200 |
| **max_clusters** | `--drain-max-clusters` | 1000~10000 | 최대 템플릿 개수 | IDP: 8000-10000, SP: 2000-4000 |

## 출력 결과

### 1. 소스별 캐시 파일 (자동 생성)
```
DRAIN_CACHE/grouped_drain_{hash}/
├── grouped_drain_parsed_events.csv     # 통합 이벤트 (소스 정보 포함)
├── session_vectors_idp.csv             # IDP 세션 벡터
├── session_vectors_sp1.csv             # SP1 세션 벡터
├── session_vectors_sp2.csv             # SP2 세션 벡터
└── grouped_drain_config.json           # 설정 정보
```

### 2. 소스별 최종 결과
```
OUTPUTS/grouped_drain_{hash}/
├── idp_iforest/                         # IDP 결과
│   ├── idp_drain_parsed_events.csv     # IDP 파싱 이벤트
│   ├── idp_drain_session_vectors.csv   # IDP 세션 벡터
│   ├── idp_pyod_anomaly_scores.csv     # IDP 이상탐지 결과
│   └── idp_summary.json                # IDP 요약
├── sp1_iforest/                         # SP1 결과
│   ├── sp1_drain_parsed_events.csv
│   ├── sp1_drain_session_vectors.csv
│   ├── sp1_pyod_anomaly_scores.csv
│   └── sp1_summary.json
└── sp2_iforest/                         # SP2 결과
    ├── sp2_drain_parsed_events.csv
    ├── sp2_drain_session_vectors.csv
    ├── sp2_pyod_anomaly_scores.csv
    └── sp2_summary.json
```

### 3. 콘솔 출력
실행 후 소스별 Drain3 설정과 상위 이상 세션이 출력됩니다:
```
[INFO] Grouped Drain config hash: a1b2c3d4
[INFO] Drain settings: similarity=0.6, depth=8, max_clusters=8192
[INFO] Model: IForest, contamination: 0.08

[INFO] IDP - Top 5 anomalous sessions:
   session_id  pyod_label  pyod_score
0  SP-ABC123           1      0.8542
1  SP-DEF456           1      0.7891
...

[INFO] SP1 - Top 5 anomalous sessions:
   session_id  pyod_label  pyod_score
0  SP-GHI789           1      0.7234
1  SP-JKL012           1      0.6789
...

[INFO] SP2 - Top 5 anomalous sessions:
   session_id  pyod_label  pyod_score
0  SP-MNO345           1      0.6543
1  SP-PQR678           1      0.6012
...
```

## OIDC 전처리 상세

### IDP 로그 전용 정규화
`idp__ssoserver.log` 파일에만 적용되는 특수 전처리:

#### 1. JWT 토큰 정규화
```
원본: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL...
변환: <:JWT:>
```

#### 2. OAuth2 파라미터 정규화
```
원본: code=SplxlOBeZQQYbYS6WxSbIA&state=xyz
변환: code=<:CODE:>&state=xyz
```

#### 3. OIDC 경로 정규화
```
원본: /oidc/authorize?response_type=code&client_id=...
변환: <:OIDC_PATH:>?response_type=<:RESP_TYPE:>&client_id=<:CLIENT_ID:>...
```

#### 4. 기타 토큰/식별자 정규화
- `access_token` → `<:AT:>`
- `refresh_token` → `<:RT:>`
- `client_id` → `<:CLIENT_ID:>`
- `redirect_uri` → `<:URL:>`
- `scope` → `<:SCOPE:>`
- PKCE 관련 → `<:PKCE:>`

## 소스별 분석 전략

### IDP 분석 (복잡도 높음)
```bash
# 세밀한 분석으로 OIDC 패턴의 미세한 차이 감지
python main.py --model LOF \
  --drain-similarity 0.3 \
  --drain-max-clusters 8000 \
  --n_neighbors 15 \
  --contamination 0.03
```

### SP1/SP2 분석 (복잡도 중간)
```bash
# 안정적인 분석으로 SAML 패턴의 명확한 이상 감지
python main.py --model IForest \
  --drain-similarity 0.6 \
  --drain-max-clusters 4000 \
  --n_estimators 500 \
  --contamination 0.05
```

### 통합 비교 분석
```bash
# 모든 소스에 대해 동일한 설정으로 비교 분석
python main.py --model ECOD \
  --drain-similarity 0.5 \
  --contamination 0.05
```

## 고급 사용법

### 1. 커스텀 소스 매핑
`config/log_paths.py`에서 파일별 소스 매핑을 수정:

```python
SOURCE_BY_FILE = {
    "custom_idp_server.log": "idp",
    "app1_sso.log": "sp1", 
    "app2_sso.log": "sp2",
    "legacy_auth.log": "idp",  # 레거시 로그도 IDP로 분류
}
```

### 2. 새로운 OIDC 패턴 추가
`config/drain_config.py`의 `IDP_ADDITIONAL_PATTERNS`에 패턴 추가:

```python
IDP_ADDITIONAL_PATTERNS = [
    # 기존 패턴들...
    {"regex_pattern": r"session_token=[A-Za-z0-9\-_]{20,}", "mask_with": r"session_token=<:SESSION:>"},
    {"regex_pattern": r"nonce=[A-Za-z0-9]{16,}", "mask_with": r"nonce=<:NONCE:>"},
]
```

### 3. 소스별 다른 모델 적용
각 소스에 최적화된 모델로 순차 실행:

```bash
# IDP: 복잡한 패턴에 LOF 적용
python main.py --model LOF --drain-similarity 0.3 --contamination 0.03

# SP: 단순한 패턴에 COPOD 적용  
python main.py --model COPOD --drain-similarity 0.7 --contamination 0.05
```

## 성능 최적화

### 소스별 캐시 시스템
- 소스별 Drain3 파라미터가 동일하면 이전 결과를 재사용
- 로그 파일 변경 시 해당 소스만 자동으로 재처리
- 소스별로 독립적인 결과 저장

### 메모리 관리
- 소스별 독립 처리로 메모리 사용량 분산
- 대용량 로그 파일을 위한 스트리밍 처리
- 소스별 진행률 표시

### OIDC 전처리 최적화
- 컴파일된 정규식 사용으로 성능 향상
- idp__ssoserver.log에만 선택적 적용
- 원본 로그 보존으로 추후 분석 가능

## 문제 해결

### 1. 소스 분류가 잘못되는 경우
`config/log_paths.py`의 `SOURCE_BY_FILE` 딕셔너리에 명시적 매핑 추가:
```python
SOURCE_BY_FILE["your_custom_file.log"] = "idp"  # 또는 "sp1", "sp2"
```

### 2. OIDC 패턴이 제대로 정규화되지 않는 경우
로그에서 새로운 패턴을 찾아 `config/drain_config.py`에 추가:
```python
IDP_ADDITIONAL_PATTERNS.append({
    "regex_pattern": r"your_custom_pattern",
    "mask_with": "<:YOUR_PLACEHOLDER:>"
})
```

### 3. 특정 소스의 세션이 너무 적은 경우
해당 소스의 세션 추출 로직 확인:
```bash
# 세션 추출 상태 확인
grep -E "(session_id|InResponseTo|ID=)" your_log_file.log
```

### 4. AutoEncoder 사용 시 오류
```bash
pip install torch torchvision
```

### 5. 메모리 부족
- 소스별로 따로 실행: 각 소스 로그만 남기고 실행
- `--drain-max-clusters` 값을 소스별로 조정

### 6. 캐시 초기화 (소스별)
```bash
rm -rf DRAIN_CACHE/
python main.py --force-reprocess
```

## CLI 파라미터 전체 목록

```bash
python main.py [OPTIONS]

PYOD 모델 옵션:
  --model TEXT              PYOD 모델 (IForest|COPOD|ECOD|LOF|AutoEncoder)
  --contamination FLOAT     이상치 비율 추정값 (0~0.5, 기본값: 0.05)
  --n_estimators INTEGER    IForest 트리 개수 (기본값: 400)
  --n_neighbors INTEGER     LOF 이웃 개수 (기본값: 20)
  --epochs INTEGER          AutoEncoder 학습 에포크 (기본값: 15)
  --batch_size INTEGER      AutoEncoder 배치 크기 (기본값: 64)
  --random_state INTEGER    랜덤 시드 (기본값: 42)

Drain3 설정 옵션 (모든 소스에 공통 적용):
  --drain-similarity FLOAT      유사도 임계값 (기본값: 0.4)
  --drain-depth INTEGER         파싱 트리 깊이 (기본값: 6)
  --drain-max-children INTEGER  최대 자식 노드 수 (기본값: 100)
  --drain-max-clusters INTEGER  최대 클러스터 수 (기본값: 4096)

기타 옵션:
  --force-reprocess         소스별 Drain3 캐시 무시하고 강제 재처리
```

## 실행 예시

### 기본 소스별 분석
```bash
djwe
```

### IDP 중심 세밀한 분석
```bash
python main.py --model LOF \
  --drain-similarity 0.3 \
  --drain-max-clusters 8000 \
  --n_neighbors 15 \
  --contamination 0.03
```

### SP 중심 빠른 분석
```bash
python main.py --model COPOD \
  --drain-similarity 0.7 \
  --drain-max-clusters 2000 \
  --contamination 0.05
```

### 딥러닝 기반 복잡 패턴 분석
```bash
python main.py --model AutoEncoder \
  --drain-similarity 0.4 \
  --epochs 30 \
  --batch_size 256 \
  --contamination 0.04
```

이제 README가 소스별 구분 분석, OIDC 전처리, 그리고 새로운 아키텍처를 모두 반영하여 업데이트되었습니다.
