# SSO Flow Analyzer 🔐

SSO(Single Sign-On) 로그 데이터를 분석하여 SAML 기반 인증 흐름의 키 값들을 연결하고 통합하는 분석 도구입니다.

## 🚀 주요 기능

### 📊 핵심 분석 기능
- **SAML 트랜잭션 매칭**: SP 요청 ID와 IDP 응답 ID를 자동으로 연결
- **흐름 분석**: 완료/미완료 트랜잭션 분석 및 성공률 계산
- **성능 분석**: 응답 시간 분석 및 통계

### 🤖 고급 이상탐지
- **다중 모델 이상탐지**: 4가지 이상탐지 알고리즘 지원
  - **Isolation Forest**: 전반적 이상치 탐지
  - **Local Outlier Factor (LOF)**: 밀도 기반 국소 이상치
  - **One-Class SVM**: 경계 기반 이상 패턴 식별
  - **Random Cut Forest**: 스트리밍 이상치 실시간 탐지 (rrcf 지원)
- **특성 중요도**: 이상탐지 기여도 분석 (통계적/Permutation/Path 중요도)
- **모델 비교**: 전체 모델 성능 자동 비교 분석

### 🎯 시각화 및 대시보드
- **인터랙티브 대시보드**: Streamlit 기반 웹 시각화
- **모델 선택 인터페이스**: 실시간 모델 전환 및 비교
- **동적 차트**: Plotly 기반 인터랙티브 시각화

### 🗂️ 데이터 관리
- **체계적 폴더 구조**: 분석 유형별/모델별 자동 폴더 생성
- **로그 파일 변환**: RAW_LOGS → LOGS 형식 자동 변환
- **모델별 결과 관리**: 알고리즘별 분리된 폴더로 결과 저장
- **안전한 데이터 처리**: NaN 값 자동 처리 및 오류 방지
- **한국어 지원**: matplotlib 한글 폰트 자동 설정
- **일관된 디자인**: 프로젝트 전체 통일된 색상 테마

## 📊 분석 결과 요약

### 전체 트랜잭션 통계
- **총 트랜잭션**: 59개
- **완료된 트랜잭션**: 14개 (23.73%)
- **미완료 트랜잭션**: 45개 (76.27%)

### 응답 시간 분석
- **평균 응답 시간**: 4.00초
- **최대 응답 시간**: 45.83초
- **최소 응답 시간**: 0.29초

### 프로바이더별 통계
- **TEST_SP1**: 완료 7개, 미완료 32개
- **TEST_SP2**: 완료 7개, 미완료 12개

## 🔑 핵심 연결 키 값들

### 1. SAML 트랜잭션 ID
- **SP 요청 ID**: `SP-{32자리 해시}` (예: `SP-f394257672cf7065cbf7b24ec93317f1`)
- **IDP 응답 ID**: `IDP-{32자리 해시}` (예: `IDP-2b392942d1f22c1e23bd907eb8fa8e26`)

### 2. 연결 관계
- **InResponseTo**: 응답이 어떤 요청에 대한 것인지 명시
- **IssueInstant**: 요청/응답 시간으로 흐름 추적
- **NameID**: 사용자 식별자 (예: `ssouser`)

### 3. 트랜잭션 흐름
```
SP 요청 → IDP 처리 → IDP 응답 → SP 완료
   ↓         ↓         ↓         ↓
SP-ID   AuthnRequest Response  InResponseTo
```

## 📁 파일 구조

```
/home/kongju/DEV/dream/
├── DATA/                          # 데이터 폴더 (체계적 구조)
│   ├── RAW_LOGS/                  # 원본 로그 파일들 (폴더별)
│   │   ├── idp/ssoserver.log
│   │   ├── sp1/ssoagent_20250821.log
│   │   └── sp2/ssoagent_20250821.log
│   ├── LOGS/                      # 변환된 로그 파일들
│   │   ├── idp__ssoserver.log
│   │   ├── sp1__ssoagent_20250821.log
│   │   └── sp2__ssoagent_20250821.log
│   ├── FLOW_ANALYSIS/             # SSO 흐름 분석 결과
│   │   ├── analysis_result.json   # 분석 결과 (JSON)
│   │   ├── transactions.csv       # 트랜잭션 데이터 (CSV)
│   │   └── sso_flow_analysis.png  # 시각화 차트 (PNG)
│   ├── ANOMALY_DETECTION/         # 이상탐지 결과 (모델별 폴더)
│   │   ├── iforest/               # Isolation Forest 결과
│   │   │   ├── sso_anomaly_results.csv
│   │   │   ├── sso_anomaly_detected.csv
│   │   │   ├── sso_anomaly_summary.json
│   │   │   └── sso_anomaly_analysis.png
│   │   ├── lof/                   # Local Outlier Factor 결과
│   │   ├── ocsvm/                 # One-Class SVM 결과
│   │   └── rcf/                   # Random Cut Forest 결과
│   ├── FEATURE_IMPORTANCE/        # 특성 중요도 분석 (모델별 폴더)
│   │   ├── iforest/               # Isolation Forest 특성 중요도
│   │   │   ├── feature_importance_results.json
│   │   │   ├── feature_importance_statistical.csv
│   │   │   ├── feature_importance_permutation.csv
│   │   │   ├── feature_importance_path.csv
│   │   │   ├── feature_importance_analysis.png
│   │   │   └── feature_importance_distributions.png
│   │   ├── lof/                   # LOF 특성 중요도 (permutation 제외)
│   │   ├── ocsvm/                 # One-Class SVM 특성 중요도
│   │   └── rcf/                   # Random Cut Forest 특성 중요도
│   └── REPORTS/                   # 변환 리포트 및 로그
│       ├── log_conversion_report_*.txt
│       └── data_organization_*.txt
├── sso_flow_analyzer.py           # 메인 분석 스크립트
├── sso_anomaly_detector.py        # 다중 모델 이상탐지 스크립트
├── sso_dashboard.py               # Streamlit 대시보드 (모델 선택 가능)
├── feature_importance_analyzer.py # 특성 중요도 분석기 (다중 모델)
├── model_config.py                # 이상탐지 모델 설정 및 구현
├── color_config.py                # 공통 색상 설정
├── folder_utils.py                # 폴더 관리 유틸리티 ⭐
├── log_formatter.py               # 로그 파일 형식 변환기 ⭐
├── data_organizer.py              # 데이터 폴더 정리 도구 ⭐
├── example_usage.py               # 사용 예시 스크립트
└── README.md                      # 문서
```

## 🛠️ 사용법

### 0. 고급 Random Cut Forest 설치 (선택사항)

전문적인 Random Cut Forest를 사용하려면 rrcf 라이브러리를 설치하세요:

```bash
conda activate anom
pip install rrcf
```

> **참고**: rrcf가 설치되지 않은 경우 기본 구현이 사용됩니다.

### 1. 로그 파일 준비 (RAW_LOGS → LOGS 변환)
```bash
# conda 환경 활성화
conda activate anom

# RAW_LOGS 폴더의 파일들을 LOGS 형식으로 변환
cd /home/kongju/DEV/dream
python log_formatter.py

# 미리보기 (실제 변환하지 않고 확인)
python log_formatter.py
# 선택: 3 (preview)
```

### 2. 기본 분석 실행
```bash
# 전체 분석 실행 (FLOW_ANALYSIS 폴더에 결과 저장)
python sso_flow_analyzer.py

# 이상탐지 실행 (기본: Isolation Forest)
python sso_anomaly_detector.py

# 특정 모델 이상탐지
python sso_anomaly_detector.py isolation_forest
python sso_anomaly_detector.py local_outlier_factor
python sso_anomaly_detector.py one_class_svm
python sso_anomaly_detector.py random_cut_forest

# 전체 모델 비교 분석
python sso_anomaly_detector.py compare

# 단일 모델 디버깅 테스트
python sso_anomaly_detector.py test one_class_svm

# 특성 중요도 분석 (기본: Isolation Forest)
python feature_importance_analyzer.py

# 특정 모델 특성 중요도 분석
python feature_importance_analyzer.py one_class_svm

# 모든 모델 특성 중요도 비교
python feature_importance_analyzer.py all

# Streamlit 대시보드 실행 (모델 선택 가능)
streamlit run sso_dashboard.py --server.port 8501
```

### 3. 폴더 관리 유틸리티
```bash
# 전체 폴더 구조 생성
python folder_utils.py create

# 경로 생성 테스트
python folder_utils.py test

# 현재 분석 결과 요약
python folder_utils.py

# 기존 데이터 정리 (필요시)
python data_organizer.py
```

### 4. 예시 스크립트 실행
```bash
# 다양한 분석 예시 확인
python example_usage.py
```

### 5. Python 코드에서 사용
```python
from sso_flow_analyzer import SSOFlowAnalyzer

# 분석기 초기화
analyzer = SSOFlowAnalyzer("/path/to/log/directory")

# 로그 파일 파싱
analyzer.parse_log_files()

# 완료된 트랜잭션 가져오기
completed = analyzer.get_complete_transactions()

# 특정 트랜잭션 찾기
transaction = analyzer.transactions["SP-specific-id"]

# DataFrame으로 변환
df = analyzer.export_to_dataframe()
```

## 📈 분석 가능한 항목들

### 1. 트랜잭션 분석
- 완료/미완료 트랜잭션 분류
- 요청-응답 매칭 상태
- 성공률 계산

### 2. 성능 분석
- 응답 시간 분포
- SP별 성능 비교
- 시간대별 트랜잭션 패턴

### 3. 흐름 추적
- 특정 사용자의 인증 흐름
- 실패한 트랜잭션 원인 분석
- 시스템 부하 패턴 분석

### 4. 대시보드 기능 ⭐
- **🤖 모델 선택**: 사이드바에서 이상탐지 모델 선택
- **📊 실시간 메트릭**: 현재 모델의 이상치 탐지율 표시
- **🔍 모델 비교**: 여러 모델의 성능을 동시에 비교
- **📈 인터랙티브 차트**: Plotly 기반 동적 시각화
- **📥 데이터 다운로드**: 분석 결과 CSV 다운로드

## 🔍 주요 분석 결과

### 완료된 트랜잭션 예시
```
요청 ID: SP-f394257672cf7065cbf7b24ec93317f1
응답 ID: IDP-2b392942d1f22c1e23bd907eb8fa8e26
프로바이더: TEST_SP1
처리 시간: 45.830초
상태: 성공
```

### SP별 성능 비교
- **TEST_SP1**: 평균 6.97초 (0.31~45.83초)
- **TEST_SP2**: 평균 1.02초 (0.29~4.50초)

## 🚨 주요 발견사항

1. **높은 실패율**: 76%의 트랜잭션이 미완료 상태
2. **성능 편차**: TEST_SP1이 TEST_SP2보다 현저히 느림
3. **극단적 응답 시간**: 0.29초~45.83초의 큰 편차

## 📋 출력 파일 설명

### 1. FLOW_ANALYSIS 폴더
- **analysis_result.json**: 전체 분석 요약, 완료/미완료 트랜잭션 상세 정보, 프로바이더별 통계
- **transactions.csv**: 모든 트랜잭션의 원시 데이터 (pandas DataFrame 형태)
- **sso_flow_analysis.png**: 시각화 차트 4개 (완료/미완료 비율, 프로바이더별 분포, 응답 시간, 시간대별 분포)

### 2. ANOMALY_DETECTION/{model}/ 폴더 (모델별)
- **sso_anomaly_results.csv**: 모든 트랜잭션의 이상치 점수 및 분류 결과
- **sso_anomaly_detected.csv**: 이상치로 분류된 트랜잭션만 추출
- **sso_anomaly_summary.json**: 모델 성능 요약, 파라미터, 탐지 통계
- **sso_anomaly_analysis.png**: 이상치 분포 및 스코어 시각화

### 3. FEATURE_IMPORTANCE/{model}/ 폴더 (모델별)
- **feature_importance_results.json**: 전체 특성 중요도 결과 요약
- **feature_importance_statistical.csv**: 통계적 특성 중요도 (Cohen's D 등)
- **feature_importance_permutation.csv**: Permutation Importance 결과 (LOF 제외)
- **feature_importance_path.csv**: Isolation Path Importance (Isolation Forest만)
- **feature_importance_analysis.png**: 특성 중요도 비교 차트
- **feature_importance_distributions.png**: 특성별 분포 시각화

### 4. REPORTS 폴더
- **log_conversion_report_*.txt**: 로그 파일 변환 결과 리포트
- **data_organization_*.txt**: 데이터 폴더 정리 결과 리포트

## 🔧 필요한 라이브러리

### 기본 라이브러리
```python
pandas                    # 데이터 처리 및 분석
matplotlib               # 기본 시각화
seaborn                  # 고급 시각화
numpy                    # 수치 계산
xml.etree.ElementTree    # XML 파싱 (SAML)
re, json, datetime, pathlib  # 표준 라이브러리
```

### 머신러닝 및 이상탐지
```python
scikit-learn            # 이상탐지 알고리즘, 전처리, 평가
rrcf                    # 고급 Random Cut Forest (선택사항)
```

### 웹 대시보드
```python
streamlit               # 인터랙티브 웹 대시보드
plotly                  # 동적 시각화
```

### 설치 방법
```bash
conda activate anom
pip install pandas matplotlib seaborn scikit-learn streamlit plotly
pip install rrcf  # 선택사항 (고급 Random Cut Forest)
```

## 💡 활용 방안

### 기본 분석
1. **성능 모니터링**: 실시간 SSO 성능 추적
2. **장애 분석**: 실패한 인증 세션 원인 분석
3. **용량 계획**: 시간대별 부하 패턴 분석
4. **보안 감사**: 사용자별 인증 활동 추적
5. **시스템 최적화**: 느린 트랜잭션 식별 및 개선

### 고급 이상탐지 활용
6. **다중 모델 비교**: 4가지 알고리즘으로 종합적 이상 패턴 탐지
7. **특성 중요도 분석**: 어떤 요소가 이상치 판별에 가장 중요한지 파악
8. **모델별 특화 분석**: 
   - **Isolation Forest**: 전반적 이상치 탐지
   - **LOF**: 밀도 기반 국소 이상치 탐지
   - **One-Class SVM**: 경계 기반 이상 패턴 식별
   - **Random Cut Forest**: 스트리밍 데이터 이상치 실시간 탐지

### 운영 및 관리
9. **체계적 데이터 관리**: 모델별 폴더 구조로 결과 정리
10. **인터랙티브 분석**: Streamlit 대시보드로 실시간 모델 비교
11. **로그 파일 표준화**: RAW_LOGS를 통일된 형식으로 자동 변환
12. **배치 처리**: 여러 모델을 한 번에 실행하여 종합 분석

## 🆕 최신 업데이트 (v2.0)

### ✨ 새로운 기능
- **체계적 폴더 구조**: 모델별/분석 유형별 자동 폴더 생성
- **로그 파일 변환기**: RAW_LOGS → LOGS 형식 자동 변환
- **다중 모델 지원**: 4가지 이상탐지 알고리즘 통합
- **인터랙티브 대시보드**: 실시간 모델 선택 및 비교
- **특성 중요도 분석**: 모델별 특성 기여도 분석
- **NaN 안전 처리**: 데이터 오류 자동 방지
- **한글 폰트 지원**: matplotlib 한국어 자동 설정

### 🔧 주요 개선사항
- 모델별 결과 파일 자동 분리 저장
- Streamlit 대시보드 모델 선택 기능
- 폴더 관리 유틸리티 추가
- 일관된 색상 테마 적용
- 실시간 성능 비교 기능

---

📧 문의사항이나 개선 제안이 있으시면 언제든 연락주세요!
