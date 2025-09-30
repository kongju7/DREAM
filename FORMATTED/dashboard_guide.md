# 인증 로그 이상 탐지 EDA 대시보드 사용 가이드

## 개요
정제된 인증 로그 데이터에 대한 종합적인 탐색적 데이터 분석을 위한 Streamlit 대시보드

## 구성 요소

### 1. 파일 구조
```
/home/kongju/DREAM/FORMATTED/
├── anomaly_detection_preprocessor.py    # 데이터 전처리기
├── anomaly_eda_dashboard.py            # 메인 대시보드
├── usage_example.py                    # 사용 예시
├── processed_data/                     # 전처리된 데이터
│   ├── events_processed.csv           # 이벤트 데이터
│   ├── sessions_aggregated.csv        # 세션 집계 데이터
│   └── preprocessing_stats.txt        # 전처리 통계
└── color_config.py (from ../color_config.py)  # 색상 설정
```

## 실행 방법

### 1. 데이터 전처리 (필수 사전 단계)
```bash
source ~/.bashrc && conda activate dream
cd /home/kongju/DREAM/FORMATTED
python anomaly_detection_preprocessor.py --input /home/kongju/DATA/DREAM/FORMATTED/sample.txt --csv
```

### 2. 대시보드 실행
```bash
source ~/.bashrc && conda activate dream
cd /home/kongju/DREAM/FORMATTED
streamlit run anomaly_eda_dashboard.py --server.port 8502
```

### 3. 브라우저 접속
- 로컬: http://localhost:8502
- 외부 접속: http://[서버IP]:8502

## 대시보드 구성

### 📊 종합 메트릭 (상단)
- **총 이벤트 수**: 전체 로그 이벤트 개수
- **총 세션 수**: 고유 세션 개수
- **성공률**: 세션 성공률 (%)
- **고위험 세션**: 이상 점수 > 1.0인 세션 수

### 📑 탭별 분석 내용

#### 1️⃣ 세션 분석
- **성공/실패 분포**: 파이 차트로 세션 성공률 시각화
- **이상 점수 분포**: 히스토그램으로 이상 점수 분포 확인
- **세션 상세 통계**: 평균 세션 시간, 이벤트 수, 실패 횟수 등

#### 2️⃣ 시계열 분석  
- **시간대별 이벤트 분포**: 24시간 기준 이벤트 패턴
- **요일별 이벤트 분포**: 월~일요일별 활동 패턴
- **세션 지속시간 분포**: 세션 길이 히스토그램

#### 3️⃣ 인증 플로우
- **이벤트 타입별 분포**: login_attempt, validation 등 단계별 분석
- **인증 단계별 분포**: step_id 1~5 단계별 분포
- **플로우 이상 패턴**: step_jump, step_reverse 등 비정상 플로우

#### 4️⃣ 이상 패턴
- **이상 패턴별 발생 횟수**: 각 이상 유형별 발생 빈도
- **시간 간격 분포**: 정상 범위 시간 간격 패턴 분석
- **상세 이상 분석**: 메시지 길이, 동시 이벤트 등

#### 5️⃣ 사용자/IP 분석
- **사용자별 이벤트 수**: 상위 10명 활동 분석  
- **IP별 이벤트 수**: 상위 10개 IP 활동 분석
- **행동 패턴 분석**: 사용자/IP별 특이 패턴

#### 6️⃣ 데이터 품질
- **이벤트 데이터 품질**: 행/컬럼 수, 결측값 현황
- **세션 데이터 품질**: 집계 데이터 품질 상태
- **완결성 리포트**: 전체 데이터 완결성 평가

## 주요 특징

### 🎨 시각화 특징
- **일관된 색상 테마**: color_config.py 기반 통일된 색상
- **인터랙티브 차트**: Plotly 기반 확대/축소/필터링 가능
- **다운로드 기능**: 각 그래프를 PNG/HTML로 다운로드 가능

### 🔍 이상 탐지 특화
- **종합 이상 점수**: 통계적 + 규칙 기반 점수 결합
- **실시간 패턴 감지**: step 점프, 빠른 요청 등 실시간 탐지
- **임계값 표시**: 위험 구간 시각적 표시

### 📈 성능 최적화
- **캐싱**: @st.cache_data로 데이터 로드 최적화
- **효율적 처리**: 대용량 데이터 청크 단위 처리
- **반응형 UI**: 다양한 화면 크기 지원

## 이상 탐지 기준

### 🚨 고위험 세션 (anomaly_score_final > 1.0)
- 통계적 이상 + 규칙 기반 위험도 종합 평가
- 세션 지속시간, 실패 횟수, 플로우 이상 등 고려

### ⚠️ 개별 이상 패턴
- **step_jump**: 인증 단계 건너뛰기
- **step_reverse**: 인증 단계 역행
- **delta_too_fast**: 10ms 미만 빠른 요청
- **delta_too_slow**: 30초 초과 느린 응답
- **has_error_keyword**: 오류 메시지 포함

## 활용 방안

### 🔒 보안 모니터링
- 실시간 이상 세션 감지
- 의심스러운 IP/사용자 식별
- 비정상 인증 플로우 탐지

### 📊 운영 최적화
- 시간대별 트래픽 패턴 파악
- 시스템 응답 시간 모니터링
- 성공률 개선 포인트 식별

### 🛡️ 위협 분석
- 공격 패턴 시각화
- 이상 행동 트렌드 분석
- 보안 정책 효과 측정

## 문제 해결

### 데이터가 없을 때
```bash
# 먼저 데이터 전처리 실행
python anomaly_detection_preprocessor.py --demo --csv
```

### 포트 충돌 시
```bash
# 다른 포트 사용
streamlit run anomaly_eda_dashboard.py --server.port 8503
```

### 의존성 오류 시
```bash
pip install streamlit plotly pandas numpy scipy kaleido
```

## 확장 가능성

### 🔄 실시간 모니터링
- 로그 스트림 연동
- 자동 알림 시스템
- 대시보드 자동 새로고침

### 🤖 머신러닝 통합
- 이상 탐지 모델 연동
- 예측 분석 추가
- 자동 분류 시스템

### 📱 모바일 최적화
- 반응형 디자인 강화
- 모바일 전용 뷰
- 푸시 알림 연동

---

**작성자**: Kong Ju  
**최종 수정**: 2025-09-29  
**버전**: 1.0
