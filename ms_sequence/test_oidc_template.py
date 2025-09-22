#!/usr/bin/env python3
"""OIDC Parameter 로그의 템플릿 처리 테스트"""

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

# 테스트용 OIDC Parameter 로그들
oidc_logs = [
    "14:33:58.642 [http-nio-40001-exec-7] DEBUG c.d.s.s.controller.OidcController - OidcController Parameter key: scope, value: address+email+openid+profile",
    "14:33:58.642 [http-nio-40001-exec-7] DEBUG c.d.s.s.controller.OidcController - OidcController Parameter key: response_type, value: code", 
    "14:33:58.642 [http-nio-40001-exec-7] DEBUG c.d.s.s.controller.OidcController - OidcController Parameter key: code_challenge_method, value: S256",
    "14:33:58.642 [http-nio-40001-exec-7] DEBUG c.d.s.s.controller.OidcController - OidcController Parameter key: state, value: d989fdfe-b265-4fe2-8b0c-f957355b1b56",
    "14:33:58.643 [http-nio-40001-exec-7] DEBUG c.d.s.s.controller.OidcController - OidcController Parameter key: logout_uri, value: http://sp2.dev.com:40007/oidc/logoutEx",
    "14:33:58.643 [http-nio-40001-exec-7] DEBUG c.d.s.s.controller.OidcController - OidcController Parameter key: nonce, value: fa8d12e2-4865-4614-9839-edb282c2c58d",
    "14:33:58.643 [http-nio-40001-exec-7] DEBUG c.d.s.s.controller.OidcController - OidcController Parameter key: code_challenge, value: JJKUnDlX/1UgRcsSLKmM90Tz7Z9FPGCFMlOGicatFtE=",
    "14:33:58.643 [http-nio-40001-exec-7] DEBUG c.d.s.s.controller.OidcController - OidcController Parameter key: client_id, value: TEST_SP2",
    "14:33:58.643 [http-nio-40001-exec-7] DEBUG c.d.s.s.controller.OidcController - OidcController Parameter key: redirect_uri, value: http://sp2.dev.com:40007/oidc/redirectAuthcode?relay=/sso/inc/oidcSessionView.jsp",
    "14:34:04.198 [http-nio-40001-exec-4] DEBUG c.d.s.s.controller.OidcController - OidcController Parameter key: SubAuthSessionId, value: d1bcfe7d-af7f-4ee9-b04a-8c4254c27c2a",
    "14:34:04.199 [http-nio-40001-exec-4] DEBUG c.d.s.s.controller.OidcController - OidcController Parameter key: uid, value: ssouser"
]

print("🔍 **OIDC Parameter 로그 템플릿 처리 테스트**")
print("=" * 60)

# 기본 Drain3 설정
config = TemplateMinerConfig()
config.load("config/drain3_template.ini")  # 기존 설정 사용
template_miner = TemplateMiner(config=config)

print(f"\n📝 **테스트 로그들 (총 {len(oidc_logs)}개):**")
for i, log in enumerate(oidc_logs[:5], 1):  # 처음 5개만 표시
    print(f"{i:2}: {log}")
print("   ... (총 11개)")

print(f"\n🔄 **Drain3 템플릿 추출 결과:**")
clusters = {}
templates = {}

for i, log in enumerate(oidc_logs, 1):
    result = template_miner.add_log_message(log)
    cluster_id = result['cluster_id']
    template = result['template_mined']
    
    if cluster_id not in clusters:
        clusters[cluster_id] = []
        templates[cluster_id] = template
    clusters[cluster_id].append(i)
    
    print(f"로그 {i:2} → 클러스터 {cluster_id} : {template}")

print(f"\n📊 **클러스터 분석:**")
print(f"총 로그 수: {len(oidc_logs)}개")
print(f"생성된 클러스터 수: {len(clusters)}개")

for cluster_id, log_indices in clusters.items():
    template = templates[cluster_id]
    print(f"\n🔸 **클러스터 {cluster_id}** ({len(log_indices)}개 로그)")
    print(f"   템플릿: {template}")
    print(f"   로그 번호: {', '.join(map(str, log_indices))}")

print(f"\n🎯 **분석 결과:**")
if len(clusters) == 1:
    print("✅ 모든 OIDC Parameter 로그가 하나의 템플릿으로 올바르게 그룹화됨!")
    print("✅ Drain3 설정이 적절함")
elif len(clusters) == len(oidc_logs):
    print("❌ 모든 로그가 각각 다른 템플릿으로 분류됨")
    print("❌ Drain3 설정 조정 필요 (similarity_threshold 낮춤)")
else:
    print(f"⚠️  {len(clusters)}개의 템플릿으로 부분 그룹화됨")
    print("⚠️  일부는 올바르게 그룹화되었으나 완전하지 않음")

print(f"\n💡 **권장 해결책:**")
if len(clusters) > 1:
    print("1. similarity_threshold를 낮춤 (예: 0.4 → 0.2)")
    print("2. 또는 전처리로 key, value 부분을 <*>로 마스킹")
    print("3. 또는 정규식으로 'Parameter key: <KEY>, value: <VALUE>' 패턴 통일")

print(f"\n🔧 **개선 가능한 전처리:**")
example_log = oidc_logs[0]
preprocessed = example_log.replace("scope, value: address+email+openid+profile", "<*>, value: <*>")
print(f"원본: {example_log}")
print(f"전처리: {preprocessed}")







