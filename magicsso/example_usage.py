#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSO Flow Analyzer 사용 예시
간단한 사용법을 보여주는 예제 스크립트

Usage:
    python example_usage.py
"""

from sso_flow_analyzer import SSOFlowAnalyzer
import pandas as pd

def simple_analysis_example():
    """간단한 분석 예시"""
    print("🔍 SSO 흐름 간단 분석 예시")
    print("=" * 50)
    
    # 분석기 생성
    analyzer = SSOFlowAnalyzer("/home/kongju/DEV/dream/DATA/LOGS")
    
    # 로그 파싱
    analyzer.parse_log_files()
    
    # 완료된 트랜잭션만 가져오기
    completed = analyzer.get_complete_transactions()
    print(f"✅ 완료된 트랜잭션: {len(completed)}개")
    
    # 특정 SP의 트랜잭션 찾기
    sp1_transactions = [t for t in completed if t.sp_provider == "TEST_SP1"]
    sp2_transactions = [t for t in completed if t.sp_provider == "TEST_SP2"]
    
    print(f"🏢 TEST_SP1 완료 트랜잭션: {len(sp1_transactions)}개")
    print(f"🏢 TEST_SP2 완료 트랜잭션: {len(sp2_transactions)}개")
    
    # 응답 시간 분석
    if completed:
        response_times = [t.transaction_duration for t in completed if t.transaction_duration]
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            print(f"⏱️  평균 응답 시간: {avg_time:.2f}초")
            print(f"⏱️  가장 빠른 응답: {min(response_times):.2f}초")
            print(f"⏱️  가장 느린 응답: {max(response_times):.2f}초")

def find_specific_transaction_example():
    """특정 트랜잭션 찾기 예시"""
    print("\n🔍 특정 트랜잭션 찾기 예시")
    print("=" * 50)
    
    analyzer = SSOFlowAnalyzer("/home/kongju/DEV/dream")
    analyzer.parse_log_files()
    
    # 특정 요청 ID로 트랜잭션 찾기
    target_request_id = "SP-f394257672cf7065cbf7b24ec93317f1"
    
    if target_request_id in analyzer.transactions:
        transaction = analyzer.transactions[target_request_id]
        print(f"🔄 트랜잭션 발견!")
        print(f"   요청 ID: {transaction.request_id}")
        print(f"   응답 ID: {transaction.response_id}")
        print(f"   SP 프로바이더: {transaction.sp_provider}")
        print(f"   처리 시간: {transaction.transaction_duration}초")
        print(f"   상태: {'✅ 완료' if transaction.is_complete() else '❌ 미완료'}")
    else:
        print(f"❌ {target_request_id} 트랜잭션을 찾을 수 없습니다.")

def dataframe_analysis_example():
    """pandas DataFrame을 이용한 고급 분석 예시"""
    print("\n📊 DataFrame 분석 예시")
    print("=" * 50)
    
    analyzer = SSOFlowAnalyzer("/home/kongju/DEV/dream")
    analyzer.parse_log_files()
    
    # DataFrame으로 변환
    df = analyzer.export_to_dataframe()
    
    # 완료된 트랜잭션만 필터링
    completed_df = df[df['transaction_duration'].notna()]
    
    if not completed_df.empty:
        print("📈 SP별 통계:")
        stats = completed_df.groupby('sp_provider').agg({
            'transaction_duration': ['count', 'mean', 'min', 'max']
        }).round(2)
        print(stats)
        
        print("\n📈 시간대별 트랜잭션 수:")
        completed_df['request_timestamp'] = pd.to_datetime(completed_df['request_timestamp'])
        completed_df['hour'] = completed_df['request_timestamp'].dt.hour
        hourly_stats = completed_df['hour'].value_counts().sort_index()
        print(hourly_stats)

def flow_correlation_example():
    """흐름 상관관계 분석 예시"""
    print("\n🔗 흐름 상관관계 분석 예시")
    print("=" * 50)
    
    analyzer = SSOFlowAnalyzer("/home/kongju/DEV/dream")
    analyzer.parse_log_files()
    
    # 요청-응답 매칭 확인
    matched_pairs = []
    for transaction in analyzer.get_complete_transactions():
        matched_pairs.append({
            'request_id': transaction.request_id,
            'response_id': transaction.response_id,
            'sp_provider': transaction.sp_provider,
            'duration': transaction.transaction_duration
        })
    
    print(f"🔗 성공적으로 매칭된 요청-응답 쌍: {len(matched_pairs)}개")
    
    # 가장 빠른/느린 트랜잭션 찾기
    if matched_pairs:
        fastest = min(matched_pairs, key=lambda x: x['duration'])
        slowest = max(matched_pairs, key=lambda x: x['duration'])
        
        print(f"\n⚡ 가장 빠른 트랜잭션:")
        print(f"   요청: {fastest['request_id']}")
        print(f"   응답: {fastest['response_id']}")
        print(f"   시간: {fastest['duration']:.3f}초")
        
        print(f"\n🐌 가장 느린 트랜잭션:")
        print(f"   요청: {slowest['request_id']}")
        print(f"   응답: {slowest['response_id']}")
        print(f"   시간: {slowest['duration']:.3f}초")

def main():
    """메인 실행 함수"""
    print("🚀 SSO Flow Analyzer 사용 예시들")
    print("=" * 80)
    
    # 각종 분석 예시 실행
    simple_analysis_example()
    find_specific_transaction_example()
    dataframe_analysis_example()
    flow_correlation_example()
    
    print("\n🎉 모든 예시 완료!")
    print("💡 더 자세한 분석을 원하시면 sso_flow_analyzer.py의 메인 함수를 실행하세요.")

if __name__ == "__main__":
    main()
