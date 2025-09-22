#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
모델별 개별 테스트 스크립트
각 이상탐지 모델을 개별적으로 테스트하여 문제를 확인합니다.

Author: Kong Ju
Date: 2025-09-01
"""

from sso_anomaly_detector import SSOAnomalyDetector, test_single_model
from model_config import SUPPORTED_MODELS


def test_all_models_individually():
    """모든 모델을 개별적으로 테스트"""
    print("🧪 모든 모델 개별 테스트")
    print("=" * 70)
    
    results = {}
    
    for model_name in SUPPORTED_MODELS.keys():
        print(f"\n{'='*60}")
        print(f"🤖 {SUPPORTED_MODELS[model_name]} 테스트 시작")
        print(f"{'='*60}")
        
        try:
            success, total, anomalies = test_single_model(model_name, contamination=0.1)
            
            if success:
                results[model_name] = {
                    'status': '성공',
                    'total': total,
                    'anomalies': anomalies,
                    'ratio': anomalies/total*100 if total > 0 else 0
                }
                print(f"✅ {SUPPORTED_MODELS[model_name]} 테스트 성공!")
                print(f"   📊 총 트랜잭션: {total}개")
                print(f"   🚨 이상치: {anomalies}개 ({anomalies/total*100:.2f}%)")
            else:
                results[model_name] = {
                    'status': '실패',
                    'total': 0,
                    'anomalies': 0,
                    'ratio': 0
                }
                print(f"❌ {SUPPORTED_MODELS[model_name]} 테스트 실패!")
        
        except Exception as e:
            print(f"❌ {SUPPORTED_MODELS[model_name]} 테스트 중 오류 발생: {e}")
            import traceback
            traceback.print_exc()
            results[model_name] = {
                'status': '오류',
                'total': 0,
                'anomalies': 0,
                'ratio': 0
            }
    
    # 전체 결과 요약
    print(f"\n{'='*70}")
    print("📊 전체 테스트 결과 요약")
    print(f"{'='*70}")
    
    for model_name, result in results.items():
        status_emoji = "✅" if result['status'] == '성공' else "❌"
        print(f"{status_emoji} {SUPPORTED_MODELS[model_name]}:")
        print(f"   상태: {result['status']}")
        if result['status'] == '성공':
            print(f"   이상치 비율: {result['ratio']:.2f}%")
        print()
    
    return results


def test_specific_models(model_names):
    """특정 모델들만 테스트"""
    print(f"🎯 특정 모델 테스트: {model_names}")
    print("=" * 50)
    
    for model_name in model_names:
        if model_name not in SUPPORTED_MODELS:
            print(f"❌ 지원하지 않는 모델: {model_name}")
            continue
        
        print(f"\n🤖 {SUPPORTED_MODELS[model_name]} 테스트")
        print("-" * 40)
        
        try:
            success, total, anomalies = test_single_model(model_name, contamination=0.1)
            
            if success:
                print(f"✅ 성공: {anomalies}/{total}개 이상치 탐지 ({anomalies/total*100:.2f}%)")
            else:
                print(f"❌ 실패")
        except Exception as e:
            print(f"❌ 오류: {e}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # 특정 모델들만 테스트
        test_models = sys.argv[1:]
        test_specific_models(test_models)
    else:
        # 모든 모델 테스트
        test_all_models_individually()
