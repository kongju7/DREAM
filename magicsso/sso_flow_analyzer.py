#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSO Flow Analyzer
SSO 흐름의 키 값들을 연결해서 데이터를 통합하는 분석기

Author: SSO Data Analyst
Date: 2025-01-21
"""

import re
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from color_config import COLORS, GRAPH_COLORS, get_palette, setup_matplotlib_style
from folder_utils import get_structured_output_path


@dataclass
class SSOTransaction:
    """SSO 트랜잭션을 나타내는 데이터 클래스"""
    # 요청 정보
    request_id: Optional[str] = None
    request_timestamp: Optional[datetime] = None
    sp_provider: Optional[str] = None
    destination_url: Optional[str] = None
    consumer_service_url: Optional[str] = None
    
    # 응답 정보  
    response_id: Optional[str] = None
    response_timestamp: Optional[datetime] = None
    in_response_to: Optional[str] = None
    status_code: Optional[str] = None
    
    # 사용자 정보
    user_id: Optional[str] = None
    name_id: Optional[str] = None
    
    # 메타데이터
    transaction_duration: Optional[float] = None
    log_source: Optional[str] = None
    
    def is_complete(self) -> bool:
        """트랜잭션이 완료되었는지 확인"""
        return (self.request_id is not None and 
                self.response_id is not None and 
                self.in_response_to == self.request_id)


class SSOFlowAnalyzer:
    """SSO 흐름 분석기"""
    
    def __init__(self, log_directory: str):
        self.log_directory = Path(log_directory)
        self.transactions: Dict[str, SSOTransaction] = {}
        self.raw_logs: List[Dict] = []
        
    def parse_log_files(self) -> None:
        """로그 파일들을 파싱하여 트랜잭션 정보 추출"""
        print("🔍 로그 파일 파싱 시작...")
        
        for log_file in self.log_directory.glob("*.log"):
            print(f"📁 파싱 중: {log_file.name}")
            self._parse_single_log_file(log_file)
            
        print(f"✅ 총 {len(self.transactions)}개의 트랜잭션 발견")
    
    def _parse_single_log_file(self, log_file: Path) -> None:
        """단일 로그 파일 파싱"""
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # IDP 로그에서 AuthnRequest 파싱
            if 'idp' in log_file.name.lower():
                self._parse_authn_requests(content, log_file.name)
                
            # SP 로그에서 Response 파싱  
            elif 'sp' in log_file.name.lower():
                self._parse_responses(content, log_file.name)
                
        except Exception as e:
            print(f"❌ {log_file.name} 파싱 오류: {e}")
    
    def _parse_authn_requests(self, content: str, source: str) -> None:
        """AuthnRequest 메시지 파싱"""
        # AuthnRequest XML 블록 찾기
        request_pattern = r'<saml2p:AuthnRequest[^>]*?ID="(SP-[a-f0-9]+)"[^>]*?IssueInstant="([^"]+)"[^>]*?ProviderName="([^"]+)"[^>]*?>(.*?)</saml2p:AuthnRequest>'
        
        for match in re.finditer(request_pattern, content, re.DOTALL):
            request_id = match.group(1)
            timestamp_str = match.group(2)
            provider_name = match.group(3)
            xml_content = match.group(4)
            
            # URL 정보 추출
            consumer_url_match = re.search(r'AssertionConsumerServiceURL="([^"]+)"', match.group(0))
            destination_match = re.search(r'Destination="([^"]+)"', match.group(0))
            
            transaction = SSOTransaction(
                request_id=request_id,
                request_timestamp=self._parse_timestamp(timestamp_str),
                sp_provider=provider_name,
                consumer_service_url=consumer_url_match.group(1) if consumer_url_match else None,
                destination_url=destination_match.group(1) if destination_match else None,
                log_source=source
            )
            
            self.transactions[request_id] = transaction
    
    def _parse_responses(self, content: str, source: str) -> None:
        """Response 메시지 파싱"""
        # Response XML 블록 찾기
        response_pattern = r'<saml2p:Response[^>]*?ID="(IDP-[a-f0-9]+)"[^>]*?InResponseTo="(SP-[a-f0-9]+)"[^>]*?IssueInstant="([^"]+)"[^>]*?>(.*?)</saml2p:Response>'
        
        for match in re.finditer(response_pattern, content, re.DOTALL):
            response_id = match.group(1)
            in_response_to = match.group(2)
            timestamp_str = match.group(3)
            xml_content = match.group(4)
            
            # 상태 코드 추출
            status_match = re.search(r'<saml2p:StatusCode Value="([^"]+)"', xml_content)
            status_code = status_match.group(1) if status_match else None
            
            # 사용자 ID 추출
            name_id_match = re.search(r'<saml2:NameID[^>]*?>([^<]+)</saml2:NameID>', xml_content)
            name_id = name_id_match.group(1) if name_id_match else None
            
            # 기존 트랜잭션에 응답 정보 추가
            if in_response_to in self.transactions:
                transaction = self.transactions[in_response_to]
                transaction.response_id = response_id
                transaction.response_timestamp = self._parse_timestamp(timestamp_str)
                transaction.in_response_to = in_response_to
                transaction.status_code = status_code
                transaction.name_id = name_id
                
                # 응답 시간 계산
                if transaction.request_timestamp and transaction.response_timestamp:
                    duration = (transaction.response_timestamp - transaction.request_timestamp).total_seconds()
                    transaction.transaction_duration = duration
            else:
                # 응답만 있는 경우 새 트랜잭션 생성
                transaction = SSOTransaction(
                    response_id=response_id,
                    response_timestamp=self._parse_timestamp(timestamp_str),
                    in_response_to=in_response_to,
                    status_code=status_code,
                    name_id=name_id,
                    log_source=source
                )
                self.transactions[in_response_to] = transaction
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """ISO 8601 타임스탬프 파싱"""
        try:
            # Z를 +00:00으로 변환
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str[:-1] + '+00:00'
            return datetime.fromisoformat(timestamp_str)
        except ValueError:
            return None
    
    def get_complete_transactions(self) -> List[SSOTransaction]:
        """완료된 트랜잭션들만 반환"""
        return [t for t in self.transactions.values() if t.is_complete()]
    
    def get_incomplete_transactions(self) -> List[SSOTransaction]:
        """미완료 트랜잭션들 반환"""
        return [t for t in self.transactions.values() if not t.is_complete()]
    
    def analyze_flow_summary(self) -> Dict:
        """흐름 요약 분석"""
        complete = self.get_complete_transactions()
        incomplete = self.get_incomplete_transactions()
        
        summary = {
            "총_트랜잭션수": len(self.transactions),
            "완료된_트랜잭션수": len(complete),
            "미완료_트랜잭션수": len(incomplete),
            "성공률": len(complete) / len(self.transactions) * 100 if self.transactions else 0
        }
        
        if complete:
            durations = [t.transaction_duration for t in complete if t.transaction_duration]
            if durations:
                summary.update({
                    "평균_응답시간_초": sum(durations) / len(durations),
                    "최대_응답시간_초": max(durations),
                    "최소_응답시간_초": min(durations)
                })
        
        return summary
    
    def get_provider_statistics(self) -> Dict:
        """프로바이더별 통계"""
        stats = {}
        for transaction in self.transactions.values():
            provider = transaction.sp_provider or "Unknown"
            if provider not in stats:
                stats[provider] = {"완료": 0, "미완료": 0}
            
            if transaction.is_complete():
                stats[provider]["완료"] += 1
            else:
                stats[provider]["미완료"] += 1
                
        return stats
    
    def export_to_dataframe(self) -> pd.DataFrame:
        """pandas DataFrame으로 내보내기"""
        data = []
        for transaction in self.transactions.values():
            data.append(asdict(transaction))
        
        df = pd.DataFrame(data)
        return df
    
    def export_to_json(self, output_file: str) -> None:
        """JSON 형태로 내보내기"""
        data = {
            "분석_요약": self.analyze_flow_summary(),
            "프로바이더_통계": self.get_provider_statistics(),
            "완료된_트랜잭션들": [asdict(t) for t in self.get_complete_transactions()],
            "미완료_트랜잭션들": [asdict(t) for t in self.get_incomplete_transactions()]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        
        print(f"📊 분석 결과가 {output_file}에 저장되었습니다.")
    
    def create_flow_visualization(self, output_dir: str = None) -> None:
        """흐름 시각화 생성"""
        if not output_dir:
            output_dir = self.log_directory
        
        # 공통 색상 스타일 적용
        setup_matplotlib_style()
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        
        # 1. 완료/미완료 트랜잭션 비율
        try:
            complete_count = len(self.get_complete_transactions())
            incomplete_count = len(self.get_incomplete_transactions())
            
            # 데이터 검증
            if complete_count > 0 or incomplete_count > 0:
                counts = []
                labels = []
                colors = []
                
                if complete_count > 0:
                    counts.append(complete_count)
                    labels.append('완료')
                    colors.append(GRAPH_COLORS['completed'])
                
                if incomplete_count > 0:
                    counts.append(incomplete_count)
                    labels.append('미완료')
                    colors.append(GRAPH_COLORS['incomplete'])
                
                if len(counts) == len(labels):
                    ax1.pie(counts, labels=labels, autopct='%1.1f%%', colors=colors)
                    ax1.set_title('트랜잭션 완료 상태')
                else:
                    ax1.text(0.5, 0.5, 'Data Length Mismatch', transform=ax1.transAxes, 
                           ha='center', va='center', fontsize=12)
                    ax1.set_title('트랜잭션 완료 상태 (Error)')
            else:
                ax1.text(0.5, 0.5, 'No Transaction Data', transform=ax1.transAxes, 
                       ha='center', va='center', fontsize=12)
                ax1.set_title('트랜잭션 완료 상태 (No Data)')
                
        except Exception as e:
            print(f"⚠️ 트랜잭션 상태 차트 생성 실패: {e}")
            ax1.text(0.5, 0.5, 'Chart Error', transform=ax1.transAxes, 
                   ha='center', va='center', fontsize=12)
            ax1.set_title('트랜잭션 완료 상태 (Error)')
        
        # 2. 프로바이더별 통계
        try:
            provider_stats = self.get_provider_statistics()
            providers = list(provider_stats.keys())
            
            if providers and len(providers) > 0:
                complete_counts = [provider_stats[p]["완료"] for p in providers]
                incomplete_counts = [provider_stats[p]["미완료"] for p in providers]
                
                # 데이터 길이 검증
                if len(providers) == len(complete_counts) == len(incomplete_counts):
                    x = range(len(providers))
                    width = 0.35
                    
                    ax2.bar([i - width/2 for i in x], complete_counts, width, 
                           label='완료', color=GRAPH_COLORS['completed'])
                    ax2.bar([i + width/2 for i in x], incomplete_counts, width, 
                           label='미완료', color=GRAPH_COLORS['incomplete'])
                    ax2.set_xlabel('서비스 프로바이더')
                    ax2.set_ylabel('트랜잭션 수')
                    ax2.set_title('프로바이더별 트랜잭션 상태')
                    ax2.set_xticks(x)
                    ax2.set_xticklabels(providers, rotation=45)
                    ax2.legend()
                else:
                    ax2.text(0.5, 0.5, 'Data Length Mismatch', transform=ax2.transAxes, 
                           ha='center', va='center', fontsize=12)
                    ax2.set_title('프로바이더별 트랜잭션 상태 (Error)')
            else:
                ax2.text(0.5, 0.5, 'No Provider Data', transform=ax2.transAxes, 
                       ha='center', va='center', fontsize=12)
                ax2.set_title('프로바이더별 트랜잭션 상태 (No Data)')
                
        except Exception as e:
            print(f"⚠️ 프로바이더별 차트 생성 실패: {e}")
            ax2.text(0.5, 0.5, 'Chart Error', transform=ax2.transAxes, 
                   ha='center', va='center', fontsize=12)
            ax2.set_title('프로바이더별 트랜잭션 상태 (Error)')
        
        # 3. 응답 시간 분포
        try:
            complete_transactions = self.get_complete_transactions()
            durations = [t.transaction_duration for t in complete_transactions if t.transaction_duration]
            
            if durations and len(durations) > 0:
                # 유효한 수치 확인
                valid_durations = [d for d in durations if isinstance(d, (int, float)) and not pd.isna(d)]
                
                if valid_durations:
                    ax3.hist(valid_durations, bins=20, alpha=0.7, color=COLORS['primary'])
                    ax3.set_xlabel('응답 시간 (초)')
                    ax3.set_ylabel('빈도')
                    ax3.set_title('응답 시간 분포')
                else:
                    ax3.text(0.5, 0.5, 'No valid duration data', transform=ax3.transAxes, 
                           ha='center', va='center', fontsize=12)
                    ax3.set_title('응답 시간 분포 (No Valid Data)')
            else:
                ax3.text(0.5, 0.5, 'No duration data', transform=ax3.transAxes, 
                       ha='center', va='center', fontsize=12)
                ax3.set_title('응답 시간 분포 (No Data)')
                
        except Exception as e:
            print(f"⚠️ 응답 시간 분포 차트 생성 실패: {e}")
            ax3.text(0.5, 0.5, 'Chart Error', transform=ax3.transAxes, 
                   ha='center', va='center', fontsize=12)
            ax3.set_title('응답 시간 분포 (Error)')
        
        # 4. 시간별 트랜잭션 수
        try:
            timestamps = [t.request_timestamp for t in complete_transactions if t.request_timestamp]
            
            if timestamps and len(timestamps) > 0:
                # 유효한 타임스탬프 확인
                valid_timestamps = [ts for ts in timestamps if pd.notna(ts)]
                
                if valid_timestamps:
                    df_time = pd.DataFrame({'timestamp': valid_timestamps})
                    df_time['hour'] = df_time['timestamp'].dt.hour
                    hourly_counts = df_time['hour'].value_counts().sort_index()
                    
                    if len(hourly_counts) > 0:
                        hours = hourly_counts.index.tolist()
                        counts = hourly_counts.values.tolist()
                        
                        # 데이터 길이 확인
                        if len(hours) == len(counts):
                            ax4.plot(hours, counts, marker='o', color=COLORS['primary'], 
                                   linewidth=2, markersize=6)
                            ax4.set_xlabel('시간 (Hour)')
                            ax4.set_ylabel('트랜잭션 수')
                            ax4.set_title('시간별 트랜잭션 분포')
                            ax4.grid(True, alpha=0.3)
                        else:
                            ax4.text(0.5, 0.5, 'Data Length Mismatch', transform=ax4.transAxes, 
                                   ha='center', va='center', fontsize=12)
                            ax4.set_title('시간별 트랜잭션 분포 (Error)')
                    else:
                        ax4.text(0.5, 0.5, 'No hourly data', transform=ax4.transAxes, 
                               ha='center', va='center', fontsize=12)
                        ax4.set_title('시간별 트랜잭션 분포 (No Groups)')
                else:
                    ax4.text(0.5, 0.5, 'No valid timestamps', transform=ax4.transAxes, 
                           ha='center', va='center', fontsize=12)
                    ax4.set_title('시간별 트랜잭션 분포 (No Valid Data)')
            else:
                ax4.text(0.5, 0.5, 'No timestamp data', transform=ax4.transAxes, 
                       ha='center', va='center', fontsize=12)
                ax4.set_title('시간별 트랜잭션 분포 (No Data)')
                
        except Exception as e:
            print(f"⚠️ 시간별 분포 차트 생성 실패: {e}")
            ax4.text(0.5, 0.5, 'Chart Error', transform=ax4.transAxes, 
                   ha='center', va='center', fontsize=12)
            ax4.set_title('시간별 트랜잭션 분포 (Error)')
        
        plt.tight_layout()
        output_path = Path(output_dir) / 'sso_flow_analysis.png'
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"📈 시각화 차트가 {output_path}에 저장되었습니다.")
    
    def print_flow_details(self, limit: int = 10) -> None:
        """상세 흐름 정보 출력"""
        print("\n" + "="*80)
        print("🔍 SSO 흐름 상세 분석 결과")
        print("="*80)
        
        # 요약 정보
        summary = self.analyze_flow_summary()
        print("\n📊 분석 요약:")
        for key, value in summary.items():
            if isinstance(value, float):
                print(f"   {key}: {value:.2f}")
            else:
                print(f"   {key}: {value}")
        
        # 완료된 트랜잭션들
        complete_transactions = self.get_complete_transactions()[:limit]
        print(f"\n✅ 완료된 트랜잭션들 (최대 {limit}개):")
        print("-" * 80)
        
        for i, transaction in enumerate(complete_transactions, 1):
            print(f"\n{i}. 트랜잭션 흐름:")
            print(f"   🔄 요청 ID: {transaction.request_id}")
            print(f"   📅 요청 시간: {transaction.request_timestamp}")
            print(f"   🏢 SP 프로바이더: {transaction.sp_provider}")
            print(f"   ⬇️  응답 ID: {transaction.response_id}")
            print(f"   📅 응답 시간: {transaction.response_timestamp}")
            print(f"   👤 사용자: {transaction.name_id}")
            print(f"   ⏱️  처리 시간: {transaction.transaction_duration:.3f}초" if transaction.transaction_duration else "   ⏱️  처리 시간: 계산 불가")
            print(f"   ✅ 상태: {transaction.status_code}")
        
        # 미완료 트랜잭션들
        incomplete_transactions = self.get_incomplete_transactions()[:5]
        if incomplete_transactions:
            print(f"\n❌ 미완료 트랜잭션들 (최대 5개):")
            print("-" * 80)
            
            for i, transaction in enumerate(incomplete_transactions, 1):
                print(f"\n{i}. 미완료 트랜잭션:")
                print(f"   🔄 요청 ID: {transaction.request_id}")
                print(f"   📅 요청 시간: {transaction.request_timestamp}")
                print(f"   🏢 SP 프로바이더: {transaction.sp_provider}")
                print(f"   ❌ 문제: 응답이 없거나 매칭되지 않음")


def main():
    """메인 실행 함수"""
    print("🚀 SSO Flow Analyzer 시작")
    print("="*50)
    
    # 경로 설정
    logs_dir = "/home/kongju/DEV/dream/DATA/LOGS"
    data_dir = "/home/kongju/DEV/dream/DATA"
    output_dir = get_structured_output_path(data_dir, "flow")
    
    # 분석기 초기화
    analyzer = SSOFlowAnalyzer(logs_dir)
    
    # 로그 파일 파싱
    analyzer.parse_log_files()
    
    # 상세 분석 결과 출력
    analyzer.print_flow_details()
    
    # JSON으로 내보내기
    analyzer.export_to_json(f"{output_dir}/analysis_result.json")
    
    # 시각화 생성
    analyzer.create_flow_visualization(output_dir)
    
    # DataFrame 내보내기
    df = analyzer.export_to_dataframe()
    df.to_csv(f"{output_dir}/transactions.csv", index=False, encoding='utf-8')
    print(f"📋 CSV 파일이 {output_dir}/transactions.csv에 저장되었습니다.")
    
    print("\n🎉 분석 완료!")


if __name__ == "__main__":
    main()
