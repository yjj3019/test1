#!/usr/bin/env python3
"""
sosreport 압축 파일 AI 분석 및 보고서 생성 모듈 (추적 분석 기능 강화 및 폰트 자동 설치)
sosreport 압축 파일을 입력받아 압축 해제, 데이터 추출, AI 분석, HTML 보고서 생성을 한 번에 수행합니다.

사용법:
    # 기본 사용법 (sosreport 압축 파일을 입력)
    python3 ai_analyzer.py sosreport-archive.tar.xz --llm-url <URL> --model <MODEL> --api-token <TOKEN>
"""

import os
import sys
import json
import requests
import argparse
import time
import re
import tarfile
import shutil
from datetime import datetime, timedelta, date # 'date' 추가
from pathlib import Path
from typing import Dict, Any, Optional, List
import html # HTML 이스케이프를 위해 추가
import io
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import subprocess # chattr 명령어 실행을 위해 추가
import urllib.request # [폰트 해결] 폰트 다운로드를 위해 추가

# --- 그래프 생성을 위한 라이브러리 ---
# "pip install matplotlib" 명령어로 설치 필요
try:
    import matplotlib
    # [수정] GUI 백엔드가 없는 환경(서버, Docker 등)에서 matplotlib이 정상적으로 동작하도록 'Agg' 백엔드를 명시적으로 지정합니다.
    # 이 코드는 pyplot을 임포트하기 전에 실행되어야 합니다.
    matplotlib.use('Agg') # GUI 백엔드 없이 실행하기 위한 설정
    import matplotlib.pyplot as plt
    import matplotlib.font_manager as fm
    import matplotlib.ticker as mticker
except ImportError:
    # 라이브러리 자체가 없는 경우에만 None으로 설정합니다. `pyplot` 등 하위 모듈의
    # ImportError는 여기서 잡히지 않도록 하여, 백엔드 문제로 전체 기능이
    # 비활성화되는 것을 방지합니다.
    matplotlib = None
    plt = None

class Color:
    """콘솔 출력에 사용할 ANSI 색상 코드입니다."""
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def _is_color_supported():
        """콘솔이 색상 출력을 지원하는지 확인합니다."""
        return sys.stdout.isatty() and os.name != 'nt'

    @staticmethod
    def info(text):
        return f"{Color.BLUE}{text}{Color.END}" if Color._is_color_supported() else text

    @staticmethod
    def success(text):
        return f"{Color.GREEN}{text}{Color.END}" if Color._is_color_supported() else text

    @staticmethod
    def warn(text):
        return f"{Color.YELLOW}{text}{Color.END}" if Color._is_color_supported() else text

    @staticmethod
    def error(text):
        return f"{Color.RED}{text}{Color.END}" if Color._is_color_supported() else text
    
    @staticmethod
    def header(text):
        return f"{Color.PURPLE}{Color.BOLD}{text}{Color.END}" if Color._is_color_supported() else text
    
    @staticmethod
    def cyan(text):
        return f"{Color.CYAN}{text}{Color.END}" if Color._is_color_supported() else text

def log_step(message: str):
    """주요 분석 단계를 나타내는 헤더를 출력합니다."""
    print(f"\n{Color.header(f'===== {message} =====')}")

class DataAnonymizer:
    """
    LLM 전송 전 데이터에서 민감 정보(IP, 호스트명, MAC 주소)를 익명화합니다.
    일관된 익명화를 위해 발견된 값을 매핑하여 관리합니다. (예: 1.2.3.4 -> ANON_IP_1)
    """
    def __init__(self):
        self.ip_map = {}
        self.hostname_map = {}
        self.mac_map = {}
        # 정규식 정의
        self.fqdn_regex = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b')
        self.ipv4_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.mac_regex = re.compile(r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b')

    def _anonymize_ip(self, match):
        ip = match.group(0)
        if ip.startswith('127.'): return ip # 루프백 주소는 유지
        if ip not in self.ip_map:
            self.ip_map[ip] = f"ANON_IP_{len(self.ip_map) + 1}"
        return self.ip_map[ip]

    def _anonymize_hostname(self, match):
        hostname = match.group(0)
        # 일반적인 단어나 파일명과의 혼동을 피하기 위한 예외 처리
        if hostname.lower() in ['all', 'default', 'localhost']: return hostname
        if '.' not in hostname or len(hostname.split('.')[-1]) > 6: return hostname

        if hostname not in self.hostname_map:
            self.hostname_map[hostname] = f"ANON_HOSTNAME_{len(self.hostname_map) + 1}"
        return self.hostname_map[hostname]
    
    def _anonymize_mac(self, match):
        mac = match.group(0)
        if mac not in self.mac_map:
            self.mac_map[mac] = f"ANON_MAC_{len(self.mac_map) + 1}"
        return self.mac_map[mac]

    def anonymize_text(self, text: str, specific_hostnames: List[str] = []) -> str:
        """단일 문자열 값에 대해 익명화를 수행합니다."""
        if not isinstance(text, str):
            return text
        
        # 1. 정확도를 위해 파싱된 특정 호스트명을 먼저 익명화
        for hostname in specific_hostnames:
            if hostname and hostname != 'N/A' and hostname.lower() != 'localhost':
                # 단어 경계(\b)를 사용하여 단어의 일부가 바뀌는 것을 방지
                text = re.sub(r'\b' + re.escape(hostname) + r'\b', self._anonymize_hostname, text, flags=re.IGNORECASE)

        # 2. 정규식을 사용하여 IP, FQDN, MAC 주소 익명화
        text = self.ipv4_regex.sub(self._anonymize_ip, text)
        text = self.fqdn_regex.sub(self._anonymize_hostname, text)
        text = self.mac_regex.sub(self._anonymize_mac, text)
        return text

    def anonymize_data(self, data: Any, specific_hostnames: List[str] = []) -> Any:
        """딕셔너리, 리스트 등 복합 데이터 구조를 재귀적으로 탐색하며 익명화를 수행합니다."""
        if isinstance(data, dict):
            return {k: self.anonymize_data(v, specific_hostnames) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.anonymize_data(item, specific_hostnames) for item in data]
        elif isinstance(data, str):
            return self.anonymize_text(data, specific_hostnames)
        else:
            return data

class SosreportParser:
    """sosreport 압축 해제 후 디렉토리에서 데이터를 파싱하여 JSON 구조로 만듭니다."""
    def __init__(self, extract_path: str):
        self.extract_path = Path(extract_path)
        subdirs = [d for d in self.extract_path.iterdir() if d.is_dir()]
        self.base_path = subdirs[0] if len(subdirs) == 1 else self.extract_path
        print(f"sosreport 데이터 분석 경로: {Color.cyan(self.base_path)}")
        
        self.report_date = datetime.now() # Fallback
        date_found = False

        # 1. timedatectl 시도 (더 정확한 정보)
        timedatectl_content = self._read_file(['sos_commands/systemd/timedatectl'])
        if timedatectl_content != 'N/A':
            try:
                # 예: Local time: Mon 2025-09-01 15:04:00 KST
                match = re.search(r'Local time:.*?(\d{4}-\d{2}-\d{2})', timedatectl_content)
                if match:
                    self.report_date = datetime.strptime(match.group(1), '%Y-%m-%d')
                    print(Color.success(f"✅ sosreport 수집일 감지 (timedatectl): {self.report_date.strftime('%Y-%m-%d')}"))
                    date_found = True
                else:
                    raise ValueError("timedatectl에서 'Local time'을 찾을 수 없음")
            except Exception as e:
                print(Color.warn(f"⚠️ 경고: timedatectl 파싱 실패: {e}. 다른 파일을 시도합니다."))

        # 2. date 파일 시도 (timedatectl 실패 또는 파일 부재 시)
        if not date_found:
            date_content = self._read_file(['sos_commands/date/date', 'sos_commands/general/date', 'date'])
            if date_content != 'N/A':
                try:
                    # 예: Mon Sep 1 15:04:00 KST 2025
                    match = re.search(r'([A-Za-z]{3})\s+[A-Za-z]{3}\s+(\d{1,2})\s+[\d:]+\s+.*?(\d{4})', date_content)
                    if match:
                        month_abbr, day, year = match.groups()
                        month_map = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
                        month = month_map.get(month_abbr)
                        if month:
                            self.report_date = datetime(int(year), month, int(day))
                            print(Color.success(f"✅ sosreport 수집일 감지 (date): {self.report_date.strftime('%Y-%m-%d')}"))
                            date_found = True
                        else:
                            raise ValueError(f"알 수 없는 월 약어: {month_abbr}")
                    else:
                         raise ValueError("인식할 수 없는 날짜 형식")
                except Exception as e:
                    print(Color.warn(f"⚠️ 경고: date 파일({date_content}) 파싱 실패: {e}."))
        
        if not date_found:
            print(Color.warn("⚠️ 경고: 'date' 또는 'timedatectl' 파일을 찾거나 파싱할 수 없어 오늘 날짜 기준으로 sar 파일을 검색합니다."))
            self.report_date = datetime.now()

        self.report_day_str = self.report_date.strftime('%d')
        self.report_full_date_str = self.report_date.strftime('%Y%m%d')
        # [추적 분석] dmesg 내용을 멤버 변수로 캐싱
        self.dmesg_content = self._read_file(['dmesg', 'sos_commands/kernel/dmesg'])
        # [개선] CPU 코어 수를 초기에 파싱하여 다른 분석에서 활용
        self.cpu_cores_count = 0


    def _read_file(self, possible_paths: List[str], default: str = 'N/A') -> str:
        """
        여러 예상 경로 중 파일을 찾아 안전하게 읽어 내용을 반환합니다.
        """
        for file_path in possible_paths:
            full_path = self.base_path / file_path
            if full_path.exists():
                try:
                    return full_path.read_text(encoding='utf-8', errors='ignore').strip()
                except Exception as e:
                    print(Color.warn(f"경고: '{file_path}' 파일 읽기 오류: {e}"))
                    return "파일 읽기 오류"
        return default
    
    def _parse_installed_packages(self) -> List[str]:
        """installed-rpms 파일에서 '패키지-버전-릴리즈' 전체 문자열을 파싱합니다."""
        rpm_content = self._read_file([
            'installed-rpms', 
            'sos_commands/rpm/sh_-c_rpm_--nodigest_-qa_--qf_NAME_-_VERSION_-_RELEASE_._ARCH_INSTALLTIME_date_awk_-F_printf_-59s_s_n_1_2_sort_-V', 
            'sos_commands/rpm/sh_-c_rpm_--nodigest_-qa_--qf_-59_NVRA_INSTALLTIME_date_sort_-V'
        ])

        if rpm_content == 'N/A' or not rpm_content.strip():
            print(Color.warn("⚠️ 'installed-rpms' 파일을 찾을 수 없거나 내용이 비어 있습니다."))
            return []
        
        packages = []
        package_pattern = re.compile(r'^([a-zA-Z0-9_.+-]+-\d+.*)')
        for line in rpm_content.split('\n'):
            line = line.strip()
            if not line or line.startswith(('gpg-pubkey', 'warning:', 'error:')):
                continue
            
            match = package_pattern.match(line)
            if match:
                packages.append(match.group(1))
            else:
                parts = line.split()
                if len(parts) > 0:
                    packages.append(parts[0])

        unique_packages = sorted(list(set(packages)))
        print(Color.success(f"✅ 설치된 패키지(버전 포함) 파싱 완료: {len(unique_packages)}개"))
        return unique_packages

    def _parse_system_details(self) -> Dict[str, Any]:
        """xsos 스타일의 상세 시스템 정보를 파싱합니다."""
        details = {}
        details['hostname'] = self._read_file(['hostname', 'sos_commands/general/hostname', 'proc/sys/kernel/hostname'])
        details['os_version'] = self._read_file(['etc/redhat-release'])
        
        uname_content = self._read_file(['uname', 'sos_commands/kernel/uname_-a'])
        uname_line = uname_content.split('\n')[0]
        parts = uname_line.split()
        if len(parts) >= 3:
            details['kernel'] = parts[2]
        else:
            details['kernel'] = uname_line

        dmidecode_content = self._read_file(['dmidecode', 'sos_commands/hardware/dmidecode'])
        model_match = re.search(r'Product Name:\s*(.*)', dmidecode_content)
        details['system_model'] = model_match.group(1).strip() if model_match else 'N/A'
        lscpu_content = self._read_file(['lscpu', 'sos_commands/processor/lscpu'])
        cpu_model = re.search(r'Model name:\s+(.*)', lscpu_content)
        # self.cpu_cores_count = 0 # [개선] CPU 코어 수를 멤버 변수로 저장 -> __init__으로 이동
        cpu_cores_match = re.search(r'^CPU\(s\):\s+(\d+)', lscpu_content, re.MULTILINE)
        if cpu_cores_match:
            self.cpu_cores_count = int(cpu_cores_match.group(1))
        details['cpu'] = f"{self.cpu_cores_count if self.cpu_cores_count > 0 else 'N/A'} x {cpu_model.group(1).strip() if cpu_model else 'N/A'}"

        meminfo_content = self._read_file(['proc/meminfo'])
        mem_total = re.search(r'MemTotal:\s+(\d+)\s+kB', meminfo_content)
        details['memory'] = f"{int(mem_total.group(1)) / 1024 / 1024:.1f} GiB" if mem_total else 'N/A'
        
        uptime_content = self._read_file(['uptime', 'sos_commands/general/uptime', 'sos_commands/host/uptime'])
        uptime_match = re.search(r'up\s+(.*?),\s+\d+\s+user', uptime_content)
        if uptime_match:
            details['uptime'] = uptime_match.group(1).strip()
        else:
            uptime_match_simple = re.search(r'up\s+(.*)', uptime_content)
            if uptime_match_simple:
                 details['uptime'] = uptime_match_simple.group(1).split(',')[0].strip()
            else:
                 details['uptime'] = uptime_content

        last_boot_str = "N/A"
        proc_stat_content = self._read_file(['proc/stat'])
        btime_match = re.search(r'^btime\s+(\d+)', proc_stat_content, re.MULTILINE)
        if btime_match:
            try:
                epoch_time = int(btime_match.group(1))
                boot_datetime = datetime.fromtimestamp(epoch_time)
                timedatectl_content = self._read_file(['sos_commands/host/timedatectl_status'])
                tz_match = re.search(r'Time zone:\s+[\w/]+\s+\((.*?),', timedatectl_content)
                tz_abbr = tz_match.group(1) if tz_match else ""
                formatted_date = boot_datetime.strftime(f'%a %b %d %H:%M:%S {tz_abbr} %Y').strip()
                last_boot_str = f"{formatted_date} (epoch: {epoch_time})"
            except (ValueError, OSError) as e:
                print(Color.warn(f"경고: 부팅 시간(epoch) 변환 실패: {e}"))
                last_boot_str = "Epoch 변환 오류"
        if last_boot_str == "N/A" or "오류" in last_boot_str:
             last_boot_str = self._read_file(['sos_commands/boot/who_-b', 'sos_commands/startup/who_-b']).replace('system boot', '').strip()
        details['last_boot'] = last_boot_str
        
        return details

    def _parse_storage(self) -> List[Dict[str, str]]:
        df_content = self._read_file(['df', 'sos_commands/filesys/df_-alPh'])
        filesystems = []
        for line in df_content.split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 6 and parts[0].startswith('/'):
                filesystems.append({'filesystem': parts[0], 'size': parts[1], 'used': parts[2], 'avail': parts[3], 'use%': parts[4], 'mounted_on': parts[5]})
        return filesystems

    def _parse_process_stats(self) -> Dict[str, Any]:
        """
        ps 출력을 파싱하여 xsos 스타일로 프로세스 통계를 생성합니다.
        - 상위 5개 사용자 (CPU, MEM, RSS 기준)
        - 상위 5개 CPU 및 메모리 사용 프로세스
        - Uninterruptible (D) 및 Zombie (Z) 상태의 프로세스 목록
        """
        ps_content = self._read_file(['sos_commands/process/ps_auxwww', 'sos_commands/process/ps_auxwwwm', 'ps'])
        if ps_content == 'N/A':
            return {'total': 0, 'by_user': [], 'uninterruptible': [], 'zombie': [], 'top_cpu': [], 'top_mem': []}

        lines = ps_content.split('\n')
        processes = []
        header_found = False

        for line in lines:
            if re.match(r'USER\s+PID\s+%CPU', line):
                header_found = True
                continue
            if not header_found:
                continue

            parts = line.split(maxsplit=10)
            if len(parts) >= 11:
                try:
                    processes.append({
                        'user': parts[0], 'pid': parts[1], 'cpu%': float(parts[2]),
                        'mem%': float(parts[3]), 'vsz': int(parts[4]), 'rss': int(parts[5]), # RSS는 KB 단위
                        'stat': parts[7], 'start': parts[8], 'time': parts[9], 'command': parts[10]
                    })
                except (ValueError, IndexError):
                    continue
        
        total_processes = len(processes)
        uninterruptible = [p for p in processes if 'D' in p['stat']]
        zombie = [p for p in processes if 'Z' in p['stat']]
        
        user_stats = {}
        for p in processes:
            user = p['user']
            if user not in user_stats:
                user_stats[user] = {'cpu%': 0.0, 'mem%': 0.0, 'rss': 0}
            user_stats[user]['cpu%'] += p['cpu%']
            user_stats[user]['mem%'] += p['mem%']
            user_stats[user]['rss'] += p['rss']
        
        # CPU 사용량 기준으로 상위 사용자 정렬
        top_users = sorted(user_stats.items(), key=lambda item: item[1]['cpu%'], reverse=True)[:5]
        
        # xsos 형식에 맞게 RSS 단위를 동적으로 변환
        def format_rss(rss_kb):
            if rss_kb > 1024 * 1024:
                return f"{rss_kb / 1024 / 1024:.2f} GiB"
            elif rss_kb > 1024:
                return f"{rss_kb / 1024:.2f} MiB"
            return f"{rss_kb:.2f} KiB"

        formatted_top_users = []
        for user, stats in top_users:
            formatted_top_users.append({
                'user': user,
                'cpu%': f"{stats['cpu%']:.1f}%",
                'mem%': f"{stats['mem%']:.1f}%",
                'rss': format_rss(stats['rss'])
            })
            
        # Top CPU 및 Memory 프로세스 정렬
        top_cpu = sorted(processes, key=lambda p: p['cpu%'], reverse=True)[:5]
        top_mem = sorted(processes, key=lambda p: p['rss'], reverse=True)[:5]
        
        # Top 메모리 프로세스의 RSS 값도 포맷팅
        for p in top_mem:
            p['rss_formatted'] = format_rss(p['rss'])
        for p in uninterruptible:
            p['rss_formatted'] = format_rss(p['rss'])
        for p in zombie:
            p['rss_formatted'] = format_rss(p['rss'])


        print(Color.success(f"✅ 프로세스 통계 파싱 완료: {total_processes}개 프로세스"))
        return {
            'total': total_processes,
            'by_user': formatted_top_users,
            'uninterruptible': uninterruptible,
            'zombie': zombie,
            'top_cpu': top_cpu,
            'top_mem': top_mem
        }

    def _parse_failed_services(self) -> List[str]:
        systemctl_content = self._read_file(['sos_commands/systemd/systemctl_list-units_--all'])
        failed_services = []
        for line in systemctl_content.split('\n'):
            if 'failed' in line:
                parts = line.strip().split()
                if len(parts) >= 4:
                    failed_services.append(f"{parts[0]} - {' '.join(parts[1:4])}")
        return failed_services

    def _parse_ip4_details(self) -> List[Dict[str, str]]:
        ip_addr_content = self._read_file(['sos_commands/networking/ip_addr', 'sos_commands/networking/ip_-d_address'])
        if ip_addr_content == 'N/A': return []
        
        interfaces = []
        blocks = re.split(r'^\d+:\s+', ip_addr_content, flags=re.MULTILINE)
        if not blocks[0].strip():
            blocks.pop(0)

        for block in blocks:
            if not block.strip(): continue
            iface_data = {}
            
            name_match = re.match(r'([\w.-]+):', block)
            if not name_match: continue
            iface_data['iface'] = name_match.group(1)

            mtu_match = re.search(r'mtu\s+(\d+)', block)
            iface_data['mtu'] = mtu_match.group(1) if mtu_match else '-'
            
            state_match = re.search(r'state\s+(\w+)', block)
            iface_data['state'] = state_match.group(1).lower() if state_match else 'unknown'
            
            master_match = re.search(r'master\s+([\w.-]+)', block)
            iface_data['master'] = master_match.group(1) if master_match else '-'

            mac_match = re.search(r'link/\w+\s+([\da-fA-F:]+)', block)
            iface_data['mac'] = mac_match.group(1) if mac_match else '-'

            ip_match = re.search(r'inet\s+([\d.]+/\d+)', block)
            iface_data['ipv4'] = ip_match.group(1) if ip_match else '-'
            
            interfaces.append(iface_data)
            
        return interfaces

    def _parse_network_details(self) -> Dict[str, Any]:
        details = {'netdev': [], 'bonding': [], 'ethtool': {}}

        netdev_content = self._read_file(['proc/net/dev'])
        for line in netdev_content.split('\n')[2:]:
            if ':' not in line: continue
            iface, stats = line.split(':', 1)
            iface = iface.strip()
            stat_values = stats.split()
            if len(stat_values) == 16:
                details['netdev'].append({
                    'iface': iface,
                    'rx_bytes': int(stat_values[0]), 'rx_packets': int(stat_values[1]), 'rx_errs': int(stat_values[2]), 'rx_drop': int(stat_values[3]),
                    'rx_fifo': int(stat_values[4]), 'rx_frame': int(stat_values[5]), 'rx_compressed': int(stat_values[6]), 'rx_multicast': int(stat_values[7]),
                    'tx_bytes': int(stat_values[8]), 'tx_packets': int(stat_values[9]), 'tx_errs': int(stat_values[10]), 'tx_drop': int(stat_values[11]),
                    'tx_fifo': int(stat_values[12]), 'tx_colls': int(stat_values[13]), 'tx_carrier': int(stat_values[14]), 'tx_compressed': int(stat_values[15])
                })

        bonding_dir = self.base_path / 'proc/net/bonding'
        if bonding_dir.is_dir():
            # [개선] xsos 스타일로 각 슬레이브의 상세 정보를 파싱합니다.
            for bond_file in bonding_dir.iterdir():
                bond_content = bond_file.read_text(encoding='utf-8', errors='ignore')
                bond_info = {'device': bond_file.name, 'slaves_info': []}
                
                mode_match = re.search(r'Bonding Mode:\s*(.*)', bond_content)
                if mode_match: bond_info['mode'] = mode_match.group(1).strip()
                
                mii_status_match = re.search(r'MII Status:\s*(.*)', bond_content)
                if mii_status_match: bond_info['mii_status'] = mii_status_match.group(1).strip()

                # 슬레이브 블록별로 파싱
                slave_blocks = bond_content.split('Slave Interface:')
                if len(slave_blocks) > 1:
                    for block in slave_blocks[1:]:
                        slave_info = {}
                        lines = block.strip().split('\n')
                        if not lines: continue

                        slave_info['name'] = lines[0].strip()
                        
                        for line in lines[1:]:
                            if ':' in line:
                                key, value = line.split(':', 1)
                                key = key.strip().lower().replace(' ', '_')
                                value = value.strip()
                                if key == 'mii_status':
                                    slave_info['mii_status'] = value
                                elif key == 'speed':
                                    slave_info['speed'] = value
                                elif key == 'duplex':
                                    slave_info['duplex'] = value
                                elif key == 'link_failure_count':
                                    slave_info['link_failures'] = value
                        bond_info['slaves_info'].append(slave_info)
                details['bonding'].append(bond_info)
        
        # --- ETHTOOL parsing (xsos style) ---
        ethtool_dir = self.base_path / 'sos_commands/networking'
        if ethtool_dir.is_dir():
            all_ifaces = [dev['iface'] for dev in details['netdev']]
            if 'lo' not in all_ifaces:
                 all_ifaces.append('lo')

            for iface_name in sorted(all_ifaces):
                iface_data = {}

                # 1. Info from `ethtool -i <iface>`
                content_i = self._read_file([f'sos_commands/networking/ethtool_-i_{iface_name}'])
                pci_bus = re.search(r'bus-info:\s*(.*)', content_i)
                driver = re.search(r'driver:\s*(.*)', content_i)
                version = re.search(r'version:\s*(.*)', content_i)
                firmware = re.search(r'firmware-version:\s*(.*)', content_i)

                iface_data['pci_bus'] = pci_bus.group(1).strip() if pci_bus else 'PCI UNKNOWN'
                driver_str = driver.group(1).strip() if driver else 'UNKNOWN'
                version_str = f" v{version.group(1).strip()}" if version and version.group(1).strip() else ''
                firmware_str = firmware.group(1).strip() if firmware else 'UNKNOWN'
                iface_data['driver_info'] = f"drv {driver_str}{version_str} / fw {firmware_str}"

                # 2. Info from `ethtool <iface>`
                content_main = self._read_file([f'sos_commands/networking/ethtool_{iface_name}'])
                link_detected = re.search(r'Link detected:\s*(yes|no)', content_main)
                speed = re.search(r'Speed:\s*(.*)', content_main)
                duplex = re.search(r'Duplex:\s*(.*)', content_main)
                autoneg = re.search(r'Auto-negotiation:\s*(on|off)', content_main)

                iface_data['link_status'] = "UNKNOWN"
                if link_detected:
                    iface_data['link_status'] = "up" if link_detected.group(1) == 'yes' else "DOWN"
                
                link_details_str = ""
                if iface_data['link_status'] == "up" and speed:
                    speed_str = speed.group(1).strip()
                    duplex_str = duplex.group(1).strip().lower() if duplex else ""
                    autoneg_str = "Y" if autoneg and autoneg.group(1) == 'on' else "N"
                    link_details_str = f"{speed_str} {duplex_str} (autoneg={autoneg_str})"
                elif iface_data['link_status'] == 'DOWN' and autoneg:
                     autoneg_str = "Y" if autoneg.group(1) == 'on' else "N"
                     link_details_str = f'(autoneg={autoneg_str})'
                iface_data['link_details'] = link_details_str

                # 3. Info from `ethtool -g <iface>`
                content_g = self._read_file([f'sos_commands/networking/ethtool_-g_{iface_name}'])
                rx_max, rx_now = '?', '?'
                
                in_preset_max, in_current_hw = False, False
                for line in content_g.split('\n'):
                    if 'Pre-set maximums:' in line:
                        in_preset_max, in_current_hw = True, False
                        continue
                    if 'Current hardware settings:' in line:
                        in_preset_max, in_current_hw = False, True
                        continue
                    
                    if in_preset_max and line.strip().startswith('RX:'):
                        parts = line.split()
                        if len(parts) >= 2: rx_max = parts[1]
                        in_preset_max = False
                    elif in_current_hw and line.strip().startswith('RX:'):
                        parts = line.split()
                        if len(parts) >= 2: rx_now = parts[1]
                        in_current_hw = False
                
                iface_data['rx_ring'] = "UNKNOWN"
                if not (rx_now == '?' and rx_max == '?'):
                    iface_data['rx_ring'] = f"{rx_now}/{rx_max}"

                # 4. Errors from `ethtool -S <iface>`
                content_s = self._read_file([f'sos_commands/networking/ethtool_-S_{iface_name}'])
                errors = {}
                error_pattern = re.compile(r'(drop|err|fail|fifo|over|crc|coll|miss|buf|lost|pause)', re.IGNORECASE)
                for line in content_s.split('\n'):
                    if error_pattern.search(line):
                        match = re.search(r'\s*([^:]+):\s*([1-9]\d*)', line)
                        if match:
                            key, value = match.groups()
                            if not re.search(r'(fdir_|veb\.)', key, re.IGNORECASE):
                                errors[key.strip()] = value
                if errors:
                    iface_data['errors'] = errors
                
                details['ethtool'][iface_name] = iface_data
        
        return details

    def _parse_routing_table(self) -> List[Dict[str, str]]:
        routing_content = self._read_file(['sos_commands/networking/ip_route_show_table_all', 'sos_commands/networking/ip_route_show'])
        routes = []
        exclusion_keywords = ["broadcast", "local", "unreachable"]

        for line in routing_content.split('\n'):
            if not line.strip(): continue
            parts = line.split()
            
            if parts[0] in exclusion_keywords:
                continue

            route_info = {'destination': parts[0], 'gateway': '-', 'device': '-', 'source': '-'}
            
            try:
                if 'via' in parts:
                    route_info['gateway'] = parts[parts.index('via') + 1]
                if 'dev' in parts:
                    route_info['device'] = parts[parts.index('dev') + 1]
                if 'src' in parts:
                    route_info['source'] = parts[parts.index('src') + 1]
            except IndexError:
                continue

            if route_info['source'].startswith('127.'): continue
            if route_info['destination'].lower() != 'default' and route_info['source'] == '-': continue
            
            routes.append(route_info)
        return routes

    def _parse_sar_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        명시된 우선순위에 따라 sosreport 수집 당일의 텍스트 기반 sar 데이터를 찾아 파싱합니다.
        """
        log_step("sar 성능 데이터 파싱")
        
        search_paths = [
            {'path': f'sos_commands/sar/sar{self.report_day_str}'},
            {'path': f'sos_commands/sar/sar{self.report_full_date_str}'},
            {'path': f'var/log/sa/sar{self.report_day_str}'},
            {'path': f'var/log/sa/sar{self.report_full_date_str}'},
        ]

        content = None
        chosen_path = None
        for candidate in search_paths:
            file_path = self.base_path / candidate['path']
            if file_path.exists():
                print(f"  -> sar 파일 발견: {Color.cyan(candidate['path'])}")
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                chosen_path = candidate['path']
                if content.strip():
                    break
        
        if not content or not content.strip():
            print(Color.info("  -> 일반 경로에서 sar 파일을 찾지 못했거나 비어있어, 종합 sar 데이터(sar -A)로 대체합니다."))
            content = self._read_file(['sos_commands/monitoring/sar_-A'])
            chosen_path = 'sos_commands/monitoring/sar_-A'
            if content == 'N/A' or not content.strip():
                print(Color.error("❌ 분석할 수 있는 sar 데이터를 찾지 못했습니다."))
                return {'cpu': [], 'memory': [], 'network': [], 'disk': [], 'load': [], 'swap': []}

        # --- 데이터 유무 진단 ---
        if 'IFACE' not in content:
            print(Color.warn("⚠️ 경고: sar 파일에 네트워크 통계(-n DEV) 섹션이 없습니다. 관련 데이터 수집 설정이 비활성화되었을 수 있습니다."))
        if 'CPU' not in content and '%user' not in content:
            print(Color.warn("⚠️ 경고: sar 파일에 CPU 통계(-u) 섹션이 없습니다."))
        if 'kbmemfree' not in content:
            print(Color.warn("⚠️ 경고: sar 파일에 메모리 통계(-r) 섹션이 없습니다."))

        performance_data = self._parse_sar_text_content(content)

        if any(v for v in performance_data.values() if v):
            num_cpu = len(performance_data.get('cpu', []))
            num_mem = len(performance_data.get('memory', []))
            num_net = len(set(d.get('timestamp') for d in performance_data.get('network', [])))
            num_disk = len(set(d.get('timestamp') for d in performance_data.get('disk', [])))
            num_load = len(performance_data.get('load', []))
            num_swap = len(performance_data.get('swap', []))
            print(Color.success(f"✅ sar 데이터 파싱 성공: {chosen_path} "
                  f"(CPU: {num_cpu}, Mem: {num_mem}, Net: {num_net}, Disk: {num_disk}, Load: {num_load}, Swap: {num_swap})"))
            return performance_data
        else:
            print(f"    - {Color.warn(f'{chosen_path} 파일에서 유효한 성능 데이터를 추출하지 못했습니다.')}")
            return {'cpu': [], 'memory': [], 'network': [], 'disk': [], 'load': [], 'swap': []}

    def _safe_float(self, value: str) -> float:
        """문자열을 float으로 안전하게 변환합니다. 변환 실패 시 0.0을 반환합니다."""
        try:
            return float(value.replace(',', '.'))
        except (ValueError, TypeError):
            return 0.0

    def _parse_cpu_line(self, parts: List[str], header_map: Dict[str, int]) -> Optional[Dict[str, Any]]:
        """sar CPU 데이터 라인을 파싱합니다."""
        cpu_col_index = header_map.get('CPU', -1)
        # 'all' CPU 라인만 처리. 인덱스가 헤더맵에 있고, 실제 데이터 파트 길이를 넘지 않으며, 값이 'all'이 아닌 경우 스킵
        if cpu_col_index != -1 and cpu_col_index < len(parts) and parts[cpu_col_index] != 'all':
            return None

        return {
            # [개선] .get()을 사용하여 KeyError 방지 및 인덱스 범위 확인 강화
            'user': self._safe_float(parts[header_map.get('pct_user')]) if header_map.get('pct_user') is not None and header_map.get('pct_user') < len(parts) else 0.0,
            'system': self._safe_float(parts[header_map.get('pct_system', header_map.get('pct_sys'))]) if header_map.get('pct_system', header_map.get('pct_sys')) is not None and header_map.get('pct_system', header_map.get('pct_sys')) < len(parts) else 0.0,
            'iowait': self._safe_float(parts[header_map.get('pct_iowait')]) if header_map.get('pct_iowait') is not None and header_map.get('pct_iowait') < len(parts) else 0.0,
            'idle': self._safe_float(parts[header_map.get('pct_idle')]) if header_map.get('pct_idle') is not None and header_map.get('pct_idle') < len(parts) else 0.0
        }

    def _parse_memory_line(self, parts: List[str], header_map: Dict[str, int]) -> Dict[str, Any]:
        """sar 메모리 데이터 라인을 파싱합니다."""
        entry = {}
        for key, index in header_map.items():
            if index < len(parts):
                entry[key] = parts[index]
        return entry

    def _parse_network_line(self, parts: List[str], header_map: Dict[str, int]) -> Optional[Dict[str, Any]]:
        """sar 네트워크 데이터 라인을 파싱합니다."""
        iface_col_index = header_map.get('IFACE', -1)
        if iface_col_index == -1 or iface_col_index >= len(parts) or parts[iface_col_index] == 'lo':
            return None
        
        entry = {}
        for key, index in header_map.items():
            if index < len(parts):
                entry[key] = parts[index]
        return entry

    def _parse_disk_line(self, parts: List[str], header_map: Dict[str, int]) -> Optional[Dict[str, Any]]:
        """
        sar 디스크 데이터 라인(-b 또는 -d)을 파싱하고, 단위를 kB/s로 정규화합니다.
        - 'sar -b'는 bread/s, bwrtn/s (블록/초, 1블록=1KB)를 제공합니다.
        - 'sar -d'는 rd_sec/s, wr_sec/s (섹터/초, 1섹터=512B)를 제공합니다.
        - 'sar -p -d'는 rkB/s, wkB/s (kB/초)를 제공합니다.
        """
        entry = {'tps': 0.0, 'read_kb_s': 0.0, 'write_kb_s': 0.0}
        
        # tps (공통)
        if 'tps' in header_map and header_map['tps'] < len(parts):
            entry['tps'] = self._safe_float(parts[header_map['tps']])

        # sar -b (bread/s, bwrtn/s) -> 1 block/s = 1 kB/s
        if 'bread_s' in header_map and header_map['bread_s'] < len(parts):
            entry['read_kb_s'] = self._safe_float(parts[header_map['bread_s']])
        if 'bwrtn_s' in header_map and header_map['bwrtn_s'] < len(parts):
            entry['write_kb_s'] = self._safe_float(parts[header_map['bwrtn_s']])

        # sar -d (rd_sec/s, wr_sec/s) -> 1 sector = 512 bytes, so (sectors/s / 2) = kB/s
        if 'rd_sec_s' in header_map and header_map['rd_sec_s'] < len(parts):
            entry['read_kb_s'] = self._safe_float(parts[header_map['rd_sec_s']]) / 2.0
        if 'wr_sec_s' in header_map and header_map['wr_sec_s'] < len(parts):
            entry['write_kb_s'] = self._safe_float(parts[header_map['wr_sec_s']]) / 2.0

        # sar -p -d (rkB/s, wkB/s)
        if 'rkB_s' in header_map and header_map['rkB_s'] < len(parts):
            entry['read_kb_s'] = self._safe_float(parts[header_map['rkB_s']])
        if 'wkB_s' in header_map and header_map['wkB_s'] < len(parts):
            entry['write_kb_s'] = self._safe_float(parts[header_map['wkB_s']])

        # DEV 컬럼이 있으면 추가 (sar -d)
        if 'DEV' in header_map and header_map['DEV'] < len(parts):
            entry['DEV'] = parts[header_map['DEV']]

        # 데이터가 하나라도 있으면 유효한 것으로 간주
        if entry['tps'] > 0 or entry['read_kb_s'] > 0 or entry['write_kb_s'] > 0:
            return entry
        
        return None

    def _parse_load_line(self, parts: List[str], header_map: Dict[str, int]) -> Dict[str, Any]:
        """sar 부하 데이터 라인을 파싱합니다."""
        # [수정] CPU 관련 키 대신 부하 평균(ldavg) 키를 사용하도록 수정
        return {
            'ldavg-1': self._safe_float(parts[header_map['ldavg-1']]) if 'ldavg-1' in header_map and header_map['ldavg-1'] < len(parts) else 0.0,
            'ldavg-5': self._safe_float(parts[header_map['ldavg-5']]) if 'ldavg-5' in header_map and header_map['ldavg-5'] < len(parts) else 0.0,
            'ldavg-15': self._safe_float(parts[header_map['ldavg-15']]) if 'ldavg-15' in header_map and header_map['ldavg-15'] < len(parts) else 0.0
        }

    def _parse_swap_line(self, parts: List[str], header_map: Dict[str, int]) -> Dict[str, Any]:
        """sar 스왑 데이터 라인을 파싱합니다."""
        return {
            'swpused_pct': self._safe_float(parts[header_map['pct_swpused']]) if 'pct_swpused' in header_map and header_map['pct_swpused'] < len(parts) else 0.0
        }

    def _parse_sar_text_content(self, sar_content: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        [개선된 알고리즘] sar 텍스트 파서. 헤더와 데이터 라인을 명확히 구분하여 안정적으로 파싱합니다.
        """
        print(Color.info("  -> [v4] 고도화된 sar 파서 실행 중..."))
        performance_data = {'cpu': [], 'memory': [], 'network': [], 'disk': [], 'load': [], 'swap': []}
        lines = sar_content.strip().replace('\r\n', '\n').split('\n')
        
        header_map: Dict[str, int] = {}
        current_section = None
        section_parser = None

        for line in lines:
            line = line.strip()
            if not line or line.startswith('Average:') or line.startswith('Linux'):
                header_map, current_section, section_parser = {}, None, None
                continue

            # [개선 v5] 헤더 라인 식별 로직을 더욱 단순하고 강력하게 변경합니다.
            # 타임스탬프로 시작하고, 라인 내에 주요 헤더 키워드 중 하나라도 포함되어 있으면 헤더로 간주합니다.
            # 이 방식은 컬럼 순서나 공백 변화에 더 유연하게 대응합니다.
            is_timestamped = re.match(r'^\d{2}:\d{2}:\d{2}(?:\s+[AP]M)?', line)
            if is_timestamped:
                expected_header_keywords = ['CPU', 'IFACE', 'kbmemfree', 'DEV', 'runq-sz', 'kbswpfree', 'proc/s', 'rxerr/s', 'tps', '%user', '%usr']
                if not any(keyword in line for keyword in expected_header_keywords):
                    header_match = False
                else:
                    header_match = True
            else:
                header_match = False

            if header_match:
                header_map, current_section, section_parser = {}, None, None
                parts = re.split(r'\s+', line)
                
                # 타임스탬프와 AM/PM을 제외한 실제 컬럼명 찾기
                metric_cols_start_index = 1
                if len(parts) > 1 and parts[1] in ['AM', 'PM']:
                    metric_cols_start_index = 2
                
                metric_cols = parts[metric_cols_start_index:]

                # 섹션 결정 및 파서 매핑
                # [수정] 헤더 감지 조건을 더 유연하게 변경합니다.
                # 주요 키워드 하나만으로도 섹션을 식별할 수 있도록 합니다.
                if 'CPU' in metric_cols and ('%user' in metric_cols or '%usr' in metric_cols):
                    current_section, section_parser = 'cpu', self._parse_cpu_line
                elif 'IFACE' in metric_cols:
                    current_section, section_parser = 'network', self._parse_network_line
                elif 'kbmemfree' in metric_cols:
                    current_section, section_parser = 'memory', self._parse_memory_line
                # [개선] 'sar -b' (tps, bread/s)와 'sar -d' (DEV, tps)를 모두 디스크 섹션으로 감지
                elif ('tps' in metric_cols and 'DEV' in metric_cols) or ('tps' in metric_cols and 'bread/s' in metric_cols):
                    performance_data.setdefault('disk', []) # disk 키가 없으면 생성
                    current_section, section_parser = 'disk', self._parse_disk_line
                elif 'runq-sz' in metric_cols:
                    current_section, section_parser = 'load', self._parse_load_line
                elif 'kbswpfree' in metric_cols and '%swpused' in metric_cols:
                    current_section, section_parser = 'swap', self._parse_swap_line
                # [신규] 네트워크 에러 및 컨텍스트 스위칭 섹션 추가
                elif 'rxerr/s' in metric_cols:
                    performance_data.setdefault('network_error', [])
                    current_section, section_parser = 'network_error', self._parse_network_line # 일반 파서 재활용
                elif 'proc/s' in metric_cols and 'cswch/s' in metric_cols:
                    performance_data.setdefault('context_switch', [])
                    current_section, section_parser = 'context_switch', self._parse_memory_line # 일반 파서 재활용
                
                if current_section:
                    # 헤더 맵 생성 (정규화 포함)
                    header_map = {
                        col.replace('%', 'pct_').replace('/', '_s').replace('%usr', 'pct_user'): i
                        for i, col in enumerate(metric_cols)
                    }
                continue

            # 데이터 라인 파싱
            if current_section and section_parser and header_map:
                parts = re.split(r'\s+', line)
                timestamp = parts[0]
                if len(parts) > 1 and parts[1] in ['AM', 'PM']:
                    timestamp += ' ' + parts[1]
                    data_values = parts[2:]
                else:
                    data_values = parts[1:]

                parsed_entry = section_parser(data_values, header_map)
                if parsed_entry:
                    parsed_entry['timestamp'] = timestamp
                    performance_data[current_section].append(parsed_entry)
                continue
                
        return performance_data

    def _find_sar_data_around_time(self, sar_section_data, target_dt, window_minutes=2):
        """[추적 분석] 특정 시간 주변의 sar 데이터를 찾습니다. 원본 데이터를 수정하지 않습니다."""
        if not sar_section_data:
            return None
        
        closest_entry = None
        min_delta = timedelta.max
        
        for entry in sar_section_data:
            try:
                # datetime 객체를 매번 생성하여 비교하고 원본 entry는 수정하지 않음
                ts_str = entry['timestamp']
                if 'PM' in ts_str or 'AM' in ts_str:
                    dt = datetime.strptime(ts_str, '%I:%M:%S %p')
                else:
                    dt = datetime.strptime(ts_str, '%H:%M:%S')
                
                entry_dt = self.report_date.replace(hour=dt.hour, minute=dt.minute, second=dt.second)
                
                delta = abs(entry_dt - target_dt)
                if delta < min_delta:
                    min_delta = delta
                    closest_entry = entry

            except (ValueError, KeyError):
                continue # 파싱 실패 시 건너뜀
        
        # window_minutes 내에 있는 경우에만 반환
        if closest_entry and min_delta <= timedelta(minutes=window_minutes):
            return closest_entry.copy() # 원본 수정을 막기 위해 복사본 반환
        return None

    def _analyze_logs_and_correlate_events(self, performance_data: Dict) -> Dict[str, Any]:
        """
        [개선] 로그 메시지를 심층 분석합니다.
        1.  **주요 이벤트 상관관계 분석**: 'I/O error', 'OOM' 등 심각한 이벤트 발생 시점의 시스템 상태(sar, dmesg)를 함께 분석합니다.
        2.  **일반 로그 패턴 통계**: '네트워크 단절', '인증 실패' 등 잠재적 문제를 나타내는 로그 패턴의 발생 빈도를 계산합니다.
        """
        log_content = self._read_file(['var/log/messages', 'var/log/syslog'])
        if log_content == 'N/A' or not log_content.strip():
            print(Color.warn("⚠️ 'var/log/messages' 파일을 찾을 수 없거나 내용이 비어 있습니다."))
            return {"critical_log_events": [], "general_log_analysis": {}}

        log_step("로그 메시지 심층 분석 (상관관계 및 패턴 통계)")
        critical_events = []
        
        # 1. 상관관계 분석을 위한 패턴 정의
        critical_patterns = {
            'io_error': re.compile(r'i/o error, dev (\w+),'),
            'oom_killer': re.compile(r'Out of memory: Kill process'),
            'segfault': re.compile(r'segfault at .* ip .* sp .* error \d+ in (\S+)'),
            'call_trace': re.compile(r'Call Trace:'),
            'hardware_error': re.compile(r'Hardware Error|MCE'),
        }

        # 2. 일반 로그 패턴 분석을 위한 패턴 및 카운터
        general_patterns = {
            "network_link_flap": re.compile(r' (link is down|link is up)'),
            "authentication_failure": re.compile(r'authentication failure|failed password', re.IGNORECASE),
            "connection_refused": re.compile(r'connection refused', re.IGNORECASE),
            "nfs_server_not_responding": re.compile(r'nfs: server .* not responding', re.IGNORECASE)
        }
        general_analysis = {key: 0 for key in general_patterns.keys()}
        
        lines = log_content.split('\n')
        for line in lines:
            # --- 일반 로그 패턴 카운팅 ---
            for key, pattern in general_patterns.items():
                if pattern.search(line):
                    general_analysis[key] += 1

            # --- 심각 이벤트 상관관계 분석 ---
            line_lower = line.lower()
            timestamp_match = re.match(r'^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
            if not timestamp_match:
                continue
            
            try:
                log_dt = datetime.strptime(f"{self.report_date.year} {timestamp_match.group(1)}", '%Y %b %d %H:%M:%S')
            except ValueError:
                continue

            context = {}
            event_type = "Unknown"

            if 'i/o error' in line_lower:
                event_type = "I/O Error"
                match = critical_patterns['io_error'].search(line)
                device = match.group(1) if match else "unknown device"
                disk_sar = self._find_sar_data_around_time(performance_data.get('disk', []), log_dt)
                if disk_sar: context['sar_disk_context'] = {k: v for k, v in disk_sar.items() if k != 'timestamp'}
                dmesg_context = [d_line for d_line in self.dmesg_content.split('\n')[-200:] if device in d_line]
                if dmesg_context: context['dmesg_context'] = dmesg_context[:5]

            elif 'out of memory' in line_lower:
                event_type = "Out of Memory"
                mem_sar = self._find_sar_data_around_time(performance_data.get('memory', []), log_dt)
                if mem_sar: context['sar_memory_context'] = {k: v for k, v in mem_sar.items() if k != 'timestamp'}
                oom_dmesg = [d_line for d_line in self.dmesg_content.split('\n') if 'Out of memory: Kill process' in d_line or 'killed process' in d_line]
                if oom_dmesg: context['dmesg_oom_details'] = oom_dmesg[-10:]

            elif 'segfault' in line_lower:
                event_type = "Segmentation Fault"
                match = critical_patterns['segfault'].search(line)
                if match: context['faulting_binary'] = match.group(1)

            elif 'call trace' in line_lower:
                event_type = "Kernel Call Trace"
            elif 'hardware error' in line_lower or 'mce' in line_lower:
                event_type = "Hardware Error"
            
            if event_type != "Unknown":
                critical_events.append({
                    "event_type": event_type,
                    "timestamp": log_dt.strftime('%Y-%m-%d %H:%M:%S'),
                    "log_message": line,
                    "correlated_context": context
                })

        print(Color.success(f"✅ 로그 분석 완료. 심각 이벤트 {len(critical_events)}개 상관관계 분석, 일반 로그 패턴 통계 완료."))
        return {
            "critical_log_events": critical_events,
            "general_log_analysis": general_analysis
        }

    def _analyze_performance_data(self, performance_data: Dict) -> Dict[str, str]:
        """
        [신규] 파싱된 sar 데이터를 기반으로 잠재적인 성능 병목 현상을 진단하고 텍스트로 요약합니다.
        """
        log_step("sar 데이터 기반 성능 병목 분석")
        analysis = {}
        
        # 1. CPU 병목 분석
        cpu_data = performance_data.get('cpu', [])
        if cpu_data:
            high_iowait_count = sum(1 for d in cpu_data if d.get('iowait', 0) > 20)
            avg_total_usage = sum(d.get('user',0)+d.get('system',0) for d in cpu_data) / len(cpu_data)

            if high_iowait_count > len(cpu_data) * 0.1: # 10% 이상 iowait이 20%를 넘는 경우
                analysis['io_bottleneck'] = (
                    f"I/O 대기 병목이 의심됩니다. 전체 측정 시간의 {high_iowait_count/len(cpu_data):.1%} 동안 "
                    f"CPU I/O Wait 비율이 20%를 초과했습니다. 최대 I/O Wait은 {max(d.get('iowait', 0) for d in cpu_data):.1f}% 입니다. "
                    "이는 스토리지 성능 저하 또는 과도한 I/O 요청으로 인해 발생할 수 있습니다."
                )
            if avg_total_usage > 75:
                 analysis['cpu_bottleneck'] = (
                    f"시스템이 지속적으로 높은 CPU 사용률을 보입니다. 평균 CPU 사용률(User+System)이 "
                    f"{avg_total_usage:.1f}%에 달합니다. CPU 자원이 부족하거나 특정 프로세스가 과도한 자원을 사용할 수 있습니다."
                )

        # 2. Load Average 분석 (CPU 코어 수 고려)
        load_data = performance_data.get('load', [])
        if load_data and self.cpu_cores_count > 0:
            high_load_count = sum(1 for d in load_data if d.get('ldavg-5', 0) > self.cpu_cores_count * 1.5)
            if high_load_count > len(load_data) * 0.1:
                analysis['high_load_average'] = (
                    f"시스템 부하가 CPU 코어 수({self.cpu_cores_count}개)에 비해 과도하게 높습니다. "
                    f"전체 측정 시간의 {high_load_count/len(load_data):.1%} 동안 5분 평균 부하가 코어 수의 1.5배를 초과했습니다. "
                    "이는 CPU 경합, I/O 대기 등 다양한 원인으로 발생할 수 있습니다."
                )

        # 3. 스왑 사용량 분석
        swap_data = performance_data.get('swap', [])
        if swap_data:
            peak_swap = max(d.get('swpused_pct', 0) for d in swap_data)
            if peak_swap > 10:
                analysis['swap_usage'] = (
                    f"메모리 부족으로 인해 스왑이 과도하게 사용되었습니다. 최대 스왑 사용률이 {peak_swap:.1f}%에 달했습니다. "
                    "이는 시스템 전반의 성능 저하를 유발할 수 있으므로 메모리 사용량 점검이 필요합니다."
                )
        
        # [신규] 4. 네트워크 에러 분석
        net_error_data = performance_data.get('network_error', [])
        if net_error_data:
            total_rx_errs = sum(self._safe_float(d.get('rxerr_s', '0')) for d in net_error_data)
            total_tx_errs = sum(self._safe_float(d.get('txerr_s', '0')) for d in net_error_data)
            if total_rx_errs > 10 or total_tx_errs > 10: # 임계치는 환경에 따라 조정
                analysis['network_errors'] = (
                    f"네트워크 에러가 지속적으로 발생했습니다 (수신 에러 총합: {total_rx_errs:.0f}, 송신 에러 총합: {total_tx_errs:.0f}). "
                    "이는 네트워크 케이블, 스위치 포트, NIC 드라이버 또는 하드웨어 자체의 문제일 수 있습니다."
                )

        # [신규] 5. 컨텍스트 스위칭 분석
        cs_data = performance_data.get('context_switch', [])
        if cs_data and self.cpu_cores_count > 0:
            avg_cswch = sum(self._safe_float(d.get('cswch_s', '0')) for d in cs_data) / len(cs_data)
            if avg_cswch > self.cpu_cores_count * 15000: # 코어당 15,000회 초과 시
                analysis['high_context_switch'] = f"초당 컨텍스트 스위칭 횟수가 평균 {avg_cswch:,.0f}회로 매우 높습니다. 이는 너무 많은 프로세스가 CPU를 얻기 위해 경쟁하고 있음을 의미하며, 애플리케이션의 스레딩 문제나 과도한 I/O 대기로 인해 발생할 수 있습니다."

        if analysis:
            print(Color.success(f"✅ 성능 병목 분석 완료. {len(analysis)}개의 잠재적 이슈 발견."))
        else:
            print(Color.success("✅ 성능 병목 분석 완료. 특이사항 없음."))

        return analysis

    def _parse_kernel_parameters(self) -> Dict[str, Any]:
        """[신규] sysctl -a 출력에서 커널 파라미터를 파싱하고 주요 값을 식별합니다."""
        log_step("커널 파라미터 파싱")
        sysctl_content = self._read_file(['sos_commands/kernel/sysctl_-a'])
        if sysctl_content == 'N/A':
            return {}
        
        params = {}
        for line in sysctl_content.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                params[key.strip()] = value.strip()
        
        # 분석에 중요한 주요 파라미터 목록
        interesting_keys = [
            'kernel.hostname', 'kernel.domainname', 'kernel.ostype', 'kernel.osrelease',
            'kernel.panic', 'kernel.panic_on_oops', 'vm.swappiness', 'vm.dirty_ratio',
            'vm.dirty_background_ratio', 'vm.overcommit_memory', 'net.core.somaxconn',
            'net.core.netdev_max_backlog', 'net.ipv4.tcp_max_syn_backlog',
            'net.ipv4.ip_local_port_range', 'fs.file-max'
        ]
        
        highlighted_params = {key: params.get(key, 'N/A') for key in interesting_keys}
        
        print(Color.success(f"✅ 커널 파라미터 파싱 완료. {len(params)}개 중 {len(highlighted_params)}개 주요 값 식별."))
        return highlighted_params

    def _parse_selinux_status(self) -> Dict[str, str]:
        """[신규] sestatus -v 출력에서 SELinux 상태를 파싱합니다."""
        sestatus_content = self._read_file(['sos_commands/selinux/sestatus_-v'])
        if sestatus_content == 'N/A':
            return {}
            
        status = {}
        for line in sestatus_content.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().replace(' ', '_').lower()
                status[key] = value.strip()
        print(Color.success(f"✅ SELinux 상태 파싱 완료. 현재 모드: {status.get('current_mode', 'N/A')}"))
        return status

    def parse(self) -> Dict[str, Any]:
        """주요 sosreport 파일들을 파싱하여 딕셔너리로 반환합니다."""
        log_step("sosreport 데이터 파싱")
        system_info = self._parse_system_details()
        system_info['routing_table'] = self._parse_routing_table()

        performance_data = self._parse_sar_data()
        performance_analysis = self._analyze_performance_data(performance_data) # [신규]

        log_analysis_result = self._analyze_logs_and_correlate_events(performance_data) # [신규]

        data = {
            "system_info": system_info,
            "ip4_details": self._parse_ip4_details(),
            "network_details": self._parse_network_details(),
            "storage": self._parse_storage(),
            "process_stats": self._parse_process_stats(),
            "failed_services": self._parse_failed_services(),
            "performance_data": performance_data,
            "installed_packages": self._parse_installed_packages(),
            "critical_log_events": log_analysis_result["critical_log_events"], # [신규]
            "general_log_analysis": log_analysis_result["general_log_analysis"], # [신규]
            "performance_analysis": performance_analysis, # [신규]
            "kernel_parameters": self._parse_kernel_parameters(), # [신규]
            "selinux_status": self._parse_selinux_status(), # [신규]
            "analysis_timestamp": datetime.now().isoformat()
        }
        print(Color.success("✅ sosreport 데이터 파싱 완료."))
        return data

class AIAnalyzer:
    MAX_FINAL_CVES = 10
    def __init__(self, llm_url: str, model_name: Optional[str] = None, 
                 endpoint_path: str = "/v1/chat/completions",
                 api_token: Optional[str] = None,
                 timeout: int = 300,
                 output_dir: str = 'output'):
        """AI 분석기 초기화"""
        match = re.search(r'https?://[^\s\)]+', llm_url)
        cleaned_url = match.group(0) if match else llm_url
        
        self.llm_url = cleaned_url.rstrip('/')
        self.model_name = model_name
        self.endpoint_path = endpoint_path
        self.completion_url = f"{self.llm_url}{self.endpoint_path}"
        self.api_token = api_token
        self.timeout = timeout
        self.session = requests.Session()
        self.output_dir = Path(output_dir)
        
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        if self.api_token:
            headers['Authorization'] = f'Bearer {self.api_token}'
        self.session.headers.update(headers)
        
        self._setup_korean_font()


        log_step("AI 분석기 초기화")
        print(f"LLM 기본 URL: {Color.cyan(self.llm_url)}")
        if self.model_name:
            print(f"사용 모델: {Color.cyan(self.model_name)}")

    def _setup_korean_font(self):
        """[폰트 해결] 스크립트 실행 환경에 구애받지 않도록 나눔고딕 폰트를 자동으로 다운로드하여 설정합니다."""
        if not plt:
            return

        font_filename = "NanumGothicBold.ttf"
        font_url = f"https://github.com/google/fonts/raw/main/ofl/nanumgothic/{font_filename}"
        
        # 스크립트와 동일한 디렉토리에 폰트 저장
        font_path = Path(__file__).parent / font_filename

        try:
            if not font_path.exists():
                print(Color.info(f"'{font_filename}' 폰트를 찾을 수 없습니다. 다운로드를 시작합니다..."))
                print(f"URL: {Color.cyan(font_url)}")
                urllib.request.urlretrieve(font_url, font_path)
                print(Color.success(f"✅ 폰트 다운로드 완료: {font_path}"))
            
            # matplotlib에 폰트 추가
            if font_path.exists():
                fm.fontManager.addfont(str(font_path))
                # 폰트 이름은 파일 이름에서 확장자를 뺀 것과 다를 수 있으므로, FontProperties로 정확히 가져옴
                font_prop = fm.FontProperties(fname=str(font_path))
                font_name = font_prop.get_name() # 'NanumGothic'
                
                plt.rc('font', family=font_name)
                # 마이너스 기호 깨짐 방지
                plt.rc('axes', unicode_minus=False)
                print(Color.success(f"✅ Matplotlib 그래프 폰트를 '{font_name}'으로 설정했습니다."))
            else:
                 raise FileNotFoundError("폰트 다운로드 후에도 파일을 찾을 수 없음")

        except Exception as e:
            print(Color.error(f"❌ 한글 폰트 설정 중 오류 발생: {e}"))
            print(Color.warn("  -> 그래프의 한글이 깨질 수 있습니다. 네트워크 연결을 확인하거나 수동으로 폰트를 설치해주세요."))

    def list_available_models(self):
        log_step(f"'{self.llm_url}' 서버에서 사용 가능한 모델 목록 조회")
        models_url = f"{self.llm_url}/v1/models"
        try:
            response = self.session.get(models_url, timeout=20)
            if response.status_code != 200:
                print(Color.error(f"❌ 모델 목록 조회 실패: HTTP {response.status_code}, 내용: {response.text[:200]}"))
                return

            models_data = response.json()
            if 'data' in models_data and models_data['data']:
                print(Color.header("\n--- 사용 가능한 모델 ---"))
                for model in models_data['data']:
                    print(f"- {model.get('id')}")
                print(Color.header("------------------------\n"))
            else:
                print(Color.error("❌ 응답에서 모델 목록을 찾을 수 없습니다."))
        except requests.exceptions.RequestException as e:
            print(Color.error(f"❌ 모델 목록 조회 중 네트워크 오류 발생: {e}"))

    def check_llm_service(self, max_retries: int = 3) -> bool:
        log_step("LLM 서비스 상태 확인")
        for attempt in range(max_retries):
            try:
                response = self.session.get(self.llm_url, timeout=10)
                if response.status_code in [200, 404, 401, 403]:
                    print(Color.success(f"✅ LLM 서비스 연결 성공 (시도 {attempt + 1}/{max_retries})"))
                    return True
            except requests.exceptions.RequestException as e:
                print(Color.warn(f"연결 시도 {attempt + 1} 실패: {e}"))
            if attempt < max_retries - 1:
                time.sleep(5)
        print(Color.error("❌ 3번 시도 후에도 LLM 서비스에 연결할 수 없습니다"))
        return False

    def test_llm_connection(self) -> bool:
        if not self.model_name:
            print(Color.warn("⚠️ 모델 이름이 지정되지 않아 연결 테스트를 건너뜁니다."))
            return False
        log_step("LLM 연결 테스트")
        try:
            test_payload = {"model": self.model_name, "messages": [{"role": "user", "content": "Connection test. Reply with 'OK'."}], "max_tokens": 10}
            response = self.session.post(self.completion_url, json=test_payload, timeout=30)
            if response.status_code == 200:
                result = response.json()
                if 'choices' in result and result.get('choices'):
                    print(Color.success(f"✅ 연결 테스트 성공: {result['choices'][0]['message']['content'].strip()}"))
                    return True
            print(Color.error(f"❌ 연결 테스트 실패: HTTP {response.status_code}, 내용: {response.text[:200]}"))
            return False
        except Exception as e:
            print(Color.error(f"❌ 연결 테스트 중 예외 발생: {e}"))
            return False

    def perform_ai_analysis(self, prompt: str, is_news_request: bool = False, base_name: Optional[str] = None) -> Any:
        log_step("AI 분석 시작")
        max_retries = 3
        wait_time = 2  # Initial wait time in seconds

        llm_log_path = None
        if is_news_request:
            log_filename = f"{base_name}_llm_security_news.log" if base_name else "llm_security_news.log"
            if not base_name:
                print(Color.warn("⚠️ 경고: base_name이 제공되지 않아 기본 로그 파일명을 사용합니다: llm_security_news.log"))
            llm_log_path = self.output_dir / log_filename

        for attempt in range(max_retries):
            try:
                payload = {
                    "model": self.model_name,
                    "messages": [
                        {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": 16384, 
                    "temperature": 0.1,
                }
                start_time = time.time()
                print(f"LLM API 호출 중... (시도 {attempt + 1}/{max_retries})")

                if llm_log_path and attempt == 0:
                    with open(llm_log_path, 'a', encoding='utf-8') as f:
                        f.write(f"\n\n--- NEW PROMPT ({datetime.now()}) ---\n")
                        f.write(prompt)
                        f.write("\n\n--- LLM RESPONSE ---\n")
                    print(Color.header("\n--- LLM에게 보낸 보안 뉴스 프롬프트 ---"))
                    print(prompt[:500] + "...")
                    print(f"자세한 내용은 {Color.cyan(llm_log_path)} 파일을 참조하세요.")
                    print(Color.header("-------------------------------------\n"))

                response = self.session.post(self.completion_url, json=payload, timeout=self.timeout)
                print(f"API 응답 시간: {time.time() - start_time:.2f}초")

                if response.status_code == 200:
                    result = response.json()
                    if 'choices' not in result or not result['choices']:
                        raise ValueError(f"API 응답에 'choices' 키가 없거나 비어 있습니다. 응답: {result}")
                    
                    ai_response = result['choices'][0]['message']['content']
                    if llm_log_path:
                        with open(llm_log_path, 'a', encoding='utf-8') as f:
                            f.write(ai_response)
                    return self._parse_ai_response_json_only(ai_response)

                if 500 <= response.status_code < 600:
                    error_message = f"API 서버 오류 (HTTP {response.status_code})"
                    print(Color.warn(f"⚠️ {error_message}. {wait_time}초 후 재시도합니다."))
                    time.sleep(wait_time)
                    wait_time *= 2
                    continue
                
                else:
                    raise ValueError(f"API 호출 실패 (재시도 불가): HTTP {response.status_code}, 내용: {response.text[:500]}")

            except (requests.exceptions.RequestException, ValueError) as e:
                print(Color.warn(f"⚠️ AI 분석 중 오류 발생 (시도 {attempt + 1}/{max_retries}): {e}"))
                if attempt < max_retries - 1:
                    time.sleep(wait_time)
                    wait_time *= 2
                else:
                    raise Exception(f"AI 분석 중 최종 오류 발생: {e}")

    def create_analysis_prompt(self, sosreport_data: Dict[str, Any], anonymize: bool = True) -> str:
        """[개선] 강화된 데이터(성능분석, 커널파라미터 등)를 포함하는 AI 분석 프롬프트를 생성합니다."""
        log_step("AI 분석 프롬프트 생성")
        
        # [개선] 기존 성능 요약 대신, 새로운 분석 데이터를 프롬프트에 포함
        data_to_send = {
            "system_info": sosreport_data.get("system_info"),
            "storage": sosreport_data.get("storage"),
            "failed_services": sosreport_data.get("failed_services"),
            "process_stats_summary": {
                "total": sosreport_data.get("process_stats", {}).get("total"),
                "zombie_count": len(sosreport_data.get("process_stats", {}).get("zombie", [])),
                "uninterruptible_count": len(sosreport_data.get("process_stats", {}).get("uninterruptible", []))
            },
            # --- 신규 데이터 추가 ---
            "performance_analysis": sosreport_data.get("performance_analysis"),
            "critical_log_events": sosreport_data.get("critical_log_events"),
            "general_log_analysis": sosreport_data.get("general_log_analysis"),
            "kernel_parameters": sosreport_data.get("kernel_parameters"),
            "selinux_status": sosreport_data.get("selinux_status")
        }

        # if anonymize:
        #     print("민감 정보 익명화 작업 수행 중...")
        #     anonymizer = DataAnonymizer()
        #     # 시스템 정보에서 호스트명을 추출하여 특정 호스트명으로 등록
        #     specific_hostnames = []
        #     hostname = sosreport_data.get("system_info", {}).get("hostname")
        #     if hostname:
        #         specific_hostnames.append(hostname)
        #     
        #     data_to_send = anonymizer.anonymize_data(data_to_send, specific_hostnames)
        #     print("✅ 익명화 완료. IP, 호스트명, MAC 주소가 마스킹되었습니다.")

        data_str = json.dumps(data_to_send, indent=2, ensure_ascii=False, default=json_serializer)

        prompt = f"""당신은 Red Hat Enterprise Linux 시스템의 문제를 해결하는 최고 수준의 전문가입니다. 다음 sosreport에서 추출한 '시스템 요약', '성능 분석', **'로그 분석'**, 그리고 **'커널 파라미터'** 데이터를 종합적으로 검토하여, 전문가 수준의 진단과 해결책을 **한국어**로 제공해주세요.

## 분석 데이터
```json
{data_str}
```

## 분석 가이드라인
1.  **critical_log_events (심각 로그 이벤트) 최우선 분석**: 이 데이터는 시스템에서 발생한 핵심 오류와 그 당시의 시스템 상태를 연결한 것입니다. 각 이벤트의 `log_message`와 `correlated_context`를 함께 분석하여 문제의 **근본 원인**을 추론하세요.
    * **예시**: `event_type`이 'I/O Error'이고, `correlated_context`에 높은 `iowait` 수치와 `dmesg`의 디스크 에러가 함께 있다면, 이는 애플리케이션 문제가 아닌 명백한 스토리지 하드웨어 또는 드라이버 문제입니다. 따라서 권장사항은 '디스크 상태 점검(smartctl), 스토리지 시스템 확인'이 되어야 합니다.
    * **예시**: `event_type`이 'Out of Memory'이고, `correlated_context`에 특정 프로세스가 메모리를 과도하게 사용한 `dmesg_oom_details`가 있다면, 해당 프로세스의 메모리 누수나 설정 오류를 의심해야 합니다.

2.  **performance_analysis (성능 분석) 결과와 연계**: `performance_analysis`에 `io_bottleneck`이나 `cpu_bottleneck`과 같은 진단이 있다면, 이를 `critical_log_events`나 `general_log_analysis`와 연관 지어 설명하세요.
    * **예시**: `performance_analysis`에 `io_bottleneck`이 있고, `general_log_analysis`에 `nfs_server_not_responding` 카운트가 높다면, 이는 로컬 스토리지가 아닌 NFS 성능 문제일 가능성이 높다고 추론할 수 있습니다.

3.  **kernel_parameters (커널 파라미터) 확인**: 비표준으로 설정된 커널 파라미터가 관찰된 문제(예: `performance_analysis`의 `swap_usage`와 `vm.swappiness` 값)와 관련이 있는지 분석하세요. SELinux가 `Enforcing` 모드가 아닌 경우, 보안상 위험 요소로 반드시 언급해야 합니다.

4.  **심각한 이슈(critical_issues) 판단 기준**: `critical_log_events`에 포함된 모든 이벤트는 잠재적으로 심각한 문제입니다. 특히 'I/O Error', 'Out of Memory', 'Hardware Error', 'Kernel Call Trace'는 시스템 다운이나 데이터 손상을 유발할 수 있으므로 **반드시 '심각한 이슈'로 분류**하고, 상관관계 분석 컨텍스트를 기반으로 구체적인 위험성을 설명해야 합니다. `performance_analysis`에서 진단된 내용도 심각도에 따라 여기에 포함될 수 있습니다.

5.  **경고(warnings) 판단 기준**: `general_log_analysis`에서 빈도가 높은 항목(예: `network_link_flap`), `failed_services` 목록, 잘못된 커널 파라미터 설정 등을 '경고'로 분류합니다.

6.  **권장사항(recommendations) 구체화**: 모든 권장사항은 분석 데이터에 기반해야 합니다. '어떤 문제(issue)'가 '어떤 해결책(solution)'으로 이어지는지 명확히 제시하고, 가능하다면 `related_logs` 필드에 근거가 된 `critical_log_events`의 `log_message`를 포함하여 신뢰도를 높여주세요.

## 최종 출력 형식
**모든 `critical_issues`, `warnings`, `recommendations`, `summary` 필드의 내용은 반드시 자연스러운 한국어로 작성해주세요.**

```json
{{
  "system_status": "정상|주의|위험",
  "overall_health_score": 100,
  "critical_issues": ["상관관계 분석 및 성능 분석을 기반으로 식별된 심각한 문제들의 구체적인 설명"],
  "warnings": ["주의가 필요한 로그 패턴, 서비스 실패, 커널 설정 등의 사항"],
  "recommendations": [
    {{
      "priority": "높음|중간|낮음",
      "category": "성능|보안|안정성|유지보수",
      "issue": "근본 원인에 대한 설명 (데이터 기반)",
      "solution": "구체적이고 실행 가능한 해결 방안 (관련 명령어 포함 권장)",
      "related_logs": ["이 권장사항의 근거가 된 특정 로그 메시지(들)"]
    }}
  ],
  "summary": "전체적인 시스템 상태와 로그/성능/커널 파라미터의 종합 분석을 통해 발견된 핵심 문제, 그리고 가장 시급한 권장사항에 대한 종합 요약"
}}
```

**중요**: 당신의 전체 응답은 오직 위 형식의 단일 JSON 객체여야 합니다. JSON 객체 앞뒤로 어떠한 설명, 요약, 추론 과정도 포함하지 마십시오.
"""
        return prompt

    def _parse_ai_response_json_only(self, ai_response: str) -> Any:
        print(Color.info("AI 응답 파싱 중..."))
        
        if not ai_response or not ai_response.strip():
            raise ValueError("AI 응답이 비어 있습니다.")

        refusal_patterns = ["i'm sorry", "i cannot", "i can't", "i am unable", "죄송합니다", "할 수 없습니다"]
        if any(pattern in ai_response.lower() for pattern in refusal_patterns):
            raise ValueError(f"LLM이 요청 처리를 거부했습니다. (응답: '{ai_response.strip()}')")

        try:
            cleaned_response = re.sub(r'^```(json)?\s*|\s*```$', '', ai_response.strip())
            return json.loads(cleaned_response)
        except json.JSONDecodeError as e:
            error_message = f"AI 응답 JSON 파싱 실패: {e}.\n--- 원본 응답 ---\n{ai_response}\n----------------"
            print(Color.error(error_message))
            raise ValueError(error_message)
        except Exception as e:
            error_message = f"AI 응답 처리 중 예측하지 못한 오류 발생: {e}.\n--- 원본 응답 ---\n{ai_response}\n----------------"
            print(Color.error(error_message))
            raise ValueError(error_message)

    def fetch_security_news(self, sos_data: Dict[str, Any], base_name: str) -> List[Dict[str, str]]:
        """
        ### 변경사항 ###
        LLM을 활용한 2단계 CVE 분석 및 선정 로직을 도입했습니다.
        1. 1단계: 최대 40개의 후보 CVE를 '패키지당 1개' 원칙으로 광범위하게 수집합니다.
        2. 2단계: 수집된 후보군을 시스템 정보와 함께 LLM에 보내 '긴급도'를 분석하고, 가장 시급한 CVE 최대 10개를 최종 선정합니다.
        3. 3단계: 선정된 10개의 CVE에 대해서만 사용자 친화적인 설명 번역을 요청합니다.
        """
        log_step("최신 RHEL 보안 뉴스 조회 및 분석 (고도화된 2단계 프로세스)")
        
        installed_packages_full = sos_data.get("installed_packages", [])
        if not installed_packages_full:
            reason = "sosreport에 설치된 패키지 정보(installed-rpms)가 없어 CVE 연관성을 분석할 수 없습니다."
            print(Color.warn(f"⚠️ {reason}"))
            return [{"reason": reason}]

        try:
            installed_packages_map = {re.sub(r'-[\d.:].*', '', pkg): pkg for pkg in installed_packages_full}
            installed_package_names_only = set(installed_packages_map.keys())
            system_info = sos_data.get("system_info", {})
            os_version = system_info.get("os_version", "N/A")
            kernel_version = system_info.get("kernel", "N/A")

            # [수정] 오프라인 CVE 데이터 파일 경로
            cve_data_path = "/data/iso/AIBox/cve_data.json"
            print(f"분석 대상 시스템: {os_version} (Kernel: {kernel_version})")
            print(f"오프라인 CVE 데이터 파일 로드: {Color.cyan(cve_data_path)}")

            try:
                with open(cve_data_path, 'r', encoding='utf-8') as f:
                    all_cves = json.load(f)
            except FileNotFoundError:
                print(Color.error(f"❌ CVE 데이터 파일을 찾을 수 없습니다: {cve_data_path}"))
                return [{"reason": f"CVE 데이터 파일({cve_data_path})을 찾을 수 없습니다."}]
            except json.JSONDecodeError as e:
                print(Color.error(f"❌ CVE 데이터 파일 JSON 파싱 실패: {e}"))
                return [{"reason": f"CVE 데이터 파일({cve_data_path})의 형식이 올바르지 않습니다."}]

            print(f"총 {len(all_cves)}개의 CVE 데이터를 Red Hat에서 가져왔습니다.")
            
            # --- 1단계: 후보 CVE 광범위하게 수집 ---
            now = datetime.now()
            start_date = now - timedelta(days=365) # 최근 1년 데이터 필터
            
            system_relevant_cves = []
            added_cve_ids = set()
            severity_order = {"critical": 2, "important": 1, "moderate": 0, "low": -1}

            for cve in all_cves:
                cve_id = cve.get('CVE')
                public_date_str = cve.get('public_date')

                if not all([cve_id, public_date_str]) or cve_id in added_cve_ids:
                    continue
                
                try:
                    cve_date_str_no_ms = public_date_str.split('.')[0].replace('Z', '')
                    cve_date = datetime.strptime(cve_date_str_no_ms, '%Y-%m-%dT%H:%M:%S')
                except ValueError:
                    continue
                
                severity_value = cve.get('severity')
                severity = severity_value.lower() if isinstance(severity_value, str) else 'low'

                # 심각도 'Critical', 'Important' 필터
                if not (start_date <= cve_date <= now and severity in ["critical", "important"]):
                    continue
                
                is_relevant = False
                matched_package_full_name = "N/A"
                for pkg_str in cve.get('affected_packages', []):
                    pkg_name_match = re.match(r'^([a-zA-Z0-9_.+-]+)-', pkg_str)
                    if pkg_name_match:
                        pkg_name = pkg_name_match.group(1)
                        if pkg_name in installed_package_names_only:
                            is_relevant = True
                            matched_package_full_name = installed_packages_map.get(pkg_name, "N/A")
                            break
                
                if is_relevant:
                    cve['matched_package'] = matched_package_full_name
                    system_relevant_cves.append(cve)
                    added_cve_ids.add(cve_id)

            print(f"시스템에 영향을 주는 CVE를 총 {len(system_relevant_cves)}개 발견했습니다.")
            system_relevant_cves.sort(key=lambda x: (severity_order.get(x.get('severity', 'low').lower(), -1), x.get('public_date')), reverse=True)
            
            # --- 1단계 선정 로직: 패키지당 1개, 최대 40개 ---
            initial_candidate_cves = []
            selected_packages = set()
            MAX_INITIAL_CVES = 40 # ### 변경: 최대 후보군 40개로 상향 ###

            for cve in system_relevant_cves:
                if len(initial_candidate_cves) >= MAX_INITIAL_CVES:
                    break

                pkg_full_name = cve.get('matched_package', '')
                if not pkg_full_name: continue
                
                pkg_name_match = re.match(r'^([a-zA-Z0-9_.+-]+)-', pkg_full_name)
                if not pkg_name_match: continue
                
                pkg_base_name = pkg_name_match.group(1)

                if pkg_base_name not in selected_packages:
                    initial_candidate_cves.append(cve)
                    selected_packages.add(pkg_base_name)

            print(f"1단계 분석: 시스템 관련 CVE 후보군 {len(initial_candidate_cves)}개를 선별했습니다. (패키지당 1개, 최대 {MAX_INITIAL_CVES}개)")

            if not initial_candidate_cves:
                reason = "시스템에 설치된 패키지에 직접적인 영향을 주는 최신 보안 뉴스가 없습니다."
                print(reason)
                return [{"reason": reason}]

            # --- 2단계: LLM을 통한 긴급도 분석 및 최종 10개 선정 ---
            cves_for_ranking = []
            for cve in initial_candidate_cves:
                cves_for_ranking.append({
                    "cve_id": cve.get('CVE'),
                    "severity": cve.get('severity'),
                    "cvss3_score": cve.get('cvss3_score'),
                    "description": cve.get('bugzilla_description', '요약 정보 없음'),
                    "matched_package": cve.get('matched_package')
                })

            ranking_prompt = f"""
[시스템 역할]
당신은 Red Hat Enterprise Linux(RHEL) 시스템의 보안을 책임지는 최고 수준의 사이버 보안 분석가입니다.

[분석 대상 시스템 정보]
- OS 버전: {os_version}
- 커널 버전: {kernel_version}

[임무]
아래에 제공된 CVE 후보 목록을 분석하여, 주어진 시스템 환경에서 가장 시급하게 조치해야 할 **최대 {self.MAX_FINAL_CVES}개의 CVE를 선정**하십시오.

[평가 기준]
단순히 CVSS 점수나 심각도 등급만으로 판단하지 마십시오. 다음 기준을 종합적으로 고려하여 "실제적인 위협"과 "긴급성"을 평가해야 합니다.
1.  **공격 벡터(Attack Vector):** 원격(Remote)에서 인증 없이 공격 가능한 취약점을 최우선으로 고려합니다.
2.  **공격 복잡도(Attack Complexity):** 공격이 쉽고 간단할수록 긴급도가 높습니다.
3.  **필요 권한(Privileges Required):** 공격에 특별한 권한이 필요 없을수록 위험합니다.
4.  **영향(Impact):** 시스템 전체를 장악할 수 있는 '코드 실행(Code Execution)'이나 '권한 상승(Privilege Escalation)'으로 이어지는 취약점의 우선순위를 높게 평가합니다.
5.  **패키지 중요도:** `kernel`, `openssl`, `glibc`, `systemd`, `coreutils`, `openssh`, `sudo`와 같은 시스템 핵심 패키지의 취약점은 더 위험합니다.

[입력 데이터: CVE 후보 목록]
```json
{json.dumps(cves_for_ranking, indent=2, ensure_ascii=False)}
```

[출력 형식]
분석 결과를 바탕으로, 가장 긴급도가 높다고 판단되는 CVE의 ID를 **순서대로** 포함하는 JSON 객체 하나만을 출력하십시오. 객체에는 "most_urgent_cves" 라는 키만 포함되어야 하며, 값은 CVE ID 문자열의 배열이어야 합니다.

```json
{{
  "most_urgent_cves": [
    "CVE-XXXX-YYYY",
    "CVE-AAAA-BBBB",
    ...
  ]
}}
```
**중요**: 당신의 응답은 반드시 위의 JSON 형식이어야 합니다. 다른 설명이나 분석 과정을 절대 포함하지 마십시오.
"""
            
            print(f"2단계 분석: LLM에게 {len(initial_candidate_cves)}개 CVE의 긴급도 분석 및 상위 {self.MAX_FINAL_CVES}개 선정을 요청합니다.")
            ranking_result = self.perform_ai_analysis(ranking_prompt, is_news_request=True, base_name=base_name)
            
            top_cve_ids = []
            if isinstance(ranking_result, dict) and 'most_urgent_cves' in ranking_result:
                top_cve_ids = ranking_result['most_urgent_cves']
                print(Color.success(f"✅ LLM이 선정한 긴급 CVE 목록 ({len(top_cve_ids)}개): {', '.join(top_cve_ids)}"))
            else:
                print(Color.warn(f"⚠️ LLM의 긴급도 분석 응답 형식이 올바르지 않아, 심각도 순으로 상위 {self.MAX_FINAL_CVES}개를 자동 선정합니다."))
                top_cve_ids = [cve['CVE'] for cve in initial_candidate_cves[:self.MAX_FINAL_CVES]]

            # LLM이 선정한 ID를 기반으로 최종 CVE 목록 필터링
            initial_cves_map = {cve['CVE']: cve for cve in initial_candidate_cves}
            final_report_cves = [initial_cves_map[cve_id] for cve_id in top_cve_ids if cve_id in initial_cves_map]

            print(f"최종 리포트에 포함할 CVE {len(final_report_cves)}개를 선정했습니다.")
            if not final_report_cves: return [{"reason": "LLM 분석 결과, 보고서에 포함할 만한 긴급 CVE가 없습니다."}]

            # --- 3단계: 최종 선정된 CVE에 대한 설명 번역 ---
            processing_data = [{"cve_id": cve['CVE'], "description": cve.get('bugzilla_description', '요약 정보 없음')} for cve in final_report_cves]

            translation_prompt = f"""
[시스템 역할]
당신은 Red Hat Enterprise Linux(RHEL) 보안 전문가입니다. 당신의 임무는 주어진 각 CVE의 영문 기술 설명을 분석하여, 시스템 관리자가 쉽게 이해할 수 있도록 핵심 내용과 시스템에 미치는 영향을 중심으로 자연스러운 한국어로 요약 및 설명하는 것입니다.

[입력 데이터]
```json
{json.dumps(processing_data, indent=2, ensure_ascii=False)}
```

[출력 지시]
아래 JSON 형식에 맞춰, 각 CVE에 대한 알기 쉬운 요약 설명을 포함하여 출력하십시오.
**중요**: 당신의 응답은 반드시 아래 JSON 형식의 객체여야 합니다. 어떠한 설명이나 추가 텍스트도 포함하지 마십시오.

```json
{{
  "processed_cves": [
    {{
      "cve_id": "CVE-XXXX-XXXX",
      "translated_description": "해당 CVE의 핵심 위협과 시스템에 미치는 영향에 대한 쉽고 명확한 한국어 요약 설명"
    }}
  ]
}}
```
"""
            print("3단계 분석: 최종 선정된 CVE에 대한 설명 번역을 LLM에 요청합니다.")
            processed_result = self.perform_ai_analysis(translation_prompt, is_news_request=True, base_name=base_name)

            final_cves_with_translation = []
            if isinstance(processed_result, dict) and 'processed_cves' in processed_result:
                processed_map = {item['cve_id']: item for item in processed_result['processed_cves']}
                for cve_data in final_report_cves:
                    cve_id = cve_data['CVE']
                    if cve_id in processed_map:
                        processed_info = processed_map[cve_id]
                        cve_date_str = cve_data.get('public_date', '')
                        if cve_date_str:
                            try:
                                cve_date_str_no_ms = cve_date_str.split('.')[0].replace('Z', '')
                                cve_data['public_date'] = datetime.strptime(cve_date_str_no_ms, '%Y-%m-%dT%H:%M:%S').strftime('%y/%m/%d')
                            except ValueError: pass
                        
                        cve_data['bugzilla_description'] = processed_info.get('translated_description', cve_data['bugzilla_description'])
                        final_cves_with_translation.append(cve_data)
                        print(Color.success(f"✅ 보안 뉴스 처리 완료: {cve_id}"))
            else:
                print(Color.warn("⚠️ LLM의 번역 처리에 실패했습니다. 원본 데이터로 보고서를 생성합니다."))
                final_cves_with_translation = final_report_cves

            print(Color.success("✅ 보안 뉴스 조회 및 처리 완료."))
            return final_cves_with_translation

        except Exception as e:
            print(Color.error(f"❌ 보안 뉴스 조회 중 심각한 오류 발생: {e}"))
            import traceback
            traceback.print_exc()
            return [{"reason": f"보안 뉴스 조회 중 오류가 발생했습니다: {e}"}]

    def create_performance_graphs(self, sos_data: Dict[str, Any]) -> Dict[str, str]:
        """성능 데이터를 바탕으로 CPU, Memory, Network, Disk I/O, Load Average 그래프를 생성합니다."""
        if not plt:
            print(Color.warn("⚠️ 그래프 생성을 건너뜁니다. 'matplotlib' 라이브러리를 설치하세요."))
            return {}

        log_step("성능 그래프 생성")
        # [수정] graphs 딕셔너리를 try 블록 바깥에서 먼저 초기화하여 변수 정의를 보장합니다.
        graphs = {}
        try:
            plt.style.use('seaborn-whitegrid')
        except OSError:
            print(Color.warn("⚠️ 'seaborn-whitegrid' 스타일을 찾을 수 없어 'ggplot'으로 대체합니다."))
            plt.style.use('ggplot')
        except Exception as e:
            print(Color.warn(f"⚠️ Matplotlib 스타일 설정 중 오류 발생: {e}"))

        perf_data = sos_data.get("performance_data", {})
        ip4_details = sos_data.get("ip4_details", [])
        interface_states = {iface.get('iface'): iface.get('state', 'unknown').upper() for iface in ip4_details}

        graph_style = {
            'figsize': (12, 6), 'title_fontsize': 16, 'label_fontsize': 12,
            'tick_rotation': 30, 'alpha': 0.7
        }
        
        # --- CPU 그래프 ---
        if perf_data.get('cpu') and len(perf_data['cpu']) > 1:
            # [개선] CPU 그래프 생성 성공/실패에 따라 graphs 딕셔너리에 결과 저장
            graphs['cpu_graph'] = "데이터 없음: CPU 통계(-u)가 수집되지 않았거나 데이터 포인트가 부족합니다."
            try:
                # CPU 데이터는 파서에서 이미 float으로 변환됨 (개선된 파서 기준)
                cpu_data, timestamps = perf_data['cpu'], [d['timestamp'] for d in perf_data['cpu']]
                user, system, iowait = [d['user'] for d in cpu_data], [d['system'] for d in cpu_data], [d['iowait'] for d in cpu_data]
                
                fig, ax = plt.subplots(figsize=graph_style['figsize'])
                ax.stackplot(timestamps, user, system, iowait, 
                             labels=['User %', 'System %', 'I/O Wait %'], 
                             colors=['#4C72B0', '#DD8452', '#C44E52'], alpha=0.7)
                
                # ax.set_title('CPU Usage (%)', fontsize=graph_style['title_fontsize'], weight='bold')
                ax.set_ylabel('Usage (%)', fontsize=graph_style['label_fontsize'])
                ax.legend(loc='upper left', frameon=True)
                ax.set_ylim(0, 100)
                ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
                plt.xticks(rotation=graph_style['tick_rotation'], ha='right')
                plt.tight_layout()
                
                buf = io.BytesIO()
                fig.savefig(buf, format='png', dpi=100)
                graphs['cpu_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
                plt.close(fig)
                print(Color.info("  - CPU 그래프 생성 완료"))
            except Exception as e:
                graphs['cpu_graph'] = f"CPU 그래프 생성 실패: {e}"
                print(Color.warn(f"  - ⚠️ CPU 그래프 생성 실패: {e}"))
        else:
            graphs['cpu_graph'] = "데이터 없음: CPU 통계(-u)가 수집되지 않았거나 데이터 포인트가 부족합니다."

        # --- 메모리(RAM) 상세 그래프 ---
        if perf_data.get('memory') and len(perf_data['memory']) > 1:
            try:
                graphs['memory_graph'] = "데이터 없음: 메모리 통계(-r)가 수집되지 않았거나 데이터 포인트가 부족합니다."
                mem_data = perf_data['memory']
                timestamps = [d['timestamp'] for d in mem_data]

                def get_float_data(key):
                    values = []
                    for d in mem_data:
                        try:
                            value_str = d.get(key, '0.0')
                            values.append(float(value_str.replace(',', '.')))
                        except (ValueError, TypeError):
                            values.append(0.0)
                    return values

                kb_metrics = {
                    'kbmemfree': get_float_data('kbmemfree'),
                    'kbmemused': get_float_data('kbmemused'),
                    'kbbuffers': get_float_data('kbbuffers'),
                    'kbcached': get_float_data('kbcached'),
                    'kbcommit': get_float_data('kbcommit'),
                    'kbactive': get_float_data('kbactive'),
                    'kbinact': get_float_data('kbinact'),
                    'kbdirty': get_float_data('kbdirty')
                }
                
                fig, ax = plt.subplots(figsize=graph_style['figsize'])
                
                for key, values in kb_metrics.items():
                    ax.plot(timestamps, values, label=key, lw=2)
                
                # ax.set_title('Memory Usage (KB)', fontsize=graph_style['title_fontsize'], weight='bold')
                ax.set_ylabel('Kilobytes', fontsize=graph_style['label_fontsize'])
                ax.legend(loc='upper left', frameon=True, fontsize='small', ncol=2)
                ax.grid(True)

                ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
                plt.xticks(rotation=graph_style['tick_rotation'], ha='right')
                
                plt.tight_layout()

                buf = io.BytesIO()
                fig.savefig(buf, format='png', dpi=100)
                graphs['memory_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
                plt.close(fig)
                print(Color.info("  - 메모리 통합 라인 그래프 생성 완료"))
            except Exception as e:
                graphs['memory_graph'] = f"메모리 그래프 생성 실패: {e}"
                print(Color.warn(f"  - ⚠️ 메모리 그래프 생성 실패: {e}"))
        else:
            graphs['memory_graph'] = "데이터 없음: 메모리 통계(-r)가 수집되지 않았거나 데이터 포인트가 부족합니다."

        # --- 네트워크 그래프 (개선된 로직) ---
        if perf_data.get('network') and len(perf_data['network']) > 1:
            network_by_iface = {}
            # [개선] 네트워크 그래프 결과를 담을 딕셔너리 초기화
            graphs['network_graphs'] = {}
            for d in perf_data['network']:
                iface = d.get('IFACE')
                if not iface: continue
                if iface not in network_by_iface: network_by_iface[iface] = []
                network_by_iface[iface].append(d)
            
            print(f"  -> sar 데이터에서 {len(network_by_iface)}개의 네트워크 인터페이스 발견: {', '.join(network_by_iface.keys())}")
            
            network_graphs_generated = False
            inactive_up_interfaces = []

            for iface, data in network_by_iface.items():
                state = interface_states.get(iface, 'UNKNOWN')
                if state != 'UP':
                    print(Color.info(f"  - {iface} 인터페이스는 'State: UP' 상태가 아니므로 그래프를 건너뜁니다. (상태: {state})"))
                    continue

                if len(data) < 2:
                    print(Color.info(f"  - {iface} 인터페이스는 데이터 포인트가 부족하여 그래프를 건너뜁니다."))
                    continue
                
                try:
                    timestamps = [d['timestamp'] for d in data]
                    
                    def get_flexible_net_data(d_list, key_patterns):
                        values = []
                        if not d_list: return []
                        
                        first_item_keys = d_list[0].keys()
                        actual_key = None
                        
                        for pattern in key_patterns:
                            normalized_pattern = pattern.replace('/', '_s')
                            if normalized_pattern in first_item_keys:
                                actual_key = normalized_pattern
                                break
                        
                        if not actual_key: 
                            return [0.0] * len(d_list)

                        for d in d_list:
                            try:
                                value_str = d.get(actual_key, '0.0')
                                values.append(float(value_str.replace(',', '.')))
                            except (ValueError, TypeError):
                                values.append(0.0)
                        return values

                    rxpck = get_flexible_net_data(data, ['rxpck/s', 'rxpck_s'])
                    txpck = get_flexible_net_data(data, ['txpck/s', 'txpck_s'])
                    rxkB = get_flexible_net_data(data, ['rxkB/s', 'rxkB_s'])
                    txkB = get_flexible_net_data(data, ['txkB/s', 'txkB_s'])
                    rxcmp = get_flexible_net_data(data, ['rxcmp/s', 'rxcmp_s'])
                    txcmp = get_flexible_net_data(data, ['txcmp/s', 'txcmp_s'])
                    rxmcst = get_flexible_net_data(data, ['rxmcst/s', 'rxmcst_s'])

                    total_traffic = sum(rxpck) + sum(txpck) + sum(rxkB) + sum(txkB)
                    if total_traffic == 0.0:
                        print(Color.info(f"  - {iface} 인터페이스는 트래픽이 없어 그래프 생성을 건너뜁니다."))
                        inactive_up_interfaces.append(iface)
                        continue

                    fig, ax1 = plt.subplots(figsize=(12, 6))
                    ax2 = ax1.twinx()
                    
                    ax1.plot(timestamps, rxpck, label='rxpck/s', color='tab:blue', linestyle='-')
                    ax1.plot(timestamps, txpck, label='txpck/s', color='tab:cyan', linestyle='-')
                    ax1.plot(timestamps, rxcmp, label='rxcmp/s', color='tab:green', linestyle=':')
                    ax1.plot(timestamps, txcmp, label='limegreen', linestyle=':')
                    ax1.plot(timestamps, rxmcst, label='rxmcst/s', color='tab:gray', linestyle='--')
                    ax1.set_ylabel('Packets/s', color='tab:blue', fontsize=graph_style['label_fontsize'])
                    ax1.tick_params(axis='y', labelcolor='tab:blue')

                    ax2.plot(timestamps, rxkB, label='rxkB/s', color='tab:red', linestyle='-')
                    ax2.plot(timestamps, txkB, label='txkB/s', color='tab:orange', linestyle='-')
                    ax2.set_ylabel('kB/s', color='tab:red', fontsize=graph_style['label_fontsize'])
                    ax2.tick_params(axis='y', labelcolor='tab:red')

                    # ax1.set_title(f'Network Traffic: {iface} (State: {state})', fontsize=graph_style['title_fontsize'], weight='bold')
                    ax1.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
                    plt.setp(ax1.get_xticklabels(), rotation=graph_style['tick_rotation'], ha='right')

                    lines1, labels1 = ax1.get_legend_handles_labels()
                    lines2, labels2 = ax2.get_legend_handles_labels()
                    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', frameon=True, ncol=2, fontsize='small')
                    plt.tight_layout()
                    
                    buf = io.BytesIO()
                    fig.savefig(buf, format='png', dpi=100)
                    graphs['network_graphs'][iface] = base64.b64encode(buf.getvalue()).decode('utf-8')
                    plt.close(fig)
                    network_graphs_generated = True
                    print(Color.info(f"  - 상세 네트워크 그래프 생성 완료: {iface}"))
                except Exception as e:
                    print(Color.warn(f"  - ⚠️ {iface} 인터페이스 그래프 생성 중 오류: {e}"))
                    import traceback
                    traceback.print_exc()

            if not network_graphs_generated:
                if inactive_up_interfaces:
                    reason = f"UP 상태인 인터페이스({', '.join(inactive_up_interfaces)})가 있지만, 기록된 트래픽이 없어 그래프를 생성하지 않았습니다."
                    graphs['network_graphs']['reason'] = reason
                else:
                    graphs['network_graphs']['reason'] = "데이터 부족: 'State: UP' 상태이면서 유효한 성능 데이터를 가진 네트워크 인터페이스가 없습니다."
        else:
             graphs['network_graphs'] = {'reason': "데이터 없음: sar 파일에서 네트워크 통계(-n DEV) 정보를 찾을 수 없습니다."}
        
        # --- 디스크 I/O 그래프 ---
        if perf_data.get('disk') and len(perf_data['disk']) > 1:
            try:
                graphs['disk_graph'] = "데이터 없음: 디스크 통계(-b 또는 -d)가 수집되지 않았거나 데이터 포인트가 부족합니다."
                # [개선] 파서가 단위를 kB/s로 정규화했으므로, 집계 로직이 단순해짐
                disk_agg = {}
                for d in perf_data['disk']:
                    # 모든 디바이스의 I/O를 합산하여 시스템 전체의 I/O 추이를 확인
                    ts = d['timestamp']
                    if ts not in disk_agg: disk_agg[ts] = {'read_kb': 0.0, 'write_kb': 0.0}
                    disk_agg[ts]['read_kb'] += d.get('read_kb_s', 0.0)
                    disk_agg[ts]['write_kb'] += d.get('write_kb_s', 0.0)

                disk_data = sorted([{'timestamp': ts, **data} for ts, data in disk_agg.items()], key=lambda x: x['timestamp'])
                if len(disk_data) > 1:
                    timestamps = [d['timestamp'] for d in disk_data]
                    read_kB, write_kB = [d['read_kb'] for d in disk_data], [d['write_kb'] for d in disk_data]

                    fig, ax = plt.subplots(figsize=graph_style['figsize'])
                    ax.plot(timestamps, read_kB, color='#64B5CD', lw=2, label='Read (kB/s)')
                    ax.fill_between(timestamps, read_kB, color='#64B5CD', alpha=graph_style['alpha'])
                    ax.plot(timestamps, write_kB, color='#C44E52', lw=2, label='Write (kB/s)')
                    ax.fill_between(timestamps, write_kB, color='#C44E52', alpha=graph_style['alpha'])

                    # ax.set_title('Disk I/O (kB/s)', fontsize=graph_style['title_fontsize'], weight='bold')
                    ax.set_ylabel('kB/s', fontsize=graph_style['label_fontsize'])
                    ax.legend(loc='upper left', frameon=True)
                    ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
                    plt.xticks(rotation=graph_style['tick_rotation'], ha='right')
                    plt.tight_layout()

                    buf = io.BytesIO()
                    fig.savefig(buf, format='png', dpi=100)
                    graphs['disk_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
                    plt.close(fig)
                    print(Color.info("  - 디스크 I/O 그래프 생성 완료"))
            except Exception as e:
                graphs['disk_graph'] = f"디스크 I/O 그래프 생성 실패: {e}"
                print(Color.warn(f"  - ⚠️ 디스크 I/O 그래프 생성 실패: {e}"))
        else:
            graphs['disk_graph'] = "데이터 없음: 디스크 통계(-b 또는 -d)가 수집되지 않았거나 데이터 포인트가 부족합니다."
        
        # --- Load Average 그래프 ---
        if perf_data.get('load') and len(perf_data['load']) > 1:
            try:
                graphs['load_average_graph'] = "데이터 없음: 부하 통계(-q)가 수집되지 않았거나 데이터 포인트가 부족합니다."
                # Load Average 데이터는 파서에서 이미 float으로 변환됨 (개선된 파서 기준)
                load_data, timestamps = perf_data['load'], [d['timestamp'] for d in perf_data['load']]
                ldavg_1, ldavg_5, ldavg_15 = [d['ldavg-1'] for d in load_data], [d['ldavg-5'] for d in load_data], [d['ldavg-15'] for d in load_data]

                fig, ax = plt.subplots(figsize=graph_style['figsize'])
                ax.plot(timestamps, ldavg_1, label='Load Avg (1 min)', color='#4C72B0')
                ax.plot(timestamps, ldavg_5, label='Load Avg (5 min)', color='#55A868')
                ax.plot(timestamps, ldavg_15, label='Load Avg (15 min)', color='#C44E52')

                # ax.set_title('System Load Average', fontsize=graph_style['title_fontsize'], weight='bold')
                ax.set_ylabel('Load', fontsize=graph_style['label_fontsize'])
                ax.legend(loc='upper left', frameon=True)
                ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
                plt.xticks(rotation=graph_style['tick_rotation'], ha='right')
                plt.tight_layout()

                buf = io.BytesIO()
                fig.savefig(buf, format='png', dpi=100)
                graphs['load_average_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
                plt.close(fig)
                print(Color.info("  - Load Average 그래프 생성 완료"))
            except Exception as e:
                graphs['load_average_graph'] = f"Load Average 그래프 생성 실패: {e}"
                print(Color.warn(f"  - ⚠️ Load Average 그래프 생성 실패: {e}"))
        else:
            graphs['load_average_graph'] = "데이터 없음: 부하 통계(-q)가 수집되지 않았거나 데이터 포인트가 부족합니다."

        # --- Swap 그래프 ---
        if perf_data.get('swap') and len(perf_data['swap']) > 1:
            try:
                graphs['swap_graph'] = "데이터 없음: 스왑 통계(-S)가 수집되지 않았거나 데이터 포인트가 부족합니다."
                swap_data, timestamps = perf_data['swap'], [d['timestamp'] for d in perf_data['swap']]
                swpused_pct = [d['swpused_pct'] for d in swap_data]

                fig, ax = plt.subplots(figsize=graph_style['figsize'])
                ax.plot(timestamps, swpused_pct, label='Swap Used %', color='#9B59B6')
                ax.fill_between(timestamps, swpused_pct, color='#9B59B6', alpha=0.3)

                # ax.set_title('Swap Usage (%)', fontsize=graph_style['title_fontsize'], weight='bold')
                ax.set_ylabel('Usage (%)', fontsize=graph_style['label_fontsize'])
                ax.legend(loc='upper left', frameon=True)
                ax.set_ylim(0, max(100, max(swpused_pct) * 1.1 if swpused_pct else 100)) # Adjust Y-axis limit
                ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
                plt.xticks(rotation=graph_style['tick_rotation'], ha='right')
                plt.tight_layout()

                buf = io.BytesIO()
                fig.savefig(buf, format='png', dpi=100)
                graphs['swap_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
                plt.close(fig)
                print(Color.info("  - Swap 사용률 그래프 생성 완료"))
            except Exception as e:
                graphs['swap_graph'] = f"Swap 사용률 그래프 생성 실패: {e}"
                print(Color.warn(f"  - ⚠️ Swap 사용률 그래프 생성 실패: {e}"))
        else:
            graphs['swap_graph'] = "데이터 없음: 스왑 통계(-S)가 수집되지 않았거나 데이터 포인트가 부족합니다."
            
        print(Color.success("✅ 모든 성능 그래프 생성 시도 완료."))
        return graphs

    def create_html_report(self, analysis_result: Dict[str, Any], sos_data: Dict[str, Any], graphs: Dict[str, str], output_dir: str, original_file: str) -> str:
        log_step("HTML 보고서 생성")
        
        base_name = Path(original_file).stem.replace('.tar', '')
        report_file = Path(output_dir) / f"{base_name}_report.html"

        status = html.escape(analysis_result.get('system_status', 'N/A'))
        score = analysis_result.get('overall_health_score', 'N/A')
        summary = html.escape(analysis_result.get('summary', '정보 없음')).replace('\n', '<br>')
        critical_issues = analysis_result.get('critical_issues', [])
        warnings = analysis_result.get('warnings', [])
        recommendations = analysis_result.get('recommendations', [])
        
        system_info = sos_data.get('system_info', {})
        ip4_details = sos_data.get('ip4_details', [])
        storage_info = sos_data.get('storage', [])
        security_news = sos_data.get('security_news', [])
        network_details = sos_data.get('network_details', {})
        process_stats = sos_data.get('process_stats', {})

        status_class_map = {"정상": "status-good", "주의": "status-warn", "위험": "status-danger"}
        status_class = status_class_map.get(status, "")

        # SVG 아이콘 정의
        svg_icons = {
            "info": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"></path></svg>""",
            "dashboard": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M13 2.05v3.03c3.39.49 6 3.39 6 6.92 0 .9-.18 1.75-.48 2.54l2.6 1.53c.56-1.24.88-2.62.88-4.07 0-5.18-3.95-9.45-9-9.95zM12 19c-3.87 0-7-3.13-7-7 0-3.53 2.61-6.43 6-6.92V2.05c-5.06.5-9 4.76-9 9.95 0 5.52 4.48 10 10 10 3.31 0 6.24-1.61 8.06-4.09l-2.6-1.53C16.17 17.98 14.21 19 12 19z"></path></svg>""",
            "network": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M23.121 8.879l-1.414 1.414L23.121 11.707l-1.414 1.414 1.414 1.414-1.414 1.414-1.414-1.414-1.414 1.414 1.414 1.414-1.414 1.414-8.485-8.485 1.414-1.414 1.414 1.414 1.414-1.414-1.414-1.414 1.414-1.414 1.414 1.414zm-9.9-1.414l-1.414 1.414-1.414-1.414-1.414 1.414 1.414 1.414-1.414 1.414-8.485-8.485 1.414-1.414 1.414 1.414 1.414-1.414-1.414-1.414 1.414-1.414 1.414 1.414 1.414-1.414 1.414 1.414z"></path></svg>""",
            "cpu": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M9 21h6v-2H9v2zm.5-4.59L11 15V9h-1.5v4.51l-1.79-1.8-1.42 1.42L9.5 16.41zm6.29-1.8L13 16.41V11.5L14.5 10v6l1.79-1.79 1.42 1.42L14.5 18.41zM20 2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h4v-2H4V4h16v12h-4v2h4c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"></path></svg>""",
            "disk": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 14H9V8h2v8zm4 0h-2V8h2v8z"></path></svg>""",
            "critical": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M12 2C6.47 2 2 6.47 2 12s4.47 10 10 10 10-4.47 10-10S17.53 2 12 2zm5 13.59L15.59 17 12 13.41 8.41 17 7 15.59 10.59 12 7 8.41 8.41 7 12 10.59 15.59 7 17 8.41 13.41 12 17 15.59z"></path></svg>""",
            "warning": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"></path></svg>""",
            "idea": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M9 21c0 .55.45 1 1 1h4c.55 0 1-.45 1-1v-1H9v1zM12 2C7.86 2 4.5 5.36 4.5 9.5c0 3.82 2.66 5.86 3.77 6.5h7.46c1.11-.64 3.77-2.68 3.77-6.5C19.5 5.36 16.14 2 12 2z"></path></svg>""",
            "shield": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M12 2L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-3zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V13H5V6.3l7-3.11v10.8z"></path></svg>""",
            "health": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"></path></svg>""",
            "summary_ai": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="icon"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zM9.5 9.5c.83 0 1.5.67 1.5 1.5s-.67 1.5-1.5 1.5-1.5-.67-1.5-1.5.67-1.5 1.5-1.5zm3 5c.83 0 1.5.67 1.5 1.5s-.67 1.5-1.5 1.5-1.5-.67-1.5-1.5.67-1.5 1.5-1.5zm3.5-2.5c.83 0 1.5.67 1.5 1.5s-.67 1.5-1.5 1.5-1.5-.67-1.5-1.5.67-1.5 1.5-1.5z"></path></svg>"""
        }

        # --- Helper functions defined inside the method to avoid scope issues ---
        def create_list_table(items: List[str], empty_message: str) -> str:
            if not items:
                return f"<tr><td colspan='1' style='text-align:center; padding: 1.5rem;'>{html.escape(empty_message)}</td></tr>"
            rows = ""
            for item in items:
                rows += f"<tr><td>{html.escape(str(item))}</td></tr>"
            return rows

        def create_storage_rows(storage_list: List[Dict[str, str]]) -> str:
            rows = ""
            if not storage_list:
                return "<tr><td colspan='6' style='text-align:center;'>데이터 없음</td></tr>"
            
            for item in storage_list:
                rows += f"""
                    <tr>
                        <td>{html.escape(item.get('filesystem', 'N/A'))}</td>
                        <td>{html.escape(item.get('size', 'N/A'))}</td>
                        <td>{html.escape(item.get('used', 'N/A'))}</td>
                        <td>{html.escape(item.get('avail', 'N/A'))}</td>
                        <td>{html.escape(item.get('mounted_on', 'N/A'))}</td>
                """
                use_pct_str = item.get('use%', '0%').replace('%', '')
                try:
                    use_pct = int(use_pct_str)
                    color = "#2ecc71"  # Green
                    if use_pct >= 90:
                        color = "#e74c3c"  # Red
                    elif use_pct >= 80:
                        color = "#f39c12"  # Orange
                    
                    rows += f"""
                        <td style="min-width: 120px;">
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <span>{use_pct}%</span>
                                <div class="progress-bar-container">
                                    <div class="progress-bar" style="width: {use_pct}%; background-color: {color};"></div>
                                </div>
                            </div>
                        </td>
                    </tr>
                    """
                except (ValueError, TypeError):
                     rows += "<td>N/A</td></tr>"
            return rows

        def create_security_news_rows(news_list):
            rows = ""
            if not news_list:
                return "<tr><td colspan='4' style='text-align:center;'>데이터 없음</td></tr>"
            
            if isinstance(news_list, list) and len(news_list) == 1 and 'reason' in news_list[0]:
                reason_text = html.escape(news_list[0]['reason'])
                return f"<tr><td colspan='4' style='text-align:center;'>{reason_text}</td></tr>"

            for item in news_list:
                cve_id = html.escape(item.get('CVE', 'N/A'))
                severity = item.get('severity', '').lower()
                matched_package = html.escape(item.get('matched_package', 'N/A'))
                
                severity_html = f"<td>{html.escape(item.get('severity', 'N/A'))}</td>"
                if severity == 'critical':
                    severity_html = f'<td style="text-align:center;"><div class="tooltip" style="font-size: 1.5em;">🔥<span class="tooltiptext">패키지: {matched_package}</span></div></td>'
                elif severity == 'important':
                    severity_html = f'<td style="text-align:center;"><div class="tooltip" style="font-size: 1.5em;">⚠️<span class="tooltiptext">패키지: {matched_package}</span></div></td>'

                rows += f"""
                    <tr>
                        <td><a href="https://access.redhat.com/security/cve/{cve_id}" target="_blank">{cve_id}</a></td>
                        {severity_html}
                        <td>{html.escape(item.get('public_date', 'N/A'))}</td>
                        <td>{html.escape(item.get('bugzilla_description', 'N/A'))}</td>
                    </tr>
                """
            return rows

        def create_recommendation_rows(recommendations_list):
            rows = ""
            if not recommendations_list:
                return "<tr><td colspan='4' style='text-align:center;'>데이터 없음</td></tr>"
            
            priority_map = {
                "높음": "high",
                "중간": "medium",
                "낮음": "low"
            }
            
            for item in recommendations_list:
                priority_text = item.get('priority', 'N/A')
                priority_class = priority_map.get(priority_text, "")
                
                related_logs = item.get('related_logs', [])
                issue_html = html.escape(str(item.get('issue', 'N/A')))
                if related_logs:
                    logs_html = html.escape('\n'.join(related_logs))
                    issue_html += f' <div class="tooltip"><span class="log-icon">💬</span><span class="tooltiptext">{logs_html}</span></div>'

                rows += f"""
                    <tr>
                        <td><span class="priority-badge {priority_class}">{html.escape(priority_text)}</span></td>
                        <td>{html.escape(str(item.get('category', 'N/A')))}</td>
                        <td>{issue_html}</td>
                        <td>{html.escape(str(item.get('solution', 'N/A')))}</td>
                    </tr>
                """
            return rows
        
        def create_ethtool_rows(ethtool_data):
            rows = ""
            if not ethtool_data:
                return "<tr><td colspan='6' style='text-align:center;'>데이터 없음</td></tr>"

            for iface, data in sorted(ethtool_data.items()):
                link_status = data.get('link_status', 'UNKNOWN').upper()
                link_details = html.escape(data.get('link_details', ''))

                status_html = ""
                if link_status == 'UP':
                    status_html = f'<span style="color: #2ecc71; font-weight: bold;">{link_status}</span> {link_details}'
                elif link_status == 'DOWN':
                    status_html = f'<span style="color: #7f8c8d;">{link_status}</span> {link_details}'
                else:
                    status_html = f'<span style="color: #f39c12;">{link_status}</span> {link_details}'

                errors_html = "없음"
                if 'errors' in data and data['errors']:
                    errors_list = [f"{k}: {v}" for k, v in data['errors'].items()]
                    if len(errors_list) > 3:
                        visible_errors = "<br>".join(html.escape(e) for e in errors_list[:3])
                        hidden_errors = html.escape("\n".join(errors_list[3:]))
                        errors_html = f'{visible_errors}<br><div class="tooltip">...외 {len(errors_list)-3}개<span class="tooltiptext">{hidden_errors}</span></div>'
                    else:
                        errors_html = "<br>".join(html.escape(e) for e in errors_list)

                rows += f"""
                <tr>
                    <td>{html.escape(iface)}</td>
                    <td>{html.escape(data.get('pci_bus', 'N/A'))}</td>
                    <td>{status_html}</td>
                    <td>rx ring {html.escape(data.get('rx_ring', 'N/A'))}</td>
                    <td>{html.escape(data.get('driver_info', 'N/A'))}</td>
                    <td>{errors_html}</td>
                </tr>
                """
            return rows

        def create_bonding_rows(bonding_data):
            rows = ""
            if not bonding_data: return "<tr><td colspan='3' style='text-align:center;'>데이터 없음</td></tr>"
            
            # [개선] xsos 스타일로 마스터와 슬레이브 정보를 상세히 표시
            for bond in bonding_data:
                master_status = bond.get('mii_status', 'N/A')
                status_color = 'color: #2ecc71;' if master_status == 'up' else 'color: #e74c3c;'
                rows += f"""
                <tr style="background-color: #f0f5f9; font-weight: bold;">
                    <td>{html.escape(bond.get('device', 'N/A'))}</td>
                    <td style="{status_color}">{html.escape(master_status.upper())}</td>
                    <td colspan="2">{html.escape(bond.get('mode', 'N/A'))}</td>
                </tr>
                """
                for slave in bond.get('slaves_info', []):
                    slave_status = slave.get('mii_status', 'N/A')
                    slave_row_style = 'background-color: #fffbe6;' if slave_status != 'up' else ''
                    rows += f"""
                    <tr style="{slave_row_style}">
                        <td style="padding-left: 2.5rem;">- {html.escape(slave.get('name', 'N/A'))}</td>
                        <td>{html.escape(slave_status)}</td>
                        <td>{html.escape(slave.get('speed', 'N/A'))}, {html.escape(slave.get('duplex', 'N/A'))}</td>
                        <td>Failures: {html.escape(slave.get('link_failures', 'N/A'))}</td>
                    </tr>
                    """
            return rows

        def create_netdev_rows(netdev_data):
            rows = ""
            if not netdev_data: return "<tr><td colspan='9' style='text-align:center;'>데이터 없음</td></tr>"
            for dev in netdev_data:
                rows += f"""
                <tr>
                    <td>{html.escape(dev.get('iface', 'N/A'))}</td>
                    <td>{dev.get('rx_bytes', 0):,}</td>
                    <td>{dev.get('rx_packets', 0):,}</td>
                    <td style="color: #e74c3c;">{dev.get('rx_errs', 0):,}</td>
                    <td style="color: #e74c3c;">{dev.get('rx_drop', 0):,}</td>
                    <td>{dev.get('tx_bytes', 0):,}</td>
                    <td>{dev.get('tx_packets', 0):,}</td>
                    <td style="color: #e74c3c;">{dev.get('tx_errs', 0):,}</td>
                    <td style="color: #e74c3c;">{dev.get('tx_drop', 0):,}</td>
                </tr>
                """
            return rows
        
        def create_process_table_rows(process_list, empty_message, include_mem=False):
            if not process_list:
                return f"<tr><td colspan='11' style='text-align:center;'>{empty_message}</td></tr>"
            rows = ""
            for p in process_list:
                command = html.escape(p.get('command', ''))
                command_short = command[:100] + '...' if len(command) > 100 else command
                
                mem_cols = ''
                if include_mem:
                    mem_cols = f"""
                        <td>{html.escape(str(p.get('mem%', '')))}</td>
                        <td>{html.escape(p.get('rss_formatted', 'N/A'))}</td>
                    """

                rows += f"""
                    <tr>
                        <td>{html.escape(p.get('user', ''))}</td>
                        <td>{html.escape(p.get('pid', ''))}</td>
                        <td>{html.escape(str(p.get('cpu%', '')))}</td>
                        {mem_cols}
                        <td>{html.escape(p.get('stat', ''))}</td>
                        <td class="tooltip">{command_short}<span class="tooltiptext">{command}</span></td>
                    </tr>
                """
            return rows

        ip4_details_rows = ""
        if not ip4_details:
            ip4_details_rows = "<tr><td colspan='6' style='text-align:center;'>데이터 없음</td></tr>"
        else:
            for item in ip4_details:
                state_val = item.get('state', 'unknown').lower()
                state_html = f'<td>{html.escape(state_val.upper())}</td>'
                if 'up' in state_val:
                    state_html = '<td style="color: #2ecc71; font-weight: bold;">UP</td>'
                elif 'down' in state_val:
                    state_html = '<td style="color: #7f8c8d;">DOWN</td>'
                
                ip4_details_rows += f"""
                    <tr>
                        <td>{html.escape(item.get('iface', 'N/A'))}</td>
                        <td>{html.escape(item.get('master', 'N/A'))}</td>
                        <td>{html.escape(item.get('mac', 'N/A'))}</td>
                        <td>{html.escape(item.get('mtu', 'N/A'))}</td>
                        {state_html}
                        <td>{html.escape(item.get('ipv4', 'N/A'))}</td>
                    </tr>
                """
        
        # [개선] 각 그래프를 개별적으로 렌더링하는 함수
        def render_graph(graph_key, title):
            graph_data = graphs.get(graph_key)
            if isinstance(graph_data, str) and graph_data.startswith('데이터 없음'):
                return f'<div class="graph-container"><h3>{title}</h3><p class="no-data-message">{html.escape(graph_data)}</p></div>'
            elif isinstance(graph_data, str) and '그래프 생성 실패' in graph_data:
                return f'<div class="graph-container"><h3>{title}</h3><p class="no-data-message" style="color: var(--danger-color);">{html.escape(graph_data)}</p></div>'
            elif isinstance(graph_data, str): # Base64 이미지 데이터
                return f'<div class="graph-container"><h3>{title}</h3><img src="data:image/png;base64,{graph_data}" alt="{title} Graph"></div>'
            return f'<div class="graph-container"><h3>{title}</h3><p class="no-data-message">그래프 데이터가 없습니다.</p></div>'

        # [개선] 네트워크 그래프 렌더링
        network_graphs_html = ""
        network_graph_data = graphs.get('network_graphs', {})
        if isinstance(network_graph_data, dict):
            if 'reason' in network_graph_data:
                network_graphs_html = f'<div class="graph-container"><h3>Network Traffic</h3><p class="no-data-message">{html.escape(network_graph_data["reason"])}</p></div>'
            else:
                for iface, img_data in sorted(network_graph_data.items()):
                    title = f'Network Traffic ({html.escape(iface)})'
                    network_graphs_html += f'<div class="graph-container"><h3>{title}</h3><img src="data:image/png;base64,{img_data}" alt="{title} Graph"></div>'
        
        # [개선] 전체 그래프 HTML 구성
        graph_html = f"""
            {render_graph('cpu_graph', 'CPU Usage (%)')}
            {render_graph('memory_graph', 'Memory Usage (KB)')}
            {render_graph('load_average_graph', 'System Load Average')}
            {render_graph('disk_graph', 'Disk I/O (kB/s)')}
            {render_graph('swap_graph', 'Swap Usage (%)')}
            {network_graphs_html}
        """
        
        html_template = f"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI 시스템 분석 보고서: {html.escape(system_info.get('hostname', ''))}</title>
    <style>
        :root {{
            --primary-color: #3498db; --secondary-color: #2c3e50;
            --success-color: #2ecc71; --warning-color: #f39c12; --danger-color: #e74c3c;
            --light-gray: #ecf0f1; --medium-gray: #bdc3c7; --dark-gray: #7f8c8d;
            --text-color: #34495e; --card-bg: #ffffff; --body-bg: #f4f6f8;
            --border-color: #dfe4ea; --box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans KR", sans-serif;
            background-color: var(--body-bg); color: var(--text-color); margin: 0; padding: 2rem;
        }}
        .container {{ max-width: 1400px; margin: auto; background: transparent; box-shadow: none; }}
        header {{
            background: linear-gradient(135deg, var(--secondary-color) 0%, #34495e 100%); color: white;
            padding: 2rem; text-align: center; border-radius: 12px;
            margin-bottom: 2rem; box-shadow: var(--box-shadow);
        }}
        header h1 {{ margin: 0; font-size: 2em; font-weight: 600; }}
        header p {{ margin: 0.5rem 0 0; font-size: 1.1em; opacity: 0.8; }}
        .summary-text {{
             font-size: 1.1em; line-height: 1.7; color: var(--text-color);
        }}
        .report-card {{
            background: var(--card-bg); border-radius: 10px; margin-bottom: 2rem;
            box-shadow: var(--box-shadow); overflow: hidden;
        }}
        .card-header {{
            background-color: #f7f9fc; border-bottom: 1px solid var(--border-color);
            padding: 1rem 1.5rem; font-size: 1.5em; font-weight: 600;
            color: var(--secondary-color); display: flex; align-items: center;
            justify-content: space-between;
        }}
        .card-header .icon {{ margin-right: 1rem; color: var(--primary-color); width: 28px; height: 28px; }}
        .card-body {{ padding: 1.5rem; }}
        .card-body h3 {{
            font-size: 1.2em; color: var(--secondary-color); margin-top: 1.5rem;
            margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--light-gray);
        }}
        .card-body h3:first-child {{ margin-top: 0; }}
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.95em;
            table-layout: auto; /* [수정] 콘텐츠 기반으로 테이블 셀 너비를 자동 조절하여 겹침 방지 */
        }}
        .data-table th, .data-table td {{
            padding: 0.9rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            word-wrap: break-word; /* [수정] 긴 텍스트가 셀을 넘어가지 않도록 자동 줄바꿈 */
            overflow-wrap: break-word; /* [수정] 표준 word-wrap 속성 */
        }}
        .data-table thead th {{
            background-color: #f7f9fc; color: var(--secondary-color); font-weight: 600;
            border-bottom: 2px solid var(--primary-color);
        }}
        .data-table tbody tr:nth-of-type(even) {{ background-color: #fdfdff; }}
        .data-table tbody tr:hover {{ background-color: #f1f5f8; }}
        .graph-container {{
            padding: 1.5rem; border: 1px solid var(--border-color); border-radius: 8px;
            background-color: #fdfdfd; margin-top: 1.5rem;
        }}
        .graph-container h3 {{ text-align: center; margin-top: 0; font-size: 1.2em; color: var(--secondary-color); }}
        .no-data-message {{ text-align: center; color: #888; padding: 2rem; }}
        .graph-container img {{ width: 100%; max-width: 100%; display: block; margin: auto; border-radius: 4px; }}
        .priority-badge {{
            padding: 0.25em 0.6em; border-radius: 5px; font-size: 0.85em;
            font-weight: 600; color: white; text-align: center;
            min-width: 50px; display: inline-block;
        }}
        .priority-badge.high {{ background-color: var(--danger-color); }}
        .priority-badge.medium {{ background-color: var(--warning-color); }}
        .priority-badge.low {{ background-color: var(--dark-gray); }}
        .tooltip {{ position: relative; display: inline-block; cursor: help; }}
        .tooltip .tooltiptext {{
            visibility: hidden; width: 450px; background-color: var(--secondary-color); color: #fff;
            text-align: left; border-radius: 6px; padding: 10px; position: absolute;
            z-index: 10; bottom: 125%; left: 50%; margin-left: -225px; opacity: 0;
            transition: opacity 0.3s; font-size: 0.85em; white-space: pre-wrap; box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }}
        .tooltip:hover .tooltiptext {{ visibility: visible; opacity: 1; }}
        .log-icon {{ font-size: 1em; color: var(--primary-color); vertical-align: middle; }}
        .progress-bar-container {{
            height: 12px; width: 100%; background-color: var(--light-gray);
            border-radius: 6px; overflow: hidden;
        }}
        .progress-bar {{ height: 100%; border-radius: 6px; transition: width 0.4s ease-in-out; }}
        .header-legend {{
            font-size: 0.7em; font-weight: 500; color: var(--dark-gray);
            display: flex; gap: 1rem; align-items: center;
        }}
        footer {{ text-align: center; padding: 2rem; font-size: 0.9em; color: var(--dark-gray); margin-top: 2rem; }}
        @media (max-width: 768px) {{
            body {{ padding: 1rem; }}
            header {{ padding: 1.5rem; }}
            .card-header {{ font-size: 1.2em; }}
            .data-table {{ font-size: 0.85em; }}
            .data-table th, .data-table td {{ padding: 0.6rem; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>AI System Analysis Report</h1>
            <p>Hostname: {html.escape(system_info.get('hostname', 'N/A'))} &nbsp;&bull;&nbsp; Report Date: {datetime.now().strftime('%Y-%m-%d')}</p>
        </header>

        <!-- ================== NEW LAYOUT START ================== -->

        <div class="report-card">
            <div class="card-header">{svg_icons['info']} 시스템 요약</div>
            <div class="card-body">
                <table class="data-table summary-table">
                    <tbody>
                        <tr><th>OS Version</th><td>{html.escape(system_info.get('os_version', 'N/A'))}</td></tr>
                        <tr><th>Kernel</th><td>{html.escape(system_info.get('kernel', 'N/A'))}</td></tr>
                        <tr><th>System Model</th><td>{html.escape(system_info.get('system_model', 'N/A'))}</td></tr>
                        <tr><th>CPU</th><td>{html.escape(system_info.get('cpu', 'N/A'))}</td></tr>
                        <tr><th>Memory</th><td>{html.escape(system_info.get('memory', 'N/A'))}</td></tr>
                        <tr><th>Uptime</th><td>{html.escape(system_info.get('uptime', 'N/A'))}</td></tr>
                        <tr><th>Last Boot</th><td>{html.escape(system_info.get('last_boot', 'N/A'))}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="report-card">
            <div class="card-header">{svg_icons['summary_ai']} AI 종합 분석</div>
            <div class="card-body">
                <p class="summary-text">{summary}</p>
            </div>
        </div>
        <div class="report-card">
            <div class="card-header">{svg_icons['critical']} AI 분석: 심각한 이슈 ({len(critical_issues)}개)</div>
            <div class="card-body">
                <table class="data-table"><tbody>{create_list_table(critical_issues, "발견된 심각한 이슈가 없습니다.")}</tbody></table>
            </div>
        </div>

        <div class="report-card">
            <div class="card-header">{svg_icons['warning']} AI 분석: 경고 사항 ({len(warnings)}개)</div>
            <div class="card-body">
                <table class="data-table"><tbody>{create_list_table(warnings, "특별한 경고 사항이 없습니다.")}</tbody></table>
            </div>
        </div>

        <div class="report-card">
            <div class="card-header">{svg_icons['idea']} AI 분석: 권장사항 ({len(recommendations)}개)</div>
            <div class="card-body">
                <table class="data-table recommendations-table">
                    <thead><tr><th>우선순위</th><th>카테고리</th><th>문제점 💬</th><th>해결 방안</th></tr></thead>
                    <tbody>{create_recommendation_rows(recommendations)}</tbody>
                </table>
            </div>
        </div>
        
        <!-- ================== ORIGINAL SECTIONS START HERE ================== -->

        <div class="report-card">
            <div class="card-header">{svg_icons['dashboard']} 자원 사용 현황</div>
            <div class="card-body">{graph_html}</div>
        </div>
        
        <div class="report-card">
            <div class="card-header">{svg_icons['disk']} 스토리지 및 파일 시스템</div>
            <div class="card-body">
                <table class="data-table storage-table">
                    <thead><tr><th>Filesystem</th><th>Size</th><th>Used</th><th>Avail</th><th>Mounted on</th><th>Usage</th></tr></thead>
                    <tbody>{create_storage_rows(storage_info)}</tbody>
                </table>
            </div>
        </div>

        <div class="report-card">
            <div class="card-header">{svg_icons['network']} 네트워크 정보</div>
            <div class="card-body">
                <h3>IP4 상세 정보</h3>
                <table class="data-table network-table">
                    <thead><tr><th>Interface</th><th>Master</th><th>MAC</th><th>MTU</th><th>State</th><th>IPv4</th></tr></thead>
                    <tbody>{ip4_details_rows}</tbody>
                </table>
                <h3>라우팅 테이블</h3>
                <table class="data-table">
                    <thead><tr><th>Destination</th><th>Gateway</th><th>Device</th><th>Source</th></tr></thead>
                    <tbody>{ "".join(f"<tr><td>{html.escape(r.get('destination', ''))}</td><td>{html.escape(r.get('gateway', ''))}</td><td>{html.escape(r.get('device', ''))}</td><td>{html.escape(r.get('source', ''))}</td></tr>" for r in system_info.get('routing_table', [])) }</tbody>
                </table>
                <h3>ETHTOOL 상태</h3>
                <table class="data-table ethtool-table">
                    <thead><tr><th>Iface</th><th>PCI Bus</th><th>Link</th><th>RX Ring</th><th>Driver/FW</th><th>Errors</th></tr></thead>
                    <tbody>{ create_ethtool_rows(network_details.get('ethtool', {})) }</tbody>
                </table>
                 <h3>NETDEV 통계</h3>
                <table class="data-table">
                    <thead><tr><th>Iface</th><th>RX Bytes</th><th>RX Pkts</th><th>RX Errs</th><th>RX Drop</th><th>TX Bytes</th><th>TX Pkts</th><th>TX Errs</th><th>TX Drop</th></tr></thead>
                    <tbody>{ create_netdev_rows(network_details.get('netdev', [])) }</tbody>
                </table>
                <h3>네트워크 본딩</h3>
                <table class="data-table">
                    <thead><tr><th>Device / Slave</th><th>MII Status</th><th>Mode / Details</th><th>Link Failures</th></tr></thead>
                    <tbody>{ create_bonding_rows(network_details.get('bonding', [])) }</tbody>
                </table>
            </div>
        </div>

        <div class="report-card">
            <div class="card-header">{svg_icons['cpu']} 프로세스 및 리소스</div>
            <div class="card-body">
                <h3>리소스 사용 현황 (상위 5개 사용자)</h3>
                <table class="data-table">
                    <thead><tr><th>User</th><th>CPU%</th><th>MEM%</th><th>RSS</th></tr></thead>
                    <tbody>{"".join(f"<tr><td>{html.escape(u.get('user', ''))}</td><td>{html.escape(u.get('cpu%', ''))}</td><td>{html.escape(u.get('mem%', ''))}</td><td>{html.escape(u.get('rss', ''))}</td></tr>" for u in process_stats.get('by_user', []))}</tbody>
                </table>
                <h3>Top 5 CPU 사용 프로세스</h3>
                <table class="data-table process-table">
                     <thead><tr><th>User</th><th>PID</th><th>CPU%</th><th>STAT</th><th>Command</th></tr></thead>
                    <tbody>{create_process_table_rows(process_stats.get('top_cpu', []), "CPU 사용량 높은 프로세스가 없습니다.")}</tbody>
                </table>
                 <h3>Top 5 메모리 사용 프로세스</h3>
                <table class="data-table process-table">
                    <thead><tr><th>User</th><th>PID</th><th>CPU%</th><th>MEM%</th><th>RSS</th><th>STAT</th><th>Command</th></tr></thead>
                    <tbody>{create_process_table_rows(process_stats.get('top_mem', []), "메모리 사용량 높은 프로세스가 없습니다.", include_mem=True)}</tbody>
                </table>
                <h3>Uninterruptible Sleep Processes ({len(process_stats.get('uninterruptible', []))}개)</h3>
                <table class="data-table process-table">
                    <thead><tr><th>User</th><th>PID</th><th>CPU%</th><th>MEM%</th><th>RSS</th><th>STAT</th><th>Command</th></tr></thead>
                    <tbody>{create_process_table_rows(process_stats.get('uninterruptible', []), "Uninterruptible Sleep 상태의 프로세스가 없습니다.", include_mem=True)}</tbody>
                </table>
                <h3>Zombie Processes ({len(process_stats.get('zombie', []))}개)</h3>
                <table class="data-table process-table">
                    <thead><tr><th>User</th><th>PID</th><th>CPU%</th><th>MEM%</th><th>RSS</th><th>STAT</th><th>Command</th></tr></thead>
                    <tbody>{create_process_table_rows(process_stats.get('zombie', []), "Zombie 상태의 프로세스가 없습니다.", include_mem=True)}</tbody>
                </table>
            </div>
        </div>

        <div class="report-card">
            <div class="card-header">
                <div style="display: flex; align-items: center;">
                    {svg_icons['shield']}
                    <span>AI 선정 긴급 보안 위협 (최대 {self.MAX_FINAL_CVES}개)</span>
                </div>
                <div class="header-legend"><span>🔥 Critical</span><span>⚠️ Important</span></div>
            </div>
            <div class="card-body">
                <table class="data-table security-table">
                    <thead><tr><th>CVE 식별자</th><th>심각도</th><th>생성일</th><th>위협 및 영향 요약</th></tr></thead>
                    <tbody>{create_security_news_rows(security_news)}</tbody>
                </table>
            </div>
        </div>

    </div>
    <footer> AI System Analyzer &nbsp;&bull;&nbsp; Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
</body>
</html>"""
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_template)
            print(Color.success(f"✅ HTML 보고서 생성 완료: {report_file}"))
            return str(report_file)
        except Exception as e:
            print(Color.error(f"❌ HTML 보고서 생성 실패: {e}"))
            raise

def win_safe_filter(member, path):
    member.name = member.name.replace(':', '_')
    return member

def decompress_sosreport(archive_path: str, extract_dir: str) -> str:
    """
    sosreport 압축 파일을 해제합니다.
    Linux 환경에서는 시스템 'tar' 명령어를 '--no-same-owner' 옵션과 함께 사용하여
    추출된 파일들이 현재 스크립트를 실행하는 사용자 소유가 되도록 합니다.
    """
    log_step(f"압축 파일 해제: {archive_path}")

    # 'tar' 명령어를 사용할 수 없는 환경(예: 기본 Windows)에서는 Python 내장 라이브러리 사용
    if not shutil.which("tar"):
        print(Color.info("INFO: 'tar' 명령어를 찾을 수 없어 Python 내장 tarfile 모듈을 사용합니다."))
        try:
            with tarfile.open(archive_path, 'r:*') as tar:
                tar.extractall(path=extract_dir, filter=win_safe_filter)
            print(Color.success(f"✅ 압축 해제 완료 (Python tarfile): {extract_dir}"))
            return extract_dir
        except tarfile.TarError as e:
            raise Exception(f"압축 파일 해제 실패: {e}")

    else: # 'tar' 명령어를 사용할 수 있는 환경 (Linux, macOS 등)
        command = ["tar", "--no-same-owner", "-xf", archive_path, "-C", extract_dir]
        
        try:
            print(f"실행 명령어: {Color.cyan(' '.join(command))}")
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(Color.success(f"✅ 압축 해제 완료 (Linux 방식): {extract_dir}"))
            return extract_dir
        except subprocess.CalledProcessError as e:
            error_message = f"""압축 파일 해제 실패: 'tar' 명령어 실행 중 오류 발생.
  - Return Code: {e.returncode}
  - STDOUT: {e.stdout.decode(errors='ignore') if e.stdout else ''}
  - STDERR: {e.stderr.decode(errors='ignore') if e.stderr else ''}"""
            raise Exception(error_message)

# [오류 수정] JSON 직렬화를 위한 헬퍼 함수
def json_serializer(obj):
    """datetime 객체를 JSON 직렬화 가능하도록 ISO 포맷 문자열로 변환합니다."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Object of type '{type(obj).__name__}' is not JSON serializable")

def main():
    parser = argparse.ArgumentParser(description='sosreport 압축 파일 AI 분석 및 보고서 생성 도구', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('sosreport_archive', nargs='?', help='분석할 sosreport 압축 파일 경로 (.tar.xz, .tar.gz 등)')
    parser.add_argument('--llm-url', required=True, help='LLM 서버의 기본 URL')
    parser.add_argument('--endpoint-path', default='/v1/chat/completions', help='API의 Chat Completions 엔드포인트 경로')
    parser.add_argument('--model', help='사용할 LLM 모델 이름 (list-models 사용 시 불필요)')
    parser.add_argument('--api-token', help='API 인증 토큰. LLM_API_TOKEN 환경 변수로도 설정 가능')
    parser.add_argument('--output', '-o', default='output', help='결과 저장 디렉토리 (기본값: output)')
    parser.add_argument('--no-html', action='store_true', help='HTML 보고서 생성을 비활성화합니다.')
    # parser.add_argument('--no-anonymize', action='store_true', help='LLM에 전송하기 전 민감 정보(IP, 호스트명 등) 익명화를 비활성화합니다.')
    parser.add_argument('--list-models', action='store_true', help='서버에서 사용 가능한 모델 목록을 조회합니다.')
    parser.add_argument('--test-only', action='store_true', help='LLM 연결 테스트만 수행 (모델 이름 필요)')
    
    args = parser.parse_args()
    
    if sys.platform != "win32" and os.geteuid() != 0:
        print(Color.warn("⚠️ 경고: 이 스크립트는 'sudo' 또는 root 권한으로 실행하는 것을 권장합니다."), file=sys.stderr)
        print(Color.warn("   만약 'sudo' 없이 실행하려면, 시스템에 'tar' 명령어가 설치되어 있어야 합니다."), file=sys.stderr)

    api_token = args.api_token or os.getenv('LLM_API_TOKEN')
    
    if not plt:
        print(Color.warn("경고: 'matplotlib' 라이브러리를 찾을 수 없어 그래프 생성 기능이 비활성화됩니다."), file=sys.stderr)
        print(Color.warn("'pip install matplotlib' 명령어로 설치해주세요."), file=sys.stderr)
    
    analyzer = AIAnalyzer(
        llm_url=args.llm_url, model_name=args.model,
        endpoint_path=args.endpoint_path, api_token=api_token,
        output_dir=args.output
    )

    if args.list_models:
        analyzer.list_available_models()
        sys.exit(0)

    if args.test_only:
        if not args.model: parser.error("--test_only 옵션은 --model 인자가 필요합니다.")
        if analyzer.check_llm_service() and analyzer.test_llm_connection():
            print(Color.success("\n✅ LLM 서비스가 정상적으로 작동합니다."))
        else:
            print(Color.error("\n❌ LLM 서비스에 문제가 있습니다."))
        sys.exit(0)

    if not args.sosreport_archive:
        parser.error("분석할 sosreport 압축 파일 경로를 입력해야 합니다.")
    if not args.model:
        parser.error("분석을 위해서는 --model 인자가 필요합니다.")
    
    if not os.path.exists(args.sosreport_archive):
        print(Color.error(f"❌ 입력된 압축 파일을 찾을 수 없습니다: {args.sosreport_archive}"))
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)
    
    extract_target_dir = None
    try:
        # --- [Flexible Temp Dir] New logic for temporary directory management ---
        base_temp_dir = Path("/tmp/sos_analyzer")
        base_temp_dir.mkdir(parents=True, exist_ok=True)
        print(f"임시 관리 디렉토리: {Color.cyan(str(base_temp_dir))}")

        # Best-effort cleanup of the contents of the base directory
        print(Color.info(f"'{base_temp_dir}' 내부의 이전 분석 데이터 정리를 시도합니다..."))
        for item in base_temp_dir.iterdir():
            try:
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()
            except Exception as e:
                print(Color.warn(f"⚠️ 경고: '{item}' 삭제 실패 (권한 문제일 수 있음), 계속 진행합니다. 오류: {e}"))
        
        # Create a new, unique temporary directory for this specific run
        extract_target_dir = tempfile.mkdtemp(prefix="analysis_", dir=str(base_temp_dir))
        print(f"이번 분석을 위한 고유 임시 디렉토리 생성: {Color.cyan(extract_target_dir)}")
        # --- [END FIX] ---

        decompress_sosreport(args.sosreport_archive, str(extract_target_dir))
        
        parser = SosreportParser(str(extract_target_dir))
        sos_data = parser.parse()

        base_name = Path(args.sosreport_archive).stem.replace('.tar', '')
        
        parsed_data_path = Path(args.output) / f"{base_name}_extracted_data.json"
        try:
            with open(parsed_data_path, 'w', encoding='utf-8') as f:
                json.dump(sos_data, f, indent=2, ensure_ascii=False, default=json_serializer)
            print(Color.success(f"✅ 전체 추출 데이터 JSON 파일로 저장 완료: {parsed_data_path}"))
        except TypeError as e:
            print(Color.error(f"❌ 전체 추출 데이터 JSON 저장 실패: 직렬화할 수 없는 데이터 타입이 포함되어 있습니다. 오류: {e}"))
        except Exception as e:
            print(Color.error(f"❌ 전체 추출 데이터 JSON 저장 실패: {e}"))

        prompt = analyzer.create_analysis_prompt(sos_data, anonymize=False)
        result = analyzer.perform_ai_analysis(prompt)
        print(Color.success("✅ AI 시스템 분석 완료!"))
        
        sos_data['ai_analysis'] = result
        sos_data['security_news'] = analyzer.fetch_security_news(sos_data, base_name)
        graphs = analyzer.create_performance_graphs(sos_data)
        
        results = {}
        if not args.no_html:
            html_path = analyzer.create_html_report(result, sos_data, graphs, args.output, args.sosreport_archive)
            results['html_file'] = html_path
        
        results['extracted_data_file'] = str(parsed_data_path)

        print(Color.header("\n분석이 성공적으로 완료되었습니다!"))
        if 'html_file' in results:
            print(f"  - HTML 보고서: {Color.cyan(results['html_file'])}")
        if 'extracted_data_file' in results:
            print(f"  - 전체 추출 데이터 (JSON): {Color.cyan(results['extracted_data_file'])}")

        # [추가] 분석 성공 후 원본 sosreport 파일 삭제
        try:
            print(f"분석 완료. 원본 sosreport 파일 삭제: {Color.cyan(args.sosreport_archive)}")
            os.remove(args.sosreport_archive)
        except OSError as e:
            print(Color.error(f"❌ 원본 파일 삭제 실패: {e}"))

    except Exception as e:
        print(Color.error(f"\n❌ 전체 분석 과정 중 오류 발생: {e}"))
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Final cleanup of the unique directory created for this run
        if extract_target_dir and Path(extract_target_dir).exists():
            print(f"분석 완료 후 임시 디렉토리 정리: {Color.cyan(extract_target_dir)}")
            shutil.rmtree(extract_target_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
