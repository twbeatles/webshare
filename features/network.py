
"""
WebShare Pro - Network Utilities
UPnP 포트 포워딩 및 네트워크 검색 기능
"""

import socket
from utils.log_manager import logger
from config import conf

try:
    import miniupnpc
    HAS_UPNP = True
except ImportError:
    HAS_UPNP = False
    # logger.add("miniupnpc 모듈이 없어 UPnP 기능을 사용할 수 없습니다.", "WARN")

def get_local_ip():
    """로컬 IP 주소 반환"""
    # 1. 시도: UDP 연결을 통한 IP 확인 (인터넷 연결 시 정확)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        # 2. 시도: 호스트네임으로 조회
        try:
            IP = socket.gethostbyname(socket.gethostname())
        except Exception:
            IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def setup_upnp(port):
    """UPnP를 사용하여 포트 포워딩 설정"""
    if not HAS_UPNP:
        return False, "miniupnpc library not installed"

    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 200
        
        logger.add("UPnP 장치 검색 중...", "INFO")
        # discover() returns number of devices found
        # delay=200ms is usually enough but ensure it doesn't block forever if library has issues
        ndevices = upnp.discover()
        
        if ndevices == 0:
            return False, "No UPnP devices found"
            
        upnp.selectigd()
        
        external_ip = upnp.externalipaddress()
        logger.add(f"UPnP 외부 IP: {external_ip}", "INFO")
        
        # 포트 매핑 추가 (External Port = Internal Port)
        # Protocol: TCP, Duration: 0 (permanent), description
        upnp.addportmapping(port, 'TCP', upnp.lanaddr, port, 'WebShare Pro', '')
        
        return True, f"Port {port} mapped successfully on {external_ip}"
        
    except Exception as e:
        logger.add(f"UPnP 설정 실패: {e}", "ERROR")
        return False, str(e)
