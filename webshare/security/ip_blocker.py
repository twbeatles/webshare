"""
WebShare Pro - IP Blocking
IP 차단 및 화이트리스트 관리
"""

from datetime import datetime, timedelta

from ..config import (
    conf, login_attempts_lock, LOGIN_ATTEMPTS,
    MAX_LOGIN_ATTEMPTS, LOGIN_BLOCK_MINUTES
)
from ..utils.log_manager import logger


def check_ip_whitelist(ip: str) -> bool:
    """IP 화이트리스트 확인"""
    whitelist = conf.get('ip_whitelist', [])
    if not whitelist:
        return True  # 화이트리스트가 비어있으면 모두 허용
    return ip in whitelist or ip == '127.0.0.1'


def check_ip_blocked(ip: str) -> tuple:
    """IP 차단 상태 확인. (차단여부, 남은시간(분))"""
    with login_attempts_lock:
        if ip not in LOGIN_ATTEMPTS:
            return False, 0
        
        info = LOGIN_ATTEMPTS[ip]
        blocked_until = info.get('blocked_until')
        
        if blocked_until:
            if datetime.now() < blocked_until:
                remaining = (blocked_until - datetime.now()).total_seconds() / 60
                return True, round(remaining)
            else:
                # 차단 해제
                del LOGIN_ATTEMPTS[ip]
                return False, 0
        
        return False, 0


def record_login_attempt(ip: str, success: bool):
    """로그인 시도 기록 (스레드 안전)"""
    with login_attempts_lock:
        if success:
            # 성공 시 기록 삭제
            if ip in LOGIN_ATTEMPTS:
                del LOGIN_ATTEMPTS[ip]
            return
        
        # 실패 기록
        now = datetime.now()
        if ip not in LOGIN_ATTEMPTS:
            LOGIN_ATTEMPTS[ip] = {'attempts': 0}
        
        LOGIN_ATTEMPTS[ip]['attempts'] += 1
        LOGIN_ATTEMPTS[ip]['last_attempt'] = now  # 마지막 시도 시간 기록
        
        # 최대 횟수 초과 시 차단
        if LOGIN_ATTEMPTS[ip]['attempts'] >= MAX_LOGIN_ATTEMPTS:
            LOGIN_ATTEMPTS[ip]['blocked_until'] = now + timedelta(minutes=LOGIN_BLOCK_MINUTES)
            logger.add(f"IP 차단: {ip} ({LOGIN_BLOCK_MINUTES}분)", "WARN")


def unblock_ip(ip: str) -> bool:
    """IP 차단 해제 (스레드 안전)"""
    with login_attempts_lock:
        if ip in LOGIN_ATTEMPTS:
            del LOGIN_ATTEMPTS[ip]
            logger.add(f"IP 차단 해제: {ip}")
            return True
        return False


def get_blocked_ips() -> list:
    """현재 차단된 IP 목록"""
    blocked = []
    now = datetime.now()
    
    with login_attempts_lock:
        for ip, info in LOGIN_ATTEMPTS.items():
            blocked_until = info.get('blocked_until')
            if blocked_until and blocked_until > now:
                blocked.append({
                    'ip': ip,
                    'blocked_until': blocked_until.isoformat(),
                    'remaining_minutes': round((blocked_until - now).total_seconds() / 60)
                })
    
    return blocked


def cleanup_expired_login_attempts(max_age_hours: int = 24) -> int:
    """
    오래된 로그인 시도 기록 정리 (메모리 누수 방지).
    
    차단이 해제되었거나 마지막 시도로부터 max_age_hours가 지난 기록을 삭제합니다.
    
    Args:
        max_age_hours: 기록 유지 최대 시간 (기본값: 24시간)
    
    Returns:
        int: 삭제된 기록 수
    """
    now = datetime.now()
    expired = []
    
    with login_attempts_lock:
        for ip, info in list(LOGIN_ATTEMPTS.items()):
            blocked_until = info.get('blocked_until')
            last_attempt = info.get('last_attempt')
            
            # 차단이 해제된 경우 (blocked_until이 과거)
            if blocked_until and blocked_until < now:
                expired.append(ip)
                continue
            
            # 차단되지 않았고, 마지막 시도가 max_age_hours 이전인 경우
            if not blocked_until and last_attempt:
                age_hours = (now - last_attempt).total_seconds() / 3600
                if age_hours > max_age_hours:
                    expired.append(ip)
                    continue
            
            # last_attempt 기록이 없는 오래된 데이터 정리
            if not blocked_until and not last_attempt:
                # 시도 횟수만 있고 차단되지 않은 경우 (비정상 상태)
                expired.append(ip)
        
        for ip in expired:
            del LOGIN_ATTEMPTS[ip]
    
    if expired:
        logger.add(f"로그인 시도 기록 정리: {len(expired)}개")
    return len(expired)
