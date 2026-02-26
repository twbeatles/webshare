"""
WebShare Pro - Log Manager
로그 관리 클래스
"""

import queue
from datetime import datetime
from typing import Optional

# 로그 큐 최대 크기 (메모리 누수 방지)
MAX_LOG_QUEUE_SIZE = 1000


class LogManager:
    """로그 큐 관리 (크기 제한으로 메모리 누수 방지)"""
    
    def __init__(self, maxsize: int = MAX_LOG_QUEUE_SIZE) -> None:
        self.queue: queue.Queue[str] = queue.Queue(maxsize=maxsize)
        self._overflow_count = 0

    def add(self, msg: str, level: str = "INFO") -> None:
        """로그 메시지 추가 (큐가 가득 차면 오래된 항목 버림)"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        formatted = f"[{timestamp}] [{level}] {msg}"
        
        # 큐가 가득 찼으면 오래된 항목 버리고 새 항목 추가
        try:
            self.queue.put_nowait(formatted)
        except queue.Full:
            try:
                self.queue.get_nowait()  # 가장 오래된 항목 버림
                self._overflow_count += 1
                self.queue.put_nowait(formatted)
            except queue.Empty:
                pass
        
        print(formatted)  # 콘솔에도 출력
    
    def get_overflow_count(self) -> int:
        """오버플로우로 버려진 로그 수 반환"""
        return self._overflow_count


# 전역 로거 인스턴스
logger = LogManager()


def log_access(ip: str, action: str, details: str = ''):
    """
    접속 로그 기록 (Centralized)
    
    Args:
        ip: 클라이언트 IP
        action: 수행 작업 (login, download, etc.)
        details: 상세 정보
    """
    from config import ACCESS_LOG, access_log_lock, MAX_LOG_LINES
    
    with access_log_lock:
        ACCESS_LOG.insert(0, {
            'time': datetime.now().isoformat(),
            'ip': ip,
            'action': action,
            'details': details
        })
        # 최대 로그 라인 수 유지
        while len(ACCESS_LOG) > MAX_LOG_LINES:
            ACCESS_LOG.pop()
