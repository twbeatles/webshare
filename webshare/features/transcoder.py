
"""
WebShare Pro - Transcoder (v7.2.3)
FFmpeg를 이용한 실시간 HLS 트랜스코딩
"""

import os
import subprocess
import time
import shutil
import threading
from ..config import conf
from ..utils.log_manager import logger

TRANSCODE_SESSIONS = {}
SESSION_LOCK = threading.Lock()

class Transcoder:
    def __init__(self, filepath, session_id):
        self.filepath = filepath
        self.session_id = session_id
        self.process = None
        self.output_dir = os.path.join(conf.get('folder'), '.webshare_transcode', session_id)
        self.playlist_path = os.path.join(self.output_dir, 'index.m3u8')
        self.last_access = time.time()
        self.max_duration = 2 * 3600  # 2 hours max
        self.started_at = None
        self.log_file = None
        
    def start(self):
        """트랜스코딩 시작"""
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        
        # ffmpeg 명령어: HLS 세그먼트 생성
        # -hls_time 10: 10초 단위
        # -hls_list_size 0: 전체 리스트 유지 
        # -g 30: Keyframe interval
        cmd = [
            'ffmpeg',
            '-i', self.filepath,
            '-c:v', 'libx264', '-preset', 'ultrafast', '-crf', '28',
            '-c:a', 'aac', '-b:a', '128k',
            '-f', 'hls',
            '-hls_time', '10',
            '-hls_list_size', '0',
            '-hls_flags', 'delete_segments',
            '-hls_segment_filename', os.path.join(self.output_dir, 'segment_%03d.ts'),
            self.playlist_path
        ]
        
        try:
            # stdout/stderr를 PIPE로 하면 버퍼가 차서 블로킹될 수 있음. DEVNULL로 보냄.
            # Windows: CREATE_NEW_PROCESS_GROUP for tree kill
            # Windows: CREATE_NEW_PROCESS_GROUP for tree kill
            creationflags = 0
            if os.name == 'nt':
                creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
            
            try:
                log_path = os.path.join(self.output_dir, 'ffmpeg.log')
                self.log_file = open(log_path, 'w', encoding='utf-8')
            except Exception:
                self.log_file = subprocess.DEVNULL
                
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=self.log_file,
                creationflags=creationflags
            )
            self.started_at = time.time()
            logger.add(f"트랜스코딩 시작: {self.session_id} ({os.path.basename(self.filepath)})")
            
            # Start timeout monitor
            threading.Thread(target=self._monitor_timeout, daemon=True).start()
            
        except FileNotFoundError:
            logger.add("ffmpeg를 찾을 수 없습니다. 트랜스코딩 불가.", "ERROR")
            raise Exception("ffmpeg not installed")
            
    def stop(self):
        """트랜스코딩 중지"""
        if self.process:
            import signal
            logger.add(f"트랜스코딩 중지 요청: {self.session_id}")
            
            # Windows: taskkill for tree kill
            if os.name == 'nt':
                try:
                    subprocess.call(['taskkill', '/F', '/T', '/PID', str(self.process.pid)], 
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass
            else:
                # Linux/Unix: kill process group
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                except Exception:
                    try:
                        self.process.terminate()
                    except Exception:
                        pass
            
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    if os.name != 'nt':
                         os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                    else:
                         self.process.kill()
                except Exception:
                    pass
            self.process = None
            
            if self.log_file and self.log_file != subprocess.DEVNULL:
                try:
                    self.log_file.close()
                except Exception:
                    pass
            self.log_file = None
        
        # 임시 파일 정리
        if os.path.exists(self.output_dir):
            try:
                shutil.rmtree(self.output_dir)
            except Exception:
                pass
        
    def keep_alive(self):
        self.last_access = time.time()

    def _monitor_timeout(self):
        """Monitor for max duration"""
        while self.process and self.process.poll() is None:
            if time.time() - self.started_at > self.max_duration:
                logger.add(f"트랜스코딩 시간 초과 강제 종료: {self.session_id}", "WARN")
                self.stop()
                break
            time.sleep(10)

def get_transcoder(filepath):
    """트랜스 코더 세션 가져오기 또는 생성"""
    import hashlib
    session_id = hashlib.md5(filepath.encode()).hexdigest()
    
    with SESSION_LOCK:
        if session_id in TRANSCODE_SESSIONS:
            transcoder = TRANSCODE_SESSIONS[session_id]
            transcoder.keep_alive()
            return transcoder
        
        transcoder = Transcoder(filepath, session_id)
        TRANSCODE_SESSIONS[session_id] = transcoder
        transcoder.start()
        
        # 백그라운드 관리 스레드 시작 (만료된 세션 정리)
        # (간단하게 구현: 요청 시마다 정리 체크하거나 별도 스레드)
        cleanup_sessions() 
        return transcoder

def cleanup_sessions():
    """만료된 세션 정리 (5분 미사용)"""
    expired = []
    now = time.time()
    
    # 1. 만료된 세션 ID 수집 (Lock 보유)
    with SESSION_LOCK:
        for sid, t in TRANSCODE_SESSIONS.items():
            if now - t.last_access > 300:  # 5분
                expired.append(sid)
        
        # 목록에서 먼저 제거 (재진입 방지)
        expired_transcoders = []
        for sid in expired:
            if sid in TRANSCODE_SESSIONS:
                expired_transcoders.append((sid, TRANSCODE_SESSIONS.pop(sid)))
    
    # 2. 프로세스 종료 (Lock 해제 상태)
    # stop() 호출 시 subprocess.wait() 등으로 시간이 걸릴 수 있으므로 락 밖에서 수행
    for sid, transcoder in expired_transcoders:
        try:
            transcoder.stop()
            logger.add(f"트랜스코딩 세션 종료: {sid}")
        except Exception as e:
            logger.add(f"세션 종료 중 오류 ({sid}): {e}", "WARN")

def stop_all_transcoders():
    """모든 트랜스코딩 종료 (서버 종료 시)"""
    with SESSION_LOCK:
        for t in TRANSCODE_SESSIONS.values():
            t.stop()
        TRANSCODE_SESSIONS.clear()
