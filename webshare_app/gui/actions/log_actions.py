"""Log view, statistics, and export actions."""

from __future__ import annotations
# pyright: reportAttributeAccessIssue=false, reportArgumentType=false
from PyQt6.QtWidgets import QFileDialog, QMessageBox
from config import MAX_LOG_LINES, STATS
from utils.log_manager import logger


class LogActionsMixin:
    def update_stats(self):
            """실시간 통계 업데이트"""
            if hasattr(self, 'stats_requests'):
                self.stats_requests.setText(f"요청: {STATS['requests']}")
            if hasattr(self, 'stats_connections'):
                self.stats_connections.setText(f"접속: {STATS['active_connections']}")
            if hasattr(self, 'stats_traffic'):
                # 트래픽 포맷팅
                total_bytes = STATS['bytes_sent'] + STATS['bytes_received']
                if total_bytes < 1024:
                    traffic_str = f"{total_bytes} B"
                elif total_bytes < 1024 * 1024:
                    traffic_str = f"{total_bytes / 1024:.1f} KB"
                elif total_bytes < 1024 * 1024 * 1024:
                    traffic_str = f"{total_bytes / 1024 / 1024:.1f} MB"
                else:
                    traffic_str = f"{total_bytes / 1024 / 1024 / 1024:.2f} GB"
                self.stats_traffic.setText(f"트래픽: {traffic_str}")


    def filter_logs(self, level):
            """로그 레벨별 필터링"""
            self.log_text.clear()
            for log in self.all_logs:
                if level == "전체" or f"[{level}]" in log:
                    self.log_text.append(log)


    def export_logs(self):
            """로그 파일로 내보내기"""
            from datetime import datetime
            filename = f"webshare_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath, _ = QFileDialog.getSaveFileName(self, "로그 저장", filename, "Text Files (*.txt)")
            if filepath:
                try:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(self.all_logs))
                    QMessageBox.information(self, "저장 완료", f"로그가 저장되었습니다.\n{filepath}")
                except IOError as e:
                    QMessageBox.critical(self, "오류", f"저장 실패: {e}")


    def clear_logs(self):
            """로그 클리어"""
            self.log_text.clear()
            self.all_logs.clear()


    def process_logs(self):
            """로그 큐 처리"""
            if self.is_closing:
                return
            try:
                current_filter = self.log_filter.currentText() if hasattr(self, 'log_filter') else "전체"
                while not logger.queue.empty():
                    msg = logger.queue.get_nowait()
                    # 모든 로그 저장
                    self.all_logs.append(msg)
                    # 최대 로그 수 제한
                    if len(self.all_logs) > MAX_LOG_LINES:
                        self.all_logs = self.all_logs[-MAX_LOG_LINES:]

                    # 필터 적용
                    if current_filter == "전체" or f"[{current_filter}]" in msg:
                        self.log_text.append(msg)

                    # Limit log lines in display
                    doc = self.log_text.document()
                    if doc is not None and doc.blockCount() > MAX_LOG_LINES:
                        cursor = self.log_text.textCursor()
                        cursor.movePosition(cursor.MoveOperation.Start)
                        cursor.movePosition(cursor.MoveOperation.Down, cursor.MoveMode.KeepAnchor,
                                          doc.blockCount() - MAX_LOG_LINES)
                        cursor.removeSelectedText()
            except Exception:
                pass

