"""Application auto-update actions."""

from __future__ import annotations
# pyright: reportAttributeAccessIssue=false, reportArgumentType=false
import os
import sys
from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt, QTimer
from config import APP_VERSION


class UpdateActionsMixin:

    def check_for_updates(self, silent: bool = False):
        """GitHub Releases 기반 최신 업데이트 확인 및 적용"""
        from pathlib import Path
        from PyQt6.QtCore import QThread, pyqtSignal
        from PyQt6.QtWidgets import QProgressDialog
        from webshare_app.core.config import (
            UPDATE_MANIFEST_URL,
            UPDATE_PUBLIC_KEY_B64,
            UPDATE_RELEASES_URL,
        )
        from webshare_app.core.update_manifest import (
            NoUpdateAvailableError,
            download_release_manifest,
            verify_release_manifest,
        )
        from webshare_app.core.update_installer import (
            launch_update_helper,
            prepare_staged_update,
            resolve_update_staging_root,
            stream_update_artifact,
            update_result_path,
        )

        if getattr(self, "_update_in_progress", False):
            if not silent:
                QMessageBox.information(self, "업데이트", "이미 업데이트 확인 또는 다운로드가 진행 중입니다.")
            return

        self._update_in_progress = True

        progress = QProgressDialog("업데이트 정보를 확인하는 중...", "취소", 0, 0, self)
        progress.setWindowTitle("업데이트 확인")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.show()
        QApplication.processEvents()

        def cleanup_state():
            self._update_in_progress = False

        def do_check():
            try:
                manifest_bytes = download_release_manifest(UPDATE_MANIFEST_URL)
                manifest = verify_release_manifest(
                    manifest_bytes,
                    public_key=UPDATE_PUBLIC_KEY_B64,
                    current_version=APP_VERSION,
                )
                progress.close()

                # 새 버전 발견 알림 다이얼로그
                reply = QMessageBox.question(
                    self,
                    "새 버전 발견",
                    f"새로운 버전 WebShare Pro v{manifest.version}이(가) 출시되었습니다.\n\n"
                    f"현재 버전: v{APP_VERSION}\n"
                    f"새 버전: v{manifest.version}\n"
                    f"파일 크기: {manifest.artifact_size / 1024 / 1024:.1f} MB\n\n"
                    "지금 업데이트를 다운로드하고 적용하시겠습니까?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )

                if reply != QMessageBox.StandardButton.Yes:
                    cleanup_state()
                    return

                # 다운로드 진행 프로그레스 다이얼로그
                download_progress = QProgressDialog(
                    "새 버전 다운로드 중...",
                    "취소",
                    0,
                    manifest.artifact_size,
                    self,
                )
                download_progress.setWindowTitle("업데이트 다운로드")
                download_progress.setWindowModality(Qt.WindowModality.WindowModal)

                staging_root = resolve_update_staging_root()

                class UpdateDownloadWorker(QThread):
                    progress_signal = pyqtSignal(int, int)
                    finished_signal = pyqtSignal(object)
                    error_signal = pyqtSignal(str)

                    def __init__(self, manifest_obj, root_path):
                        super().__init__()
                        self.manifest = manifest_obj
                        self.root = root_path
                        self._is_canceled = False

                    def cancel(self):
                        self._is_canceled = True

                    def run(self):
                        try:
                            def chunk_gen():
                                downloaded = 0
                                for chunk in stream_update_artifact(self.manifest):
                                    if self._is_canceled:
                                        raise RuntimeError("사용자에 의해 다운로드가 취소되었습니다.")
                                    downloaded += len(chunk)
                                    self.progress_signal.emit(downloaded, self.manifest.artifact_size)
                                    yield chunk

                            staged_path = prepare_staged_update(
                                self.manifest,
                                chunks=chunk_gen(),
                                staging_root=self.root,
                                approve=lambda _m, _path: not self._is_canceled,
                            )
                            if self._is_canceled:
                                self.error_signal.emit("다운로드가 취소되었습니다.")
                            else:
                                self.finished_signal.emit(staged_path)
                        except Exception as worker_exc:
                            self.error_signal.emit(str(worker_exc))

                worker = UpdateDownloadWorker(manifest, staging_root)
                self._current_update_worker = worker

                def on_progress(current, total):
                    download_progress.setValue(current)

                def on_cancel():
                    worker.cancel()

                download_progress.canceled.connect(on_cancel)

                def on_finished(staged):
                    download_progress.close()
                    cleanup_state()
                    if not staged:
                        QMessageBox.warning(self, "취소됨", "업데이트 준비가 취소되었습니다.")
                        return

                    # 실행 파일 및 백업 경로 계산 (개발 모드 안전장치)
                    is_frozen = getattr(sys, "frozen", False)
                    if not is_frozen:
                        QMessageBox.information(
                            self,
                            "다운로드 완료 (개발 모드)",
                            f"새 버전 바이너리가 스테이징 폴더에 다운로드되었습니다:\n{staged}\n\n"
                            "현재 소스코드(개발 모드)로 실행 중이므로 자동 교체를 실행하지 않습니다.",
                        )
                        return

                    target_exe = Path(sys.executable).resolve()
                    backup_exe = target_exe.parent / f"{target_exe.name}.v{APP_VERSION}.bak"
                    result_file = update_result_path(staging_root)

                    # 헬퍼 프로세스 실행 후 현재 앱 종료
                    launch_update_helper(
                        target=target_exe,
                        staged=staged,
                        backup=backup_exe,
                        parent_pid=os.getpid(),
                        expected_sha256=manifest.artifact_sha256,
                        expected_size=manifest.artifact_size,
                        result_file=result_file,
                    )

                    QMessageBox.information(
                        self,
                        "재시작 중",
                        "업데이트를 적용하기 위해 프로그램을 재시작합니다.",
                    )
                    self.is_closing = True
                    QApplication.quit()

                def on_error(err_msg):
                    download_progress.close()
                    cleanup_state()
                    QMessageBox.critical(self, "다운로드 실패", f"업데이트 다운로드 중 오류가 발생했습니다:\n{err_msg}")

                worker.progress_signal.connect(on_progress)
                worker.finished_signal.connect(on_finished)
                worker.error_signal.connect(on_error)

                download_progress.show()
                worker.start()

            except NoUpdateAvailableError:
                progress.close()
                cleanup_state()
                if not silent:
                    QMessageBox.information(
                        self,
                        "최신 버전",
                        f"현재 최신 버전(v{APP_VERSION})을 사용 중입니다.",
                    )
            except Exception as exc:
                progress.close()
                cleanup_state()
                if not silent:
                    QMessageBox.critical(
                        self,
                        "업데이트 오류",
                        f"업데이트 확인 중 오류가 발생했습니다:\n{exc}",
                    )

        QTimer.singleShot(50, do_check)

