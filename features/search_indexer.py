"""
WebShare Pro - Search Indexer (v7.2.3)
메모리 기반 고속 파일 검색 인덱서
"""

import os
import threading
from datetime import datetime
from utils.log_manager import logger

class SearchIndexer:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(SearchIndexer, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        
        self.index = {}  # {filename_lower: [{path, is_dir, name}]}
        self.doc_index = [] # List of {name, path, is_dir} for optimized search
        self.is_indexing = False
        self.pending_update = False  # NEW: Re-index trigger flag
        self.last_indexed = None
        self.last_build_seconds = 0.0
        self.last_item_count = 0
        self.last_error = ""
        self.index_lock = threading.RLock()
        self._debounce_timer = None
        self._initialized = True
        logger.add("SearchIndexer 초기화됨")

    @staticmethod
    def _should_skip_dir(name: str) -> bool:
        lower = name.lower()
        if lower.startswith('.webshare'):
            return True
        if lower.startswith('.'):
            return True
        if lower == '__pycache__':
            return True
        return False

    def build_index(self, root_path):
        """인덱스 전체 빌드 (백그라운드 실행 권장)"""
        # Re-entry check is handled within the while loop pattern below or via lock check
        # But here we want to ensure we don't start parallel builds, but do queue one up.
        
        with self.index_lock:
            if self.is_indexing:
                self.pending_update = True
                return
            self.is_indexing = True
            self.pending_update = False

        try:
            while True:
                logger.add(f"파일 인덱싱 시작: {root_path}")
                start_time = datetime.now()
                
                new_index = {}
                new_doc_index = []
                
                count = 0
                for root, dirs, files in os.walk(root_path):
                    # 숨김/시스템 폴더 제외
                    dirs[:] = [d for d in dirs if not self._should_skip_dir(d)]

                    for name in dirs:
                        try:
                            rel_path = os.path.relpath(os.path.join(root, name), root_path).replace('\\', '/')
                            lower_name = name.lower()
                            bucket = new_index.setdefault(lower_name, [])
                            bucket.append({
                                'name': name,
                                'path': rel_path,
                                'is_dir': True
                            })
                            new_doc_index.append({
                                'name': name,
                                'path': rel_path,
                                'is_dir': True,
                                'lower_name': lower_name
                            })
                            count += 1
                        except Exception:
                            continue

                    for name in files:
                        try:
                            # 숨김 파일 제외
                            if name.startswith('.'):
                                continue
                            rel_path = os.path.relpath(os.path.join(root, name), root_path).replace('\\', '/')
                            lower_name = name.lower()
                            
                            # Dict Index (Exact/Prefix match optimization)
                            bucket = new_index.setdefault(lower_name, [])
                            bucket.append({
                                'name': name,
                                'path': rel_path,
                                'is_dir': False
                            })
                            
                            # List Index (Full scan fallback)
                            new_doc_index.append({
                                'name': name,
                                'path': rel_path,
                                'is_dir': False,
                                'lower_name': lower_name
                            })
                            count += 1
                        except Exception:
                            continue
                
                elapsed = (datetime.now() - start_time).total_seconds()
                with self.index_lock:
                    self.index = new_index
                    self.doc_index = new_doc_index
                    self.last_indexed = datetime.now()
                    self.last_build_seconds = elapsed
                    self.last_item_count = count
                    self.last_error = ""
                    logger.add(f"파일 인덱싱 완료: {count}개 항목 ({elapsed:.2f}초)")
                    
                    # Check for pending updates
                    if self.pending_update:
                        logger.add("인덱싱 중 변경사항 감지됨. 재시작...")
                        self.pending_update = False
                        continue  # Loop again to re-index
                    else:
                        self.is_indexing = False
                        break # Exit loop
            
        except Exception as e:
            logger.add(f"인덱싱 중 오류 발생: {e}", "ERROR")
            with self.index_lock:
                self.is_indexing = False
                self.last_error = str(e)

    def search(self, query, max_results=100):
        """검색 쿼리 실행"""
        if not query:
            return []
            
        query = query.lower().strip()
        results = []
        
        with self.index_lock:
            seen_paths = set()
            # 1. Exact match priority
            if query in self.index:
                for item in self.index[query]:
                    path = item.get('path', '')
                    if not path:
                        continue
                    seen_paths.add(path)
                    results.append({
                        'name': item.get('name', os.path.basename(path)),
                        'path': path,
                        'is_dir': bool(item.get('is_dir', False))
                    })
            
            # 2. Substring match (scan all docs)
            # This is still O(N) but N is number of files, much faster than disk walk
            count = 0
            for doc in self.doc_index:
                if query in doc['lower_name']:
                    # O(1) 중복 제거
                    if doc['path'] in seen_paths:
                        continue
                        
                    seen_paths.add(doc['path'])
                    results.append({
                        'name': doc['name'],
                        'path': doc['path'],
                        'is_dir': doc['is_dir']
                    })
                    count += 1
                    if count >= max_results:
                        break

        return results[:max_results]

    def get_status(self):
        """인덱서 상태 정보"""
        with self.index_lock:
            return {
                'is_indexing': self.is_indexing,
                'pending_update': self.pending_update,
                'last_indexed': self.last_indexed.isoformat() if self.last_indexed else None,
                'last_build_seconds': self.last_build_seconds,
                'indexed_items': self.last_item_count,
                'name_bucket_count': len(self.index),
                'document_count': len(self.doc_index),
                'last_error': self.last_error,
            }

    def update_event(self, root_path):
        """파일 변경 이벤트 발생 시 인덱스 리빌드 트리거 (Debounce 5초)"""
        with self.index_lock:
            if self.is_indexing:
                self.pending_update = True
                return

        if self._debounce_timer:
            self._debounce_timer.cancel()
            
        self._debounce_timer = threading.Timer(5.0, self.build_index, args=[root_path])
        self._debounce_timer.daemon = True
        self._debounce_timer.start()

# 전역 인스턴스
indexer = SearchIndexer()
