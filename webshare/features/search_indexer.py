"""
WebShare Pro - Search Indexer (v7.2.3)
메모리 기반 고속 파일 검색 인덱서
"""

import os
import threading
from datetime import datetime
from ..utils.log_manager import logger

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
        
        self.index = {}  # {filename_lower: [full_paths]}
        self.doc_index = [] # List of {name, path, is_dir} for optimized search
        self.is_indexing = False
        self.pending_update = False  # NEW: Re-index trigger flag
        self.last_indexed = None
        self.index_lock = threading.RLock()
        self._debounce_timer = None
        self._initialized = True
        logger.add("SearchIndexer 초기화됨")

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
                    # 숨김 폴더/시스템 폴더 제외
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    
                    for name in files + dirs:
                        try:
                            full_path = os.path.join(root, name)
                            rel_path = os.path.relpath(full_path, root_path).replace('\\', '/')
                            lower_name = name.lower()
                            
                            # Dict Index (Exact/Prefix match optimization)
                            if lower_name not in new_index:
                                new_index[lower_name] = []
                            new_index[lower_name].append(rel_path)
                            
                            # List Index (Full scan fallback)
                            new_doc_index.append({
                                'name': name,
                                'path': rel_path,
                                'is_dir': name in dirs,
                                'lower_name': lower_name
                            })
                            count += 1
                        except Exception:
                            continue
                
                with self.index_lock:
                    self.index = new_index
                    self.doc_index = new_doc_index
                    self.last_indexed = datetime.now()
                    
                    # Check for pending updates
                    if self.pending_update:
                        logger.add("인덱싱 중 변경사항 감지됨. 재시작...")
                        self.pending_update = False
                        continue  # Loop again to re-index
                    else:
                        self.is_indexing = False
                        break # Exit loop
                    
                elapsed = (datetime.now() - start_time).total_seconds()
                logger.add(f"파일 인덱싱 완료: {count}개 항목 ({elapsed:.2f}초)")
            
        except Exception as e:
            logger.add(f"인덱싱 중 오류 발생: {e}", "ERROR")
            with self.index_lock:
                self.is_indexing = False

    def search(self, query, max_results=100):
        """검색 쿼리 실행"""
        if not query:
            return []
            
        query = query.lower().strip()
        results = []
        
        with self.index_lock:
            # 1. Exact match priority
            if query in self.index:
                 for path in self.index[query]:
                     name = os.path.basename(path)
                     results.append({
                         'name': name,
                         'path': path,
                         'is_dir': False # 정확히 알 수 없음, 경로만으로는
                     })
            
            # 2. Substring match (scan all docs)
            # This is still O(N) but N is number of files, much faster than disk walk
            count = 0
            for doc in self.doc_index:
                if query in doc['lower_name']:
                    # 중복 제거 (Exact match에서 이미 추가된 경우)
                    # 성능을 위해 단순 리스트업 후 클라이언트가 처리하게 하거나, 여기서 set 사용
                    if any(r['path'] == doc['path'] for r in results):
                        continue
                        
                    results.append({
                        'name': doc['name'],
                        'path': doc['path'],
                        'is_dir': doc['is_dir']
                    })
                    count += 1
                    if count >= max_results:
                        break
                        
        return results[:max_results]

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
