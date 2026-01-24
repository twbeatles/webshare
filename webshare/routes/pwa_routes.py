
"""
WebShare Pro - PWA Routes
Manifest.json 및 Service Worker 제공
"""

from flask import Blueprint, send_from_directory, jsonify, make_response, current_app
import os

pwa_bp = Blueprint('pwa', __name__, url_prefix='/')

@pwa_bp.route('/manifest.json')
def manifest():
    """PWA Manifest 반환"""
    manifest_data = {
        "name": "WebShare Pro",
        "short_name": "WebShare",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#f8fafc",
        "theme_color": "#6366f1",
        "icons": [
            {
                "src": "/static/logo.png",
                "sizes": "1024x1024",
                "type": "image/png"
            }
        ],
        "scope": "/",
        "orientation": "any"
    }
    return jsonify(manifest_data)

@pwa_bp.route('/sw.js')
def service_worker():
    """Service Worker 스크립트 반환 (동적 버전 주입)"""
    from ..config import APP_VERSION
    
    # 캐시 버전 (앱 버전 + 타임스탬프 또는 단순히 앱 버전)
    cache_version = f"webshare-v{APP_VERSION}"
    
    sw_script = f"""
const CACHE_NAME = '{cache_version}';
const OFFLINE_URL = '/';

self.addEventListener('install', (event) => {{
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {{
            return cache.addAll([
                OFFLINE_URL,
                '/static/logo.png',
                'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
                'https://cdn.jsdelivr.net/npm/marked/marked.min.js',
                'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/highlight.min.js',
                'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/styles/github-dark.min.css'
            ]);
        }})
    );
    self.skipWaiting();
}});

self.addEventListener('activate', (event) => {{
    event.waitUntil(
        caches.keys().then((cacheNames) => {{
            return Promise.all(
                cacheNames.map((cacheName) => {{
                    if (cacheName !== CACHE_NAME) {{
                        return caches.delete(cacheName);
                    }}
                }})
            );
        }})
    );
    self.clients.claim();
}});

self.addEventListener('fetch', (event) => {{
    const url = new URL(event.request.url);
    
    // 1. API 요청 및 HTML 문서: Network First (최신 데이터 우선)
    if (url.pathname.startsWith('/api/') || event.request.mode === 'navigate') {{
        event.respondWith(
            fetch(event.request)
                .catch(() => {{
                    return caches.match(event.request)
                        .then((response) => {{
                             // 오프라인일 경우 캐시된 페이지나 오프라인 페이지 반환
                             return response || caches.match(OFFLINE_URL);
                        }});
                }})
        );
    }} 
    // 2. 정적 자원 (Static Assets): Cache First (성능 우선)
    else if (url.pathname.startsWith('/static/') || url.hostname.includes('cdnjs') || url.hostname.includes('jsdelivr')) {{
        event.respondWith(
            caches.match(event.request).then((response) => {{
                return response || fetch(event.request).then((networkResponse) => {{
                    return caches.open(CACHE_NAME).then((cache) => {{
                        cache.put(event.request, networkResponse.clone());
                        return networkResponse;
                    }});
                }});
            }})
        );
    }}
    // 3. 그 외 (기본): Network First
    else {{
        event.respondWith(
            fetch(event.request).catch(() => caches.match(event.request))
        );
    }}
}});
"""
    response = make_response(sw_script)
    response.headers['Content-Type'] = 'application/javascript'
    # SW 파일은 캐시되지 않도록 설정
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response


