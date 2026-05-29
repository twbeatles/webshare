"""
WebShare Pro - PWA routes.
"""

from flask import Blueprint, jsonify, make_response

pwa_bp = Blueprint("pwa", __name__, url_prefix="/")


@pwa_bp.route("/manifest.json")
def manifest():
    return jsonify(
        {
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
                    "type": "image/png",
                }
            ],
            "scope": "/",
            "orientation": "any",
        }
    )


@pwa_bp.route("/sw.js")
def service_worker():
    from config import APP_VERSION

    cache_version = f"webshare-v{APP_VERSION}"
    sw_script = f"""
const CACHE_NAME = '{cache_version}';
const OFFLINE_URL = '/offline.html';

self.addEventListener('install', (event) => {{
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll([
            OFFLINE_URL,
            '/static/logo.png',
            '/static/css/app.css',
            '/static/js/app-core.js',
            '/static/js/app-modals.js',
            '/static/js/app-upload.js',
            '/static/js/app-bootstrap.js',
            '/static/vendor/fontawesome/css/all.min.css',
            '/static/vendor/fontawesome/webfonts/fa-solid-900.woff2',
            '/static/vendor/fontawesome/webfonts/fa-regular-400.woff2',
            '/static/vendor/fontawesome/webfonts/fa-brands-400.woff2',
            '/static/vendor/marked/marked.min.js',
            '/static/vendor/dompurify/purify.min.js',
            '/static/vendor/hls/hls.min.js',
            '/static/vendor/highlight/highlight.min.js',
            '/static/vendor/highlight/github-dark.min.css'
        ]))
    );
    self.skipWaiting();
}});

self.addEventListener('activate', (event) => {{
    event.waitUntil(
        caches.keys().then((cacheNames) => Promise.all(
            cacheNames.map((cacheName) => cacheName !== CACHE_NAME ? caches.delete(cacheName) : undefined)
        ))
    );
    self.clients.claim();
}});

self.addEventListener('fetch', (event) => {{
    const url = new URL(event.request.url);

    if (url.pathname.startsWith('/api/')) {{
        event.respondWith(fetch(event.request));
    }} else if (event.request.mode === 'navigate') {{
        event.respondWith(fetch(event.request).catch(() => caches.match(OFFLINE_URL)));
    }} else if (url.pathname.startsWith('/static/') || url.hostname.includes('cdnjs') || url.hostname.includes('jsdelivr')) {{
        event.respondWith(
            caches.match(event.request).then((response) => (
                response || fetch(event.request).then((networkResponse) => {{
                    return caches.open(CACHE_NAME).then((cache) => {{
                        cache.put(event.request, networkResponse.clone());
                        return networkResponse;
                    }});
                }})
            ))
        );
    }} else {{
        event.respondWith(fetch(event.request).catch(() => caches.match(event.request)));
    }}
}});
"""
    response = make_response(sw_script)
    response.headers["Content-Type"] = "application/javascript"
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@pwa_bp.route("/offline.html")
def offline_page():
    html = """<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WebShare Offline</title>
  <style>
    body { margin: 0; font-family: system-ui, sans-serif; background: #f8fafc; color: #0f172a; display: grid; min-height: 100vh; place-items: center; }
    main { max-width: 28rem; padding: 2rem; text-align: center; }
  </style>
</head>
<body><main><h1>오프라인 상태입니다</h1><p>네트워크가 복구되면 WebShare Pro를 다시 사용할 수 있습니다.</p></main></body>
</html>"""
    response = make_response(html)
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    response.headers["Cache-Control"] = "public, max-age=86400"
    return response
