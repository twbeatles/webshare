(function () {
    "use strict";

    const LIB_URLS = {
        marked: ["/static/vendor/marked/marked.min.js", "https://cdn.jsdelivr.net/npm/marked/marked.min.js"],
        dompurify: ["/static/vendor/dompurify/purify.min.js", "https://cdn.jsdelivr.net/npm/dompurify@3.2.6/dist/purify.min.js"],
        hls: ["/static/vendor/hls/hls.min.js", "https://cdn.jsdelivr.net/npm/hls.js@latest"],
        hljs: ["/static/vendor/highlight/highlight.min.js", "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/highlight.min.js"],
        hljsCss: ["/static/vendor/highlight/github-dark.min.css", "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/styles/github-dark.min.css"],
    };
    const HLS_EXTENSIONS = new Set([".mkv", ".avi", ".mov", ".wmv", ".flv"]);
    const resourcePromises = Object.create(null);

    function toBool(value) {
        if (typeof value === "boolean") return value;
        if (typeof value === "string") return value.toLowerCase() === "true";
        return Boolean(value);
    }

    const state = {
        page: Number(window.LIST_INITIAL_PAGE || 1),
        pageSize: Number(window.LIST_PAGE_SIZE || 200),
        hasNext: toBool(window.LIST_HAS_NEXT),
        totalCount: Number(window.LIST_TOTAL_COUNT || 0),
        totalPages: Number(window.LIST_TOTAL_PAGES || 1),
        sortBy: String(window.LIST_SORT_BY || "name"),
        sortOrder: String(window.LIST_SORT_ORDER || "asc"),
        query: String(window.LIST_QUERY || "").trim(),
        loading: false,
    };

    function loadScriptOnce(key, src) {
        if (resourcePromises[key]) return resourcePromises[key];
        resourcePromises[key] = new Promise((resolve, reject) => {
            const existing = document.querySelector(`script[data-ws-lib="${key}"]`);
            if (existing) {
                if (existing.dataset.loaded === "true") resolve();
                else existing.addEventListener("load", () => resolve(), { once: true });
                return;
            }

            const sources = Array.isArray(src) ? src.slice() : [src];
            const script = document.createElement("script");
            script.async = true;
            script.dataset.wsLib = key;
            script.addEventListener("load", () => {
                script.dataset.loaded = "true";
                resolve();
            });
            script.addEventListener("error", () => {
                if (sources.length > 0) {
                    script.src = sources.shift();
                    return;
                }
                reject(new Error(`Failed to load ${key}`));
            });
            document.head.appendChild(script);
            script.src = sources.shift();
        });
        return resourcePromises[key];
    }

    function loadStyleOnce(key, href) {
        if (resourcePromises[key]) return resourcePromises[key];
        resourcePromises[key] = new Promise((resolve) => {
            const existing = document.querySelector(`link[data-ws-style="${key}"]`);
            if (existing) {
                resolve();
                return;
            }
            const sources = Array.isArray(href) ? href.slice() : [href];
            const link = document.createElement("link");
            link.rel = "stylesheet";
            link.dataset.wsStyle = key;
            link.addEventListener("load", () => resolve(), { once: true });
            link.addEventListener("error", () => {
                if (sources.length > 0) {
                    link.href = sources.shift();
                    return;
                }
                resolve();
            });
            document.head.appendChild(link);
            link.href = sources.shift();
        });
        return resourcePromises[key];
    }

    async function ensureMarkedAndHighlight() {
        const tasks = [];
        if (typeof window.marked === "undefined") tasks.push(loadScriptOnce("marked", LIB_URLS.marked));
        if (typeof window.hljs === "undefined") tasks.push(loadScriptOnce("hljs", LIB_URLS.hljs));
        tasks.push(loadStyleOnce("hljs-css", LIB_URLS.hljsCss));
        await Promise.all(tasks);
    }

    async function ensureMarkdownSanitizer() {
        if (typeof window.DOMPurify !== "undefined") return;
        try {
            await loadScriptOnce("dompurify", LIB_URLS.dompurify);
        } catch (_) {
            // Fallback sanitizer is used when CDN loading fails.
        }
    }

    async function ensureHls() {
        if (typeof window.Hls !== "undefined") return;
        await loadScriptOnce("hls", LIB_URLS.hls);
    }

    function debounce(fn, wait) {
        let timer = null;
        return function debounced(...args) {
            clearTimeout(timer);
            timer = setTimeout(() => fn.apply(this, args), wait);
        };
    }

    function escapeHtml(value) {
        return String(value || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function normalizeCapabilities(value) {
        const source = value && typeof value === "object" ? value : {};
        return {
            read: toBool(source.read),
            write: toBool(source.write),
            delete: toBool(source.delete),
            rename: toBool(source.rename),
            move: toBool(source.move),
            copy: toBool(source.copy),
            upload: toBool(source.upload),
            mkdir: toBool(source.mkdir),
            edit: toBool(source.edit),
            trash: toBool(source.trash),
            unzip: toBool(source.unzip),
        };
    }

    function fallbackSanitizeHtml(value) {
        const template = document.createElement("template");
        template.innerHTML = String(value || "");
        const blockedTags = new Set([
            "script",
            "style",
            "iframe",
            "object",
            "embed",
            "form",
            "input",
            "button",
            "textarea",
            "select",
            "link",
            "meta",
        ]);
        const walker = document.createTreeWalker(template.content, NodeFilter.SHOW_ELEMENT);
        const toRemove = [];

        while (walker.nextNode()) {
            const element = walker.currentNode;
            const tag = String(element.tagName || "").toLowerCase();
            if (blockedTags.has(tag)) {
                toRemove.push(element);
                continue;
            }
            Array.from(element.attributes).forEach((attr) => {
                const attrName = String(attr.name || "").toLowerCase();
                const attrValue = String(attr.value || "").trim();
                if (attrName.startsWith("on")) {
                    element.removeAttribute(attr.name);
                    return;
                }
                if (["src", "href", "xlink:href", "action", "formaction"].includes(attrName)) {
                    const normalized = attrValue.toLowerCase();
                    const isAllowed =
                        normalized.startsWith("http://") ||
                        normalized.startsWith("https://") ||
                        normalized.startsWith("mailto:") ||
                        normalized.startsWith("tel:") ||
                        normalized.startsWith("/") ||
                        normalized.startsWith("./") ||
                        normalized.startsWith("../") ||
                        normalized.startsWith("#") ||
                        !normalized.includes(":");
                    if (!isAllowed) {
                        element.removeAttribute(attr.name);
                    }
                }
            });
        }

        toRemove.forEach((node) => node.remove());
        return template.innerHTML;
    }

    function sanitizePreviewHtml(value) {
        const html = String(value || "");
        if (typeof window.DOMPurify !== "undefined") {
            return window.DOMPurify.sanitize(html, {
                USE_PROFILES: { html: true },
                FORBID_TAGS: ["script", "style", "iframe", "object", "embed", "form", "input", "button", "textarea", "select", "link", "meta"],
                ALLOW_UNKNOWN_PROTOCOLS: false,
            });
        }
        return fallbackSanitizeHtml(html);
    }

    function renderMarkdownHtml(value) {
        const source = String(value || "");
        if (typeof window.marked === "undefined") {
            return `<pre><code>${escapeHtml(source)}</code></pre>`;
        }
        return sanitizePreviewHtml(window.marked.parse(source));
    }

    function encodePath(path) {
        if (!path) return "";
        return String(path).split("/").map(encodeURIComponent).join("/");
    }

    function fmtBytes(bytes) {
        const b = Number(bytes || 0);
        if (b < 1024) return `${b} B`;
        if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
        if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`;
        return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
    }

    function fmtDate(ts) {
        const num = Number(ts || 0);
        if (!num) return "";
        const d = new Date(num * 1000);
        if (Number.isNaN(d.getTime())) return "";
        const y = d.getFullYear();
        const m = String(d.getMonth() + 1).padStart(2, "0");
        const day = String(d.getDate()).padStart(2, "0");
        const hh = String(d.getHours()).padStart(2, "0");
        const mm = String(d.getMinutes()).padStart(2, "0");
        return `${y}-${m}-${day} ${hh}:${mm}`;
    }

    function iconFor(item) {
        if (item.is_dir) return { cls: "fa-solid fa-folder", color: "var(--folder)" };
        const ext = String(item.ext || "").toLowerCase();
        const map = {
            image: { cls: "fa-solid fa-image", color: "#ec4899" },
            video: { cls: "fa-solid fa-film", color: "#8b5cf6" },
            audio: { cls: "fa-solid fa-music", color: "#ec4899" },
            archive: { cls: "fa-solid fa-file-zipper", color: "#6366f1" },
            text: { cls: "fa-solid fa-file-code", color: "#64748b" },
        };
        if (ext === ".pdf") return { cls: "fa-solid fa-file-pdf", color: "#ef4444" };
        if (ext === ".doc" || ext === ".docx") return { cls: "fa-solid fa-file-word", color: "#2563eb" };
        if (ext === ".xls" || ext === ".xlsx") return { cls: "fa-solid fa-file-excel", color: "#16a34a" };
        if (ext === ".ppt" || ext === ".pptx") return { cls: "fa-solid fa-file-powerpoint", color: "#ea580c" };
        if (ext === ".py") return { cls: "fa-brands fa-python", color: "#3b82f6" };
        if (ext === ".js") return { cls: "fa-brands fa-js", color: "#facc15" };
        if (ext === ".html" || ext === ".htm") return { cls: "fa-brands fa-html5", color: "#f97316" };
        if (ext === ".css") return { cls: "fa-brands fa-css3-alt", color: "#06b6d4" };
        if (ext === ".json") return { cls: "fa-solid fa-code", color: "#a855f7" };
        if (ext === ".md" || ext === ".markdown") return { cls: "fa-brands fa-markdown", color: "#64748b" };
        return map[item.type] || { cls: "fa-solid fa-file", color: "#94a3b8" };
    }

    function createItemElement(item) {
        const capabilities = normalizeCapabilities(item.capabilities);
        const li = document.createElement("li");
        li.className = "file-item data-item";
        li.tabIndex = 0;
        li.setAttribute("role", "listitem");
        li.dataset.path = item.path || "";
        li.dataset.name = item.name || "";
        li.dataset.type = item.type || "file";
        li.dataset.size = String(item.size || 0);
        li.dataset.date = String(item.mtime || 0);
        li.dataset.ext = item.ext || "";
        li.dataset.isDir = item.is_dir ? "true" : "false";
        li.dataset.capabilities = JSON.stringify(capabilities);

        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.className = "file-check";
        checkbox.value = item.name || "";
        checkbox.setAttribute("aria-label", `${item.name || ""} 선택`);
        checkbox.addEventListener("click", (evt) => {
            evt.stopPropagation();
            if (typeof window.toggleBatch === "function") window.toggleBatch(checkbox);
        });
        li.appendChild(checkbox);

        const iconWrap = document.createElement("div");
        iconWrap.className = `file-icon ${item.is_dir ? "folder" : ""}`;
        iconWrap.setAttribute("aria-hidden", "true");
        const icon = iconFor(item);
        iconWrap.innerHTML = `<i class="${icon.cls}" style="color:${icon.color}"></i>`;
        li.appendChild(iconWrap);

        if (!item.is_dir && item.type === "image") {
            const preview = document.createElement("img");
            preview.className = "preview";
            preview.loading = "lazy";
            preview.style.display = "none";
            preview.src = `/download/${encodePath(item.path)}`;
            preview.alt = item.name || "";
            li.appendChild(preview);
        }

        const info = document.createElement("div");
        info.className = "file-info";
        const sizeText = item.is_dir ? "" : fmtBytes(item.size);
        const modText = fmtDate(item.mtime);
        info.innerHTML = `
            <div class="file-name">${escapeHtml(item.name)}</div>
            <div class="file-meta">${escapeHtml(sizeText)}${sizeText && modText ? " • " : ""}${escapeHtml(modText)}</div>
        `;
        info.addEventListener("click", () => {
            if (typeof window.handleItemClick === "function") {
                window.handleItemClick(item.path || "", item.type || "file", Boolean(item.is_dir), item.ext || "");
            } else if (item.is_dir) {
                window.location.href = `/browse/${encodePath(item.path)}`;
            } else {
                window.location.href = `/download/${encodePath(item.path)}`;
            }
        });
        li.appendChild(info);

        const actions = document.createElement("div");
        actions.className = "file-actions";

        if (!item.is_dir && item.type === "text" && capabilities.edit) {
            const editBtn = document.createElement("button");
            editBtn.className = "btn-icon btn-outline";
            editBtn.setAttribute("aria-label", "편집");
            editBtn.innerHTML = '<i class="fa-solid fa-pen"></i>';
            editBtn.addEventListener("click", (evt) => {
                evt.stopPropagation();
                if (typeof window.openEditor === "function") {
                    window.openEditor(item.path || "", item.name || "", item.ext || "");
                }
            });
            actions.appendChild(editBtn);
        }

        if (capabilities.read) {
            const downloadBtn = document.createElement("button");
            downloadBtn.className = "btn-icon btn-outline";
            downloadBtn.setAttribute("aria-label", "다운로드");
            downloadBtn.innerHTML = '<i class="fa-solid fa-download"></i>';
            downloadBtn.addEventListener("click", (evt) => {
                evt.stopPropagation();
                if (typeof window.downloadItem === "function") {
                    window.downloadItem(item.path || "");
                } else {
                    window.location.href = `/download/${encodePath(item.path)}`;
                }
            });
            actions.appendChild(downloadBtn);
        }

        if (capabilities.delete && !item.is_dir) {
            const deleteBtn = document.createElement("button");
            deleteBtn.className = "btn-icon btn-danger";
            deleteBtn.setAttribute("aria-label", "삭제");
            deleteBtn.innerHTML = '<i class="fa-solid fa-trash"></i>';
            deleteBtn.addEventListener("click", (evt) => {
                evt.stopPropagation();
                if (typeof window.deleteItem === "function") window.deleteItem(item.path || "");
            });
            actions.appendChild(deleteBtn);
        }

        li.appendChild(actions);

        li.addEventListener("contextmenu", (evt) => {
            if (typeof window.openCtx === "function") {
                window.openCtx(evt, item.path || "", item.name || "", item.type || "file", capabilities);
            }
        });
        li.addEventListener("keydown", (evt) => {
            if (evt.key === "Enter" && typeof window.handleItemClick === "function") {
                window.handleItemClick(item.path || "", item.type || "file", Boolean(item.is_dir), item.ext || "");
            }
        });
        return li;
    }

    function renderItemsIncrementally(list, items) {
        const chunkSize = 40;
        return new Promise((resolve) => {
            if (!items.length) {
                resolve();
                return;
            }

            let cursor = 0;
            function renderChunk() {
                const fragment = document.createDocumentFragment();
                const limit = Math.min(cursor + chunkSize, items.length);
                for (; cursor < limit; cursor += 1) {
                    fragment.appendChild(createItemElement(items[cursor]));
                }
                list.appendChild(fragment);

                if (cursor < items.length) {
                    requestAnimationFrame(renderChunk);
                    return;
                }
                resolve();
            }

            requestAnimationFrame(renderChunk);
        });
    }

    function updatePager() {
        const textEl = document.getElementById("listPaginationText");
        const btn = document.getElementById("loadMoreBtn");
        if (textEl) {
            textEl.textContent = `${state.totalCount.toLocaleString()}개 / ${state.page}페이지`;
        }
        if (btn) {
            btn.style.display = state.hasNext ? "inline-flex" : "none";
            btn.disabled = state.loading;
        }
    }

    function getListEndpoint() {
        const path = String(window.CURRENT_PATH || "").trim();
        const encodedPath = path ? path.split("/").map(encodeURIComponent).join("/") : "";
        return encodedPath ? `/api/list/${encodedPath}` : "/api/list/";
    }

    async function fetchList(append) {
        if (state.loading) return;
        state.loading = true;
        updatePager();

        const targetPage = append ? state.page + 1 : 1;
        const params = new URLSearchParams({
            page: String(targetPage),
            page_size: String(state.pageSize),
            sort: state.sortBy,
            order: state.sortOrder,
            q: state.query,
        });

        try {
            const res = await fetch(`${getListEndpoint()}?${params.toString()}`, { credentials: "same-origin" });
            const data = await res.json();
            if (!res.ok || !data.success) {
                throw new Error(data.error || "목록을 불러오지 못했습니다.");
            }

            const list = document.getElementById("fileList");
            if (!list) return;

            const parentRow = list.querySelector(".parent-folder");
            if (!append) {
                list.innerHTML = "";
                if (parentRow) list.appendChild(parentRow);
            }

            const fetchedItems = data.items || [];
            await renderItemsIncrementally(list, fetchedItems);

            if (!append && fetchedItems.length === 0) {
                const empty = document.createElement("div");
                empty.className = "empty-state";
                empty.innerHTML = `
                    <i class="fa-solid fa-folder-open"></i>
                    <p>${escapeHtml((window.T && (window.T.empty_folder || window.T.empty)) || "폴더가 비어있습니다")}</p>
                `;
                list.appendChild(empty);
            }

            const paging = data.pagination || {};
            window.CURRENT_CAPABILITIES = normalizeCapabilities(data.directory_capabilities || window.CURRENT_CAPABILITIES);
            if (typeof window.applyDirectoryCapabilities === "function") {
                window.applyDirectoryCapabilities(window.CURRENT_CAPABILITIES);
            }
            state.page = Number(paging.page || targetPage);
            state.totalCount = Number(paging.total_count || 0);
            state.totalPages = Number(paging.total_pages || 1);
            state.hasNext = toBool(paging.has_next);
        } catch (err) {
            if (typeof window.showToast === "function") {
                window.showToast(err.message || "목록 로드 실패", "error");
            }
        } finally {
            state.loading = false;
            updatePager();
        }
    }

    async function fetchDashboardSummary() {
        try {
            const res = await fetch("/api/dashboard/summary", { credentials: "same-origin" });
            if (!res.ok) return;
            const data = await res.json();
            const summary = data || {};
            const metrics = summary.metrics || {};
            const disk = summary.disk || {};

            const stUptime = document.getElementById("st_uptime");
            const stReq = document.getElementById("st_req");
            const stSent = document.getElementById("st_sent");
            const stRecv = document.getElementById("st_recv");
            if (stUptime) stUptime.innerText = metrics.uptime || "-";
            if (stReq) stReq.innerText = Number(metrics.requests || 0).toLocaleString();
            if (stSent) stSent.innerText = metrics.bytes_sent_fmt || "0 B";
            if (stRecv) stRecv.innerText = metrics.bytes_received_fmt || "0 B";

            const diskText = document.getElementById("diskText");
            const diskFill = document.getElementById("diskFill");
            if (diskText) {
                diskText.innerText = `${disk.used_fmt || disk.used || "-"} / ${disk.total_fmt || disk.total || "-"} (${disk.percent || 0}%)`;
            }
            if (diskFill) {
                const percent = Number(disk.percent || 0);
                diskFill.style.width = `${Math.max(0, Math.min(100, percent))}%`;
            }
        } catch (_) {
            // no-op
        }
    }

    async function canonicalLoadSystemStats() {
        let modal = document.getElementById("systemStatsModal");
        if (!modal) {
            modal = document.createElement("div");
            modal.id = "systemStatsModal";
            modal.className = "overlay";
            modal.style.display = "none";
            modal.innerHTML = `
                <div class="modal-content" style="max-width:760px;">
                    <div class="modal-header">
                        <h3><i class="fa-solid fa-server"></i> 시스템 모니터링</h3>
                        <button class="btn-icon" onclick="closeModal('systemStatsModal')"><i class="fa-solid fa-xmark"></i></button>
                    </div>
                    <div id="systemStatsContent" style="padding:12px 4px;"></div>
                </div>
            `;
            document.body.appendChild(modal);
        }

        const container = document.getElementById("systemStatsContent");
        if (!container) return;
        container.innerHTML =
            '<div style="text-align:center; padding:30px;"><i class="fa-solid fa-spinner fa-spin" style="font-size:1.5rem;"></i></div>';

        if (typeof window.openModal === "function") {
            window.openModal("systemStatsModal");
        } else {
            modal.style.display = "flex";
        }

        try {
            const res = await fetch("/api/dashboard/summary", { credentials: "same-origin" });
            const summary = await res.json();
            if (!res.ok) throw new Error(summary.error || "failed");

            const metrics = summary.metrics || {};
            const disk = summary.disk || {};
            const percent = Number(disk.percent || 0);
            const color = percent > 90 ? "var(--danger)" : percent > 70 ? "var(--warning)" : "var(--success)";

            container.innerHTML = `
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">서버 가동시간</div>
                        <div class="stat-value">${escapeHtml(metrics.uptime || "-")}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">총 요청수</div>
                        <div class="stat-value">${Number(metrics.requests || 0).toLocaleString()}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">전송된 데이터</div>
                        <div class="stat-value">${escapeHtml(metrics.bytes_sent_fmt || "0 B")}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">수신된 데이터</div>
                        <div class="stat-value">${escapeHtml(metrics.bytes_received_fmt || "0 B")}</div>
                    </div>
                </div>
                <div class="admin-section" style="margin-top:20px;">
                    <h4><i class="fa-solid fa-hard-drive"></i> 디스크 사용량</h4>
                    <p><strong>사용:</strong> ${escapeHtml(disk.used_fmt || disk.used || "-")} / ${escapeHtml(disk.total_fmt || disk.total || "-")} (${percent}%)</p>
                    <div class="disk-bar"><div class="disk-fill" style="width:${Math.max(0, Math.min(100, percent))}%; background:${color};"></div></div>
                    <p style="margin-top:10px;"><strong>여유 공간:</strong> ${escapeHtml(disk.free_fmt || disk.free || "-")}</p>
                </div>
            `;
        } catch (_) {
            container.innerHTML =
                '<div style="text-align:center; color:var(--danger); padding:20px;"><i class="fa-solid fa-circle-exclamation"></i> 시스템 정보를 불러오지 못했습니다.</div>';
        }
    }

    function canonicalToggleTheme() {
        const html = document.documentElement;
        const current = html.getAttribute("data-theme") || "light";
        const next = current === "light" ? "dark" : "light";
        html.setAttribute("data-theme", next);
        localStorage.setItem("theme", next);

        const icon = document.querySelector('[data-tooltip="테마 변경"] i');
        if (icon) icon.className = next === "dark" ? "fa-solid fa-sun" : "fa-solid fa-moon";
    }

    function canonicalToggleLanguage() {
        const currentLang = document.documentElement.lang || "ko";
        const nextLang = currentLang === "ko" ? "en" : "ko";
        const token = document.querySelector('meta[name="csrf-token"]')?.content || "";
        fetch("/set_language", {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": token,
            },
            body: JSON.stringify({ lang: nextLang, csrf_token: token }),
        })
            .then((r) => r.json())
            .then((d) => {
                if (d.success) window.location.reload();
            });
    }

    function installLazyWrappers() {
        const originalOpenEditor = typeof window.openEditor === "function" ? window.openEditor : null;
        if (originalOpenEditor && !originalOpenEditor.__wsLazyWrapped) {
            const wrappedOpenEditor = async function (path, name, ext, readOnly) {
                try {
                    const normalizedExt = String(ext || "").toLowerCase();
                    if (readOnly && HLS_EXTENSIONS.has(normalizedExt)) {
                        await ensureHls();
                    }
                } catch (_) {
                    // Hls 전역이 없으면 기존 코드에서 ReferenceError가 날 수 있어 폴백 정의
                    if (typeof window.Hls === "undefined") {
                        window.Hls = { isSupported: () => false };
                    }
                }
                return originalOpenEditor.apply(this, arguments);
            };
            wrappedOpenEditor.__wsLazyWrapped = true;
            window.openEditor = wrappedOpenEditor;
        }

        const originalToggleMarkdownPreview =
            typeof window.toggleMarkdownPreview === "function" ? window.toggleMarkdownPreview : null;
        if (originalToggleMarkdownPreview && !originalToggleMarkdownPreview.__wsLazyWrapped) {
            const wrappedTogglePreview = async function () {
                try {
                    await Promise.all([ensureMarkedAndHighlight(), ensureMarkdownSanitizer()]);
                } catch (_) {
                    if (typeof window.marked === "undefined") {
                        window.marked = {
                            parse: (value) =>
                                `<pre><code>${String(value || "")
                                    .replace(/&/g, "&amp;")
                                    .replace(/</g, "&lt;")
                                    .replace(/>/g, "&gt;")}</code></pre>`,
                        };
                    }
                }
                return originalToggleMarkdownPreview.apply(this, arguments);
            };
            wrappedTogglePreview.__wsLazyWrapped = true;
            window.toggleMarkdownPreview = wrappedTogglePreview;
        }

        const originalPreviewMarkdown =
            typeof window.previewMarkdown === "function" ? window.previewMarkdown : null;
        if (originalPreviewMarkdown && !originalPreviewMarkdown.__wsLazyWrapped) {
            const wrappedPreviewMarkdown = async function () {
                try {
                    await Promise.all([ensureMarkedAndHighlight(), ensureMarkdownSanitizer()]);
                } catch (_) {
                    if (typeof window.marked === "undefined") {
                        window.marked = {
                            parse: (value) =>
                                `<pre><code>${String(value || "")
                                    .replace(/&/g, "&amp;")
                                    .replace(/</g, "&lt;")
                                    .replace(/>/g, "&gt;")}</code></pre>`,
                        };
                    }
                }
                return originalPreviewMarkdown.apply(this, arguments);
            };
            wrappedPreviewMarkdown.__wsLazyWrapped = true;
            window.previewMarkdown = wrappedPreviewMarkdown;
        }
    }

    window.WebShareCoreLoadMore = function () {
        fetchList(true);
    };
    window.fetchStats = fetchDashboardSummary;
    window.loadSystemStats = canonicalLoadSystemStats;
    window.toggleTheme = canonicalToggleTheme;
    window.toggleLanguage = canonicalToggleLanguage;
    window.wsSanitizePreviewHtml = sanitizePreviewHtml;
    window.wsRenderMarkdownHtml = renderMarkdownHtml;
    window.sortFiles = function () {
        const sortEl = document.getElementById("sortOrder");
        state.sortBy = sortEl ? sortEl.value : "name";
        fetchList(false);
    };
    window.filterFiles = debounce(function () {
        const input = document.getElementById("searchInput");
        state.query = input ? input.value.trim() : "";
        fetchList(false);
    }, 250);

    document.addEventListener("DOMContentLoaded", () => {
        installLazyWrappers();

        const sortEl = document.getElementById("sortOrder");
        if (sortEl && state.sortBy) sortEl.value = state.sortBy;

        const searchInput = document.getElementById("searchInput");
        if (searchInput && state.query) searchInput.value = state.query;
        if (searchInput) {
            searchInput.addEventListener("input", () => window.filterFiles());
        }

        const loadMoreBtn = document.getElementById("loadMoreBtn");
        if (loadMoreBtn) {
            loadMoreBtn.addEventListener("click", () => window.WebShareCoreLoadMore());
        }

        if (window.ENABLE_API_LIST_RENDER) {
            fetchList(false);
        } else {
            updatePager();
        }
        fetchDashboardSummary();
    });
})();
