package handlers

// Browser page shell for the Go backend (ISSUE-006).
//
// The Go core long served JSON only: GET / answered 401 JSON and /browse/
// did not exist, so a browser pointed at a frozen-exe server saw nothing
// but {"code":"UNAUTHORIZED",...}. Python renders templates/index.html for
// both routes; the full template port is still pending, so this file serves
// minimal standalone pages instead (the same browser/API split the share
// routes already use, ISSUE-005):
//
//   - GET / from a browser navigation  -> login HTML form (POSTs to /)
//   - GET / from an API caller         -> 401 JSON (unchanged contract)
//   - GET /browse/ authenticated       -> minimal file-browser shell that
//     drives the existing JSON list/download APIs with same-origin fetch
//   - GET /browse/ anonymous          -> 302 / for browsers, 401 for APIs
//     (denyUnauthenticated, Python login_required parity)

import (
	"bytes"
	"encoding/json"
	"html"
	"net/http"
	"strings"
)

// wantsBrowserHTML reports whether the caller navigates as a browser page
// (Accept: text/html) rather than an API client. Unlike the share routes'
// wantsShareJSON (which treats a missing Accept as a browser), this
// requires an explicit text/html preference so curl/scripts with no (or
// */*) Accept keep the exact JSON contract they have today.
func wantsBrowserHTML(r *http.Request) bool {
	if r.URL.Query().Get("format") == "json" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Requested-With")), "XMLHttpRequest") {
		return false
	}
	lowered := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(lowered, "application/json") {
		return false
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/json") {
		return false
	}
	return strings.Contains(accept, "text/html")
}

// writeLoginHTML renders the password form. The card style intentionally
// matches writeShareHTML (share password page) so both minimal Go pages
// look like one product.
func writeLoginHTML(w http.ResponseWriter, status int, errMsg string) {
	errBlock := ""
	if errMsg != "" {
		errBlock = "<div class=\"error\">" + html.EscapeString(errMsg) + "</div>"
	}
	writeShareHTML(w, status, "로그인 - WebShare Pro", "WebShare Pro",
		"<p>비밀번호를 입력하세요.</p>"+errBlock+
			"<form method=\"post\" action=\"/\">"+
			"<input type=\"password\" name=\"password\" placeholder=\"비밀번호를 입력하세요\" required autofocus>"+
			"<button type=\"submit\">로그인</button></form>")
}

// writeBrowseHTML serves the minimal file-browser shell. The listing
// itself comes from the existing GET /api/list/ JSON API (same-origin
// fetch carries the session cookie), so no new data contract is added.
// Server-provided strings reach the DOM via textContent only.
func (a *App) writeBrowseHTML(w http.ResponseWriter, sub, role string) {
	boot, _ := json.Marshal(map[string]any{"sub": sub, "role": role})
	// The bootstrap block lives inside a <script> element (raw-text
	// context: entities are NOT decoded), so escape </ as <\/ (valid
	// JSON) instead of HTML-escaping, which would break JSON.parse.
	boot = bytes.ReplaceAll(boot, []byte("</"), []byte(`<\/`))
	page := "<!DOCTYPE html><html lang=\"ko\"><head>" +
		"<meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">" +
		"<title>파일 - WebShare Pro</title>" +
		"<style>*{box-sizing:border-box}body{font-family:sans-serif;background:#f1f5f9;margin:0;color:#1e293b}" +
		"header{background:#0f172a;color:#fff;padding:12px 20px;display:flex;gap:12px;align-items:center}" +
		"header .path{color:#cbd5e1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}" +
		"header .sp{flex:1}header a{color:#fff}" +
		"main{max-width:960px;margin:24px auto;padding:0 16px}" +
		"table{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 10px 25px rgba(0,0,0,.08)}" +
		"th,td{text-align:left;padding:10px 14px;border-bottom:1px solid #e2e8f0;font-size:.95rem}" +
		"th{background:#f8fafc;color:#475569}td.num{text-align:right;white-space:nowrap}" +
		"a.row{color:#1d4ed8;text-decoration:none}a.row:hover{text-decoration:underline}" +
		".error{background:#fef2f2;color:#b91c1c;padding:12px 16px;border-radius:12px;margin-bottom:16px}" +
		"#pager{display:flex;gap:12px;align-items:center;justify-content:center;margin:16px 0}" +
		"button{padding:8px 18px;border:1px solid #cbd5e1;border-radius:8px;background:#fff;cursor:pointer}" +
		"button:disabled{opacity:.4;cursor:default}</style></head><body>" +
		"<header><strong>WebShare Pro</strong><span class=\"path\" id=\"crumb\"></span>" +
		"<span class=\"sp\"></span><span id=\"role\"></span><a href=\"/logout\">로그아웃</a></header>" +
		"<main><div id=\"err\" class=\"error\" hidden></div>" +
		"<table><thead><tr><th>이름</th><th>크기</th><th>수정 시각</th><th>동작</th></tr></thead>" +
		"<tbody id=\"rows\"></tbody></table>" +
		"<div id=\"pager\"><button id=\"prev\">이전</button><span id=\"pinfo\"></span>" +
		"<button id=\"next\">다음</button></div></main>" +
		"<script id=\"boot\" type=\"application/json\">" + string(boot) + "</script>" +
		"<script>(function(){\"use strict\";" +
		"var boot=JSON.parse(document.getElementById(\"boot\").textContent);" +
		"var sub=boot.sub||\"\",page=1;" +
		"var rows=document.getElementById(\"rows\"),err=document.getElementById(\"err\");" +
		"function enc(p){return p.split(\"/\").map(encodeURIComponent).join(\"/\");}" +
		"function size(n){if(n==null)return\"-\";if(n<1024)return n+\" B\";" +
		"var u=[\"KB\",\"MB\",\"GB\",\"TB\"],i=-1,v=n;" +
		"do{v/=1024;i++;}while(v>=1024&&i<u.length-1);return v.toFixed(1)+\" \"+u[i];}" +
		"function time(t){if(!t)return\"-\";var d=new Date(t*1000);" +
		"return isNaN(d)?\"-\":d.toLocaleString();}" +
		"function link(href,text){var a=document.createElement(\"a\");" +
		"a.href=href;a.className=\"row\";a.textContent=text;return a;}" +
		"async function load(){err.hidden=true;" +
		"var url=\"/api/list/\"+(sub?enc(sub):\"\")+\"?page=\"+page+\"&page_size=200\";" +
		"var res=await fetch(url,{headers:{\"Accept\":\"application/json\"," +
		"\"X-Requested-With\":\"XMLHttpRequest\"}});" +
		"if(res.status===401){location.href=\"/\";return;}" +
		"var doc=await res.json();" +
		"if(!doc||doc.success!==true){show((doc&&doc.error)||(\"오류 \"+res.status));return;}" +
		"render(doc);}" +
		"function show(m){err.textContent=m;err.hidden=false;}" +
		"function render(doc){sub=doc.path||\"\";" +
		"document.getElementById(\"crumb\").textContent=\"/\"+sub;" +
		"document.getElementById(\"role\").textContent=boot.role||\"\";" +
		"rows.textContent=\"\";" +
		"if(sub){var up=sub.split(\"/\").slice(0,-1).join(\"/\");" +
		"var tr=document.createElement(\"tr\"),td=document.createElement(\"td\");" +
		"td.colSpan=4;td.appendChild(link(up?\"/browse/\"+enc(up):\"/browse/\",\"상위 폴더로\"));" +
		"tr.appendChild(td);rows.appendChild(tr);}" +
		"(doc.items||[]).forEach(function(it){" +
		"var tr=document.createElement(\"tr\");" +
		"var n=document.createElement(\"td\");" +
		"if(it.is_dir){n.appendChild(link(\"/browse/\"+enc(it.path),it.name||\"\"));}" +
		"else{n.textContent=it.name||\"\";}" +
		"var s=document.createElement(\"td\");s.className=\"num\";" +
		"s.textContent=it.is_dir?\"-\":size(it.size);" +
		"var m=document.createElement(\"td\");m.className=\"num\";m.textContent=time(it.mtime);" +
		"var a=document.createElement(\"td\");" +
		"if(it.is_dir){a.appendChild(link(\"/browse/\"+enc(it.path),\"열기\"));}" +
		"else{var d=link(\"/download/\"+enc(it.path),\"다운로드\");" +
		"if(it.type===\"archive\"||(it.ext&&it.ext.toLowerCase()===\".zip\")){d.textContent=\"다운로드\";}" +
		"a.appendChild(d);}" +
		"tr.appendChild(n);tr.appendChild(s);tr.appendChild(m);tr.appendChild(a);" +
		"rows.appendChild(tr);});" +
		"var pg=doc.pagination||{};" +
		"document.getElementById(\"pinfo\").textContent=" +
		"(pg.page||1)+\" / \"+(pg.total_pages||1)+\" · 전체 \"+(pg.total_count||0)+\"개\";" +
		"document.getElementById(\"prev\").disabled=!pg.has_prev;" +
		"document.getElementById(\"next\").disabled=!pg.has_next;}" +
		"document.getElementById(\"prev\").addEventListener(\"click\",function(){" +
		"if(page>1){page--;load();}});" +
		"document.getElementById(\"next\").addEventListener(\"click\",function(){page++;load();});" +
		"load();})();</script></body></html>"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
}
