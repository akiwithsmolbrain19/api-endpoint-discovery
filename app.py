"""Hosted real-time dashboard: crawled sites + endpoints (scroll boxes), click endpoint -> analysis."""
import json, queue, threading, uuid
from datetime import datetime, timezone
from flask import Flask, Response, jsonify, request

from crawler import crawl
from endpoint_discovery import discover_endpoints
from endpoint_analysis import EndpointAnalyzer

app = Flask(__name__)
scans = {}

HTML = """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>
<title>API Endpoint Discovery</title>
<style>
:root{--bg:#f8fafc;--fg:#0f172a;--card:#fff;--line:#e2e8f0;--mut:#64748b;--hov:#f1f5f9;--sel:#e0f2fe;--code-bg:#0f172a;--code-fg:#e2e8f0;--btn-bg:#0f172a;--btn-fg:#fff}
[data-theme=dark]{--bg:#0f172a;--fg:#e2e8f0;--card:#1e293b;--line:#334155;--mut:#94a3b8;--hov:#334155;--sel:#0c4a6e;--code-bg:#020617;--code-fg:#e2e8f0;--btn-bg:#e2e8f0;--btn-fg:#0f172a}
body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;background:var(--bg);color:var(--fg)}
header{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}input{padding:.6rem;font-size:1rem;flex:1;min-width:280px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg)}
button{padding:.6rem 1.2rem;cursor:pointer;background:var(--btn-bg);color:var(--btn-fg);border:0;border-radius:8px;font-weight:600}
.top{display:flex;justify-content:space-between;align-items:center}
.icon-btn{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:.4rem .8rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1rem;margin-top:1rem}
h2{margin:.2rem 0;font-size:1.05rem}.count{background:var(--line);border-radius:10px;padding:0 10px;font-size:.8rem}
.scroll{max-height:260px;overflow:auto;border:1px solid var(--line);border-radius:8px}
table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid var(--line);padding:.45rem;text-align:left;font-size:.85rem;word-break:break-all}
thead th{position:sticky;top:0;background:var(--card)}
tr.ep{cursor:pointer}tr.ep:hover{background:var(--hov)}tr.ep.sel{background:var(--sel)}
.badge{padding:2px 10px;border-radius:12px;font-size:.75rem;color:#fff}.confirmed{background:#16a34a}.likely{background:#ca8a04}.uncertain{background:#64748b}.unlikely{background:#dc2626}.pending{background:#94a3b8}
#detail pre{background:var(--code-bg);color:var(--code-fg);border-radius:8px;padding:1rem;overflow:auto;max-height:400px;font-size:.8rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.5rem;margin:.5rem 0}
.kv{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:.5rem}.kv b{display:block;font-size:.72rem;color:var(--mut)}
#status,.mut{color:var(--mut);font-size:.9rem}</style></head>
<body>
<div class=top><h1>API Endpoint Discovery</h1><button class=icon-btn onclick=toggle() id=tb>🌙 Dark</button></div>
<header><input id=url value="http://localhost:8000/"><button onclick=start()>Scan</button><span id=status></span></header>
<div class=card><h2>Sites crawled <span class=count id=n1>0</span></h2><div class=scroll><table><thead><tr><th>URL</th><th>Status</th><th>Content-Type</th></tr></thead><tbody id=rows1></tbody></table></div></div>
<div class=card><h2>Endpoints found <span class=count id=n2>0</span> <small class=mut>— click one to expand/collapse its analysis</small></h2><div class=scroll><table><thead><tr><th>URL</th><th>Source</th><th>Result</th></tr></thead><tbody id=rows2></tbody></table></div></div>
<script>
function toggle(){const h=document.documentElement;const d=h.getAttribute('data-theme')==='dark';h.setAttribute('data-theme',d?'light':'dark');document.getElementById('tb').textContent=d?'🌙 Dark':'☀️ Light';try{localStorage.setItem('theme',d?'light':'dark')}catch(e){}}
(function(){try{if(localStorage.getItem('theme')==='dark'){document.documentElement.setAttribute('data-theme','dark');document.getElementById('tb').textContent='☀️ Light'}}catch(e){}})();
let es;const store={};let done=false;function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;')}
function msg(ev){return (ev||[]).map(x=>String(x).replace(/^\\d+:\\s*/,'')).join('; ')}
function start(){document.getElementById('rows1').innerHTML='';document.getElementById('rows2').innerHTML='';
done=false;
['n1','n2'].forEach(i=>document.getElementById(i).textContent='0');document.getElementById('status').textContent='Scanning…';
for(const k in store)delete store[k];
const u=document.getElementById('url').value;
fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u})}).then(r=>r.json()).then(d=>{
if(es)es.close();es=new EventSource('/api/stream/'+d.scan_id);
es.onmessage=e=>{const m=JSON.parse(e.data);
if(m.page){const t=document.getElementById('rows1');t.insertAdjacentHTML('beforeend','<tr><td>'+esc(m.page.url)+'</td><td>'+esc(m.page.status)+'</td><td>'+esc(m.page.content_type)+'</td></tr>');document.getElementById('n1').textContent=t.children.length;}
if(m.candidate){const t=document.getElementById('rows2');const id='e'+t.children.length;
t.insertAdjacentHTML('beforeend','<tr class=ep id='+id+' onclick="show(\\''+id+'\\')"><td>'+esc(m.candidate.url)+'</td><td>'+esc(m.candidate.source)+'</td><td><span class="badge pending">analyzing…</span></td></tr>');
store[id]={candidate:m.candidate,result:null};document.getElementById('n2').textContent=t.children.length;}
if(m.result){const k=Object.keys(store).find(k=>store[k].candidate&&store[k].candidate.url===m.result.url);
if(k){store[k].result=m.result;const row=document.getElementById(k);if(row){const b=(m.result.api_behavior||{}).classification||'uncertain';
row.cells[2].innerHTML='<span class="badge '+b+'">'+b+'</span>';}}}
if(m.done){document.getElementById('status').textContent='Scan complete';done=true;es.close();}}});}
function show(id){const row=document.getElementById(id);
const nxt=row.nextSibling;
if(nxt&&nxt.classList&&nxt.classList.contains('detail')){nxt.remove();row.classList.remove('sel');return;}
document.querySelectorAll('tr.detail').forEach(r=>r.remove());document.querySelectorAll('tr.ep').forEach(r=>r.classList.remove('sel'));
row.classList.add('sel');const e=store[id];
const tr=document.createElement('tr');tr.className='detail';
const td=document.createElement('td');td.colSpan=3;
if(!e.result){td.innerHTML='<span class=mut>'+esc(e.candidate.url)+' — '+(done?'analysis unavailable.':'scanning in progress…')+'</span>';}
else{const r=e.result,b=(r.api_behavior||{}).classification||'',a=(r.access||{}).classification||'';
const params=r.parameters||[];
td.innerHTML='<span class="badge '+b+'">'+b+'</span> '+esc(a)
+'<div class=grid>'+[['Status',r.status],['Content-Type',r.content_type],['Size',r.response_size],['Time (ms)',r.response_time_ms],['Access',a],['Method',r.method]].map(x=>'<div class=kv><b>'+x[0]+'</b>'+esc(x[1])+'</div>').join('')+'</div>'
+'<p><b>Evidence:</b> '+esc(msg((r.api_behavior||{}).evidence))+'</p>'
+(params.length?'<p><b>Parameters:</b> '+esc(JSON.stringify(params))+'</p>':'')
+'<pre>'+esc(JSON.stringify(r,null,2))+'</pre>';}
tr.appendChild(td);row.after(tr);}
</script></body></html>"""

def emit(sid, obj):
    scans[sid]["q"].put(obj)

def run_scan(sid):
    s = scans[sid]; target = s["target"]
    try:
        records = crawl(target, max_pages=50)
        s["pages"] = records
        for r in records:
            emit(sid, {"page": {"url": r.get("url"), "status": r.get("status"), "content_type": r.get("content_type")}})
        cands = discover_endpoints(records, target)
        s["candidates"] = cands
        for c in cands:
            emit(sid, {"candidate": {"url": c.get("url"), "source": c.get("source"), "sources": c.get("sources")}})
        with EndpointAnalyzer() as an:
            for c in cands:
                r = an.analyze_endpoint(c)
                s["results"].append(r)
                emit(sid, {"result": r})
        s["status"] = "done"
        emit(sid, {"done": f"Done — {len(records)} pages, {len(cands)} endpoints"})
    except Exception as e:
        s["status"] = "error"; emit(sid, {"done": f"Error: {e}"})

@app.route("/")
def index(): return HTML

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url.startswith(("http://", "https://")): url = "http://" + url
    sid = uuid.uuid4().hex[:8]
    scans[sid] = {"status": "running", "target": url,
                  "pages": [], "candidates": [], "results": [], "q": queue.Queue(),
                  "created_at": datetime.now(timezone.utc).isoformat()}
    threading.Thread(target=run_scan, args=(sid,), daemon=True).start()
    return jsonify({"scan_id": sid})

@app.route("/api/stream/<sid>")
def stream(sid):
    if sid not in scans: return jsonify({"error": "unknown"}), 404
    q = scans[sid]["q"]
    def gen():
        yield "retry: 2000\n\n"
        while True:
            try: m = q.get(timeout=30)
            except queue.Empty:
                yield ": ping\n\n"; continue
            yield "data: " + json.dumps(m, default=str) + "\n\n"
            if "done" in m: break
    return Response(gen(), mimetype="text/event-stream")

@app.route("/api/result/<sid>")
def result(sid):
    if sid not in scans: return jsonify({"error": "unknown"}), 404
    s = scans[sid]
    return jsonify({"status": s["status"], "target": s["target"], "pages": s["pages"],
                    "candidates": s["candidates"], "results": s["results"]})

if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), threaded=True)
