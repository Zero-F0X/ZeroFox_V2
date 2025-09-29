#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZeroFox — Fast async XSS scanner with user-provided HTML dashboard template

This script writes the provided dashboard template (your design) to the output HTML file
and appends live findings by injecting small `<script>` snippets that call a
`receiveReport(...)` function embedded in the template. That function is added to the
template so the UI will update live (no page reload required beyond initial open).

Usage:
  pip install "httpx[http2]" beautifulsoup4 colorama aiofiles requests
  python zerofox_async_html_report.py --targets example.com --workers 120 --outdir output_report --html-output vuln.html

Only use on authorized targets.
"""

import os
import sys
import re
import time
import argparse
import urllib.parse
import asyncio
from itertools import cycle
from typing import List, Optional, Tuple, Dict, Set

import httpx
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as colorama_init
import aiofiles

colorama_init(autoreset=True)

# -------------------------
# Minimal config
# -------------------------
XSS_PAYLOAD_FILE = "xss.txt"
SMOKE_PAYLOAD_COUNT = 30
OUTDIR_DEFAULT = "output_report"
CONCURRENCY_DEFAULT = 120
RATE_LIMIT_PER_HOST = 0.02
REQUEST_TIMEOUT = 6.0
VERIFY_TLS = False
BATCH_EVIDENCE_FLUSH = 20
SAVE_EVIDENCE = True
HTTP2_PREFERRED = True

# -------------------------
# Dashboard template (user-provided) with small addition:
# - a receiveReport(report) JS function inserted after sample dataset
# - the rest of your template remains unchanged
# -------------------------
DASHBOARD_HTML = r'''<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ZeroFox — XSS Incident Dashboard</title>

  <!-- Fonts -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&family=Share+Tech+Mono&display=swap" rel="stylesheet">

  <style>
    :root{
      --bg:#060606;
      --panel:#0f0f12;
      --accent:#ff0033;
      --accent-2:#8b00ff;
      --muted:#9aa0a6;
      --glass: rgba(255,255,255,0.03);
      --glow: 0 6px 30px rgba(255,0,51,0.12);
    }
    *{box-sizing:border-box}
    html,body{height:100%;margin:0;font-family:Inter,system-ui,Segoe UI,Roboto,"Helvetica Neue",Arial}
    body{background:radial-gradient(1200px 600px at 10% 10%, rgba(139,0,255,0.06), transparent),
          radial-gradient(1000px 500px at 90% 90%, rgba(255,0,51,0.06), transparent),
          var(--bg);color:#e9eef6;}

    /* subtle animated noise background for eerie feel */
    .bg-noise{
      position:fixed;inset:0;pointer-events:none;mix-blend-mode:overlay;opacity:0.12;
      background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200"><filter id="n"><feTurbulence baseFrequency="0.9" numOctaves="2"/></filter><rect width="100%" height="100%" filter="url(%23n)"/></svg>');
    }

    /* Layout */
    .app{display:grid;grid-template-columns:260px 1fr;gap:24px;padding:28px;height:100vh}

    /* Sidebar */
    .sidebar{background:linear-gradient(180deg,var(--panel),rgba(16,16,20,0.8));border-radius:14px;padding:20px;box-shadow:var(--glow);position:relative;overflow:hidden}
    .logo{display:flex;gap:12px;align-items:center;margin-bottom:18px}
    .logo .mark{width:44px;height:44px;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--accent-2));display:flex;align-items:center;justify-content:center;font-weight:800;font-family:'Share Tech Mono';box-shadow:0 6px 20px rgba(139,0,255,0.15)}
    .logo h1{font-size:16px;margin:0}
    .logo p{margin:0;font-size:12px;color:var(--muted)}

    .nav{margin-top:18px}
    .nav a{display:flex;align-items:center;gap:10px;padding:10px;border-radius:8px;color:#dbe6ff;text-decoration:none;font-weight:600}
    .nav a:hover{background:linear-gradient(90deg,rgba(255,0,51,0.06),rgba(139,0,255,0.04));transform:translateX(4px)}

    .stats{margin-top:20px}
    .card{background:linear-gradient(180deg,rgba(255,255,255,0.02),transparent);padding:12px;border-radius:10px;margin-bottom:12px}
    .num{font-size:20px;font-weight:800}
    .label{font-size:11px;color:var(--muted)}

    /* Main */
    .main{padding:20px}
    .topbar{display:flex;justify-content:space-between;align-items:center;gap:12px}
    .search{display:flex;align-items:center;gap:8px;background:var(--glass);padding:10px;border-radius:10px;width:420px}
    .search input{flex:1;background:transparent;border:0;color:inherit;outline:none}

    .controls{display:flex;gap:8px;align-items:center}
    .btn{padding:10px 14px;border-radius:10px;border:0;background:linear-gradient(90deg,var(--accent),var(--accent-2));font-weight:700;color:white;cursor:pointer;box-shadow:var(--glow)}
    .btn.ghost{background:transparent;border:1px solid rgba(255,255,255,0.06)}

    .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:18px}
    .panel{background:linear-gradient(180deg,rgba(255,255,255,0.02),transparent);border-radius:12px;padding:16px;min-height:120px;position:relative}
    .panel h3{margin:0 0 10px 0;font-size:13px}
    .metric{font-size:28px;font-weight:800}

    /* Reports table */
    .table-wrap{margin-top:18px;background:linear-gradient(180deg, rgba(255,255,255,0.02), transparent); border-radius:12px;padding:8px}
    table{width:100%;border-collapse:collapse;font-size:13px}
    thead th{font-size:12px;color:var(--muted);text-align:left;padding:12px 8px}
    tbody tr{border-top:1px solid rgba(255,255,255,0.03);transition:background 0.2s}
    tbody tr:hover{background:linear-gradient(90deg, rgba(255,0,51,0.03), rgba(139,0,255,0.02))}
    td{padding:10px 8px}
    .tag{padding:6px 8px;border-radius:8px;font-weight:700;font-size:12px}
    .vuln{background:linear-gradient(90deg, #ff0033, #ff7a88);color:white}
    .fixed{background:linear-gradient(90deg,#22c55e,#7be495);color:#012a10}
    .unknown{background:linear-gradient(90deg,#f59e0b,#ffd580);color:#2a1900}

    /* Log / console */
    .log{margin-top:18px;background:#050505;border-radius:10px;padding:12px;height:180px;overflow:auto;font-family:'Share Tech Mono';font-size:12px;color:#b7c7ff}
    .log .row{padding:6px 0;border-bottom:1px dashed rgba(255,255,255,0.02)}

    /* Modal */
    .modal{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:linear-gradient(180deg,rgba(0,0,0,0.6),rgba(0,0,0,0.85));backdrop-filter:blur(4px);opacity:0;pointer-events:none;transition:0.2s}
    .modal.open{opacity:1;pointer-events:auto}
    .modal .box{width:900px;background:linear-gradient(180deg,#0b0b0c, #0f0f12);border-radius:12px;padding:18px;box-shadow:0 20px 60px rgba(0,0,0,0.7)}

    /* Glitch title */
    .title{font-family:'Share Tech Mono';font-size:22px;letter-spacing:2px;position:relative}
    .title::before,.title::after{content:attr(data-text);position:absolute;left:2px;top:0;opacity:0.8}
    .title::before{color:var(--accent);mix-blend-mode:screen;transform:translate(-2px, -2px) skewX(-6deg);filter:blur(0.8px)}
    .title::after{color:var(--accent-2);mix-blend-mode:screen;transform:translate(2px,2px) skewX(6deg);filter:blur(0.8px)}

    /* small responsive */
    @media(max-width:980px){.app{grid-template-columns:1fr;padding:16px}.grid{grid-template-columns:repeat(2,1fr)}.search{width:100%}}
    @media(max-width:640px){.grid{grid-template-columns:1fr}}

    /* scary pulse animation */
    .scan-led{width:10px;height:10px;border-radius:50%;background:var(--accent);box-shadow:0 0 8px rgba(255,0,51,0.6);animation:beat 1.8s infinite}
    @keyframes beat{0%{transform:scale(1)}50%{transform:scale(1.45)}100%{transform:scale(1)}}

    /* download link style */
    .small{font-size:12px;color:var(--muted)}

  </style>
</head>
<body>
  <div class="bg-noise" aria-hidden></div>

  <div class="app">
    <aside class="sidebar">
      <div class="logo">
        <div class="mark">ZF</div>
        <div>
          <h1>ZeroFox</h1>
          <p>Autonomous XSS Hunter</p>
        </div>
      </div>

      <nav class="nav">
        <a href="#">Dashboard</a>
        <a href="#">Scans</a>
        <a href="#">Payloads</a>
        <a href="#">Settings</a>
        <a href="#">Export</a>
      </nav>

      <div class="stats">
        <div class="card">
          <div class="label">Total Findings</div>
          <div class="num" id="total-findings">0</div>
        </div>
        <div class="card">
          <div class="label">Vulnerable Now</div>
          <div class="num" id="vuln-now">0</div>
        </div>
        <div class="card">
          <div class="label">Fixed</div>
          <div class="num" id="fixed-count">0</div>
        </div>
      </div>

      <div style="position:absolute;bottom:18px;left:20px;right:20px;">
        <div class="small">ZeroFox &copy; 2025</div>
        <div class="small">Theme: dark • vibe: ominous</div>
      </div>
    </aside>

    <main class="main">
      <div class="topbar">
        <div style="display:flex;gap:12px;align-items:center">
          <div class="title" data-text="ZEROFOX XSS REPORT">ZEROFOX XSS REPORT</div>
          <div style="display:flex;align-items:center;gap:8px;margin-left:10px"><div class="scan-led" title="scanner" ></div><div class="small">Live Scanner</div></div>
        </div>

        <div style="display:flex;align-items:center;gap:12px">
          <div class="search">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden><path d="M21 21l-4.35-4.35" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path><circle cx="11" cy="11" r="6" stroke="currentColor" stroke-width="2"></circle></svg>
            <input id="q" placeholder="search URL / payload / status" />
          </div>
          <div class="controls">
            <button class="btn" id="btn-sim">Simulate Alert</button>
            <button class="btn ghost" id="export-csv">Export CSV</button>
          </div>
        </div>
      </div>

      <div class="grid">
        <div class="panel">
          <h3>Active Scan</h3>
          <div class="metric" id="active-scan">idle</div>
          <div class="small" style="margin-top:8px">Target: <span id="active-target">-</span></div>
        </div>
        <div class="panel">
          <h3>Last Found</h3>
          <div class="metric" id="last-found">—</div>
          <div class="small" style="margin-top:8px">Timestamp: <span id="last-ts">—</span></div>
        </div>
        <div class="panel">
          <h3>Top Payload</h3>
          <div class="metric" id="top-payload"><script>alert(1)</script></div>
          <div class="small" style="margin-top:8px">Seen: <span id="top-count">0</span> times</div>
        </div>
      </div>

      <section class="table-wrap">
        <table>
          <thead>
            <tr>
              <th style="width:40px">#</th>
              <th>URL</th>
              <th>Payload</th>
              <th style="width:120px">Status</th>
              <th style="width:180px">Timestamp</th>
              <th style="width:120px">Action</th>
            </tr>
          </thead>
          <tbody id="reports">
            <!-- rows injected by JS -->
          </tbody>
        </table>
      </section>

      <div class="log" id="log">
        <!-- console rows -->
      </div>

    </main>
  </div>

  <!-- Modal detail -->
  <div class="modal" id="modal">
    <div class="box">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div>
          <h2 style="margin:0;font-family:'Share Tech Mono'">Report Detail</h2>
          <div class="small">Detail view & payload analysis</div>
        </div>
        <div><button class="btn" id="copy-payload">Copy Payload</button></div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 320px;gap:12px">
        <div style="background:#020203;padding:12px;border-radius:8px;font-family:'Share Tech Mono'" id="detail-left">
          <!-- left detail -->
        </div>
        <div style="background:#070709;padding:12px;border-radius:8px;">
          <h4 style="margin:0 0 10px 0">Quick Remediation</h4>
          <ol style="margin:0 0 12px 18px;color:var(--muted)">
            <li>Properly escape output on the server side (context-aware).</li>
            <li>Use CSP with script-src and strict directives.</li>
            <li>Sanitize user input and use an allowlist for HTML.</li>
            <li>Run regression test and re-scan until fixed.</li>
          </ol>
          <div class="small">Severity: <strong id="detail-sev">High</strong></div>
        </div>
      </div>

      <div style="display:flex;justify-content:flex-end;margin-top:12px;gap:8px">
        <button class="btn ghost" id="close-modal">Close</button>
        <button class="btn" id="mark-fixed">Mark Fixed</button>
      </div>

    </div>
  </div>

  <script>
    // sample dataset
    const sample = [
      {id:1,url:'http://example.com/login',payload:"<script>alert('XSS')</script>",status:'vulnerable',ts:'2025-09-29 19:00:15'},
      {id:2,url:'http://testsite.com/search?q=',payload:"<img src=x onerror=alert(1)>",status:'fixed',ts:'2025-09-29 18:45:03'},
      {id:3,url:'http://shop.local/product?id=12',payload:'" onmouseover=alert(1)"',status:'vulnerable',ts:'2025-09-28 08:14:10'}
    ];

    const reportsEl = document.getElementById('reports');
    const logEl = document.getElementById('log');

    // state
    let reports = [...sample];
    let nextId = 100;

    function render(){
      reportsEl.innerHTML='';
      reports.forEach((r,i)=>{
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${i+1}</td>
          <td title="${r.url}">${r.url.length>40? r.url.slice(0,40)+'...':r.url}</td>
          <td title="${r.payload}"><code style="font-family:'Share Tech Mono'">${escapeHtml(r.payload)}</code></td>
          <td><span class="tag ${r.status==='vulnerable'?'vuln':(r.status==='fixed'?'fixed':'unknown')}">${r.status}</span></td>
          <td>${r.ts}</td>
          <td><button class="btn ghost" onclick="openDetail(${r.id})">View</button></td>
        `;
        reportsEl.appendChild(tr);
      });

      // stats
      document.getElementById('total-findings').textContent = reports.length;
      document.getElementById('vuln-now').textContent = reports.filter(r=>r.status==='vulnerable').length;
      document.getElementById('fixed-count').textContent = reports.filter(r=>r.status==='fixed').length;

      // top payload
      const counts = {};
      reports.forEach(r=> counts[r.payload] = (counts[r.payload]||0)+1);
      const top = Object.keys(counts).sort((a,b)=>counts[b]-counts[a])[0]||'—';
      document.getElementById('top-payload').textContent = top;
      document.getElementById('top-count').textContent = counts[top]||0;

      // last found
      const last = reports.slice().sort((a,b)=> new Date(b.ts) - new Date(a.ts))[0];
      if(last){document.getElementById('last-found').textContent = last.url;document.getElementById('last-ts').textContent = last.ts}
    }

    function escapeHtml(s){return s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;')}

    // logs
    function log(msg){
      const row = document.createElement('div');row.className='row';row.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;logEl.prepend(row);
    }

    // receiveReport: called by injected script snippets to add live findings
    function receiveReport(obj){
      try{
        // normalize timestamp
        if(!obj.ts) obj.ts = new Date().toISOString().slice(0,19).replace('T',' ');
        obj.id = obj.id || nextId++;
        reports.unshift(obj);
        render();
        log('NEW FIND: '+obj.url+' — '+obj.payload);
        flashHeader();
        showToast('New XSS found: '+obj.url);
      }catch(e){console.error('receiveReport error',e)}
    }

    // simulate incoming report (live)
    function simulateIncoming(){
      const payloads = ["<script>alert(1)</script>","<svg/onload=alert(1)>","<img src=x onerror=alert(1)>",'" onmouseover=alert(1)"'];
      const urls = ['http://victim.local/pay','http://intranet/admin','http://shop.local/item?cat=5','http://legacy.app/comment'];
      const p = payloads[Math.floor(Math.random()*payloads.length)];
      const u = urls[Math.floor(Math.random()*urls.length)] + (Math.random()<0.5?'/':'?id='+Math.floor(Math.random()*999));
      const r = {id: nextId++, url:u, payload:p, status:'vulnerable', ts: new Date().toISOString().slice(0,19).replace('T',' ')};
      reports.unshift(r);
      render();
      log('NEW FIND: '+u+' — '+p);
      // visual alert
      flashHeader();
      showToast('New XSS found: '+u);
    }

    function flashHeader(){
      const el = document.querySelector('.title');
      el.style.transition='none';el.style.opacity=0.25;setTimeout(()=>{el.style.transition='0.3s';el.style.opacity=1},120);
    }

    // modal
    const modal = document.getElementById('modal');
    let currentDetail = null;
    function openDetail(id){
      const r = reports.find(x=>x.id===id);
      currentDetail = r;
      document.getElementById('detail-left').innerHTML = `
        <div style="font-size:12px;color:var(--muted)">URL</div>
        <div style="margin-bottom:10px">${r.url}</div>
        <div style="font-size:12px;color:var(--muted)">Payload</div>
        <pre style="background:#030305;padding:10px;border-radius:8px;color:#ffd7e0">${escapeHtml(r.payload)}</pre>
        <div style="margin-top:8px" class="small">Status: <strong>${r.status}</strong></div>
      `;
      document.getElementById('detail-sev').textContent = r.status==='vulnerable'?'High':'Low';
      modal.classList.add('open');
    }
    document.getElementById('close-modal').addEventListener('click',()=>modal.classList.remove('open'));
    document.getElementById('mark-fixed').addEventListener('click',()=>{
      if(!currentDetail) return;
      currentDetail.status='fixed';render();log('Marked fixed: '+currentDetail.url);modal.classList.remove('open');
    });
    document.getElementById('copy-payload').addEventListener('click',()=>{
      if(!currentDetail) return;navigator.clipboard.writeText(currentDetail.payload).then(()=>showToast('Payload copied'));
    });

    // toast
    function showToast(msg){
      const t = document.createElement('div');t.textContent=msg; t.style.position='fixed';t.style.right='20px';t.style.bottom='20px';t.style.background='linear-gradient(90deg,var(--accent),var(--accent-2))';t.style.padding='10px 14px';t.style.borderRadius='8px';t.style.boxShadow='var(--glow)';t.style.fontWeight='700';document.body.appendChild(t);
      setTimeout(()=>{t.style.transition='0.4s';t.style.opacity=0;t.style.transform='translateY(18px)';},2200);
      setTimeout(()=>t.remove(),2700);
    }

    // export csv
    document.getElementById('export-csv').addEventListener('click',()=>{
      const rows = [['id','url','payload','status','timestamp'],...reports.map(r=>[r.id,r.url,r.payload,r.status,r.ts])];
      const csv = rows.map(r=> r.map(c=> '"'+String(c).replaceAll('"','""')+'"').join(',')).join('\n');
      const blob = new Blob([csv],{type:'text/csv'});const url = URL.createObjectURL(blob);
      const a=document.createElement('a');a.href=url;a.download='zerofox_reports.csv';document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
      showToast('CSV exported');
    });

    // search
    document.getElementById('q').addEventListener('input', (e)=>{
      const q = e.target.value.toLowerCase();
      const rows = reports.filter(r=> r.url.toLowerCase().includes(q)||r.payload.toLowerCase().includes(q)||r.status.toLowerCase().includes(q));
      reportsEl.innerHTML='';rows.forEach((r,i)=>{
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${i+1}</td>
          <td title="${r.url}">${r.url.length>40? r.url.slice(0,40)+'...':r.url}</td>
          <td title="${r.payload}"><code style=\"font-family:'Share Tech Mono'\">${escapeHtml(r.payload)}</code></td>
          <td><span class="tag ${r.status==='vulnerable'?'vuln':(r.status==='fixed'?'fixed':'unknown')}">${r.status}</span></td>
          <td>${r.ts}</td>
          <td><button class="btn ghost" onclick="openDetail(${r.id})">View</button></td>
        `;
        reportsEl.appendChild(tr);
      });
    });

    // simulate button
    document.getElementById('btn-sim').addEventListener('click',()=>simulateIncoming());

    // initial render
    render();

    // periodic simulation to feel "live" (every ~22s)
    setInterval(()=>{
      if(Math.random()<0.45) simulateIncoming();
    },22000);

    // keyboard shortcut: N to add fake
    document.addEventListener('keydown', (e)=>{ if(e.key.toLowerCase()==='n') simulateIncoming(); });

    // log initial
    log('ZeroFox dashboard initialized');

  </script>
</body>
</html>
'''

# -------------------------
# Helpers to write/append to report
# -------------------------
async def write_dashboard(outdir: str, filename: str):
    ensure_dir(outdir)
    path = os.path.join(outdir, filename)
    async with aiofiles.open(path, 'w', encoding='utf-8') as f:
        await f.write(DASHBOARD_HTML)
    return path

async def append_report_snippet(outdir: str, filename: str, url: str, payload: str, status: str = 'vulnerable'):
    # create a JS snippet that calls receiveReport with a small object
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    obj = {
        'id': int(time.time()*1000) % 100000000,
        'url': url,
        'payload': payload,
        'status': status,
        'ts': ts
    }
    # JSON-safe string
    import json
    js = f"<script>if(typeof receiveReport==='function'){chr(32)}receiveReport({json.dumps(obj)});</script>\n"
    path = os.path.join(outdir, filename)
    async with aiofiles.open(path, 'a', encoding='utf-8') as f:
        await f.write(js)
    return True

# -------------------------
# The rest of the scanner is intentionally minimal here: we will implement a fast
# async smoke test loop and call append_report_snippet() immediately on hits.
# This keeps the sample focused on wiring the template with live updates.
# -------------------------

async def fetch_text(client: httpx.AsyncClient, url: str, timeout: float) -> Optional[str]:
    try:
        r = await client.get(url, timeout=timeout)
        return r.text or ""
    except Exception:
        return None

async def test_payloads_on_url(client: httpx.AsyncClient, url: str, payloads: List[str], timeout: float) -> Optional[Tuple[str, str, str]]:
    for p in payloads:
        test_url = inject_payload(url, p)
        text = await fetch_text(client, test_url, timeout)
        if text is None:
            continue
        dec = urllib.parse.unquote_plus(p)
        if p in text or dec in text:
            return (test_url, p, text)
    return None

def make_session_factory(proxies_cycle: Optional[cycle], verify_tls: bool, limits: Optional[httpx.Limits]=None, http2: bool=True):
    def factory():
        proxy = None
        if proxies_cycle:
            proxy = next(proxies_cycle)
        client = httpx.AsyncClient(http2=http2, verify=verify_tls, timeout=REQUEST_TIMEOUT, limits=limits)
        if proxy:
            client._proxies = {"all://": proxy}
        return client
    return factory

async def worker_job_quick(url: str, smoke_payloads: List[str], session_factory, host_rl, global_rl, outdir, html_filename):
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    await host_rl.wait(host)
    await global_rl.wait()
    client = session_factory()
    try:
        res = await test_payloads_on_url(client, url, smoke_payloads, REQUEST_TIMEOUT)
        if res:
            test_url, p, text = res
            # save small evidence
            relpath = None
            if SAVE_EVIDENCE:
                ev_dir = ensure_dir(os.path.join(outdir, 'evidence'))
                safe = safe_name_for_file(test_url)
                fn = os.path.join(ev_dir, f"{safe}__resp.html")
                try:
                    async with aiofiles.open(fn, 'w', encoding='utf-8') as f:
                        await f.write(f"<!-- payload: {p} -->\n")
                        await f.write(text or '')
                    relpath = os.path.relpath(fn, outdir)
                except Exception:
                    relpath = None
            # append live to dashboard
            await append_report_snippet(outdir, html_filename, test_url, p, 'vulnerable')
            print(Fore.MAGENTA + Style.BRIGHT + f"[>>> FOUND] {test_url} (payload: {p})" + Style.RESET_ALL)
    finally:
        await client.aclose()

async def run_quick_scan(urls: List[str], smoke_payloads: List[str], concurrency: int, proxies: List[str], outdir: str, html_filename: str):
    ensure_dir(outdir)
    await write_dashboard(outdir, html_filename)
    limits = httpx.Limits(max_keepalive_connections=max(10, concurrency//2), max_connections=max(50, concurrency*2))
    proxies_cycle = cycle(proxies) if proxies else None
    session_factory = make_session_factory(proxies_cycle, verify_tls=VERIFY_TLS, limits=limits, http2=HTTP2_PREFERRED)

    host_rl = HostRateLimiter(RATE_LIMIT_PER_HOST)
    global_rl = GlobalRateLimiter(400)

    sem = asyncio.Semaphore(concurrency)
    tasks = []

    async def sem_job(u):
        async with sem:
            await worker_job_quick(u, smoke_payloads, session_factory, host_rl, global_rl, outdir, html_filename)

    for u in urls:
        tasks.append(asyncio.create_task(sem_job(u)))

    await asyncio.gather(*tasks)
    print(Fore.GREEN + f"[✓] Quick scan finished. Live dashboard: {os.path.join(outdir, html_filename)}" + Style.RESET_ALL)

# -------------------------
# CLI
# -------------------------

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--targets','-t', required=True, help='domain or file with URLs')
    p.add_argument('--workers', type=int, default=CONCURRENCY_DEFAULT)
    p.add_argument('--proxies')
    p.add_argument('--outdir', default=OUTDIR_DEFAULT)
    p.add_argument('--html-output', default='contoh.html')
    p.add_argument('--limit-urls', type=int, default=0)
    return p.parse_args()


def gather_target_urls(arg_target: str, limit: int=0) -> List[str]:
    if os.path.exists(arg_target):
        with open(arg_target, 'r', encoding='utf-8') as f:
            urls = [l.strip() for l in f if l.strip()]
        return filter_parameterized(urls, limit if limit>0 else None)
    domain = arg_target.strip()
    print(Fore.CYAN + f"[~] Gathering URLs from Wayback + quick crawl for {domain} ..." + Style.RESET_ALL)
    wayback = load_wayback(domain, limit=1000)
    crawled = crawl_site(f"http://{domain}", max_depth=1, max_pages=200)
    combined = list(dict.fromkeys(wayback + crawled))
    return filter_parameterized(combined, limit if limit>0 else None)


def load_proxies_from_file(path: Optional[str]) -> List[str]:
    if not path:
        return []
    if not os.path.exists(path):
        print(Fore.YELLOW + f"[!] Proxy file not found: {path}" + Style.RESET_ALL)
        return []
    with open(path, 'r', encoding='utf-8') as f:
        return [l.strip() for l in f if l.strip()]


def main():
    args = parse_args()
    proxies = load_proxies_from_file(args.proxies) if args.proxies else []
    targets_arg = args.targets
    targets = gather_target_urls(targets_arg, limit=args.limit_urls)
    if not targets:
        print(Fore.YELLOW + "[!] No parameterized URLs found to scan." + Style.RESET_ALL)
        return
    full_payloads = load_payloads(XSS_PAYLOAD_FILE)
    smoke_payloads = full_payloads[:SMOKE_PAYLOAD_COUNT]
    print(Fore.MAGENTA + "ZeroFox — quick live scanner" + Style.RESET_ALL)
    print(Fore.GREEN + f"[i] Targets: {len(targets)} URLs | Workers: {args.workers} | Proxies: {len(proxies)} | HTML output: {args.html_output}" + Style.RESET_ALL)
    try:
        asyncio.run(run_quick_scan(targets, smoke_payloads, args.workers, proxies, args.outdir, args.html_output))
    except Exception as e:
        print(Fore.RED + f"[!] Runtime error: {e}" + Style.RESET_ALL)

if __name__ == '__main__':
    main()
