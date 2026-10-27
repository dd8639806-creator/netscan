#!/usr/bin/env python3
"""dashboard.py - live web dashboard for NetScan.

Run:   python3 dashboard.py
Open:  http://127.0.0.1:5050
Needs: pip3 install flask   (and netscan.py + risk.py in the same folder)
"""
import ipaddress
import socket

from flask import Flask, jsonify, request

import netscan

app = Flask(__name__)


def is_lab_target(target):
    """Only allow private / local IPs, so the tool is used on your own lab only."""
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(target))
        return ip.is_private or ip.is_loopback
    except Exception:
        return False


@app.route("/")
def home():
    return PAGE


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True)
    target = (data.get("target") or "").strip()
    demo = bool(data.get("demo"))
    try:
        if demo:
            xml = netscan.load_demo_scan()
        else:
            if not is_lab_target(target):
                return jsonify(error="Scan only your own lab machines (private IPs like 192.168.x.x)."), 400
            xml = netscan.run_nmap_scan(target)
        findings = netscan.parse_nmap_xml(xml)
        report = netscan.match_vulnerabilities(findings, netscan.load_vuln_db(), False)
        report = netscan.add_risk(report)
        rating, top = netscan.compute_risk_rating(report)
    except Exception as e:
        return jsonify(error=str(e)), 500

    rows = []
    counts = {}
    for r in report:
        v = r["vulnerability"]
        sev = v["severity"] if v else "CLEAN"
        counts[sev] = counts.get(sev, 0) + 1
        rows.append({
            "host": f"{r['ip']}:{r['port']}", "service": r["service"],
            "product": f"{r['product']} {r['version']}".strip(),
            "severity": sev, "score": r["score"],
            "cve": v["cve"] if v else "-",
            "description": v["description"] if v else "No known vulnerability found",
            "fix": v["fix"] if v else "No action needed.",
            "exploit": bool(v and v.get("exploit")),
        })
    return jsonify(target="demo sample" if demo else target, rating=rating,
                   top=top, counts=counts, rows=rows)


PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetScan Dashboard</title>
<style>
 body{font-family:'Segoe UI',Arial,sans-serif;background:#0F172A;color:#E2E8F0;margin:0;padding:30px}
 .wrap{max-width:1200px;margin:0 auto}
 h1{margin:0 0 18px;font-size:26px} h1 span{color:#5EEAD4;font-weight:400}
 .bar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:18px}
 input[type=text]{background:#1E293B;border:1px solid #334155;color:#E2E8F0;padding:10px 12px;border-radius:8px;font-size:14px}
 button{background:#0D9488;color:#fff;border:0;padding:11px 22px;border-radius:8px;font-size:14px;font-weight:bold;cursor:pointer}
 button:disabled{opacity:.5}
 #msg{color:#FBBF24;margin-bottom:14px;min-height:20px}
 .cards,.row{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:18px}
 .card,.panel{background:#1E293B;border-radius:10px;padding:18px 22px;flex:1;min-width:200px}
 .label{font-size:12px;color:#94A3B8;text-transform:uppercase;letter-spacing:1px}
 .value{font-size:28px;font-weight:bold;margin-top:6px}
 h3{margin:0 0 12px;font-size:13px;color:#94A3B8;text-transform:uppercase;letter-spacing:1px}
 .donutwrap{display:flex;gap:22px;align-items:center;flex-wrap:wrap}
 #donut{width:150px;height:150px;border-radius:50%;position:relative}
 #donut div{position:absolute;inset:30px;background:#1E293B;border-radius:50%}
 .lg{font-size:13px;margin:4px 0} .dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px}
 .meter{height:14px;border-radius:7px;background:linear-gradient(90deg,#16A34A,#D97706,#DC2626);position:relative;margin:10px 0 6px}
 #needle{position:absolute;top:-5px;width:4px;height:24px;background:#fff;border-radius:2px}
 #first{background:#0F172A;border-left:4px solid #DC2626;padding:10px 12px;border-radius:6px;font-size:13.5px;margin-top:6px}
 table{width:100%;border-collapse:collapse;background:#1E293B;border-radius:10px;overflow:hidden}
 th{background:#0F172A;text-align:left;padding:12px;font-size:12px;text-transform:uppercase;color:#94A3B8}
 td{padding:12px;border-top:1px solid #334155;font-size:13.5px;vertical-align:top}
 .badge{color:#fff;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:bold}
 .sbar{height:6px;background:#334155;border-radius:3px;margin-top:5px;width:80px}
 .sbar i{display:block;height:6px;border-radius:3px}
 .fix{color:#86EFAC} .ex{color:#FCA5A5;font-size:10px;font-weight:bold}
 .tw{overflow-x:auto}
</style></head><body><div class="wrap">
<h1>NetScan <span>Vulnerability Dashboard</span></h1>
<div class="bar">
 <input type="text" id="target" value="192.168.56.101" placeholder="Target IP">
 <label><input type="checkbox" id="demo" checked> Demo mode</label>
 <button id="go">Start Scan</button>
</div>
<div id="msg"></div>
<div id="out" style="display:none">
 <div class="cards">
  <div class="card"><div class="label">Ports scanned</div><div class="value" id="c1"></div></div>
  <div class="card"><div class="label">Flagged risky</div><div class="value" id="c2"></div></div>
  <div class="card"><div class="label">Highest score</div><div class="value" id="c3"></div></div>
  <div class="card" id="rc"><div class="label">Overall risk</div><div class="value" id="c4"></div></div>
 </div>
 <div class="row">
  <div class="panel"><h3>Severity mix</h3>
   <div class="donutwrap"><div id="donut"><div></div></div><div id="legend"></div></div></div>
  <div class="panel"><h3>Risk meter</h3>
   <div class="meter"><i id="needle"></i></div>
   <h3 style="margin-top:22px">Fix first</h3><div id="first"></div></div>
 </div>
 <div class="tw"><table><thead><tr><th>Host:Port</th><th>Service</th><th>Product</th><th>Severity</th>
  <th>Score</th><th>CVE</th><th>Description</th><th>How to fix</th></tr></thead><tbody id="rows"></tbody></table></div>
</div></div>
<script>
const C={CRITICAL:'#DC2626',HIGH:'#EA580C',MEDIUM:'#D97706',LOW:'#65A30D',UNKNOWN:'#64748B',CLEAN:'#16A34A'};
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

$('go').onclick=async()=>{
  $('go').disabled=true; $('msg').textContent='Scanning... please wait';
  try{
    const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({target:$('target').value,demo:$('demo').checked})});
    const d=await r.json();
    if(!r.ok) throw new Error(d.error);
    render(d); $('msg').textContent='';
  }catch(e){ $('msg').textContent='Error: '+e.message; }
  $('go').disabled=false;
};

function render(d){
  $('out').style.display='block';
  const risky=d.rows.filter(r=>r.severity!=='CLEAN').length;
  $('c1').textContent=d.rows.length; $('c2').textContent=risky; $('c3').textContent=d.top+'/100';
  $('c4').textContent=d.rating; $('c4').style.color=C[d.rating]||'#fff';
  $('rc').style.border='1px solid '+(C[d.rating]||'#334155');

  const keys=Object.keys(d.counts), total=keys.reduce((a,k)=>a+d.counts[k],0);
  let acc=0, stops=[], lg='';
  keys.forEach(k=>{
    const s=acc/total*100; acc+=d.counts[k]; const e=acc/total*100;
    stops.push(C[k]+' '+s+'% '+e+'%');
    lg+='<div class="lg"><span class="dot" style="background:'+C[k]+'"></span>'+esc(k)+': '+d.counts[k]+'</div>';
  });
  $('donut').style.background='conic-gradient('+stops.join(',')+')';
  $('legend').innerHTML=lg;

  $('needle').style.left='calc('+Math.min(d.top,100)+'% - 2px)';
  const f=d.rows[0];
  $('first').innerHTML=f&&f.score>0
    ? '<b>'+esc(f.host)+' '+esc(f.product)+'</b> (score '+f.score+')<br><span class="fix">'+esc(f.fix)+'</span>'
    : 'Nothing risky found.';

  $('rows').innerHTML=d.rows.map(r=>'<tr><td>'+esc(r.host)+'</td><td>'+esc(r.service)+'</td><td>'+esc(r.product)+'</td>'
    +'<td><span class="badge" style="background:'+(C[r.severity]||C.UNKNOWN)+'">'+esc(r.severity)+'</span></td>'
    +'<td><b>'+r.score+'</b>/100'+(r.exploit?'<br><span class="ex">EXPLOIT AVAILABLE</span>':'')
    +'<div class="sbar"><i style="width:'+r.score+'%;background:'+(C[r.severity]||C.UNKNOWN)+'"></i></div></td>'
    +'<td>'+esc(r.cve)+'</td><td>'+esc(r.description)+'</td><td class="fix">'+esc(r.fix)+'</td></tr>').join('');
}
</script></body></html>"""


if __name__ == "__main__":
    print("NetScan dashboard: http://127.0.0.1:5050")
    app.run(host="127.0.0.1", port=5050)
