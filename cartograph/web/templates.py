"""Inline HTML for the local web UI (self-contained, no CDN)."""

from __future__ import annotations

INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cartograph</title>
<style>
  :root{color-scheme:dark}
  body{margin:0;background:#0e1116;color:#e6edf3;font-family:Segoe UI,Arial,sans-serif}
  header{padding:18px 24px;border-bottom:1px solid #30363d}
  header h1{margin:0;font-size:20px;color:#58a6ff}
  header p{margin:4px 0 0;color:#8b949e;font-size:13px}
  main{padding:24px;max-width:1200px;margin:0 auto}
  form{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:8px}
  input[type=text]{flex:1;min-width:240px;padding:10px 12px;background:#161b22;border:1px solid #30363d;
                   border-radius:6px;color:#e6edf3;font-size:15px}
  label{font-size:13px;color:#8b949e;display:flex;align-items:center;gap:5px}
  input[type=number]{width:64px;padding:6px;background:#161b22;border:1px solid #30363d;border-radius:6px;color:#e6edf3}
  button{padding:10px 18px;background:#238636;border:0;border-radius:6px;color:#fff;font-size:15px;cursor:pointer}
  button:disabled{opacity:.5;cursor:default}
  #reset{background:#30363d}
  .note{color:#8b949e;font-size:12px;margin:2px 0 18px}
  #status{margin:14px 0;color:#8b949e}
  .spinner{display:inline-block;width:14px;height:14px;border:2px solid #30363d;border-top-color:#58a6ff;
           border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle;margin-right:8px}
  @keyframes spin{to{transform:rotate(360deg)}}
  section{margin-top:24px;display:none}
  h2{font-size:16px;border-bottom:1px solid #30363d;padding-bottom:6px}
  iframe{width:100%;height:640px;border:1px solid #30363d;border-radius:8px;background:#0e1116}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #21262d;vertical-align:top}
  th{color:#8b949e;font-weight:600}
  td.score{font-weight:700;color:#ff7b72}
  .pill{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:2px 8px;font-size:12px}
  a.dl{color:#58a6ff;margin-right:16px}
</style>
</head>
<body>
<header>
  <h1>Cartograph</h1>
  <p>Passive attack-surface map – reads public data only, sends nothing to the target.</p>
</header>
<main>
  <form id="f">
    <input type="text" id="domain" placeholder="example.com" autocomplete="off" autofocus>
    <label><input type="checkbox" id="score" checked> score</label>
    <label>max hosts <input type="number" id="maxh" value="60" min="1" max="500"></label>
    <label>max IPs <input type="number" id="maxi" value="60" min="1" max="500"></label>
    <label><input type="checkbox" id="eps"> endpoints</label>
    <button id="go" type="submit">Map</button>
    <button id="reset" type="button">Reset</button>
  </form>
  <div class="note">Passive collection takes ~1 minute (public sources are rate-limited).</div>
  <div id="status"></div>

  <section id="graphSec"><h2>Attack-surface graph</h2>
    <div id="dl"></div>
    <iframe id="graph"></iframe>
  </section>
  <section id="topSec"><h2>Top exposed assets</h2><table id="topTbl"></table></section>
  <section id="takeoverSec"><h2>Subdomain-takeover candidates</h2><table id="takeoverTbl"></table></section>
  <section id="clusterSec"><h2>Shared-infrastructure clusters</h2><table id="clusterTbl"></table></section>
</main>
<script>
  const $ = id => document.getElementById(id);
  const esc = s => String(s).replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
  const show = id => $(id).style.display = "block";

  function rows(tbl, head, data, cells){
    let h = "<tr>" + head.map(x=>"<th>"+x+"</th>").join("") + "</tr>";
    h += data.map(d => "<tr>" + cells(d).join("") + "</tr>").join("");
    $(tbl).innerHTML = h;
  }

  let controller = null, timer = null;

  function stopTimer(){ if(timer){ clearInterval(timer); timer = null; } }
  function reset(){
    if(controller){ controller.abort(); controller = null; }
    stopTimer();
    $("status").innerHTML = "";
    $("go").disabled = false;
    ["graphSec","topSec","takeoverSec","clusterSec"].forEach(s => $(s).style.display="none");
  }
  $("reset").addEventListener("click", reset);

  $("f").addEventListener("submit", async e => {
    e.preventDefault();
    const domain = $("domain").value.trim();
    if(!domain) return;
    if(controller) controller.abort();
    controller = new AbortController();
    $("go").disabled = true;
    ["graphSec","topSec","takeoverSec","clusterSec"].forEach(s => $(s).style.display="none");

    const started = Date.now();
    const tick = () => {
      const s = Math.round((Date.now()-started)/1000);
      $("status").innerHTML = '<span class="spinner"></span>Collecting ' + esc(domain)
        + ' … ' + s + 's (uncached targets take 1–3 min – Reset to cancel)';
    };
    tick(); stopTimer(); timer = setInterval(tick, 1000);

    try{
      const r = await fetch("/api/scan", {
        method:"POST", headers:{"Content-Type":"application/json"}, signal: controller.signal,
        body: JSON.stringify({
          domain, score:$("score").checked, max_hosts:+$("maxh").value,
          max_ips:+$("maxi").value, include_endpoints:$("eps").checked
        })
      });
      if(!r.ok){ const t = await r.json().catch(()=>({detail:r.statusText}));
        throw new Error(t.detail || ("HTTP "+r.status)); }
      const res = await r.json();
      stopTimer();
      $("status").innerHTML = "Mapped <b>"+esc(res.domain)+"</b> – "+res.node_count+" nodes.";

      $("graph").srcdoc = res.graph_html;
      $("dl").innerHTML = '<a class="dl" href="/download/'+res.id+'.html">download graph HTML</a>'
                        + '<a class="dl" href="/download/'+res.id+'.json">download graph JSON</a>';
      show("graphSec");

      if(res.top.length){
        rows("topTbl", ["Score","Host","Reasons"], res.top,
          d => ['<td class="score">'+Math.round(d.score)+'</td>',
                "<td>"+esc(d.host)+"</td>",
                '<td>'+d.reasons.map(x=>'<span class="pill">'+esc(x)+'</span>').join(" ")+'</td>']);
        show("topSec");
      }
      if(res.takeover.length){
        rows("takeoverTbl", ["Host","CNAME","Provider"], res.takeover,
          d => ["<td>"+esc(d.host)+"</td>","<td>"+esc(d.cname)+"</td>","<td>"+esc(d.provider)+"</td>"]);
        show("takeoverSec");
      }
      if(res.clusters.length){
        rows("clusterTbl", ["Size","Hosts"], res.clusters,
          d => ["<td>"+d.size+"</td>","<td>"+d.hosts.map(esc).join(", ")+"</td>"]);
        show("clusterSec");
      }
    }catch(err){
      stopTimer();
      if(err.name === "AbortError"){ $("status").innerHTML = "Cancelled."; }
      else{ $("status").innerHTML = '<span style="color:#ff7b72">Error: '+esc(err.message)+'</span>'; }
    }finally{
      stopTimer();
      $("go").disabled = false;
      controller = null;
    }
  });
</script>
</body>
</html>
"""
