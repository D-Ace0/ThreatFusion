"use strict";
const $ = id => document.getElementById(id);
let current = null;
function el(tag, text, cls) { const e = document.createElement(tag); if(text !== undefined) e.textContent = text; if(cls) e.className = cls; return e; }
async function request(path, options={}) {
  const headers = {"Content-Type":"application/json", ...(options.headers || {})};
  if($("api-key").value) headers["X-API-Key"] = $("api-key").value;
  const response = await fetch(path, {...options, headers});
  if(!response.ok) { let message = `Request failed (${response.status})`; try { const data=await response.json(); message=typeof data.detail === "string" ? data.detail : message; } catch {} throw new Error(message); }
  return response;
}
function status(text, error=false) { $("status").textContent=text; $("status").className=error?"error":""; }
function render(a) {
  current=a; $("result").hidden=false; $("result-ioc").textContent=a.ioc.value;
  $("result-notice").textContent=a.mode==="demo"?"SIMULATED DEMO RESULT — Fictional fixture values. This is not a real VirusTotal report or a maliciousness verdict.":"LIVE RESULT — Existing provider intelligence. Missing sources and zero detections do not prove safety.";
  $("result-meta").textContent=`${a.mode.toUpperCase()} • ${a.ioc.type.toUpperCase()} • ${new Date(a.created_at).toLocaleString()} • ${a.id}`;
  $("metrics").replaceChildren();
  const riskTitle=a.mode==="demo"?"Simulated risk":"Heuristic risk";
  for(const [name,value,caption] of [[riskTitle,a.score.risk,a.mode==="demo"?`Fictional scenario: ${a.score.label}`:a.score.label],["Confidence",a.score.confidence,"Completeness proxy"],["Coverage",a.score.coverage,"Usable / eligible sources"],["Freshness",a.score.freshness,"Observation recency"]]) {
    const box=el("div",undefined,"metric"); box.append(el("div",name,"metric-title"),el("div",value===null?"Unknown":`${value}${name===riskTitle?"":"%"}`,"metric-value"),el("small",caption));
    const bar=el("div",undefined,"bar"), fill=el("div",undefined,"bar-fill"); fill.style.width=`${value || 0}%`; bar.append(fill); box.append(bar); $("metrics").append(box);
  }
  $("evidence").replaceChildren();
  for(const r of a.results) {
    const card=el("div",undefined,"source"), heading=el("div",undefined,"source-head"); heading.append(el("span",a.mode==="demo"?`${r.source} (simulated)`:r.source),el("span",`${r.status}${r.cached?" / cache":""}`,"badge muted")); card.append(heading);
    card.append(el("p",r.message || `Retrieved ${new Date(r.retrieved_at).toLocaleString()}`));
    for(const e of r.evidence) { card.append(el("div",`${e.metric}: ${e.value}${e.total?` / ${e.total}`:""}`,"value"),el("p",e.description),el("p",`Observed: ${e.observed_at?new Date(e.observed_at).toLocaleString():"Unknown"}`),el("p",`Source: ${e.source_url}`)); }
    if(r.retry_after !== null) card.append(el("p",`Retry after ${Math.ceil(r.retry_after)} seconds`));
    $("evidence").append(card);
  }
  $("explanation").replaceChildren();
  for(const c of a.score.contributions) { const row=el("div",undefined,"contribution"); row.append(el("span",c.source),el("span",`+${c.points}`,"points"),el("p",c.reason)); $("explanation").append(row); }
  if(!a.score.contributions.length) $("explanation").append(el("p","No usable evidence. Risk remains unknown."));
}
async function history() {
  const data=await (await request("/api/history")).json(); $("history").replaceChildren();
  if(!data.length) $("history").append(el("p","No investigations yet. Try a demo fixture above."));
  for(const a of data) { const row=el("div",undefined,"history-row"), info=el("div",a.ioc.value); info.append(el("small",`${a.mode==="demo"?"DEMO (SIMULATED)":"LIVE"} • ${new Date(a.created_at).toLocaleString()} • ${a.score.label}`)); const open=el("button","Open","secondary"); open.addEventListener("click",()=>{render(a);$("result").scrollIntoView({behavior:"smooth"});}); row.append(info,open); $("history").append(row); }
}
$("analyze-form").addEventListener("submit",async event=>{event.preventDefault();$("analyze").disabled=true;status("Gathering source evidence…");try { const a=await (await request("/api/analyze",{method:"POST",body:JSON.stringify({value:$("ioc").value,allow_url:$("allow-url").checked,refresh:$("refresh").checked})})).json();render(a);status(a.mode==="demo"?"Synthetic demo complete. No external requests were made.":"Analysis complete. Review source gaps before making decisions.");await history();} catch(error){status(error.message,true);} finally{$("analyze").disabled=false;}});
for(const format of ["json","pdf"]) $("export-"+format).addEventListener("click",async()=>{if(!current)return;try{const response=await request(`/api/analyses/${current.id}/report?format=${format}`), url=URL.createObjectURL(await response.blob()), link=el("a");link.href=url;link.download=`threatfusion-${current.id}.${format}`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(error){status(error.message,true);}});
$("reload-history").addEventListener("click",()=>history().catch(e=>status(e.message,true)));
$("clear-history").addEventListener("click",async()=>{if(!confirm("Delete all local investigation history and cache?"))return;try{await request("/api/history",{method:"DELETE"});current=null;$("result").hidden=true;await history();status("Local data cleared.");}catch(e){status(e.message,true);}});
async function initialize(){$("samples").replaceChildren();const health=await(await request("/api/health")).json();$("mode-notice").hidden=false;$("mode-notice").textContent=health.mode==="demo"?"DEMO MODE — All results are fictional fixtures for learning. No live VirusTotal data is being used.":"LIVE MODE — Real provider lookups. Non-public indicators stay blocked; full URLs require consent.";$("ioc").placeholder=health.mode==="demo"?"Try 203.0.113.42 (fictional demo fixture)":"Enter a public IP, domain, URL, or hash";$("mode").textContent=health.mode==="demo"?"● DEMO / SYNTHETIC":"● LIVE / LOOKUP ONLY";if(health.mode==="demo"){const data=await(await request("/api/demo")).json();for(const value of data.indicators){const button=el("button",value);button.type="button";button.addEventListener("click",()=>{$("ioc").value=value;$("ioc").focus();});$("samples").append(button);}}await history();}
$("api-key").addEventListener("change",()=>initialize().then(()=>status("Session connected.")).catch(e=>status(e.message,true)));
initialize().catch(e=>status(e.message,true));
