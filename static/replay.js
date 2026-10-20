/* BLACKBOX v1.2 — evidence-based network replay. No external libraries. */
let replayTimer=null;
function stopReplay(){if(replayTimer!==null){clearInterval(replayTimer);replayTimer=null}}
async function loadReplay(){
 if(!state.caseId){state.replay=null;return}
 const selected=state.caseId;
 try{const story=await api(`/cases/${encodeURIComponent(selected)}/replay`);
     if(state.caseId===selected){state.replay=story;state.replayIndex=0;if(state.page==='replay')render()}}
 catch(e){toast('Replay unavailable: '+e.message,true)}
}
function playReplay(){
 if(!state.replay?.steps?.length){toast('No replay data. Import a capture first.',true);return}
 if(replayTimer!==null){stopReplay();render();return}
 if(state.replayIndex>=state.replay.steps.length-1)state.replayIndex=0;
 replayTimer=setInterval(()=>{
   if(state.page!=='replay'){stopReplay();return}
   if(state.replayIndex>=state.replay.steps.length-1){stopReplay();render();return}
   state.replayIndex++;render();
 },1300);
 render();
}
function stepReplay(next){
 const count=state.replay?.steps?.length||0;
 if(!count)return;
 state.replayIndex=Math.max(0,Math.min(count-1,Number(next)||0));render();
}
function replayDiagram(step){
 const scores=new Map();
 for(const link of step.links){scores.set(link.src,(scores.get(link.src)||0)+link.packets);scores.set(link.dst,(scores.get(link.dst)||0)+link.packets)}
 const hosts=[...scores.keys()].sort((a,b)=>scores.get(b)-scores.get(a)).slice(0,10);
 if(!hosts.length)return '<div class="replay-no-links">No source-to-destination IP conversations in this window. Inspect packet samples on the right.</div>';
 const pos=new Map(hosts.map((host,i)=>{let theta=2*Math.PI*i/hosts.length-Math.PI/2;return [host,{x:455+295*Math.cos(theta),y:190+136*Math.sin(theta)}]}));
 const lines=step.links.filter(link=>pos.has(link.src)&&pos.has(link.dst)).map(l=>{
   const a=pos.get(l.src),b=pos.get(l.dst);
   return `<g><line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#53d0f2" stroke-opacity=".40" stroke-width="${Math.min(5,1.7+Math.log2(l.packets+1)/2)}"/><circle cx="${(a.x+b.x)/2}" cy="${(a.y+b.y)/2}" r="3" fill="#78e4ff"/></g>`
 }).join('');
 const nodes=hosts.map((host,i)=>{
   const p=pos.get(host),important=step.findings.some(f=>f.summary.includes(host));
   return `<g><circle cx="${p.x}" cy="${p.y}" r="${important?25:20}" fill="#122c42" stroke="${important?'#ffb47a':'#75c9e6'}" stroke-width="2.5"/><circle cx="${p.x}" cy="${p.y}" r="5" fill="${important?'#ffb47a':'#81d6ed'}"/><text x="${p.x}" y="${p.y+35}" text-anchor="middle" fill="#dceef8" font-size="12">${html(host.length>23?host.slice(0,23)+'…':host)}</text></g>`
 }).join('');
 return `<svg class="replay-graph" viewBox="0 0 910 390" role="img" aria-label="Observed source-destination communications in this time window"><defs><radialGradient id="replaybg"><stop offset="0" stop-color="#143952"/><stop offset="1" stop-color="#0a1526"/></radialGradient></defs><rect width="910" height="390" fill="url(#replaybg)" rx="18"/><g opacity=".12" stroke="#87c9ec">${Array.from({length:10},(_,i)=>`<path d="M${i*100} 0v390"/>`).join('')}${Array.from({length:6},(_,i)=>`<path d="M0 ${i*75}h910"/>`).join('')}</g>${lines}${nodes}<text x="20" y="367" fill="#79b3c9" font-size="12">OBSERVED CONNECTIONS · diagram layout is illustrative, not a physical map</text></svg>`
}
function replayNote(step){
 if(step.findings.length)return `A rule-based signal appears in this window. ${step.findings.length} finding(s) need analyst review. This is not confirmed malicious activity.`;
 if(step.packet_count)return `BLACKBOX observed ${step.packet_count} packet(s) in this time interval. No rule finding begins here; that is not proof of safe traffic.`;
 return 'No timestamped packets were observed in this interval. This may be a gap between captures or recorded events.';
}
function pageReplay(){
 const story=state.replay,steps=story?.steps||[];
 if(!steps.length)return title('INCIDENT REPLAY','Watch the evidence unfold','Replay timestamped observations, not a fabricated attack animation.')+'<section class="panel replay-empty"><h2>No evidence to replay</h2><p>Import a capture, or open two synthetic demo cases to learn the process.</p><button class="primary-btn" data-action="demo-start">Open demo captures →</button></section>';
 const i=Math.min(Math.max(state.replayIndex||0,0),steps.length-1),s=steps[i];
 const tick=steps.map((f,n)=>`<button type="button" data-action="replay-jump" data-step="${n}" title="Window ${n+1}: ${f.packet_count} packets" class="replay-tick ${n===i?'selected':''} ${f.findings.length?'has-finding':''}" aria-label="Go to window ${n+1}" aria-current="${n===i?'step':'false'}"><span style="height:${Math.min(85,8+Math.round(f.packet_count/Math.max(1,...steps.map(x=>x.packet_count))*75))}%"></span></button>`).join('');
 const findings=s.findings.length?s.findings.map(f=>`<div class="replay-alert"><div>${sev(f.severity)} <b>${html(f.title)}</b></div><p>${html(f.summary)}</p><div class="evidence-list">${f.packet_ids.slice(0,5).map(id=>`<button data-action="show-packet" data-id="${id}">Packet ${id} ↗</button>`).join('')}<button data-action="finding" data-id="${html(f.id)}">Review finding ↗</button></div></div>`).join(''):'<p class="replay-muted">No rule finding starts in this interval. This does not establish benign activity.</p>';
 const packets=s.packet_samples.map(p=>`<button type="button" class="replay-packet" data-action="show-packet" data-id="${p.id}"><span class="mono">#${p.id} · ${html(p.proto)}</span><strong>${html(p.src||'—')} → ${html(p.dst||'—')}</strong><small>${html(p.note||'Original frame '+p.frame_no)} · ${clock(p.ts)} UTC</small></button>`).join('')||'<p class="replay-muted">No packet examples in this interval.</p>';
 const protocols=s.protocols.map(p=>`${html(p.proto)} <b>${p.packets}</b>`).join(' · ')||'No decoded protocols';
 const pane=title('INCIDENT REPLAY','See the story in the evidence','Watch what was actually captured. The animation does not claim a verified attack chain.',`<button class="ghost-btn" data-page="findings">Review findings ↗</button><button class="ghost-btn" data-page="assistant">Ask Copilot ↗</button>`);
 return pane+`<section class="replay-banner"><div><span class="replay-label">◉ TIME-BASED RECONSTRUCTION · EVIDENCE GROUNDED</span><h2>One capture. <em>Every clue in context.</em></h2><p>Move through recorded activity and open original packet references at any moment.</p></div><div class="replay-stat-pills"><span>${short(story.total_packets)} <small>packets</small></span><span>${story.steps.length} <small>windows</small></span><span>${state.findings.length} <small>rule findings</small></span></div></section>
 <div class="replay-workspace"><div class="replay-main"><section class="panel replay-canvas"><div class="panel-head"><h2>OBSERVED NETWORK · WINDOW ${i+1}/${steps.length}</h2><span>${clock(s.start_ts)} – ${clock(s.end_ts)} UTC</span></div>${replayDiagram(s)}<div class="replay-data-strip"><div><small>PACKETS</small><b>${s.packet_count}</b></div><div><small>OBSERVED BYTES</small><b>${bytes(s.bytes)}</b></div><div><small>SOURCE HOSTS</small><b>${s.source_hosts}</b></div><div><small>PROTOCOLS</small><b class="proto-list">${protocols}</b></div></div></section><section class="panel replay-player"><div class="replay-controls"><button data-action="replay-prev" aria-label="Previous moment">←</button><button class="replay-play" data-action="replay-play" aria-label="${replayTimer!==null?'Pause':'Play'} replay">${replayTimer!==null?'Ⅱ Pause':'▶ Play'}</button><button data-action="replay-next" aria-label="Next moment">→</button><div><strong>Moment ${i+1} / ${steps.length}</strong><small>${when(s.start_ts)}</small></div></div><div class="replay-track">${tick}</div><input class="replay-slider" id="replaySeek" type="range" min="0" max="${steps.length-1}" value="${i}" aria-label="Seek to replay window"/><p class="replay-muted">Playback moves through captured timestamps, not reconstructed attacker actions. Select any bar to inspect that interval.</p></section></div>
 <aside class="replay-inspector"><section class="panel"><div class="panel-head"><h2>ANALYST NARRATIVE</h2><span>DETERMINISTIC</span></div><div class="replay-narrative">${html(replayNote(s))}</div><div class="replay-section-head">Finding evidence</div>${findings}<div class="replay-section-head">Packet samples</div><div class="replay-packets">${packets}</div>${isReadOnly()?'<div class="replay-ai-info">Read-only public demo: no cloud AI calls are made.</div>':`<button class="primary-btn replay-ask" data-action="ask-replay" data-step="${i+1}">Ask Copilot about this moment ↗</button>`}</section></aside></div><p class="replay-limits">RESEARCH & TRAINING TOOL · Observed activity ≠ proven intrusion. Grouped flows are directional packet summaries. Full packet inspection is available in the original capture.</p>`;
}
async function demoStart(){
 if(state.busy)return;
 if(isReadOnly()){
   if(!state.cases.length){toast('Public demo requires seeding by its administrator.',true);return}
   state.caseId=(state.cases.find(c=>c.name.includes('ARP consistency'))||state.cases[0]).id;await refreshCase();navigate('overview');return;
 }
 try{busy(true,'IMPORTING LAB CASES…');const result=await api('/demo',{method:'POST'});
     state.chat=[];state.trafficLoaded=false;state.replayIndex=0;
     await loadCases(result.case_id);navigate('overview');toast('Two synthetic demo cases are available. Choose between them above.');}
 catch(e){toast('Could not start demonstration: '+e.message,true)}
 finally{busy(false)}
}
