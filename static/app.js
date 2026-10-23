'use strict';
const $=s=>document.querySelector(s);
const state={auth:{authenticated:false,username:null,csrf:null},cases:[],caseId:'',caseData:null,summary:null,findings:[],caps:[],topology:{nodes:[],edges:[]},timeline:[],page:'overview',selectedHost:'',packets:[],packetOffset:0,packetsSearch:'',packetsProtocol:'',flows:[],dns:[],flowIp:'',chat:[],trafficLoaded:false,busy:false,modelMode:'offline',replay:null,replayIndex:0,agentBrief:null,trace:null,traceId:'',mlResults:null,mlLoaded:false};
const html=(s)=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short=n=>!Number.isFinite(Number(n))?'—':Math.abs(n)>=1e9?(n/1e9).toFixed(1)+'B':Math.abs(n)>=1e6?(n/1e6).toFixed(1)+'M':Math.abs(n)>=1e3?(n/1e3).toFixed(1)+'K':String(n);
const bytes=n=>{if(n==null)return'—';let v=Number(n),i=0;while(v>=1024&&i<4){v/=1024;i++}return (i===0?v.toFixed(0):v.toFixed(1))+' '+['B','KB','MB','GB','TB'][i]};
const when=t=>!t?'UNKNOWN TIME':new Date(t*1000).toISOString().replace('T',' ').replace('.000Z',' UTC');
const clock=t=>!t?'--:--:--':new Date(t*1000).toISOString().slice(11,19);
const fmtDay=t=>!t?'—':new Date(t*1000).toISOString().slice(0,10);
const ico={overview:'<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 10h18M10 3v18"/>',capture:'<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M8 12h8M12 8v8"/>',graph:'<circle cx="6" cy="7" r="2"/><circle cx="18" cy="7" r="2"/><circle cx="12" cy="18" r="2"/><path d="M8 8l3 8m5-8-3 8M8 7h8"/>',target:'<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 1v5m0 12v5M1 12h5m12 0h5"/>',activity:'<path d="M3 12h4l3-7 4 14 3-7h4"/>',chat:'<path d="M3 5h18v12H8l-5 4z"/><path d="M7 9h10M7 13h7"/>',document:'<path d="M6 2h9l5 5v15H6z"/><path d="M14 2v6h6M9 12h8M9 16h8"/>'};
document.querySelectorAll('i[data-ico]').forEach(el=>el.innerHTML=`<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">${ico[el.dataset.ico]}</svg>`);
async function api(path,opt={}){
 const m=(opt.method||'GET').toUpperCase();
 const headers={...(opt.body instanceof FormData?{}:{'Content-Type':'application/json'}),...(opt.headers||{})};
 if(!['GET','HEAD','OPTIONS'].includes(m)&&state.auth?.csrf)headers['X-BB-CSRF']=state.auth.csrf;
 const r=await fetch('/api'+path,{...opt,headers,credentials:'same-origin'});
 let data;try{data=await r.json()}catch{data={detail:'The server returned an unexpected response.'}}
 if(!r.ok)throw Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail));
 return data;
}
function isGalleryMode(){return ['hybrid','local-hybrid'].includes(state.health?.mode);}
function isAccountMode(){return ['multi-user','hybrid','local-auth','local-hybrid'].includes(state.health?.mode);}
function isReadOnly(){return state.health?.mode==='public-demo'||(isGalleryMode()&&(!state.auth?.authenticated||state.caseData?.owner==='public-demo'));}
function mayCreate(){return state.health?.mode!=='public-demo'&&(!isAccountMode()||Boolean(state.auth?.authenticated));}
let authRegister=false;
function showAuth(register=false){
 authRegister=register;
 const hybrid=isGalleryMode();
 const firstRun=Boolean(state.health?.first_run_setup);
 $('#authLayer').classList.remove('hidden');
 $('#authHeading').textContent=register?'Create your investigation account':'Your evidence. Your workspace.';
 $('#authDescription').textContent=register?(firstRun?'Create your first private account here. Your captures and reports will stay in your own local workspace.':'Registration requires an invitation code. Your captures and reports will be private to your account.'):'Sign in to upload network captures, save investigations and export your reports privately.';
 $('#inviteRow').hidden=!register||firstRun;
 $('#authInvite').required=register&&!firstRun;
 $('#authPassword').autocomplete=register?'new-password':'current-password';
 $('#authSubmit').textContent=register?'Create private account →':'Sign in securely →';
 $('#authSwitch').textContent=register?'Already have an account? Sign in':firstRun?'Create your first local account':'Create an invited account';
 $('#authSwitch').hidden=!state.health?.registration_enabled;
 $('#authExplore').hidden=!hybrid;
 $('#authClose').hidden=!hybrid;
 $('#authError').textContent='';
 $('#authPassword').value='';$('#authInvite').value='';
 $('#authUsername').focus();
}
function closeAuth(){if(isGalleryMode()){ $('#authLayer').classList.add('hidden');showGateway();}}
function displayAccount(){
 const enabled=isAccountMode();
 $('#accountButton').hidden=!enabled;
 if(enabled)$('#accountButton').textContent=state.auth?.authenticated?'◉ '+state.auth.username+' · Sign out':'🔒 Sign in / Register';
 applyDeploymentMode();
}
async function authStartup(){
 if(!isAccountMode())return;
 state.auth=await api('/auth/session');
 displayAccount();
 if(['multi-user','local-auth'].includes(state.health.mode)&&!state.auth.authenticated)showAuth();
}
async function doSignOut(){
 if(!confirm('Sign out of this private workspace?'))return;
 await api('/auth/logout',{method:'POST',body:'{}'});
 state.auth={authenticated:false,username:null,csrf:null};
 state.caseId='';state.caseData=null;state.chat=[];state.packets=[];state.mlLoaded=false;state.mlResults=null;
 await loadCases();displayAccount();
 if(['multi-user','local-auth'].includes(state.health.mode))showAuth();
 else {navigate('library');showGateway();}
 toast('Signed out. Your private evidence remains saved on the server.');
}
function showGateway(){
 if(!isGalleryMode())return;
 $('#authLayer').classList.add('hidden');
 $('#gatewayPrivate').textContent=state.auth?.authenticated?'Continue private workspace →':state.health?.first_run_setup?'Create private account →':'Sign in to private workspace →';
 $('#gatewayLayer').classList.remove('hidden');
 $('#gatewayPrivate').focus();
}
function hideGateway(){$('#gatewayLayer').classList.add('hidden');}
function privateLogin(){hideGateway();if(state.auth?.authenticated){navigate('library');return;}showAuth(Boolean(state.health?.first_run_setup));}
async function exploreDemo(){
 hideGateway();
 try{
  if(state.auth?.authenticated){
   await api('/auth/logout',{method:'POST',body:'{}'});
   state.auth={authenticated:false,username:null,csrf:null};
   state.caseId='';state.caseData=null;state.chat=[];state.packets=[];state.mlResults=null;state.mlLoaded=false;
   displayAccount();
  }
  await loadCases();
  const first=state.cases.find(c=>c.owner==='public-demo');
  if(first&&state.caseId!==first.id){state.caseId=first.id;$('#caseSelect').value=first.id;await refreshCase();}
  navigate(first?'overview':'library');
  if(!first)toast('No demo investigations yet. Launch BLACKBOX from the Windows BAT file.',true);
 }catch(err){toast(err.message,true);showGateway();}
}
$('#gatewayPrivate').addEventListener('click',privateLogin);
$('#gatewayDemo').addEventListener('click',exploreDemo);
$('#gatewayHelp').addEventListener('click',()=>{hideGateway();toggleGuide(true)});
$('#accountButton').addEventListener('click',async()=>{
 try{if(state.auth?.authenticated)await doSignOut();else showAuth(Boolean(state.health?.first_run_setup));}catch(err){toast(err.message,true)}
});
$('#authClose').addEventListener('click',closeAuth);
$('#authExplore').addEventListener('click',()=>{$('#authLayer').classList.add('hidden');exploreDemo()});
$('#authSwitch').addEventListener('click',()=>showAuth(!authRegister));
$('#authForm').addEventListener('submit',async(e)=>{
 e.preventDefault();const b=$('#authSubmit');b.disabled=true;$('#authError').textContent='';
 try{
  const username=$('#authUsername').value.trim(),password=$('#authPassword').value;
  const payload={username,password};
  if(authRegister&&!state.health?.first_run_setup)payload.invite_code=$('#authInvite').value;
  const r=await api(authRegister?'/auth/register':'/auth/login',{method:'POST',body:JSON.stringify(payload)});
  state.auth={authenticated:true,username:r.username,csrf:r.csrf};
   if(authRegister)state.health=await api('/health');
  $('#authLayer').classList.add('hidden');
  state.caseId='';state.caseData=null;state.chat=[];state.mlLoaded=false;state.mlResults=null;
  await loadCases();displayAccount();navigate('library');
  toast('Welcome to your private BLACKBOX workspace.');
 }catch(err){$('#authError').textContent=err.message;}finally{b.disabled=false}
});
function toast(msg,error=false){const d=document.createElement('div');d.className='toast'+(error?' error':'');d.textContent=msg;$('#notifications').appendChild(d);setTimeout(()=>d.remove(),6500)}
function busy(flag,msg='Processing…'){state.busy=flag;$('#importTop').disabled=flag;$('#importTop').innerHTML=flag?`<span class="load-spin"></span>${html(msg)}`:'+ IMPORT PCAP';}
function navigate(page){if(page!=='replay')stopReplay();state.page=page;state.selectedHost='';document.querySelectorAll('[data-page]').forEach(n=>n.classList.toggle('active',n.dataset.page===page));render();const active=document.querySelector('.nav-link.active');active?.scrollIntoView({block:'nearest',inline:'nearest'});}
async function loadCases(selectId){state.cases=await api('/cases');if(selectId!==undefined){state.caseId=selectId}else if(!state.cases.some(c=>c.id===state.caseId)){state.caseId=(state.cases.find(c=>c.name.includes('ARP consistency'))||state.cases[0])?.id||''}
 const select=$('#caseSelect');select.innerHTML='<option value="">Choose a case…</option>'+state.cases.map(c=>`<option value="${html(c.id)}">${html(c.name)}</option>`).join('');select.value=state.caseId;
 await refreshCase();}
async function refreshCase(){if(!state.caseId){state.caseData=null;state.summary=null;state.findings=[];state.caps=[];state.timeline=[];state.topology={nodes:[],edges:[]};state.replay=null;state.agentBrief=null;state.trace=null;state.traceId='';stopReplay();render();return}
 try{const cid=encodeURIComponent(state.caseId);const [data,findings,topology,timeline,agentBrief]=await Promise.all([api(`/cases/${cid}`),api(`/cases/${cid}/findings`),api(`/cases/${cid}/topology`),api(`/cases/${cid}/timeline`),api(`/cases/${cid}/agent-brief`)]);
 if(state.traceId&&!findings.some(x=>x.id===state.traceId)){state.traceId='';state.trace=null}state.caseData=data.case;state.summary=data.summary;state.caps=data.captures;state.findings=findings;state.topology=topology;state.timeline=timeline;state.agentBrief=agentBrief;await loadReplay();$('#findingsCount').textContent=findings.length;
 render();}catch(e){toast(e.message,true)}}
function title(eyebrow,name,desc,buttons=''){return `<header class="page-header"><div><div class="eyebrow">${html(eyebrow)}</div><h1>${html(name)}</h1><p class="subhead">${html(desc)}</p></div>${buttons?`<div class="toolbar">${buttons}</div>`:''}</header>`}
function none(){return `<div class="launch"><div class="launch-copy"><span class="launch-kicker"><span class="edition-beacon"></span> THE NETWORK TELLS A STORY</span><h1>Find the signal.<br><em>Understand the incident.</em></h1><p>Uncover relationships hidden inside thousands of packets. BLACKBOX turns network evidence into a clear timeline, explainable findings and a report you can trust enough to verify.</p><div class="launch-actions">${!mayCreate()?'<button class="primary-btn" data-action="demo-start">Explore capture gallery ↗</button>':'<button class="primary-btn" data-action="new-case">＋ Start an investigation →</button>'}<button class="ghost-btn" data-action="demo-start">▶ Open two synthetic demo cases</button><button class="ghost-btn" data-action="open-guide">How BLACKBOX works ↗</button></div><div class="launch-trust">◈ &nbsp; LOCAL-FIRST &nbsp; • &nbsp; EVIDENCE-BASED &nbsp; • &nbsp; HUMAN REVIEW</div></div><div class="launch-visual"><img class="launch-logo" src="/assets/blackbox-cube.png" alt="BLACKBOX black cube mark"></div></div><div class="feature-strip"><div><b>01</b><strong>Import</strong><span>PCAP & PCAPNG</span></div><div><b>02</b><strong>Understand</strong><span>Evidence explorer</span></div><div><b>03</b><strong>Investigate</strong><span>Evidence assistant</span></div><div><b>04</b><strong>Report</strong><span>Traceable output</span></div></div>`}
function metric(label,value,foot,code){return `<div class="metric"><span class="corner">${code}</span><div class="label">${label}</div><div class="value">${value}</div><div class="foot">${foot}</div></div>`}
function sev(s){return `<span class="badge ${html(s)}">${html(s)}</span>`}
function timelineHTML(events,limit=5){if(!events.length)return `<div class="timeline-empty">No events yet. Import captured traffic to build an evidence timeline.</div>`;return `<div class="timeline-list">${events.slice(0,limit).map(e=>`<div class="timeline-event ${html(e.severity)}"><span class="when">${when(e.ts)}</span><b>${html(e.title)}</b><p>${html(e.subtitle)}</p>${e.kind==='finding'?`<button data-action="finding" data-id="${html(e.id)}">VIEW PACKET EVIDENCE ↗</button>`:''}</div>`).join('')}</div>`}
function protocolChart(){const rows=state.summary?.protocols?.slice(0,9)||[];if(!rows.length)return '<p class="dim">No parsed protocol data.</p>';const max=Math.max(...rows.map(r=>r.count),1);return `<div class="small-chart">${rows.map((r,i)=>`<div class="bar-item"><small>${short(r.count)}</small><div class="bar" style="height:${Math.max(4,Math.round(r.count/max*92))}px;background:${['#6da9cb','#789db9','#b18b70','#91b3b0','#d59b85','#6689a8'][i%6]}"></div><small title="${html(r.name)}">${html(r.name)}</small></div>`).join('')}</div>`}
function studioBars(rows){
 const vals=(rows||[]).slice(0,13).map(x=>typeof x==='number'?x:Number(x.count||0));
 if(!vals.length)return `<span class="kpi-empty">—</span>`;
 const max=Math.max(1,...vals);
 return `<div class="studio-bars" aria-hidden="true">${vals.map((v,i)=>`<i style="height:${Math.max(10,Math.round(v/max*100))}%;opacity:${.55+i/(vals.length*2)}"></i>`).join('')}</div>`;
}
function studioMetric(label,value,sub,icon,kind,vals){return `<article class="studio-metric studio-${kind}"><span class="studio-metric-icon" aria-hidden="true">${icon}</span><div class="studio-metric-copy"><div class="studio-metric-title">${html(label)}</div><strong>${html(value)}</strong><small>${html(sub)}</small></div>${studioBars(vals)}</article>`}
function commandTimelineHTML(){
 const events=state.timeline||[];
 if(!events.length)return `<div class="studio-empty">No events yet. Import a capture or open the two labelled lab examples.</div>`;
 return `<div class="studio-event-list">${events.slice(0,5).map(e=>`<div class="studio-event ${html((e.severity||'').toLowerCase())}"><span class="studio-event-time">${clock(e.ts)}</span><div class="studio-event-detail"><span class="studio-event-bullet"></span><b>${html(e.title)}</b><small>${html(e.subtitle||'Observed network activity')}</small>${e.kind==='finding'?`<button data-action="finding" data-id="${html(e.id)}" class="studio-inline">Review evidence ↗</button>`:''}</div></div>`).join('')}</div>`;
}
function overviewReplay(){
 const windows=state.replay?.steps||[];
 const points=windows.slice(0,24);
 let mid=state.replayIndex||0;
 return `<section class="studio-panel studio-replay-teaser"><div class="studio-panel-heading"><h2><span class="studio-panel-icon">▷</span> Incident replay</h2><button data-page="replay" class="studio-panel-link">Open replay ↗</button></div><p class="studio-desc">Explore recorded traffic, moment by moment</p><div class="studio-preview-player"><button class="studio-play-btn" data-page="replay" aria-label="Open the replay player">▶</button><div class="studio-preview-track" aria-label="Replay windows">${points.length?points.map((w,i)=>`<button class="studio-preview-tick ${w.findings?.length?'flagged':''}" data-page="replay" title="Open replay window ${i+1}" aria-label="Open incident replay"></button>`).join(''):'<span class="studio-preview-empty">Upload evidence to enable replay</span>'}</div><span class="studio-time">${points.length} windows</span></div>${points.some(w=>w.findings?.length)?`<button class="studio-replay-finding" data-page="replay"><span class="studio-redpulse">◆</span> Rule-based signals in replay <span>Inspect packets →</span></button>`:`<div class="studio-replay-note">${state.summary?.stats?.packet_count||0} stored packet observations</div>`}</section>`;
}
function studioFindings(){
 const findings=state.findings||[];
 return `<section class="studio-panel studio-bottom-panel"><div class="studio-panel-heading"><h2><span class="studio-panel-icon">◈</span> Latest findings <small>${findings.length} rule signals</small></h2><button class="studio-panel-link" data-page="findings">View all ↗</button></div>${findings.length?`<div class="studio-tablewrap"><table class="studio-findings-table"><thead><tr><th>Severity</th><th>Time (UTC)</th><th>Observation</th><th>Evidence</th></tr></thead><tbody>${findings.slice(0,5).map(f=>`<tr><td>${sev(f.severity)}</td><td class="mono">${clock(f.first_seen)}</td><td><button data-action="finding" data-id="${html(f.id)}" class="studio-row-link">${html(f.title)}</button></td><td>${f.evidence?.[0]?`<button class="studio-evidence-chip" data-action="show-packet" data-id="${f.evidence[0]}">Packet #${f.evidence[0]} ↗</button>`:'<span class="dim">No packet ref</span>'}</td></tr>`).join('')}</tbody></table></div>`:`<div class="studio-empty">No rule detections. This does not establish that the traffic is safe. <button data-page="traffic" class="studio-panel-link">Inspect packets →</button></div>`}</section>`;
}
function studioCopilot(){
 const findings=state.findings||[];
 const leading=findings[0];
 return `<section class="studio-panel studio-bottom-panel studio-copilot"><div class="studio-panel-heading"><h2><span class="studio-panel-icon">✦</span> BLACKBOX Copilot</h2><button data-page="assistant" class="studio-panel-link">Open Copilot ↗</button></div><div class="studio-copilot-body"><span class="studio-copilot-eyebrow">✧ EVIDENCE-BASED / HUMAN-REVIEWED</span>${leading?`<h3>${html(leading.title)}</h3><p>${html(leading.summary)}</p><div class="studio-copilot-evidence">${(leading.evidence||[]).slice(0,3).map(id=>`<button data-action="show-packet" data-id="${id}"><span>◉</span> Packet #${id} <span>View ↗</span></button>`).join('')}</div>`:`<h3>Ready to explore the evidence</h3><p>Ask questions about protocols, suspicious patterns, or a specific packet. The Copilot supports explanations—not automatic threat verdicts.</p>`}<button class="studio-ask-btn" data-page="assistant">Ask about this investigation <span>↗</span></button></div></section>`;
}
function pageOverview(){
 const s=state.summary,n=s.stats,protocols=s.protocols||[],findings=state.findings||[];
 const hi=findings.filter(f=>String(f.severity).toLowerCase()==='high').length;
 const alertCounts=['low','medium','high'].map(sev=>findings.filter(f=>String(f.severity).toLowerCase()===sev).length);
 return `<div class="studio-dashboard"><div class="studio-hero"><div><span class="studio-overline">◈ &nbsp; CASE INTELLIGENCE / ${html(state.caseData?.name||'UNTITLED')}</span><h1>Investigation <span>Command Center</span></h1><p>Unify network data, uncover anomalies, and follow the evidence—one packet at a time.</p></div><div class="studio-hero-motto">EVERY PACKET<br>HAS A STORY</div></div>
 <div class="studio-kpis">${studioMetric('Analyzed packets',short(n.packet_count),'Imported packet records','▤','violet',state.caps.map(c=>c.frame_count||0))}${studioMetric('Observed hosts',short(n.src_hosts),'Source IP addresses','▣','mint',state.topology.nodes.slice(0,12).map(n=>n.bytes||0))}${studioMetric('Rule findings',short(s.findings.total),'High severity: '+hi,'⚠','coral',alertCounts)}${studioMetric('Protocols observed',String(protocols.length),'Decoded protocol groups','⌘','blue',protocols)}${studioMetric('Evidence files',String(s.captures.total),'Capture sources recorded','⬡','green',state.caps.map(c=>c.size||0))}</div>
 <div class="studio-main-grid"><section class="studio-panel studio-network-panel"><div class="studio-panel-heading"><div><h2><span class="studio-panel-icon">⬡</span> Network relationship map</h2><p>Observed hosts, connections and finding-associated activity</p></div><button data-page="investigation" class="studio-panel-link">Explore network ↗</button></div>${sceneHTML()}<div id="hostInspection"></div></section><div class="studio-side-stack"><section class="studio-panel studio-timeline-panel"><div class="studio-panel-heading"><h2><span class="studio-panel-icon">◷</span> Event timeline</h2><button data-page="replay" class="studio-panel-link">View all ↗</button></div>${commandTimelineHTML()}</section>${overviewReplay()}</div></div>
 <div class="studio-bottom-grid">${studioFindings()}${studioCopilot()}</div><div class="studio-trust"><span>◈ &nbsp; DATA FROM SELECTED CASE</span><span>Unusual behavior ≠ verified intrusion</span><button data-page="report">View case report ↗</button></div></div>`;
}
function project(cx,cy){return {x:470+(cx-cy)*76,y:100+(cx+cy)*36}}
function sceneHTML(){
 const all=state.topology.nodes||[];
 if(!all.length)return `<div class="scene studio-network-scene"><div class="scene-note"><b>No observed hosts yet</b><p>Import a capture to visualize verified network relationships.</p><button class="primary-btn" data-action="choose-upload">Import PCAP →</button></div></div>`;
 const alerts=new Set();for(const f of state.findings||[]){for(const key of ['source','destination','host','ip']){const ip=f.indicators?.[key];if(typeof ip==='string')alerts.add(ip)}}
 const nodes=all.slice(0,12);
 const coords=[[480,235],[665,152],[302,317],[828,279],[177,175],[723,352],[372,112],[528,375],[150,365],[835,110],[313,420],[586,72]];
 const positions=new Map(nodes.map((n,i)=>[n.ip,{x:coords[i][0],y:coords[i][1]}]));
 const edges=(state.topology.edges||[]).filter(e=>positions.has(e.src)&&positions.has(e.dst)).slice(0,38);
 const paths=edges.map((e,i)=>{const a=positions.get(e.src),b=positions.get(e.dst);const hot=alerts.has(e.src)||alerts.has(e.dst);const dx=b.x-a.x,dy=b.y-a.y;const bend=Math.min(65,Math.max(16,Math.abs(dx)/6));const cx=(a.x+b.x)/2+(-dy)/(Math.hypot(dx,dy)||1)*bend;const cy=(a.y+b.y)/2+dx/(Math.hypot(dx,dy)||1)*bend;return `<path d="M${a.x} ${a.y} Q${cx.toFixed(1)} ${cy.toFixed(1)} ${b.x} ${b.y}" class="studio-arc ${hot?'studio-arc-flagged':''}"/>`}).join('');
 const palette=['#ef63ba','#5fe4c3','#a783ff','#42c9fb','#ffb56a','#6bcdfa'];
 const verts=nodes.map((n,i)=>{const p=positions.get(n.ip),hot=alerts.has(n.ip),color=hot?'#fb6c88':palette[i%palette.length],name=n.ip.length>24?n.ip.slice(0,23)+'…':n.ip;return `<g class="studio-svg-host" tabindex="0" role="button" aria-label="Inspect host ${html(n.ip)}" data-ip="${html(n.ip)}" style="--node-color:${color}"><circle cx="${p.x}" cy="${p.y}" r="26" fill="${color}" opacity=".10" filter="url(#bb-blur)"/><circle cx="${p.x}" cy="${p.y}" r="20" fill="none" stroke="${color}" opacity=".40" stroke-width="1"/><circle cx="${p.x}" cy="${p.y}" r="12" fill="${color}" opacity=".12" stroke="${color}" stroke-width="2"/><circle cx="${p.x}" cy="${p.y}" r="5.5" fill="${color}"/><text class="studio-node-name" x="${p.x}" y="${p.y+34}" text-anchor="middle">${html(name)}</text>${hot?`<text x="${p.x}" y="${p.y+49}" class="studio-node-flag" text-anchor="middle">RULE SIGNAL</text>`:''}</g>`}).join('');
 return `<div class="scene studio-network-scene"><div class="studio-network-legend"><span><i style="background:#5fe4c3"></i> Observed</span><span><i style="background:#fb6c88"></i> Rule-associated</span><span class="studio-network-hint">Click any node to inspect</span></div><svg viewBox="0 0 980 510" class="topology-svg studio-nebula" aria-label="Observed IP hosts and network connections; illustrative layout, not physical geolocation" role="img" preserveAspectRatio="xMidYMid meet"><defs><pattern id="bbdots" width="26" height="26" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="1" fill="#63708e" opacity=".18"/></pattern><filter id="bb-blur"><feGaussianBlur stdDeviation="13"/></filter><radialGradient id="bbhalo"><stop stop-color="#48275c" stop-opacity=".37"/><stop offset=".75" stop-color="#101628" stop-opacity=".12"/><stop offset="1" stop-color="#070b15" stop-opacity="0"/></radialGradient></defs><rect width="980" height="510" fill="url(#bbhalo)"/><rect width="980" height="510" fill="url(#bbdots)"/>${paths}${verts}</svg><div class="studio-map-foot"><span><b>${nodes.length}</b> visible hosts</span><span><b>${edges.length}</b> visible relationships</span><span class="studio-map-notice">Conceptual topology, not physical location</span></div></div>`;
}
function pageInvestigation(){return title('VISUAL INVESTIGATION','Network relationships','Inspect actual hosts and conversations. Diagram positions are illustrative, not physical locations.',`<button class="ghost-btn" data-page="traffic">Open packet explorer ↗</button>`)+`<section class="panel topology-panel"><div class="panel-head"><h2>TOPOLOGY · SELECT A DEVICE TO PIVOT</h2><span>TOP 16 HOSTS / OBSERVED TRAFFIC</span></div>${sceneHTML()}<div id="hostInspection"></div></section><div class="callout">Graph links show observed communications, not verified connectivity or device ownership. IP classifications and physical locations are not inferred.</div>`}
function pageCaptures(){return title('EVIDENCE VAULT','Source captures','Import real PCAP or PCAPNG files; capture hashes preserve a verifiable chain of source file identity.',`<button class="primary-btn" data-action="choose-upload">+ Import capture</button>`)+
 `<div class="dropzone" id="dropzone" tabindex="0" role="button" aria-label="Import a network capture"><div class="icon">⇧</div><b>Drop a network capture here</b><p>PCAP / PCAPNG · Max ${state.health?.limits?.upload_mb||100} MB · Local processing only</p><span class="badge info">BROWSE FILES</span></div><div class="callout">Supported packet framing: Ethernet, VLAN, Linux SLL/SLL2, raw IP and BSD loopback. Unsupported protocols are retained as metadata and marked explicitly. TCP reconstruction, application decryption, and full protocol dissection are out of scope for this release.</div>`+
 `<section class="panel"><div class="panel-head"><h2>REGISTERED EVIDENCE FILES</h2><span>${state.caps.length} SOURCE FILES</span></div>${state.caps.length?state.caps.map(c=>`<div class="source-card"><div class="src-left"><b>${html(c.filename)}</b><p>${bytes(c.size)} · ${c.frame_count.toLocaleString()} frames · ${html(c.status)} · SHA-256 <span class="mono" title="${html(c.sha256)}">${html(c.sha256.slice(0,24))}…</span></p>${c.error?`<p class="warning-text">${html(c.error)}</p>`:''}</div><div class="src-right">${!isReadOnly()?`<button class="ghost-btn" data-action="download-original" data-id="${html(c.id)}">↓ Original PCAP</button>`:''}${sev(c.status==='ready'?'low':'medium')}<button class="ghost-btn" data-action="remove-capture" data-id="${html(c.id)}">Remove</button></div></div>`).join(''):`<div class="empty-panel">No capture is attached. Upload a PCAP file or open a provided lab case.</div>`}</section><div style="margin-top:18px"><button class="ghost-btn" data-action="download-ml-features">↓ Export ML flow features (CSV)</button> <button class="ghost-btn" data-action="demo-start">Open two lab PCAP cases</button><span class="dim" style="font-size:11px;margin-left:12px">Captured packet records; attack labels and original provenance are not independently verified.</span></div>`+`<div class="bb18-info"><b>Saved securely on this machine/server</b><p>Reopen captures under <button class="ghost-btn" data-page="library">Saved investigations</button>, or use the case selector at the top. Your original PCAP remains stored until you remove the capture or case.</p></div>`+captureLibrary()}
function tracePanel(f){
 if(state.traceId!==f.id)return '';
 const t=state.trace;
 if(!t)return `<section class="trace-lab trace-loading" role="status">Verifying packet references for this case…</section>`;
 const indicators=Object.entries(t.indicators||{}).map(([k,v])=>`<span class="trace-indicator"><small>${html(k.replaceAll('_',' '))}</small><b>${html(Array.isArray(v)?v.join(', '):v)}</b></span>`).join('');
 const cards=(t.alternatives||[]).map((a,i)=>`<div class="trace-hypothesis"><div class="trace-hlabel">${i===0?'HYPOTHESIS A':'HYPOTHESIS B'} · NOT VERIFIED</div><h4>${html(a.title)}</h4><p>${html(a.interpretation)}</p><div class="trace-check"><b>What would distinguish it?</b><p>${html(a.verify_with)}</p></div></div>`).join('');
 const events=(t.representative_packets||[]).map(p=>`<button type="button" data-action="show-packet" data-id="${Number(p.packet_id)}" class="trace-event"><span class="trace-event-time">${p.ts?clock(p.ts):'TIME UNKNOWN'}</span><span class="trace-event-path"><b>#${Number(p.frame_no)} · ${html(p.protocol)}</b><small>${html(p.src)}${p.src_port!=null?':'+p.src_port:''} → ${html(p.dst)}${p.dst_port!=null?':'+p.dst_port:''}</small><small class="trace-event-source">${html(p.capture)} · source frame ${Number(p.frame_no)}</small></span><span class="trace-arrow">↗</span></button>`).join('');
 return `<section class="trace-lab" aria-label="BLACKBOX TRACE: challenge this finding"><div class="trace-head"><div><span class="trace-kicker">◈ BLACKBOX TRACE / EVIDENCE CHALLENGE</span><h3>What else could explain this?</h3><p>Two plausible interpretations. No automatic verdict. Every linked packet is checked against this case.</p></div><button class="ghost-btn" type="button" data-action="trace-close">Close ✕</button></div><div class="trace-status">${html(t.review_status)}</div><div class="trace-section-label">WHAT THE CAPTURE ACTUALLY SHOWS</div><p class="trace-observed">${html(t.observed)}</p><div class="trace-indicators">${indicators}</div><div class="trace-section-label">CHALLENGE THE EXPLANATION</div><div class="trace-hypotheses">${cards}</div><div class="trace-section-label">FOLLOW THE PACKET TRAIL <small>REPRESENTATIVE PACKETS, NOT ALL MATCHES</small></div><div class="trace-events">${events||'<p class="dim">No linked packets were available.</p>'}</div><div class="trace-sources">${(t.sources||[]).map(x=>`<div><b>${html(x.filename)}</b><small>SHA-256 ${html(x.sha256)}</small></div>`).join('')}</div><div class="trace-last"><b>What remains unknown?</b><ul>${(t.limitations||[]).map(x=>`<li>${html(x)}</li>`).join('')}</ul></div><div class="trace-actions"><button class="primary-btn" type="button" data-action="trace-export" data-format="md">↓ Download TRACE report</button><button class="ghost-btn" type="button" data-action="trace-export" data-format="json">Export JSON</button><button class="ghost-btn" type="button" data-page="assistant">Ask Investigator ↗</button></div><p class="trace-footer">Determined from stored case evidence · No ML or LLM inference was used for this TRACE assessment</p></section>`;
}
async function openTrace(fid){
 if(!state.caseId)return;
 if(state.traceId===fid&&state.trace){state.trace=null;state.traceId='';render();return}
 const cid=state.caseId;state.traceId=fid;state.trace=null;
 if(state.page!=='findings')navigate('findings');else render();
 try{const result=await api(`/cases/${encodeURIComponent(cid)}/trace/${encodeURIComponent(fid)}`);
  if(state.caseId!==cid||state.traceId!==fid)return;
  state.trace=result;render();requestAnimationFrame(()=>document.getElementById('f-'+fid)?.querySelector('.trace-lab')?.scrollIntoView({block:'nearest',behavior:'smooth'}));
 }catch(err){state.traceId='';state.trace=null;render();toast(err.message,true)}
}
async function exportTrace(fid,format){
 const url=`/api/cases/${encodeURIComponent(state.caseId)}/trace/${encodeURIComponent(fid)}/export?format=${format}`;
 const r=await fetch(url);if(!r.ok)throw Error('TRACE export failed');
 const blob=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);
 a.download=`BLACKBOX-TRACE-${fid.slice(0,9)}.${format==='json'?'json':'md'}`;
 document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),1000);
}
function pageFindings(){return title('RULE FINDINGS','Signals worth investigating','Detections are derived from actual packet fields and rule thresholds. They are not definitive conclusions.',`<button class="ghost-btn" data-action="reanalyze">↻ Re-analyze evidence</button>`)+`<section class="panel"><div class="panel-head"><h2>INVESTIGATION QUEUE</h2><span>${state.findings.length} RULE MATCHES</span></div>${state.findings.length?state.findings.map(f=>`<article class="finding" id="f-${html(f.id)}"><div>${sev(f.severity)}<p class="mono dim" style="margin-top:8px;font-size:10px">${html(f.confidence)} confidence</p></div><div><h3>${html(f.title)}</h3><p>${html(f.summary)}</p><div class="finding-extra"><b>Next check:</b> ${html(f.recommendation)}</div><div class="trace-trigger"><button type="button" class="trace-open-btn" data-action="trace-open" data-id="${html(f.id)}">◈ ${state.traceId===f.id?'Hide TRACE':'Challenge this conclusion'} ↗</button><span>Explore alternative explanations backed by packet evidence</span></div><details><summary>View indicators & packet evidence</summary><div class="callout">${Object.entries(f.indicators).map(([k,v])=>`<div><b>${html(k)}</b>: ${html(Array.isArray(v)?v.join(', '):v)}</div>`).join('')}</div><div class="evidence-list">${f.evidence.map(id=>`<button data-action="show-packet" data-id="${id}">PACKET ID ${id} ↗</button>`).join('')}</div></details>${tracePanel(f)}</div><div><span class="mono dim" style="font-size:10px">${fmtDay(f.first_seen)}</span></div></article>`).join(''):`<div class="empty-panel">No configured detector threshold was exceeded. This does not prove the network is safe. Add relevant traffic and inspect the packet explorer.</div>`}</section>`}
function pageTraffic(){return title('PACKET EXPLORER','Raw facts, not guesses','Search stored packet metadata, trace IP relationships, inspect ports and verify the evidence behind each rule.',`<button class="ghost-btn" data-page="findings">Findings →</button>`)+`<div class="toolbar" style="margin-bottom:15px"><input id="packetSearch" class="input search" placeholder="IP, domain, host…" value="${html(state.packetsSearch)}"><select class="input" id="packetProto"><option value="">All protocols</option>${['TCP','UDP','ARP','ICMP','ICMPv6','OTHER'].map(x=>`<option value="${x}" ${state.packetsProtocol===x?'selected':''}>${x}</option>`).join('')}</select><button class="primary-btn" data-action="search-packets">Search</button><button class="ghost-btn" data-action="reset-packets">Reset</button></div>`+
 `<div class="panel"><div class="panel-head"><h2>PACKET METADATA</h2><span>NO PAYLOAD BYTES STORED</span></div><div class="table-wrap"><table><thead><tr><th>Packet ID</th><th>Time (UTC)</th><th>Source</th><th>Destination</th><th>Proto</th><th>Info</th><th>Bytes</th></tr></thead><tbody>${state.packets.length?state.packets.map(p=>`<tr><td class="mono">${p.id}</td><td class="mono">${clock(p.ts)}</td><td><button class="text-link mono" data-action="host" data-ip="${html(p.src)}">${html(p.src)}${p.src_port!==null?':'+p.src_port:''}</button></td><td><button class="text-link mono" data-action="host" data-ip="${html(p.dst)}">${html(p.dst)}${p.dst_port!==null?':'+p.dst_port:''}</button></td><td>${html(p.proto)}</td><td>${html(p.dns_query?`DNS ${p.dns_query}`:p.tls_sni?`TLS SNI ${p.tls_sni}`:p.http_host?`HTTP ${p.http_method} ${p.http_host}`:p.tcp_flags?`TCP ${p.tcp_flags}`:p.note)}</td><td class="mono">${p.length}</td></tr>`).join(''):'<tr><td colspan="7" class="empty-panel">No matching packets. Try another filter.</td></tr>'}</tbody></table></div><div class="pagination"><button data-action="prev-packets" ${state.packetOffset<=0?'disabled':''}>← Previous</button><span>Offset ${state.packetOffset} · ${state.packets.length} shown</span><button data-action="next-packets" ${state.packets.length<100?'disabled':''}>Next →</button></div></div>`+
 `<div class="lower-grid"><section class="panel"><div class="panel-head"><h2>TOP CONVERSATIONS</h2><span>UNIDIRECTIONAL FLOW COUNTS</span></div><div class="table-wrap"><table><thead><tr><th>Source → Destination</th><th>Protocol</th><th>Packets</th><th>Observed bytes</th></tr></thead><tbody>${state.flows.slice(0,30).map(f=>`<tr><td class="mono">${html(f.src)}:${f.src_port??'–'} → ${html(f.dst)}:${f.dst_port??'–'}</td><td>${html(f.proto)}</td><td>${f.packets}</td><td>${bytes(f.bytes)}</td></tr>`).join('')}</tbody></table></div></section><section class="panel"><div class="panel-head"><h2>OBSERVED DNS</h2><span>TOP ${Math.min(state.dns.length,20)} QUERIES</span></div><div class="table-wrap"><table><thead><tr><th>Domain</th><th>Count</th><th>NX</th></tr></thead><tbody>${state.dns.slice(0,20).map(d=>`<tr><td style="overflow-wrap:anywhere">${html(d.domain)}</td><td>${d.count}</td><td>${d.nxdomain}</td></tr>`).join('')}</tbody></table></div></section></div>`}
function specialistCards(){
 const agents=state.agentBrief?.agents||[];
 return `<section class="specialist-shell" aria-label="Evidence specialist agents"><div class="specialist-header"><div><div class="eyebrow">DETERMINISTIC SPECIALIST AGENTS</div><h2>Three perspectives. One verified case.</h2><p>Traffic facts, heuristic threat signals, and observed timeline—not three unrelated AI guesses.</p></div><span class="specialist-local">● READ-ONLY · LOCAL</span></div><div class="specialist-grid">${agents.length?agents.map((a,i)=>{
  const icon=['⌁','◇','◷'][i]||'◉';const count=(a.packet_refs||[]).length;const findings=(a.finding_ids||[]).length;
  const links=(a.packet_refs||[]).slice(0,2).map(ref=>`<button class="specialist-ref" data-action="show-packet" data-id="${Number(ref.packet_id)}" title="Frame ${Number(ref.frame_no)} · ${html(ref.capture)}">#${Number(ref.frame_no)} packet ↗</button>`).join('');
  const found=(a.finding_ids||[]).slice(0,1).map(id=>`<button class="specialist-ref" data-action="finding" data-id="${html(id)}">Finding ${html(id.slice(0,7))} ↗</button>`).join('');
  return `<article class="specialist-card specialist-${html(a.agent)}"><span class="specialist-icon">${icon}</span><span class="specialist-status">${html(a.status)}</span><h3>${html(a.title)}</h3><p>${html(a.summary)}</p><div class="specialist-meta"><span>${count} verified packets</span><span>${findings} linked findings</span></div><div class="specialist-links">${found}${links}</div></article>`
 }).join(''):'<p class="specialist-empty">Create an investigation and upload evidence to activate all three specialists.</p>'}</div><p class="specialist-disclaimer">Every packet button resolves to stored evidence from this case. These agents do not independently confirm attacks. DeepSeek combines their findings only when you choose Cloud AI.</p></section>`;
}

function pageAssistant(){return title('EVIDENCE ASSISTANT','Ask the investigation','Chat with BLACKBOX Copilot about the app, networking, and your case evidence.',`<span class="badge info">LOCAL-FIRST</span>`)+specialistCards()+`<div class="chat-space"><section class="panel chat-main"><div class="panel-head"><h2>ANALYST CONVERSATION</h2><span>NOT A THREAT VERDICT</span></div><div class="chat-history" id="chatHistory">${state.chat.length?state.chat.map(m=>`<div class="bubble ${m.role}"><span class="who">${m.role==='user'?'YOU':'BLACKBOX / '+html(m.engine)}</span>${html(m.text)}${m.tools?.length?`<div class="mono" style="color:#8bb9cc;font-size:10px;margin-top:12px">READ-ONLY TOOLS: ${html(m.tools.join(', '))}</div>`:''}${m.ids?.length?`<div class="evidence-list">${m.ids.map(i=>`<button data-action="finding" data-id="${html(i)}">FINDING ${html(i.slice(0,8))} ↗</button>`).join('')}</div>`:''}${m.packetIds?.length?`<div class="evidence-list">${m.packetIds.map(id=>`<button data-action="show-packet" data-id="${Number(id)}">PACKET ${Number(id)} ↗</button>`).join('')}</div>`:''}</div>`).join(''):`<div class="empty-panel"><b>Meet BLACKBOX Copilot.</b><p>Say hello, ask about a page, or investigate evidence. Example: Which IPs generated the most traffic? Are there suspicious DNS queries? Describe the observed findings.</p></div>`}</div><form id="chatForm" class="chat-composer"><input class="input" id="chatInput" placeholder="Ask me anything about BLACKBOX, security or your case…" minlength="2" maxlength="1400" required autocomplete="off"><button class="primary-btn" type="submit">Investigate →</button></form></section><aside class="panel"><div class="panel-head"><h2>INVESTIGATOR TOOLS</h2></div><div class="help-list"><div class="eyebrow">QUICK QUESTIONS</div>${['What can you do?','Explain this page','How do I investigate a PCAP?','Explain replay step 1','What happened in this capture?','Which hosts generated the most traffic?','Are there unusual DNS queries?','Show the largest network flows','Which protocols are present?'].map(q=>`<button data-action="ask-example" data-question="${html(q)}">${html(q)} ↗</button>`).join('')}<hr style="border:0;border-top:1px solid #30465a;margin:20px 0"><label class="agent-model-label" for="modelMode">ANALYSIS MODE</label><select class="input" id="modelMode" aria-label="Analysis model"><option value="offline" ${state.modelMode==='offline'?'selected':''}>Offline evidence (no AI API)</option>${state.health?.cloud_ai?.configured?`<option value="cloud" ${state.modelMode==='cloud'?'selected':''}>Cloud AI · ${html(state.health.cloud_ai.provider)} / ${html(state.health.cloud_ai.model)}</option>`:''}${state.health?.ollama_configured?`<option value="local" ${state.modelMode==='local'?'selected':''}>Local Ollama</option>`:''}</select><p>${state.health?.cloud_ai?.configured?'Cloud provider configured. When chosen, questions, host metadata, DNS names and findings are sent to the provider. Raw PCAP files are never sent.':'To use an API key without Ollama, run SETUP_CLOUD_AI.bat in the BLACKBOX folder, then restart the server.'}</p><p>AI answers can be wrong. Always check cited packet evidence.</p></div></aside></div>`}
function pageLibrary(){
 const entries=state.cases||[];
 return title('SAVED INVESTIGATIONS','Your case library', 'Cases and PCAP/PCAPNG originals are stored persistently on the BLACKBOX server, not in your browser. You can reopen a case after restarting the application.', `${mayCreate()?'<button class="primary-btn" data-action="new-case">+ New investigation</button>':''}`)+
 `<section class="bb18-grid">${entries.length?entries.map(c=>`<article class="bb18-case"><span class="eyebrow">SAVED CASE · ${html(c.created_at?.slice(0,10)||'')}</span><h3>${html(c.name)}</h3><p>${html(c.description||'No description')}</p><p class="dim">${Number(c.captures||0)} capture(s) · ${Number(c.findings||0)} rule finding(s)</p><button class="primary-btn" data-action="open-old-case" data-id="${html(c.id)}">Open investigation →</button></article>`).join(''):'<div class="empty-panel">No saved investigations yet. Create a case and upload PCAP evidence.</div>'}</section><section class="bb18-info"><b>Where are my captures kept?</b><p>Local Windows: <code>%USERPROFILE%\.blackbox-investigator\captures</code>. Linux/macOS: <code>~/.blackbox-investigator/captures</code>. Case history is kept in <code>blackbox.sqlite3</code> inside the same data directory. If <code>BLACKBOX_DATA_DIR</code> is configured, that folder is used instead.</p><p>Deleting a case deletes its stored files. Back up the entire data folder for long-term retention. This is device/server storage, not automatic cloud sync.</p></section>`;
}
async function pageMlLoad(){
 if(!state.caseId||state.mlLoaded)return;
 try{state.mlResults=await api(`/cases/${encodeURIComponent(state.caseId)}/ml/anomalies`);state.mlLoaded=true;if(state.page==='ml')render();}
 catch(e){state.mlLoaded=true;state.mlResults={status:'error',disclaimer:e.message,anomalies:[]};if(state.page==='ml')render()}
}
function pageMl(){
 if(!state.mlLoaded){pageMlLoad();return title('ML LAB','Unsupervised anomaly screening','Analyzing directional flows with a local Isolation Forest. No cloud requests are made.')+'<div class="empty-panel">Calculating case-relative outlier scores…</div>'}
 const m=state.mlResults||{},ready=m.status==='ready';
 return title('ML LAB','Unsupervised anomaly screening','Live case-relative Isolation Forest. This is working ML, but it is not a trained supervised attack classifier.',`<button class="ghost-btn" data-action="refresh-ml">↻ Analyze again</button><button class="ghost-btn" data-action="download-ml-features">↓ Export flow features</button>`)+
 `<section class="bb18-info"><b>ML status: ${html(m.status||'unknown')}</b><p>Flows: ${Number(m.flows||0)} · Algorithm: ${html(m.method||'IsolationForest')}${ready?' · Relative outliers flagged: '+Number(m.anomaly_count||0):''}</p><p>${html(m.disclaimer||'')}</p>${!ready?`<p>At least ${Number(m.min_flows||24)} directional flows are needed in this case. Upload a larger capture to run the ML baseline.</p>`:''}</section>`+
 (ready?`<section class="bb18-grid">${(m.anomalies||[]).map(a=>`<article class="bb18-case"><span class="eyebrow">UNSUPERVISED FLOW OUTLIER · ${html(a.flow_id)}</span><h3>${html(a.src_ip)} → ${html(a.dst_ip)}</h3><p>${html(a.protocol)} · ${html(a.dst_port==null?'port unknown':'destination port '+a.dst_port)} · ${Number(a.packet_count||0)} packets</p><p class="dim">Relative outlier score: ${Number(a.anomaly_score||0).toFixed(4)} (not attack probability)</p><p>${html(a.explanation)}</p>${(a.evidence_packet_ids||[]).slice(0,4).map(id=>`<button class="ghost-btn" data-action="show-packet" data-id="${html(id)}">Packet #${html(id)} ↗</button>`).join('')}</article>`).join('')||'<div class="empty-panel">No statistical outliers in this case.</div>'}</section>`:'');
}
function pageReport(){const s=state.summary,fs=state.findings;return title('CASE DOSSIER','Evidence report','Understand the case in plain language, with source hashes and evidence-backed findings.',`<button class="primary-btn" data-action="download-pdf">↓ Download readable PDF</button><button class="ghost-btn" data-action="download-ai-pdf">✦ AI-enhanced PDF (opt-in)</button><button class="ghost-btn" data-action="download-report">Markdown</button><button class="ghost-btn" data-action="download-json">↓ Export JSON</button>`)+`<section class="report-preview"><div class="eyebrow">BLACKBOX / FORENSIC NOTES</div><h3>${html(state.caseData.name)}</h3><p class="dim">${html(state.caseData.description||'No case description provided.')}</p><p class="mono">CASE ${html(state.caseData.id)}<br>PACKETS ${s.stats.packet_count} · FILES ${state.caps.length} · FINDINGS ${fs.length}</p><hr><h3>Plain-language summary</h3><p>BLACKBOX reviewed ${s.stats.packet_count.toLocaleString()} packet records across ${state.caps.length} stored capture(s) and identified ${fs.length} rule-based observation(s) worth investigating. ${fs.length?"An alert is not proof of an intrusion; check each linked packet and alternative explanation.":"No rule threshold was reached; that does not certify network safety."}</p><h3>Evidence integrity</h3>${state.caps.length?state.caps.map(c=>`<p><b>${html(c.filename)}</b> (${html(c.status)})<br><span class="mono" style="font-size:11px;overflow-wrap:anywhere">SHA-256 ${html(c.sha256)}</span></p>`).join(''):'<p>No captures have been imported.</p>'}<hr><h3>Findings for analyst review</h3>${fs.length?fs.map(f=>`<p><b>${html(f.title)}</b> ${sev(f.severity)}<br>${html(f.summary)}<br><span class="mono dim">Evidence packet IDs: ${f.evidence.join(', ')}</span></p>`).join(''):'<p>No rule thresholds were crossed. This does not certify safety.</p>'}<hr><h3>Scope & limitations</h3><p>No packet payloads retained in the database. Capture payload remains in the local uploaded source file. Packet decoding is limited; fragmented streams and encrypted sessions may obscure activity. Alerts are heuristic leads, not proof of malicious activity. Inspect original captures in Wireshark when deeper protocol validation is required.</p><button class="danger-btn" data-action="delete-case">Delete entire case and local capture files</button></section>`}
async function loadTraffic(){if(!state.caseId)return;try{const id=encodeURIComponent(state.caseId);[state.packets,state.flows,state.dns]=await Promise.all([api(`/cases/${id}/packets?limit=100&offset=${state.packetOffset}&proto=${encodeURIComponent(state.packetsProtocol)}&search=${encodeURIComponent(state.packetsSearch)}`),api(`/cases/${id}/flows?limit=150`),api(`/cases/${id}/dns?limit=100`)]);state.trafficLoaded=true;if(state.page==='traffic')render();}catch(e){state.trafficLoaded=true;toast(e.message,true)}}
function render(){if($('#sidebarCase')){$('#sidebarCase').textContent=state.caseData?.name||'No case selected';$('#sidebarFrames').textContent=state.summary?(Number(state.summary.stats.packet_count||0).toLocaleString()+' packets · '+(state.findings?.length||0)+' findings'):'Select a case to begin'}let page=$('#page');applyDeploymentMode();if(!state.caseData&&state.page!=='library'){page.innerHTML=none();return}if(state.page==='traffic'&&!state.trafficLoaded)loadTraffic()
 applyDeploymentMode();page.innerHTML=({library:pageLibrary,ml:pageMl,overview:pageOverview,captures:pageCaptures,investigation:pageInvestigation,replay:pageReplay,findings:pageFindings,traffic:pageTraffic,assistant:pageAssistant,report:pageReport}[state.page]||pageOverview)();if(state.page==='captures')bindDropzone();if(state.page==='overview'||state.page==='investigation')updateInspector();if(isReadOnly())applyReadOnlyView()}
function updateInspector(){const slot=$('#hostInspection');if(!slot)return;if(!state.selectedHost){slot.innerHTML='';return}slot.innerHTML=`<div class="host-inspector"><b>HOST INSPECTOR · ${html(state.selectedHost)}</b><div class="facts">Loading observed peers…</div></div>`;
 api(`/cases/${encodeURIComponent(state.caseId)}/hosts/${encodeURIComponent(state.selectedHost)}`).then(d=>{if(state.selectedHost!==d.ip)return;slot.innerHTML=`<div class="host-inspector"><b>HOST INSPECTOR · ${html(d.ip)}</b><div class="facts">${d.frames} packet records · ${bytes(d.bytes)} observed · ${d.peers.length} leading peers<br>${d.peers.slice(0,7).map(p=>`${html(p.peer)}: ${p.packets} packets`).join('<br>')}</div><button class="ghost-btn" data-action="filter-host" data-ip="${html(d.ip)}">Inspect host packets →</button></div>`;}).catch(e=>toast(e.message,true));}
function bindDropzone(){const el=$('#dropzone');if(!el)return;el.addEventListener('click',()=>$('#captureFile').click());el.addEventListener('keydown',e=>{if(e.key==='Enter')$('#captureFile').click()});el.addEventListener('dragover',e=>{e.preventDefault();el.classList.add('dragover')});el.addEventListener('dragleave',()=>el.classList.remove('dragover'));el.addEventListener('drop',e=>{e.preventDefault();el.classList.remove('dragover');const f=e.dataTransfer.files[0];if(f)upload(f)})}
async function upload(file){if(isReadOnly()){toast('Sign in and open a private case to upload PCAPs.',true);return}if(!state.caseId){toast('Create an investigation case first.',true);return}if(state.busy)return;
 try{busy(true,'IMPORTING…');const body=new FormData();body.append('file',file,file.name);const r=await api(`/cases/${encodeURIComponent(state.caseId)}/captures`,{method:'POST',body});state.flows=[];state.packets=[];state.dns=[];state.trafficLoaded=false;state.mlLoaded=false;state.mlResults=null;state.packetOffset=0;
 await refreshCase();toast(`${r.frames.toLocaleString()} packets ingested. ${r.case_findings} rule findings.${r.status!=='ready'?' NOTE: partial capture':''}`,r.status!=='ready');navigate('overview')}
 catch(e){toast('Import failed: '+e.message,true)}finally{busy(false);$('#captureFile').value=''}}
// Open two explicitly synthetic sample cases; never claim real captured attacks.
function openModal(){if(!mayCreate()){showAuth();return}$('#modalLayer').classList.remove('hidden');$('#caseName').focus()}
function closeModal(){ $('#modalLayer').classList.add('hidden');$('#caseForm').reset()}
async function newCase(e){e.preventDefault();const name=$('#caseName').value.trim(),description=$('#caseDescription').value.trim();if(!name)return;try{const d=await api('/cases',{method:'POST',body:JSON.stringify({name,description})});closeModal();state.flows=[];state.packets=[];state.dns=[];state.trafficLoaded=false;state.mlLoaded=false;state.mlResults=null;state.chat=[];await loadCases(d.id);toast('Investigation case created. Import a capture to begin.')}catch(err){toast(err.message,true)}}
async function ask(question){if(!state.caseId)return;if(state.busy)return;const model=state.modelMode;const history=state.chat.filter(m=>m.engine!=='WORKING' && (m.role==='user'||m.role==='agent')).slice(-8).map(m=>({role:m.role==='agent'?'assistant':'user',content:m.text.slice(0,1100)}));state.chat.push({role:'user',text:question});state.chat.push({role:'agent',text:'Reviewing packet metadata…',engine:'WORKING'});render();try{const r=isReadOnly()?await api(`/cases/${encodeURIComponent(state.caseId)}/explain?question=${encodeURIComponent(question.slice(0,300))}`):await api(`/cases/${encodeURIComponent(state.caseId)}/ask`,{method:'POST',body:JSON.stringify({question,use_local_model:model==='local',use_cloud_model:model==='cloud',history,page:state.page})});state.chat[state.chat.length-1]={role:'agent',text:r.answer+'\n\n'+r.notice,engine:r.engine,ids:r.finding_ids,packetIds:r.packet_ids||[],tools:(r.specialists_used||[]).map(x=>x+' agent').concat(r.tools_used||[])}}catch(e){state.chat[state.chat.length-1]={role:'agent',text:'Unable to answer: '+e.message,engine:'ERROR'}}render();let c=$('#chatHistory');if(c)c.scrollTop=c.scrollHeight;}
async function showPacket(id){
 try{
  const p=await api(`/cases/${encodeURIComponent(state.caseId)}/packets/${encodeURIComponent(id)}`);
  const pairs=[['Stored packet ID',p.id],['Original frame number',p.frame_no],['Capture filename',p.filename],['Capture SHA-256',p.sha256],['Time UTC',when(p.ts)],['Source',p.src+(p.src_port!=null?':'+p.src_port:'')],['Destination',p.dst+(p.dst_port!=null?':'+p.dst_port:'')],['Protocol',p.proto],['Length',p.length+' bytes'],['TCP flags',p.tcp_flags],['DNS query',p.dns_query],['DNS response code',p.dns_rcode],['DNS answers',p.dns_answers],['TLS SNI',p.tls_sni],['HTTP host',p.http_host],['HTTP method',p.http_method],['ARP source IP',p.arp_ip],['ARP source MAC',p.arp_mac],['Notes',p.note]];
  let layer=document.createElement('div');layer.className='modal-layer';layer.id='packetDetailsLayer';
  layer.innerHTML=`<div class="modal packet-modal" role="dialog" aria-modal="true" aria-label="Packet metadata details"><div class="modal-top"><b>PACKET EVIDENCE · ${p.id}</b><button data-close-packet aria-label="Close">×</button></div><p class="subhead">Packet metadata as actually parsed from the uploaded source capture. Open frame ${p.frame_no} in Wireshark for full contents.</p><div class="packet-rows">${pairs.filter(([,v])=>v!==null&&v!==undefined&&v!=='').map(([k,v])=>`<div><span>${html(k)}</span><b>${html(v)}</b></div>`).join('')}</div><div class="modal-actions"><button class="ghost-btn" data-close-packet>Close</button></div></div>`;
  layer.addEventListener('click',e=>{if(e.target===layer||e.target.closest('[data-close-packet]'))layer.remove()});document.body.appendChild(layer);
 }catch(e){toast(e.message,true)}
}

async function renderFinding(id){navigate('findings');requestAnimationFrame(()=>{let el=document.getElementById('f-'+id);if(el){el.scrollIntoView({behavior:'smooth',block:'center'});el.querySelector('details').open=true}})}
async function downloadMlFeatures(){
 if(!state.caseId)return;
 try{
  const url=`/api/cases/${encodeURIComponent(state.caseId)}/ml/features.csv`;
  const r=await fetch(url);
  if(!r.ok)throw Error('ML feature export failed');
  const blob=await r.blob();const link=document.createElement('a');
  link.href=URL.createObjectURL(blob);link.download='BLACKBOX-flow-features.csv';
  document.body.appendChild(link);link.click();link.remove();
  setTimeout(()=>URL.revokeObjectURL(link.href),800);
  toast('Exported PCAP-derived flow features for ML. Attack labels are intentionally blank.');
 }catch(err){toast(err.message,true)}
}
async function downloadAiPdf(){
 if(!state.caseId)return;
 const cloud=Boolean(state.health?.cloud_ai?.configured);
 const mode=cloud?'cloud':'local';
 if(cloud&&!confirm('Generate an AI-assisted PDF? Selected case metadata and your request will be sent to your configured cloud model. Raw PCAP bytes are not sent. Continue?'))return;
 if(!cloud&&!confirm('Use your configured local Ollama model to explain this report? No cloud metadata is sent. Continue?'))return;
 try{
  toast('Generating the AI-assisted report. Please wait…');
  const r=await fetch(`/api/cases/${encodeURIComponent(state.caseId)}/report/ai.pdf`,{
    method:'POST',headers:{'Content-Type':'application/json',...(state.auth?.csrf?{'X-BB-CSRF':state.auth.csrf}:{})},body:JSON.stringify({mode})});
  if(!r.ok){let err=await r.json().catch(()=>({}));throw Error(err.detail||'AI model unavailable')}
  const blob=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='BLACKBOX-'+state.caseId.slice(0,8)+'-AI-explained.pdf';document.body.appendChild(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(a.href),1800);
 }catch(err){toast('AI-enhanced PDF unavailable: '+err.message+'. Use the regular PDF, which needs no AI key.',true)}
}
async function downloadReport(format){if(!state.caseId)return;const url=`/api/cases/${encodeURIComponent(state.caseId)}/report?format=${format}`;try{const r=await fetch(url);if(!r.ok)throw Error('Export failed');const blob=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='BLACKBOX-'+state.caseId.slice(0,8)+'.'+(format==='json'?'json':format==='pdf'?'pdf':'md');document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),800)}catch(e){toast(e.message,true)}}
$('#navigation').addEventListener('click',e=>{const b=e.target.closest('[data-page]');if(b)navigate(b.dataset.page)});
$('#caseSelect').addEventListener('change',async e=>{state.caseId=e.target.value;state.trace=null;state.traceId='';state.chat=[];state.packets=[];state.flows=[];state.dns=[];state.trafficLoaded=false;state.mlLoaded=false;state.mlResults=null;state.packetOffset=0;await refreshCase()});
$('#demoTop').addEventListener('click',demoStart);
$('#newCaseBtn').addEventListener('click',openModal);$('#closeModal').addEventListener('click',closeModal);$('#cancelModal').addEventListener('click',closeModal);$('#caseForm').addEventListener('submit',newCase);
$('#modalLayer').addEventListener('click',e=>{if(e.target===$('#modalLayer'))closeModal()});
$('#importTop').addEventListener('click',()=>state.caseId?$('#captureFile').click():openModal());
$('#captureFile').addEventListener('change',e=>{if(e.target.files[0])upload(e.target.files[0])});
$('#page').addEventListener('click',async e=>{
 const nav=e.target.closest('[data-page]');if(nav){navigate(nav.dataset.page);return}
 const host=e.target.closest('[data-ip]');if(host){if(host.dataset.action==='host'||host.dataset.action==='filter-host'){state.packetsSearch=host.dataset.ip;state.packetOffset=0;state.packets=[];await loadTraffic();navigate('traffic')}else if(host.dataset.ip){state.selectedHost=host.dataset.ip;updateInspector()}return}
 const btn=e.target.closest('[data-action]');if(!btn)return;const action=btn.dataset.action;
 try{
 if(action==='new-case')openModal();
 if(action==='demo-start')await demoStart();
 if(action==='replay-prev'){stopReplay();stepReplay(state.replayIndex-1)}
 if(action==='replay-next'){stopReplay();stepReplay(state.replayIndex+1)}
 if(action==='replay-jump'){stopReplay();stepReplay(Number(btn.dataset.step))}
 if(action==='replay-play')playReplay();
 if(action==='ask-replay'){const step=Number(btn.dataset.step)+1;state.page='assistant';navigate('assistant');await ask('Explain replay step '+step+' in this case with the observed connections, packet evidence IDs, and any heuristic findings. What remains uncertain?');}
 if(action==='open-guide')toggleGuide(true);
 if(action==='choose-upload')$('#captureFile').click();
 if(action==='new-case')openModal();
 if(action==='open-old-case'){state.caseId=btn.dataset.id;state.trace=null;state.traceId='';state.mlLoaded=false;state.mlResults=null;state.chat=[];state.trafficLoaded=false;$('#caseSelect').value=state.caseId;await refreshCase();navigate('overview');}
 if(action==='refresh-ml'){state.mlLoaded=false;state.mlResults=null;render();}
 if(action==='download-original'){if(isReadOnly())throw Error('Source PCAP download is only available for your private cases');const id=encodeURIComponent(state.caseId),cap=encodeURIComponent(btn.dataset.id);window.location.href=`/api/cases/${id}/captures/${cap}/download`;}
 if(action==='explain-report'){navigate('assistant');await ask('Explain this case to a non-expert: what the recorded packets show, which findings have evidence, alternative benign explanations, and what remains unknown. Cite source packet IDs and do not invent an attack.');}

 if(action==='remove-capture'){if(confirm('Delete this capture and its packet records?')){await api(`/cases/${encodeURIComponent(state.caseId)}/captures/${encodeURIComponent(btn.dataset.id)}`,{method:'DELETE'});state.packets=[];state.flows=[];state.dns=[];await refreshCase();toast('Capture removed and findings recalculated.')}}
 if(action==='delete-case'){if(confirm('Delete the entire case, its records AND original uploaded capture files?')){await api(`/cases/${encodeURIComponent(state.caseId)}`,{method:'DELETE'});state.chat=[];state.packets=[];state.flows=[];state.dns=[];await loadCases('');toast('Case deleted.')}}
 if(action==='reanalyze'){await api(`/cases/${encodeURIComponent(state.caseId)}/investigate`,{method:'POST'});await refreshCase();toast('Rule engine ran again on stored packet metadata.');}
 if(action==='finding')renderFinding(btn.dataset.id);
 if(action==='trace-open')await openTrace(btn.dataset.id);
 if(action==='trace-close'){state.trace=null;state.traceId='';render();}
 if(action==='trace-export'&&state.traceId)await exportTrace(state.traceId,btn.dataset.format==='json'?'json':'md');
 if(action==='show-packet')showPacket(btn.dataset.id);
 if(action==='search-packets'){state.packetsSearch=$('#packetSearch')?.value||'';state.packetsProtocol=$('#packetProto')?.value||'';state.packetOffset=0;await loadTraffic()}
 if(action==='reset-packets'){state.packetsSearch='';state.packetsProtocol='';state.packetOffset=0;await loadTraffic()}
 if(action==='prev-packets'){state.packetOffset=Math.max(0,state.packetOffset-100);await loadTraffic()}
 if(action==='next-packets'){state.packetOffset+=100;await loadTraffic()}
 if(action==='ask-example')ask(btn.dataset.question);
 if(action==='download-report')downloadReport('md');
 if(action==='download-pdf')downloadReport('pdf');
 if(action==='download-ai-pdf')downloadAiPdf();
 if(action==='download-json')downloadReport('json');
 if(action==='download-ml-features')downloadMlFeatures();
 }catch(err){toast(err.message,true)}
});
$('#page').addEventListener('change',e=>{if(e.target.id==='modelMode')state.modelMode=e.target.value;if(e.target.id==='replaySeek'){stopReplay();stepReplay(e.target.value)}});
$('#page').addEventListener('submit',e=>{if(e.target.id==='chatForm'){e.preventDefault();let q=$('#chatInput').value.trim();if(q)ask(q)}});
$('#page').addEventListener('keydown',e=>{if(e.target.classList?.contains('host')&&(e.key==='Enter'||e.key===' ')){e.preventDefault();state.selectedHost=e.target.dataset.ip;updateInspector()}});
(async()=>{try{state.health=await api('/health');await authStartup();applyDeploymentMode();if(!['multi-user','local-auth'].includes(state.health.mode)||state.auth?.authenticated)await loadCases();if(isGalleryMode())showGateway()}catch(err){toast('Backend unavailable: '+err.message,true);$('#page').innerHTML='<div class="empty-panel">Could not reach BLACKBOX server. Run python run.py and reload the page.</div>'}})();

// Interface guidance, accessible on every view. No third-party JavaScript or assets.
function toggleGuide(open){$('#guideBackdrop').classList.toggle('hidden',!open);$('#guideDrawer').classList.toggle('hidden',!open);if(open)$('#guideDrawer').focus()}
$('#helpTop').addEventListener('click',()=>toggleGuide(true));
$('#helpSide').addEventListener('click',()=>toggleGuide(true));
$('#closeGuide').addEventListener('click',()=>toggleGuide(false));
$('#guideBackdrop').addEventListener('click',()=>toggleGuide(false));
$('#guideDrawer').addEventListener('click',e=>{const p=e.target.closest('[data-guide-page]');if(p){toggleGuide(false);navigate(p.dataset.guidePage)}});
document.addEventListener('keydown',e=>{if(e.key==='Escape')toggleGuide(false)});
function applyDeploymentMode(){
 const mode=state.health?.mode||'local';
 const readOnly=isReadOnly();
 $('#newCaseBtn').hidden=!mayCreate();
 $('#importTop').hidden=readOnly;
 const labels={'local':'LOCAL WORKSPACE','public-demo':'PUBLIC · READ ONLY','private-hosted':'PRIVATE WORKSPACE','multi-user':'ACCOUNT WORKSPACE','local-auth':'LOCAL · SIGN IN','local-hybrid':state.auth?.authenticated?'LOCAL PRIVATE + DEMO':'LOCAL DEMO · SIGN IN','hybrid':state.auth?.authenticated?'PRIVATE + PUBLIC GALLERY':'PUBLIC GALLERY · SIGN IN'};
 $('#modePill').innerHTML=`<span class="pulse-dot"></span> ${html(labels[mode]||'ENGINE ONLINE')}`;
 $('#privacyMode').textContent=readOnly?'LAB PCAP EVIDENCE':'CONTROLLED EVIDENCE ENGINE';
 document.body.classList.toggle('read-only',readOnly);
}
function applyReadOnlyView(){
 // Disable every write operation in the UI; backend also independently enforces this.
 document.querySelectorAll('[data-action="choose-upload"],[data-action="load-sample"],[data-action="remove-capture"],[data-action="delete-case"],[data-action="reanalyze"],[data-action="download-ai-pdf"],#dropzone').forEach(el=>{el.setAttribute('aria-disabled','true');el.classList.add('read-only-action');if(el.tagName==='BUTTON')el.disabled=true});
 const composer=$('#chatForm');if(composer&&!composer.nextElementSibling?.classList?.contains('demo-notice'))composer.insertAdjacentHTML('afterend','<div class="demo-notice">Read-only gallery: you can ask offline evidence questions. No API key or cloud calls.</div>');

}

// Accessible application guide: helps operators understand each step without a cloud model.
(function(){const drawer=document.getElementById('guideDrawer'),backdrop=document.getElementById('guideBackdrop');if(!drawer)return;const open=()=>{drawer.classList.remove('hidden');backdrop.classList.remove('hidden');drawer.focus();},close=()=>{drawer.classList.add('hidden');backdrop.classList.add('hidden')};['helpSide','helpTop'].forEach(id=>document.getElementById(id)?.addEventListener('click',open));document.getElementById('closeGuide')?.addEventListener('click',close);backdrop.addEventListener('click',close);document.addEventListener('keydown',e=>{if(e.key==='Escape')close()});drawer.querySelectorAll('[data-guide-page]').forEach(btn=>btn.addEventListener('click',()=>{close();navigate(btn.dataset.guidePage)}));})();

// Source-linked five-capture testing reference; not an automatic threat verdict.
function captureLibrary(){
 const sources=[
 ['ARP identity claims','Bundled lab PCAP','Tested: 278 packets / 2 review signals',null],
 ['DNS / DHCP baseline','Bundled lab PCAP','Tested: 304 packets / 0 rule signals',null],
 ['Legacy service activity','Bundled lab PCAP','Tested: 278 packets / 1 review signal',null],
 ['Suspicious multi-pattern training','Synthetic PCAP · in samples/training','Generated training traffic; test file upload locally',null],
 ['Nmap SYN scanning','Public external capture','Documented Nmap lab; not tested here','https://github.com/Ryan-Sapone/Nmap-and-Wireshark-Lab/blob/main/SS%20Scan.pcapng'],
 ['HTTP / TCP file transfer','Public external capture','Wireshark ECN sample; not tested here','https://wiki.wireshark.org/SampleCaptures']
 ];
 return `<section class="panel capture-library"><div class="panel-head"><h2>SIX PCAP TEST RESOURCES</h2><a href="/assets/BLACKBOX_Test_Guide.pdf" target="_blank" rel="noopener" class="library-guide">Full PDF guide ↗</a></div><div class="capture-library-list">${sources.map((x,i)=>`<div class="capture-library-item"><span class="capture-n">${String(i+1).padStart(2,'0')}</span><div><b>${html(x[0])}</b><small>${html(x[1])} · ${html(x[2])}</small></div>${x[3]?`<a href="${html(x[3])}" target="_blank" rel="noopener noreferrer">Source ↗</a>`:'<span class="source-tag">LOCAL LAB</span>'}</div>`).join('')}</div><p class="dim" style="padding:0 17px 15px;font-size:11px">Lab data provenance is not independently verified; verify licensing and packet content before publishing. External sources are linked, not redistributed.</p></section>`;
}
