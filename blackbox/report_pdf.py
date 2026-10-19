"""Human-readable investigation PDF; deliberately evidence-derived, not LLM-generated."""
from __future__ import annotations
import io
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
from . import storage, trace

FONT='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
BOLD='/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
if Path(FONT).exists() and Path(BOLD).exists():
    pdfmetrics.registerFont(TTFont('BlackboxSans',FONT))
    pdfmetrics.registerFont(TTFont('BlackboxSans-Bold',BOLD))
else:
    FONT='Helvetica';BOLD='Helvetica-Bold'
F='BlackboxSans' if FONT.endswith('.ttf') else FONT
FB='BlackboxSans-Bold' if BOLD.endswith('.ttf') else BOLD
NAVY=colors.HexColor('#14162A');PURPLE=colors.HexColor('#7449B7');SLATE=colors.HexColor('#526078')


def _txt(s):
    return escape(str(s if s is not None else 'Unknown')).replace('\n',' ').replace('\r',' ')

def _utc(ts):
    if not ts:return 'Not recorded'
    try:return datetime.fromtimestamp(float(ts),timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError,OverflowError):return 'Invalid timestamp'


def build(case_id, ai_commentary=None, ai_engine=None):
    case=storage.get_case(case_id)
    if case is None:raise ValueError('Case not found')
    summary=storage.summary(case_id)
    finds=storage.list_findings(case_id)
    caps=storage.list_captures(case_id)
    stats=summary['stats']
    b=io.BytesIO()
    doc=SimpleDocTemplate(b,pagesize=A4,leftMargin=19*mm,rightMargin=19*mm,topMargin=19*mm,bottomMargin=20*mm,
      title=f"BLACKBOX Investigation - {case['name'][:90]}",author='BLACKBOX Investigator',pageCompression=1)
    styles={
     'title':ParagraphStyle('ReportTitle',fontName=FB,fontSize=22,leading=30,textColor=NAVY,spaceAfter=8),
     'sub':ParagraphStyle('ReportSub',fontName=F,fontSize=10,leading=15,textColor=SLATE,spaceAfter=8),
     'h':ParagraphStyle('ReportHeading',fontName=FB,fontSize=13,leading=19,textColor=PURPLE,spaceBefore=13,spaceAfter=6),
     'body':ParagraphStyle('ReportBody',fontName=F,fontSize=9.0,leading=15,textColor=NAVY,spaceAfter=7),
     'small':ParagraphStyle('ReportSmall',fontName=F,fontSize=7.6,leading=12,textColor=SLATE,spaceAfter=5,wordWrap='CJK'),
     'item':ParagraphStyle('ReportItem',fontName=F,fontSize=8.5,leading=13,textColor=NAVY,spaceAfter=5,wordWrap='CJK'),
    }
    story=[]
    P=lambda s,st='body':Paragraph(_txt(s),styles[st])
    story += [P('BLACKBOX / INVESTIGATION REPORT','small'),P(case['name'],'title'),P('A readable, evidence-based summary of the uploaded network captures. This is an investigation aid, not a confirmed attack verdict.','sub'),
      HRFlowable(width='100%',thickness=1,color=colors.HexColor('#DED8E9')),Spacer(1,4*mm)]
    story.append(P('Executive summary','h'))
    observed=f"BLACKBOX examined {stats['packet_count']:,} parsed packet records from {len(caps)} capture file(s), totaling {stats['traffic_bytes']:,} observed packet-length bytes. "
    if finds:
        observed+=f"The configured heuristic rules highlighted {len(finds)} pattern(s) needing review; {sum(f['severity']=='high' for f in finds)} are marked high review priority. "
        observed+='These flags describe suspicious-looking behavior; they do not establish malicious intent or a successful attack.'
    else:
        observed+='No configured rule thresholds were exceeded. This does not guarantee the network is safe.'
    story.append(P(observed))
    if case['description']:story.append(P('Investigation context: '+case['description'],'small'))
    if ai_commentary:
        story.append(P('Optional AI-assisted explanation','h'))
        story.append(P('Model: '+str(ai_engine)+' | LLM-generated interpretation, not verified packet evidence. Independently check every claim and packet reference.','small'))
        for paragraph in str(ai_commentary)[:5000].split('\n'):
            if paragraph.strip():story.append(P(paragraph[:1400]))
    stats_rows=[['PACKET RECORDS',f"{stats['packet_count']:,}"],['OBSERVED SOURCE HOSTS',str(stats['src_hosts'])],['EVIDENCE FILES',str(len(caps))],['FINDINGS FOR REVIEW',str(len(finds))],['EARLIEST OBSERVATION',_utc(stats.get('first_ts'))],['LATEST OBSERVATION',_utc(stats.get('last_ts'))]]
    table=Table([[P(x,'small'),P(y,'item')] for x,y in stats_rows],colWidths=[63*mm,105*mm],hAlign='LEFT')
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#F4F0F9')),('BOTTOMPADDING',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),6),('LINEBELOW',(0,0),(-1,-2),0.5,colors.HexColor('#DBD3E6'))]))
    story.append(table)
    story.append(P('What the capture shows','h'))
    protocols=summary['protocols'][:7]
    if protocols:
        story.append(P('Observed protocol mix: '+', '.join(f"{p['name']} ({p['count']:,} packets)" for p in protocols)+'.'))
    talkers=summary['top_talkers'][:5]
    if talkers:story.append(P('Most active observed source addresses: '+', '.join(f"{h['ip']} ({h['packets']:,} packets)" for h in talkers)+'.'))
    story.append(P('These are packet observations only: an IP address does not identify a person, and volume alone does not establish an attack.','small'))
    story.append(P('Suspicious patterns and next checks','h'))
    if not finds:story.append(P('There are no rule alerts in the selected evidence. Review traffic coverage and examine any outside logs before drawing a conclusion.'))
    for idx,f in enumerate(finds[:40],1):
        elements=[P(f"{idx}. [{f['severity'].upper()} review priority] {f['title']}",'item'),
                  P('Observed: '+f['summary']),
                  P('Why review this: the rule matched packet observations; it is not evidence of confirmed compromise.','small')]
        alt=trace.ALTERNATIVES.get(f['rule'])
        if alt:
            elements.append(P('Possible explanations: '+alt[0][0]+' OR '+alt[1][0]+'. Neither is confirmed.','small'))
            elements.append(P('Next check: '+alt[0][2],'small'))
        else:elements.append(P('Next check: '+f['recommendation'],'small'))
        ref=[]
        for pid in f.get('evidence',[])[:6]:
            p=storage.get_packet(case_id,int(pid)) if str(pid).isdigit() else None
            if p:ref.append(f"{p['filename']} / frame {p['frame_no']} (packet ID {pid})")
        if ref:elements.append(P('Evidence: '+'; '.join(ref),'small'))
        elements.append(Spacer(1,3*mm))
        story.append(KeepTogether(elements))
    if len(finds)>40:story.append(P(f"Only the first 40 of {len(finds)} findings are listed; inspect the case in BLACKBOX for the remainder.",'small'))
    story.append(P('Evidence files and how to revisit them','h'))
    if not caps:story.append(P('No capture files are stored with this investigation.'))
    for c in caps:
        story.append(P(c['filename']+f" - {c['frame_count']:,} frames - {c['status']}",'item'))
        story.append(P('SHA-256: '+c['sha256'],'small'))
        story.append(P('Imported: '+c['imported_at']+' | Capture ID: '+c['id'],'small'))
    story.append(P('Open BLACKBOX > Saved investigations, choose this case, then Evidence Vault to see or download its stored capture. The original PCAP is retained on the server disk until the case/capture is deleted. Reports do not contain the full packet payload.','small'))
    story.append(P('Important limitations','h'))
    for line in [
      'Heuristic rule findings are leads, not proof of malicious intent or a successful intrusion.',
      'Captures may omit packets, devices or time periods; encrypted traffic and application context are limited.',
      'A PDF summary is not an independent forensic chain-of-custody certification.',
      'The report narrative is generated from stored, verified case data, not by an LLM. An optional AI Copilot can discuss the case separately; generated text must be checked against packet evidence.',
      'If an unsupervised ML screening panel is available, it detects relative statistical outliers, not verified attacks or an externally validated supervised classifier.'
    ]:story.append(P('- '+line,'small'))
    story.append(P('Case ID: '+case_id,'small'))
    def number(canvas,doc_):
        canvas.saveState();w,h=A4
        canvas.setFont(F,7.5);canvas.setFillColor(SLATE)
        canvas.drawString(19*mm,12*mm,'BLACKBOX  /  Evidence-based investigation')
        canvas.drawRightString(w-19*mm,12*mm,f'Page {doc_.page}')
        canvas.restoreState()
    doc.build(story,onFirstPage=number,onLaterPages=number)
    return b.getvalue()
