"""SQLite case storage. Captured payload bytes are intentionally never stored in the DB."""
from __future__ import annotations
import json,sqlite3,uuid
from datetime import datetime,timezone
from pathlib import Path
from contextlib import contextmanager
import os

DATA=Path(os.environ.get('BLACKBOX_DATA_DIR',str(Path.home()/'.blackbox-investigator'))).resolve()
CAPTURES=DATA/'captures'
SCHEMA='''
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS cases (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS captures (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
 filename TEXT NOT NULL, stored_path TEXT NOT NULL, sha256 TEXT NOT NULL,
 size INTEGER NOT NULL, imported_at TEXT NOT NULL,
 status TEXT NOT NULL, frame_count INTEGER NOT NULL DEFAULT 0, supported_frames INTEGER NOT NULL DEFAULT 0,
 error TEXT NOT NULL DEFAULT '', first_ts REAL, last_ts REAL
);
CREATE TABLE IF NOT EXISTS packets (
 id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
 capture_id TEXT NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
 frame_no INTEGER NOT NULL, ts REAL NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL,
 proto TEXT NOT NULL, src_port INTEGER, dst_port INTEGER, length INTEGER NOT NULL,
 tcp_flags TEXT NOT NULL, dns_query TEXT NOT NULL, dns_qtype INTEGER, dns_rcode INTEGER,
 dns_response INTEGER NOT NULL, dns_answers TEXT NOT NULL,
 tls_sni TEXT NOT NULL,http_host TEXT NOT NULL,http_method TEXT NOT NULL,
 arp_ip TEXT NOT NULL,arp_mac TEXT NOT NULL,note TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_packets_case_ts ON packets(case_id,ts);
CREATE INDEX IF NOT EXISTS idx_packets_case_src ON packets(case_id,src);
CREATE INDEX IF NOT EXISTS idx_packets_case_dst ON packets(case_id,dst);
CREATE INDEX IF NOT EXISTS idx_packets_capture_frame ON packets(capture_id,frame_no);
CREATE TABLE IF NOT EXISTS findings (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
 rule TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
 confidence TEXT NOT NULL, summary TEXT NOT NULL,
 recommendation TEXT NOT NULL, indicators TEXT NOT NULL, evidence TEXT NOT NULL,
 first_seen REAL NOT NULL, last_seen REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id,severity);
'''


def init_db():
    DATA.mkdir(parents=True,exist_ok=True,mode=0o700)
    CAPTURES.mkdir(parents=True,exist_ok=True,mode=0o700)
    # Raw PCAPs and case metadata are sensitive even when only metadata is exposed in the UI.
    # Secure the containing directories on POSIX; Windows uses filesystem ACLs.
    if os.name=='posix':
        DATA.chmod(0o700)
        CAPTURES.chmod(0o700)
    with connect() as con:
        con.executescript(SCHEMA)
        cols={r['name'] for r in con.execute('PRAGMA table_info(cases)')}
        if 'owner' not in cols: con.execute("ALTER TABLE cases ADD COLUMN owner TEXT NOT NULL DEFAULT ''")

@contextmanager
def connect():
    con=sqlite3.connect(str(DATA/'blackbox.sqlite3'),timeout=30)
    con.row_factory=sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    con.execute('PRAGMA secure_delete=ON')
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback();raise
    finally: con.close()


def rowdict(row): return dict(row) if row else None

def create_case(name,description='',owner=''):
    case={'id':str(uuid.uuid4()),'name':name.strip()[:120],'description':description.strip()[:1000],
      'created_at':datetime.now(timezone.utc).isoformat(),'owner':owner}
    with connect() as db: db.execute('INSERT INTO cases(id,name,description,created_at,owner) VALUES (:id,:name,:description,:created_at,:owner)',case)
    return case


def get_case(case_id):
    with connect() as db:
        return rowdict(db.execute('SELECT * FROM cases WHERE id=?',(case_id,)).fetchone())


def list_cases(owner=None):
    with connect() as db:
        return [dict(x) for x in db.execute('''SELECT c.*, COUNT(DISTINCT cap.id) captures,
           (SELECT COUNT(*) FROM findings f WHERE f.case_id=c.id) findings
           FROM cases c LEFT JOIN captures cap ON cap.case_id=c.id
           WHERE (? IS NULL OR c.owner=?) GROUP BY c.id ORDER BY c.created_at DESC''',(owner,owner))]


def new_capture(case_id,filename,path,sha,size):
    obj=dict(id=str(uuid.uuid4()),case_id=case_id,filename=filename[:200],stored_path=str(path),
             sha256=sha,size=size,imported_at=datetime.now(timezone.utc).isoformat(),status='processing')
    with connect() as db:
        db.execute('''INSERT INTO captures(id,case_id,filename,stored_path,sha256,size,imported_at,status)
         VALUES (:id,:case_id,:filename,:stored_path,:sha256,:size,:imported_at,:status)''',obj)
    return obj

FIELDS=('case_id','capture_id','frame_no','ts','src','dst','proto','src_port','dst_port','length',
   'tcp_flags','dns_query','dns_qtype','dns_rcode','dns_response','dns_answers','tls_sni','http_host',
   'http_method','arp_ip','arp_mac','note')
INSERT='INSERT INTO packets('+','.join(FIELDS)+') VALUES ('+','.join('?' for _ in FIELDS)+')'

def add_packets(rows):
    with connect() as db: db.executemany(INSERT,rows)


def update_capture(capid,status,count,supported,first_ts,last_ts,error=''):
    with connect() as db:
        db.execute('''UPDATE captures SET status=?, frame_count=?,supported_frames=?,first_ts=?,last_ts=?,error=? WHERE id=?''',
        (status,count,supported,first_ts,last_ts,error[:1000],capid))


def list_captures(case_id):
    with connect() as db:
        return [dict(x) for x in db.execute('''SELECT id,filename,sha256,size,imported_at,status,
           frame_count,supported_frames,error,first_ts,last_ts FROM captures WHERE case_id=? ORDER BY imported_at DESC''',(case_id,))]


def get_capture(case_id,capid):
    with connect() as db:
        return rowdict(db.execute('SELECT * FROM captures WHERE case_id=? AND id=?',(case_id,capid)).fetchone())


def delete_capture(case_id,capid):
    cap=get_capture(case_id,capid)
    if not cap:return False
    with connect() as db:db.execute('DELETE FROM captures WHERE id=? AND case_id=?',(capid,case_id))
    try:Path(cap['stored_path']).unlink(missing_ok=True)
    except OSError:pass
    return True


def delete_case(case_id):
    caps=[]
    with connect() as db:
        caps=[x['stored_path'] for x in db.execute('SELECT stored_path FROM captures WHERE case_id=?',(case_id,))]
        cur=db.execute('DELETE FROM cases WHERE id=?',(case_id,))
    for c in caps:
        try:Path(c).unlink(missing_ok=True)
        except OSError: pass
    return cur.rowcount>0


def query_packets(case_id, limit=100,offset=0, ip='',proto='', search=''):
    q='SELECT id,capture_id,frame_no,ts,src,dst,proto,src_port,dst_port,length,tcp_flags,dns_query,dns_rcode,dns_answers,tls_sni,http_host,http_method,arp_ip,arp_mac,note FROM packets WHERE case_id=?'
    vals=[case_id]
    if ip: q+=' AND (src=? OR dst=?)'; vals.extend([ip,ip])
    if proto: q+=' AND proto=?';vals.append(proto.upper())
    if search:
        q+=' AND (src LIKE ? OR dst LIKE ? OR dns_query LIKE ? OR tls_sni LIKE ? OR http_host LIKE ?)'
        vals.extend([f'%{search[:120]}%']*5)
    q+=' ORDER BY ts,frame_no LIMIT ? OFFSET ?';vals.extend([limit,offset])
    with connect() as db:return [dict(r) for r in db.execute(q,vals)]


def get_packet(case_id, packet_id):
    with connect() as db:
        row=db.execute("""SELECT p.id,p.capture_id,p.frame_no,p.ts,p.src,p.dst,p.proto,
           p.src_port,p.dst_port,p.length,p.tcp_flags,p.dns_query,p.dns_rcode,p.dns_answers,
           p.tls_sni,p.http_host,p.http_method,p.arp_ip,p.arp_mac,p.note,
           c.filename,c.sha256 FROM packets p
           JOIN captures c ON p.capture_id=c.id WHERE p.case_id=? AND p.id=?""",
           (case_id,packet_id)).fetchone()
    return rowdict(row)


def list_findings(case_id):
    order="CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END"
    with connect() as db:
        rows=[dict(r) for r in db.execute(f'SELECT * FROM findings WHERE case_id=? ORDER BY {order},first_seen',(case_id,))]
    for r in rows:
        r['evidence']=json.loads(r['evidence']);r['indicators']=json.loads(r['indicators'])
    return rows


def get_finding(case_id,fid):
    with connect() as db:
        row=rowdict(db.execute('SELECT * FROM findings WHERE case_id=? AND id=?',(case_id,fid)).fetchone())
    if row:row['evidence']=json.loads(row['evidence']);row['indicators']=json.loads(row['indicators'])
    return row


def set_findings(case_id,findings):
    with connect() as db:
        db.execute('DELETE FROM findings WHERE case_id=?',(case_id,))
        db.executemany('''INSERT INTO findings(id,case_id,rule,title,severity,confidence,summary,recommendation,indicators,evidence,first_seen,last_seen)
          VALUES (:id,:case_id,:rule,:title,:severity,:confidence,:summary,:recommendation,:indicators,:evidence,:first_seen,:last_seen)''',[
            dict(f,indicators=json.dumps(f['indicators']),evidence=json.dumps(f['evidence'])) for f in findings])


def summary(case_id):
    with connect() as db:
        s=rowdict(db.execute('''SELECT count(*) packet_count, COALESCE(SUM(length),0) traffic_bytes,
          COUNT(DISTINCT CASE WHEN src<>'' THEN src END) src_hosts,
          MIN(NULLIF(ts,0)) first_ts,MAX(NULLIF(ts,0)) last_ts
          FROM packets WHERE case_id=?''',(case_id,)).fetchone())
        protocols=[dict(r) for r in db.execute('''SELECT proto as name,count(*) count, SUM(length) bytes FROM packets WHERE case_id=? GROUP BY proto ORDER BY count DESC''',(case_id,))]
        hosts=[dict(r) for r in db.execute('''SELECT src ip,COUNT(*) packets,SUM(length) bytes FROM packets
          WHERE case_id=? AND src<>'' GROUP BY src ORDER BY packets DESC LIMIT 25''',(case_id,))]
        findings=rowdict(db.execute('''SELECT COUNT(*) total,SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) high,
          SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) medium FROM findings WHERE case_id=?''',(case_id,)).fetchone())
        caps=rowdict(db.execute('''SELECT COUNT(*) total,COALESCE(SUM(frame_count),0) frames,
          SUM(CASE WHEN status IN ('partial','failed') THEN 1 ELSE 0 END) incomplete FROM captures WHERE case_id=?''',(case_id,)).fetchone())
    return {'stats':s,'protocols':protocols,'top_talkers':hosts,'findings':findings,'captures':caps}


def flows(case_id,limit=250, ip=''):
    where='WHERE case_id=? AND src<>\'\' AND dst<>\'\'';vals=[case_id]
    if ip: where+=' AND (src=? OR dst=?)';vals.extend([ip,ip])
    with connect() as db:
        return [dict(r) for r in db.execute(f'''SELECT src,dst,proto,src_port,dst_port, COUNT(*) packets,
           SUM(length) bytes,MIN(NULLIF(ts,0)) first_ts,MAX(NULLIF(ts,0)) last_ts,
           SUM(CASE WHEN tcp_flags LIKE '%S%' AND tcp_flags NOT LIKE '%A%' THEN 1 ELSE 0 END) syn_count,
           SUM(CASE WHEN tcp_flags LIKE '%R%' THEN 1 ELSE 0 END) resets
           FROM packets {where} GROUP BY src,dst,proto,src_port,dst_port ORDER BY bytes DESC LIMIT ?''',vals+[limit])]


def dns_stats(case_id,limit=250):
    with connect() as db:
        return [dict(r) for r in db.execute('''SELECT dns_query domain,COUNT(*) count,
           SUM(CASE WHEN dns_response=1 THEN 1 ELSE 0 END) responses,
           SUM(CASE WHEN dns_rcode=3 THEN 1 ELSE 0 END) nxdomain,
           MIN(NULLIF(ts,0)) first_ts FROM packets WHERE case_id=? AND dns_query<>''
           GROUP BY dns_query ORDER BY count DESC LIMIT ?''',(case_id,limit))]


def host_details(case_id,ip):
    with connect() as db:
        row=rowdict(db.execute('''SELECT COUNT(*) frames,SUM(length) bytes,
          MIN(NULLIF(ts,0)) first_ts,MAX(NULLIF(ts,0)) last_ts FROM packets
          WHERE case_id=? AND (src=? OR dst=?)''',(case_id,ip,ip)).fetchone())
        peers=[dict(x) for x in db.execute('''SELECT CASE WHEN src=? THEN dst ELSE src END peer,
             COUNT(*) packets,SUM(length) bytes FROM packets
             WHERE case_id=? AND (src=? OR dst=?) AND src<>dst
             GROUP BY peer ORDER BY packets DESC LIMIT 20''',(ip,case_id,ip,ip))]
        names=[dict(x) for x in db.execute('''SELECT DISTINCT dns_query name FROM packets
            WHERE case_id=? AND (src=? OR dst=?) AND dns_query<>'' LIMIT 25''',(case_id,ip,ip))]
    return {'ip':ip,**row,'peers':peers,'dns_queries':[x['name'] for x in names]}


def topology(case_id,limit=60):
    with connect() as db:
        nodes=[dict(r) for r in db.execute('''SELECT ip,SUM(count) packets,SUM(bytes) bytes FROM (
          SELECT src ip,COUNT(*) count,SUM(length) bytes FROM packets WHERE case_id=? AND src<>'' GROUP BY src
          UNION ALL SELECT dst ip,COUNT(*) count,SUM(length) bytes FROM packets WHERE case_id=? AND dst<>'' GROUP BY dst)
          GROUP BY ip ORDER BY packets DESC LIMIT ?''',(case_id,case_id,limit))]
        keep={x['ip'] for x in nodes}
        edges=[dict(r) for r in db.execute('''SELECT src,dst,COUNT(*) packets,SUM(length) bytes FROM packets
             WHERE case_id=? AND src<>'' AND dst<>'' AND src<>dst
             GROUP BY src,dst ORDER BY bytes DESC LIMIT 2000''',(case_id,))]
        flagged={x['ip'] for x in db.execute('''SELECT src ip FROM packets WHERE case_id=? AND dst_port IN (23,3389,445)
            GROUP BY src HAVING COUNT(*)>10''',(case_id,))}
    return {'nodes':[dict(n,flagged=n['ip'] in flagged) for n in nodes],
            'edges':[e for e in edges if e['src'] in keep and e['dst'] in keep][:180]}


def timeline(case_id,limit=160):
    out=[]
    for f in list_findings(case_id):
        out.append({'kind':'finding','id':f['id'],'ts':f['first_seen'],'title':f['title'],'severity':f['severity'],'subtitle':f['summary'][:180]})
    for c in list_captures(case_id):
        out.append({'kind':'capture','id':c['id'],'ts':c['first_ts'] or 0,'title':'Capture imported: '+c['filename'],'severity':'info','subtitle':f"{c['frame_count']} frames / {c['status']}"})
    return sorted(out,key=lambda x:x['ts'])[:limit]


def capture_path_exists(path):
    with connect() as db:
        return db.execute('SELECT 1 FROM captures WHERE stored_path=? LIMIT 1',(path,)).fetchone() is not None


def count_cases(owner=None):
    with connect() as db:
        return int(db.execute('SELECT COUNT(*) FROM cases WHERE (? IS NULL OR owner=?)',(owner,owner)).fetchone()[0])


def capture_usage(case_id,owner=None):
    """Aggregate quotas from persistent SQLite data, not client-supplied counters."""
    with connect() as db:
        case_captures=db.execute('SELECT COUNT(*) FROM captures WHERE case_id=?',(case_id,)).fetchone()[0]
        owner_bytes=db.execute("""SELECT COALESCE(SUM(cap.size),0) FROM captures cap JOIN cases c ON cap.case_id=c.id
                     WHERE (? IS NULL OR c.owner=?)""",(owner,owner)).fetchone()[0]
        total_bytes=db.execute('SELECT COALESCE(SUM(size),0) FROM captures').fetchone()[0]
    return {'case_captures':case_captures,'owner_bytes':owner_bytes,'total_bytes':total_bytes}


def dhcp_stats(case_id):
    with connect() as db:
        return [dict(row) for row in db.execute('''SELECT note AS event,COUNT(*) AS packets,
               MIN(NULLIF(ts,0)) AS first_ts FROM packets
               WHERE case_id=? AND note LIKE 'DHCP %'
               GROUP BY note ORDER BY first_ts''',(case_id,))]
