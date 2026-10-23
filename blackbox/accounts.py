"""Per-user HTTP Basic accounts; salted scrypt password hashes stored in private data volume."""
import os,json,hashlib,hmac,re,secrets,threading
from pathlib import Path
from . import storage

def location():return storage.DATA/'users.json'

def accounts():
    path=location()
    return json.loads(path.read_text()) if path.exists() else {}

_registration_lock=threading.Lock()

def add(username,password,first_account_only=False):
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{3,48}',username):raise ValueError('Username must be 3-48 safe characters')
    if len(password)<16:raise ValueError('Password must be at least 16 characters')
    with _registration_lock:
        users=accounts()
        if first_account_only and users:raise ValueError('First account setup is already complete; please sign in')
        if username in users:raise ValueError('User already exists')
        salt=secrets.token_bytes(16)
        users[username]={'salt':salt.hex(),'hash':hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1).hex()}
        location().parent.mkdir(parents=True,exist_ok=True)
        temporary=location().with_suffix('.tmp')
        with open(temporary,'w') as f:
            os.chmod(temporary,0o600);json.dump(users,f)
        os.replace(temporary,location())

def verify(username,password):
    entry=accounts().get(username)
    if not entry:return False
    try:
        digest=hashlib.scrypt(password.encode(),salt=bytes.fromhex(entry['salt']),n=2**14,r=8,p=1)
        return hmac.compare_digest(digest,bytes.fromhex(entry['hash']))
    except (ValueError,KeyError):return False


# Browser sessions: randomly generated bearer tokens; only SHA-256 digests are
# persisted. The browser cookie is HttpOnly + Secure on hosted HTTPS deployments.
import sqlite3,time
from contextlib import contextmanager
SESSION_LIFETIME_SECONDS = 12 * 60 * 60
SESSION_COOKIE = 'bb_session'

@contextmanager
def _auth_db():
    storage.DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn=sqlite3.connect(str(storage.DATA / 'auth.sqlite3'), timeout=15)
    conn.row_factory=sqlite3.Row
    conn.execute('CREATE TABLE IF NOT EXISTS sessions (digest TEXT PRIMARY KEY, username TEXT NOT NULL, csrf TEXT NOT NULL, expires_at INTEGER NOT NULL)')
    conn.execute('CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at)')
    try:
        with conn:
            yield conn
    finally:
        conn.close()

def create_session(username):
    token=secrets.token_urlsafe(32)
    csrf=secrets.token_urlsafe(32)
    expiry=int(time.time())+SESSION_LIFETIME_SECONDS
    with _auth_db() as con:
        con.execute('DELETE FROM sessions WHERE expires_at < ?', (int(time.time()),))
        con.execute('INSERT INTO sessions(digest,username,csrf,expires_at) VALUES(?,?,?,?)',
                    (hashlib.sha256(token.encode()).hexdigest(),username,csrf,expiry))
    return token, csrf

def get_session(token):
    if not token or len(token)>256:return None
    digest=hashlib.sha256(token.encode()).hexdigest()
    with _auth_db() as con:
        row=con.execute('SELECT username,csrf FROM sessions WHERE digest=? AND expires_at>?',
                        (digest,int(time.time()))).fetchone()
    return dict(row) if row else None

def revoke_session(token):
    if not token:return
    with _auth_db() as con:
        con.execute('DELETE FROM sessions WHERE digest=?', (hashlib.sha256(token.encode()).hexdigest(),))
