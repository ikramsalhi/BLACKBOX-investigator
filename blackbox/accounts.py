"""Per-user HTTP Basic accounts; salted scrypt password hashes stored in private data volume."""
import os,json,hashlib,hmac,re,secrets
from pathlib import Path
from . import storage

def location():return storage.DATA/'users.json'

def accounts():
    path=location()
    return json.loads(path.read_text()) if path.exists() else {}

def add(username,password):
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{3,48}',username):raise ValueError('Username must be 3-48 safe characters')
    if len(password)<16:raise ValueError('Password must be at least 16 characters')
    users=accounts()
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
