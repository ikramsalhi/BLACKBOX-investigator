"""Prepare TWO generated synthetic demonstrations for a public READ-ONLY investigation gallery.
Only run in an isolated, newly initialized BLACKBOX_DATA_DIR, then switch to
BLACKBOX_DEPLOY_MODE=public-demo. Do NOT point at private evidence databases.
"""
import os
if os.environ.get('BLACKBOX_DEPLOY_MODE','local')!='local':
    raise SystemExit('Seed with BLACKBOX_DEPLOY_MODE=local; restart in public-demo.')
from fastapi.testclient import TestClient
from blackbox.main import app
from blackbox import storage
if storage.list_cases():raise SystemExit('Refusing to seed a nonempty database')
with TestClient(app) as client:
    response=client.post('/api/demo')
    response.raise_for_status()
    ids=[r['id'] for r in storage.list_cases()]
    assert len(ids)==2,ids
    with storage.connect() as db:
        for cid in ids:db.execute("UPDATE cases SET owner='public-demo' WHERE id=?",(cid,))
    for x in storage.list_cases('public-demo'):
        print(x['name'], x['id'], storage.summary(x['id'])['stats']['packet_count'],'frames')
print('Published read-only synthetic cases; no real attacks or third-party captures included.')
