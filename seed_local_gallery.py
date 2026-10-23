"""Seed synthetic public gallery cases on localhost without altering saved investigations."""
import hashlib, os, secrets
from blackbox import storage
from blackbox.main import LAB_CASES, ROOT, MAX_UPLOAD, _parse_and_store
if os.environ.get('BLACKBOX_DEPLOY_MODE') != 'local-hybrid':
    raise SystemExit('This demo setup is intended only for local-hybrid mode')
storage.init_db()
for name, description, filename in LAB_CASES:
    if any(c['name']==name for c in storage.list_cases('public-demo')):
        print('Demo already available:', name)
        continue
    source=ROOT/'samples'/'demo_pcaps'/filename
    data=source.read_bytes()
    if len(data)>MAX_UPLOAD:raise SystemExit('Bundled demo capture exceeds the limit')
    case=storage.create_case(name,description,'public-demo')
    tmp=storage.CAPTURES/(secrets.token_hex(20)+'.capture')
    try:
        tmp.write_bytes(data)
        _parse_and_store(case['id'],filename,tmp,hashlib.sha256(data).hexdigest(),len(data))
        print('Ready:',name)
    except Exception:
        storage.delete_case(case['id'])
        raise
    finally:
        if tmp.exists() and not storage.capture_path_exists(str(tmp)):
            tmp.unlink(missing_ok=True)
print('Public demo cases ready; existing cases preserved.')
