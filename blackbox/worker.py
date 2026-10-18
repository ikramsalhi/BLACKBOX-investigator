"""Parse an uploaded capture outside the API process (no shell execution)."""
from __future__ import annotations
import sys,json,os

def restrict_resources():
    if os.name != 'posix':
        return  # On Windows the subprocess timeout still applies; OS quotas require a Job Object.
    import resource
    max_ram=int(os.environ.get('BLACKBOX_WORKER_MEMORY_MB','768'))*1024*1024
    cpu=int(os.environ.get('BLACKBOX_WORKER_CPU_SECONDS','90'))
    resource.setrlimit(resource.RLIMIT_AS,(max_ram,max_ram))
    resource.setrlimit(resource.RLIMIT_CPU,(cpu,cpu))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))

def main():
    restrict_resources()
    from .main import _parse_and_store
    cid,filename,path,digest,size=sys.argv[1:6]
    try:
        result=_parse_and_store(cid,filename,__import__('pathlib').Path(path),digest,int(size))
    except Exception as exc:
        from fastapi import HTTPException
        if isinstance(exc,HTTPException):
            result={'error':exc.detail,'status':exc.status_code}
        else:
            result={'error':'Unable to process capture securely','status':422}
    print(json.dumps(result,ensure_ascii=True,default=str))

if __name__=='__main__':main()
