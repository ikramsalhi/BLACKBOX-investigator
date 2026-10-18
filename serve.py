"""ASGI entrypoint for container reverse proxy; do not directly publish port 8000."""
import uvicorn
if __name__=='__main__':
    uvicorn.run('blackbox.main:app', host='0.0.0.0',port=8000,proxy_headers=True,forwarded_allow_ips='127.0.0.1')
