"""Launch local BLACKBOX; do not expose to the public internet without hardening."""
import uvicorn
if __name__=='__main__':
    print('BLACKBOX Investigator: http://127.0.0.1:8765')
    uvicorn.run('blackbox.main:app',host='127.0.0.1',port=8765,reload=False)
