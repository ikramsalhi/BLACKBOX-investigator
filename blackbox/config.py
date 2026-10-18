"""Load private cloud AI settings from a local, git-ignored .env file.

Explicit process environment variables take precedence. Never expose the API key
through any API response or log. Only known provider URLs are supported.
"""
from pathlib import Path
import os

ROOT = Path(__file__).resolve().parent.parent


def load_private_env():
    if os.environ.get('BLACKBOX_PARSER_WORKER')=='1': return
    path = ROOT / '.env'
    if not path.exists():
        return
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        line=line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k,v=line.split('=',1)
        k=k.strip()
        if k not in {'BLACKBOX_CLOUD_PROVIDER','BLACKBOX_CLOUD_API_KEY','BLACKBOX_CLOUD_MODEL'}:
            continue
        v=v.strip().strip('"').strip("'")
        os.environ.setdefault(k,v)

load_private_env()

PROVIDERS={
    'groq': ('https://api.groq.com/openai/v1/chat/completions','llama-3.3-70b-versatile'),
    'gemini': ('https://generativelanguage.googleapis.com/v1beta/openai/chat/completions','gemini-2.5-flash'),
    'openai': ('https://api.openai.com/v1/chat/completions','gpt-4.1-mini'),
    'deepseek': ('https://api.deepseek.com/chat/completions','deepseek-flash'),
}


def cloud_settings():
    provider=os.environ.get('BLACKBOX_CLOUD_PROVIDER','').strip().lower()
    key=os.environ.get('BLACKBOX_CLOUD_API_KEY','').strip()
    if provider not in PROVIDERS or not key:
        return None
    url,default_model=PROVIDERS[provider]
    model=os.environ.get('BLACKBOX_CLOUD_MODEL','').strip() or default_model
    if len(model)>110 or any(c in model for c in '\r\n'):
        raise ValueError('Invalid cloud AI model name')
    return {'provider':provider,'model':model,'url':url,'key':key}


def safe_cloud_status():
    settings=cloud_settings()
    return {'configured':bool(settings),'provider':settings['provider'] if settings else None,
            'model':settings['model'] if settings else None}
