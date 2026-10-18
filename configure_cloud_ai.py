"""Interactive secret-safe setup, keeps API key out of browser and source code."""
from pathlib import Path
from getpass import getpass
import os

HERE=Path(__file__).resolve().parent
MODELS={'groq':'llama-3.3-70b-versatile','gemini':'gemini-2.5-flash','openai':'gpt-4.1-mini','deepseek':'deepseek-flash'}
print('\nBLACKBOX — Cloud AI configuration (no Ollama needed)\n')
print('Choose provider: 1 Groq, 2 Gemini, 3 OpenAI, 4 DeepSeek')
choice=input('Provider [1/2/3/4]: ').strip()
provider={'1':'groq','2':'gemini','3':'openai','4':'deepseek'}.get(choice)
if not provider:
    print('Invalid provider. Nothing changed.');raise SystemExit(1)
key=getpass('Paste API key (hidden while typing): ').strip()
if not key or '\n' in key or '\r' in key:
    print('Invalid API key. Nothing changed.');raise SystemExit(1)
print('Recommended default model:',MODELS[provider])
model=input('Model [press Enter to use default]: ').strip() or MODELS[provider]
if len(model)>110 or any(c in model for c in ('\r','\n','"')):
    print('Invalid model name. Nothing changed.');raise SystemExit(1)
config=f'BLACKBOX_CLOUD_PROVIDER={provider}\nBLACKBOX_CLOUD_API_KEY={key}\nBLACKBOX_CLOUD_MODEL={model}\n'
path=HERE/'.env'
path.write_text(config,encoding='utf-8')
try:os.chmod(path,0o600)
except OSError:pass
print('\nSaved private configuration to .env (git-ignored).')
print('Restart BLACKBOX, open Investigator, choose Cloud AI.')
print('NOTE: Only use the cloud model with traffic you are authorized to share with the provider.')
