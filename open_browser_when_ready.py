"""Wait until BLACKBOX is reachable, then open the web browser."""
import time,urllib.request,webbrowser
URL='http://127.0.0.1:8765'
for _ in range(120):
    try:
        with urllib.request.urlopen(URL+'/api/health',timeout=1) as response:
            if response.status==200:
                webbrowser.open(URL,new=2)
                break
    except (OSError,ValueError):
        time.sleep(.5)
