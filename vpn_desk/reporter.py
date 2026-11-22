from __future__ import annotations
import json, urllib.request, base64
from datetime import datetime, timezone

def sanitized_report(stats):
    # Deliberately excludes configuration URIs, hosts, tokens, and source URLs.
    return {'generated_at':datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'application':'VPNDesk','schema_version':1,'statistics':{k:int(v) for k,v in stats.items()}}

def publish_github(settings, stats):
    repo=(settings.get('github_repo') or '').strip(); token=(settings.get('github_token') or '').strip()
    if not repo or not token: return False,'GitHub не настроен: укажите репозиторий и токен в настройках.'
    if '/' not in repo or len(repo.split('/'))!=2: return False,'Репозиторий должен иметь вид owner/repository.'
    owner,name=repo.split('/',1); branch=settings.get('github_branch') or 'main'; path=settings.get('github_path') or 'reports/vpndesk-stats.json'
    api=f'https://api.github.com/repos/{owner}/{name}/contents/{path}'
    body=json.dumps(sanitized_report(stats),ensure_ascii=False,indent=2).encode()
    # Get existing SHA for update.
    sha=None
    try:
        req=urllib.request.Request(api+f'?ref={branch}',headers={'Authorization':f'Bearer {token}','Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        with urllib.request.urlopen(req,timeout=15) as r: sha=json.loads(r.read()).get('sha')
    except Exception: pass
    payload={'message':'Update VPNDesk sanitized statistics','content':base64.b64encode(body).decode(),'branch':branch}
    if sha: payload['sha']=sha
    req=urllib.request.Request(api,data=json.dumps(payload).encode(),method='PUT',headers={'Authorization':f'Bearer {token}','Accept':'application/vnd.github+json','Content-Type':'application/json','X-GitHub-Api-Version':'2022-11-28'})
    try:
        with urllib.request.urlopen(req,timeout=20) as r: return 200 <= r.status < 300, f'GitHub HTTP {r.status}'
    except Exception as exc: return False,f'Не удалось опубликовать отчёт: {exc}'
