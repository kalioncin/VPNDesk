from __future__ import annotations
import json
from pathlib import Path

DEFAULTS = {
  'theme':'dark','language':'ru','watch_enabled':False,'watch_folders':[],
  'schedule_enabled':False,'schedule_minutes':240,'startup_prompted':False,
  'tray_enabled':True,'auto_load':True,'max_workers':32,'tcp_timeout':4.0,
  'max_file_mb':512,'max_archive_unpacked_mb':1024,'github_auto':True,
  'github_repo':'','github_branch':'main','github_path':'reports/vpndesk-stats.json',
  'source_timeout':12,'source_max_mb':32,'recheck_hours':12,
  'energy_saving_enabled':False,'energy_check_limit':300,'energy_timeout':1.5,
  'portable_mode':False,'hardware_profile':{},
  'auto_shutdown_enabled':False,'auto_shutdown_time':'00:00',
  'maintenance_enabled':False,'maintenance_interval_days':7,'last_maintenance':'',
  'singbox_path':'','onboarding_completed':False,'performance_plan':'','protocol_timeout':10.0,
}
class Settings:
    def __init__(self, path: Path):
        self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True)
        self.data=dict(DEFAULTS)
        if self.path.exists():
            try:
                loaded=json.loads(self.path.read_text('utf-8'))
                if isinstance(loaded,dict): self.data.update({k:v for k,v in loaded.items() if k in DEFAULTS})
            except (OSError,json.JSONDecodeError): pass
    def save(self):
        tmp=self.path.with_suffix('.tmp')
        tmp.write_text(json.dumps(self.data,ensure_ascii=False,indent=2),encoding='utf-8')
        tmp.replace(self.path)
    def reset(self):
        self.data=dict(DEFAULTS); self.save()
