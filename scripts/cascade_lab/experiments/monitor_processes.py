"""Low-frequency read-only process sampling for the live lab only."""
import psutil,time,json,sys
from pathlib import Path
root=psutil.Process(int(sys.argv[1]));out=Path(sys.argv[2]);known={}
with out.open('w') as f:
    while root.is_running() and root.status()!=psutil.STATUS_ZOMBIE:
        now=time.time();rows=[]
        try:children=root.children(recursive=True)
        except psutil.Error:break
        for proc in children:
            try:
                p=known.setdefault(proc.pid,proc);first=not hasattr(p,'_lab_seen');cpu=p.cpu_percent(None);p._lab_seen=True
                rows.append(dict(pid=p.pid,command=p.cmdline(),rss_bytes=p.memory_info().rss,cpu_percent_one_core_100=cpu,cpu_first_sample_unprimed=first,threads=p.num_threads(),file_descriptors=p.num_fds()))
            except psutil.Error:continue
        f.write(json.dumps({'utc':now,'processes':rows})+'\n');f.flush();time.sleep(1)
