#!/usr/bin/env python3
"""Retain build inputs locally and check restoration byte-for-byte. No build/train."""
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

REPO=Path(__file__).resolve().parents[3]
OUT=REPO/'datasets/v5_sources/freeze_input_retention_2026-10-26'
REPORT=Path(__file__).with_name('external-input-retention.json')
SOURCES={
 'pilot-pools':Path('/home/sebas/Documents/Codex/2026-10-22/firewall-c1-model2-continuidad/work/pilot-integration-007/pools'),
 'benign-pools':REPO/'datasets/v5_sources/benign',
 'assembled-attack':REPO/'datasets/v5_sources/final_candidate/attack_pool.jsonl',
 'original-audit-pool':REPO/'datasets/v5_sources/attack',
 'patt-license':REPO/'reports/v5/dataset-preregistration-v1/final-run-2026-10-25-v3/PATT_LICENSE.txt',
}

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1<<20),b''):h.update(chunk)
    return h.hexdigest()


def main():
    OUT.mkdir(exist_ok=False)
    archive=OUT/'inputs.tar.gz';inventory=[]
    with tarfile.open(archive,'w:gz') as tar:
        for label,source in SOURCES.items():
            files=sorted(p for p in source.rglob('*') if p.is_file()) if source.is_dir() else [source]
            for p in files:
                if p.is_symlink():raise ValueError('source symlink refused')
                rel=str(Path(label)/(p.relative_to(source) if source.is_dir() else p.name))
                inventory.append({'member':rel,'source':str(p),'sha256':sha(p),'bytes':p.stat().st_size})
                tar.add(p,arcname=rel,recursive=False)
    restored=0
    with tempfile.TemporaryDirectory(prefix='firewall-input-restore-') as tmp:
        with tarfile.open(archive,'r:gz') as tar:tar.extractall(tmp,filter='data')
        for item in inventory:
            p=Path(tmp)/item['member']
            if sha(p)!=item['sha256'] or p.stat().st_size!=item['bytes']:raise ValueError('recovery differs')
            restored+=1
    python=Path('/usr/bin/python3').resolve()
    report={'schema':'v5-external-input-retention/v1','archive':str(archive),'archive_sha256':sha(archive),
      'archive_bytes':archive.stat().st_size,'files':inventory,'recovery_files_verified':restored,
      'recovery_pass':True,'recovery_method':'temporary extraction + SHA-256 and size of every member; no regeneration',
      'python':{'path':str(python),'sha256':sha(python),'version':subprocess.check_output([str(python),'--version'],text=True).strip()},
      'patt_source':{'repository':'https://github.com/swisskyrepo/PayloadsAllTheThings.git','commit':'e961fef231d8327bae83b563fab50aec2e6b77c0'},
      'limitations':['Local retained archive on the same machine; independent off-device backup is not verified.',
                     'Recovery verifies source bytes, not a new A2 build. A2 remains the already accredited run.',
                     'Python binary identified; no claim of a self-contained portable interpreter image.',
                     'No redistribution of third-party data. CSIC is not included.']}
    REPORT.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'archive':str(archive),'files':restored,'recovery_pass':True,'bytes':archive.stat().st_size}))


if __name__=='__main__':main()
