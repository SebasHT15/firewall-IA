"""Audited Flask static-handler policy for the pinned six lab apps.

This is a new app-bound policy, not a change to fast-path-policy/v1 semantics.
Exact public assets and audited constant GET documents, bound to source and image.
Header enums plus explicit v2 syntax profiles. Unknown inputs continue to V5.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import adapters

CONTRACT = 'sec-challenges-public-resource/v3'
# These six audited entry points all instantiate Flask(__name__) with default static handler;
# none registers before/after request hooks, custom static views or global session/auth middleware.
ENTRY = {'An0nB0ard':'blog.py','CatP1cs':'challenge/mycats.py',
         'Inf3ct':'challenge/infect.py','ObC00ki3s':'server.py',
         'D33pTh0ught':'D33p.py','ag3ncy':'agency.py'}
BROWSER_UA = tuple(dict.fromkeys(
    [f'Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{n}.0.0.0 Safari/537.36'
     for platform in ('X11; Linux x86_64','Windows NT 10.0; Win64; x64','Macintosh; Intel Mac OS X 10_15_7') for n in range(120,151)] +
    [f'Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{n}.0 Safari/537.36'
     for platform in ('X11; Linux x86_64','Windows NT 10.0; Win64; x64','Macintosh; Intel Mac OS X 10_15_7') for n in range(120,151)] +
    [f'Mozilla/5.0 ({platform}; rv:{n}.0) Gecko/20100101 Firefox/{n}.0'
     for platform in ('X11; Linux x86_64','X11; Ubuntu; Linux x86_64','Windows NT 10.0; Win64; x64','Macintosh; Intel Mac OS X 10.15') for n in range(115,151)] +
    [f'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{major}.{minor} Safari/605.1.15'
     for major in range(16,20) for minor in range(7)] +
    [f'curl/8.{minor}.{patch}' for minor in range(16) for patch in range(3)] +
    [f'python-requests/2.{minor}.{patch}' for minor in range(28,34) for patch in range(7)] + ['fwlab-agent/2.0']))

def enum(values): return {'type':'enum','values':list(dict.fromkeys(values))}

def source_identity(app, apps_root=None):
    root=Path(apps_root or adapters.DEFAULT_APPS_ROOT).resolve()
    ad=adapters.ADAPTERS[app];rel=Path(adapters.WEB_SUBDIR)/ad['source_subdir']
    commit=subprocess.run(['git','-C',str(root),'rev-parse','HEAD'],capture_output=True,text=True,check=True).stdout.strip()
    if commit!=adapters.PINNED_APPS_COMMIT: raise ValueError('static contract app commit mismatch')
    dirty=subprocess.run(['git','-C',str(root),'status','--porcelain','--untracked-files=all','--',str(rel)],capture_output=True,text=True,check=True).stdout
    if dirty: raise ValueError('static contract refuses changed/untracked app sources')
    raw=subprocess.run(['git','-C',str(root),'ls-files','-z','--',str(rel)],capture_output=True,check=True).stdout
    names=[x.decode('utf-8')for x in raw.split(b'\0')if x]
    files={}
    for n in sorted(names):
        p=root/n
        if p.is_symlink() or not p.is_file(): raise ValueError('app source must be regular tracked files')
        files[n]=hashlib.sha256(p.read_bytes()).hexdigest()
    digest=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return root/rel,digest,files


def contract_ref(app, apps_root=None, image_id=None):
    _,digest,_=source_identity(app,apps_root)
    if not isinstance(image_id,str) or not image_id.startswith('sha256:') or len(image_id) != 71 or any(c not in '0123456789abcdef' for c in image_id[7:]):
        raise ValueError('contract requires full image SHA256')
    return f'{CONTRACT}:{adapters.PINNED_APPS_COMMIT}:{app}:{digest}:{image_id}'


def static_assets(app,apps_root=None):
    source,digest,files=source_identity(app,apps_root)
    entry=source/ENTRY[app];base=entry.parent/'static'
    result=[]
    for p in sorted(base.rglob('*')):
        if p.is_file():
            rel=p.relative_to(base).as_posix()
            if any(not all(c.isalnum()and c.isascii() or c in '-._~' for c in s) or s in ('.','..') for s in rel.split('/')):
                continue
            if p.is_symlink(): raise ValueError('symlink not allowed in static contract')
            # Every asset must itself occur in the tracked source identity.
            if not any((Path(adapters.DEFAULT_APPS_ROOT if apps_root is None else apps_root)/n).resolve()==p.resolve()for n in files):
                raise ValueError('untracked static asset')
            result.append('/static/'+rel)
    if not result:raise ValueError('static contract has no eligible tracked assets')
    return result


def policy(app,apps_root=None):
    ad=adapters.ADAPTERS[app];host=ad['hostname']
    paths=sorted({path.split('?')[0] for _,path,_,_ in ad['routes']
                  if '*'not in path and '<'not in path} | {'/'})
    queries={p:kind for p,kind in (('/post','uint-id'),('/show','basename-img')) if p in paths}
    ref_grammar={'type':'public_referer','origins':[f'https://{host}',f'https://{host}:8443'],
                 'paths':paths,'queries':queries,'relative_root':True}
    headers={
        'host':enum((host,host+':8443')),
        'user-agent':enum(BROWSER_UA),
        'accept':enum(('*/*','text/css,*/*;q=0.1','image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
                       'image/avif,image/webp,*/*','image/webp,image/apng,image/*,*/*;q=0.8',
                       'image/webp,image/avif,image/jxl,image/heic,image/heic-sequence,video/*;q=0.8,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5','image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5',
                       'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                       'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                       'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7')),
        'accept-language':{'type':'language_preferences'},
        'accept-encoding':enum(('gzip, deflate, br','gzip, deflate','gzip, deflate, br, zstd','identity')),
        'referer':ref_grammar,
        'origin':enum((f'https://{host}:8443',f'https://{host}')),
        'sec-fetch-site':enum(('same-origin','same-site','none')),
        'sec-fetch-mode':enum(('no-cors','cors','navigate','same-origin')),
        'sec-fetch-dest':enum(('image','style','script','font','empty','document')),
        'cache-control':enum(('no-cache','max-age=0')),
        'pragma':enum(('no-cache',)),
        'dnt':enum(('0','1')),
        'upgrade-insecure-requests':enum(('1',)),
        'sec-fetch-user':enum(('?1',)),
        'sec-ch-ua':{'type':'client_hints'},
        'sec-ch-ua-mobile':enum(('?0','?1')),
        'sec-ch-ua-platform':enum(('"Linux"','"Windows"','"macOS"')),
        'priority':enum(tuple(f'u={n}{suffix}' for n in range(8) for suffix in ('',', i'))),

    }
    doc = {'schema':'fast-path-policy/v2','policy_id':f'sec-challenges-{app}-public-v3',
            'status':'PROPOSED','canonical_contract':'canonical-request/v1','http_versions':['HTTP/1.1'],
            'rules':[{'id':f'static-{i:03d}','methods':['GET','HEAD'],'path':asset.strip('/').split('/'),
                      'query':{},'required_query':[],'headers':headers,'required_headers':['host']}for i,asset in enumerate(static_assets(app,apps_root))]}
    # Every audited home GET is constant, without request inputs, auth, hooks
    # or state reads. POST on the same URL is NEVER eligible.
    for path in (('/', '/register') if app == 'An0nB0ard' else ('/',)):
        doc['rules'].append({'id':'constant-home' if path=='/' else 'constant-register',
                            'methods':['GET'],'path':path.strip('/').split('/') if path!='/' else [],
                            'query':{},'required_query':[], 'headers':dict(headers),'required_headers':['host']})
    # A single, audited unregistered path returns the constant Werkzeug 404.
    # This does NOT allow arbitrary unknown URLs, nor bypass status-based checks.
    doc['rules'].append({'id':'constant-favicon-404','methods':['GET'],'path':['favicon.ico'],
                         'query':{},'required_query':[],'headers':dict(headers),'required_headers':['host']})
    # Conditional GET chooses 200/304 on the same public bytes, without state.
    for rule in doc['rules']:
        rule['headers']=dict(headers)
        if rule['id'].startswith('static-'):
            rule['headers'].update({'if-none-match':{'type':'entity_tag'},'if-modified-since':{'type':'http_date'}})
        if app=='ObC00ki3s':
            rule['headers']['cookie']={'type':'question_cookie'}
    if app == 'CatP1cs':
        # Audited /show handler joins exactly static/img/<img>. A finite list of
        # tracked basenames gives the same public-resource contract, not an open
        # path parameter or an exemption for anything ending in an image suffix.
        images=[p.rsplit('/',1)[1]for p in static_assets(app,apps_root)if p.startswith('/static/img/')]
        doc['rules'].append({'id':'public-cat-image','methods':['GET','HEAD'],'path':['show'],
                             'query':{'img':enum(images)},'required_query':['img'],
                             'headers':dict(headers),'required_headers':['host']})
    return doc
