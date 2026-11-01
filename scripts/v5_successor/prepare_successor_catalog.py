"""Author URL templates and apply the unchanged structural near-duplicate audit."""
import argparse,copy,hashlib,json,sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[2];sys.path.insert(0,str(REPO/'scripts/dataset'))
import v5_catalog as K
OUT=REPO/'reports/v5/successor-2026-10-30/catalog'

def slot(kind,**kw):return dict(type=kind,names=K.NAMES_FOR_TYPE[kind],**kw)

def expanded_definitions():
    """Typed request shapes, not additional independent attack sources."""
    query=[
        ('image-preview','GET',['pictures','proxy','preview'],['int','url']),
        ('feed-refresh','DELETE',['syndication','refresh','pending'],['bool','url','int']),
        ('document-source','GET',['documents','ingest','source'],['url','token','number']),
        ('avatar-origin','GET',['avatars','import','origin'],['token','url','bool']),
        ('translation-resource','DELETE',['translations','fetch','resource'],['number','int','url']),
        ('archive-location','GET',['archives','remote','location'],['url','bool','token','int']),
        ('link-inspection','GET',['links','security','inspection'],['bool','url','number','token']),
        ('calendar-fetch','DELETE',['calendars','sync','fetch'],['int','token','url','bool']),
        ('video-cover','GET',['videos','poster','cover'],['url','number','bool','int','token']),
        ('document-link','GET',['attachments','resolve','link'],['token','int','bool','url','number']),
    ]
    form=[
        ('capture-resource','POST',['screenshots','capture','resource'],['int','url']),
        ('import-address','PUT',['inventories','batch','address'],['bool','url','int']),
        ('notify-endpoint','PATCH',['notifications','transport','endpoint'],['token','url','number']),
        ('syndicate-content','POST',['articles','syndicate','content'],['number','int','url']),
        ('verify-callback','PUT',['callbacks','verify','destination'],['url','bool','token']),
        ('mirror-package','PATCH',['packages','mirror','registry'],['url','number','bool','int']),
        ('fetch-transcript','POST',['transcripts','download','asset'],['bool','url','token','number']),
        ('subscribe-stream','PUT',['streams','subscribe','channel'],['int','token','url','bool']),
        ('render-page','PATCH',['pages','render','snapshot'],['number','url','int','bool','token']),
        ('attach-source','POST',['records','attach','source'],['token','int','bool','url','number']),
    ]
    json_defs=[
        ('embed-image','POST',['embeds','images','submit'],['int','url']),
        ('import-table','PUT',['tables','transfer','import'],['bool','url','int']),
        ('check-webhook','PATCH',['webhooks','destinations','check'],['token','url','number']),
        ('refresh-index','POST',['indexes','content','refresh'],['number','int','url']),
        ('configure-feed','PUT',['feeds','polling','settings'],['url','bool','token']),
        ('schedule-capture','PATCH',['captures','schedule','entry'],['url','number','bool','int']),
        ('register-asset','POST',['assets','registry','entry'],['bool','url','token','number']),
        ('update-origin','PUT',['origins','routing','update'],['int','token','url','bool']),
        ('create-render-job','PATCH',['renderers','queue','job'],['number','url','int','bool','token']),
        ('resolve-remote-data','POST',['datasets','remote','resolve'],['token','int','bool','url','number']),
    ]
    defs=[]
    for carrier,items in [('query',query),('form',form),('json',json_defs)]:
        for name,method,path,kinds in items:
            fields=[slot(kind) for kind in kinds]
            defs.append((name,carrier,method,path,{'object':fields} if carrier=='json' else fields))
    return defs

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--expanded',action='store_true');args=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    original=json.loads((REPO/'scripts/dataset/v5_templates/catalog_v1.json').read_text())
    defs=[
      ('remote-thumbnail','query','GET',['resolver','v2','thumbnail'],[slot('url'),slot('int')]),
      ('feed-inspection','query','GET',['integrations','feeds','inspect'],[slot('url'),slot('bool')]),
      ('source-task','query','DELETE',['jobs','imports','source'],[slot('url'),slot('token')]),
      ('remote-media','form','POST',['media','remote','retrieve'],[slot('url'),slot('int'),slot('bool')]),
      ('catalog-connect','form','PUT',['connectors','catalog','register'],[slot('url'),slot('number')]),
      ('channel-address','form','PATCH',['subscriptions','channel','configure'],[slot('url'),slot('token')]),
      ('asset-inspection','json','POST',['rendering','assets','inspect'],{'object':[slot('url'),slot('bool')]}),
      ('automation-hook','json','PUT',['automations','tasks','register'],{'object':[{'names':'object','object':[slot('url'),slot('token')]}]}),
      ('export-target','json','PATCH',['reports','export','schedule'],{'object':[slot('int'),{'names':'object','object':[slot('url'),slot('number'),slot('bool')]}]}),
    ]
    if args.expanded:defs+=expanded_definitions()
    new=[]
    for name,carrier,method,path,body in defs:
        template=dict(name='v51-'+name,cluster='v51-'+name,carrier=carrier,method=method,path=path)
        template['json' if carrier=='json' else 'fields']=body;new.append(template)
    candidate=copy.deepcopy(original);candidate.update(status='PROPOSED_SUCCESSOR_NOT_OWNER_RATIFIED',note=f'Original templates preserved; {len(new)} new typed URL structures for source-independent successor splits. Structures do not count as independent attack sources. No field-name-based label rule added.');candidate['templates']+=new
    suffix='-expanded' if args.expanded else ''
    path=OUT/f'catalog-v51{suffix}.DRAFT.json'
    if path.exists():raise RuntimeError('Do not overwrite a previous catalog proposal')
    path.write_text(json.dumps(candidate,indent=2)+'\n')
    catalog=K.load_catalog(str(path));report=K.audit(catalog);report.update(status='STRUCTURAL_AUDIT_PASS_PROPOSAL' if report['ok'] else 'BLOCKED',new_templates=len(new),original_templates=len(original['templates']),new_template_names=[x['name'] for x in new],old_catalog_sha256=hashlib.sha256((REPO/'scripts/dataset/v5_templates/catalog_v1.json').read_bytes()).hexdigest(),training_authorized=False)
    (OUT/f'structural_audit{suffix}.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ['status','new_templates','original_templates','findings','strata']},indent=2))
if __name__=='__main__':main()
