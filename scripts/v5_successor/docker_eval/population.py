"""Own synthetic application traffic, declared before measuring any candidate."""
import hashlib
import json
import random
import urllib.parse as U

SEED = 20261102
CANARY = 'FWLAB_SYNTHETIC_SECRET_92f730b1'


def population(callback_ip):
    cases = []

    def add(method, target, *, label='ALLOW', family='routine', cohort='new_application_DEV',
            body='', content_type=None, component='', oracle=None, expected=None, session=None):
        cid = f'docker-dev-{len(cases):04d}'
        cases.append(dict(id=cid, method=method, target=target, label=label, category=family,
                          family=family, cohort=cohort, body=body, content_type=content_type,
                          component_id=component or family, oracle=oracle, expected=expected,
                          session=session))

    def get(path, args=None, **kw):
        add('GET', path + ('?' + U.urlencode(args) if args else ''), **kw)

    for s in range(15):
        comp, session = f'shop-session-{s:02d}', f'session-{s:02d}'
        kw = dict(component=comp, session=session)
        get('/', **kw)
        get('/products', dict(category=('office', 'sport', 'food')[s % 3], page=s+1,
                              sort=('id', 'price')[s % 2], limit=8), **kw)
        get(f'/products/{s % 8 + 1}', **kw)
        get('/search', dict(q=('coffee', 'keyboard', 'water', 'mug', 'shoes')[s % 5]), **kw)
        get('/login', **kw)
        add('POST', '/login', body=U.urlencode(dict(username=f'labguest{s}', password=f'DemoPass{s}')),
            content_type='application/x-www-form-urlencoded', **kw)
        get('/profile', **kw)
        add('POST', '/cart', body=U.urlencode(dict(product_id=s % 8+1, quantity=s % 3+1)),
            content_type='application/x-www-form-urlencoded', **kw)
        get('/cart', **kw)
        add('POST', '/checkout', body=U.urlencode(dict(address=f'{s+1} Example Street', card_last4='0000')),
            content_type='application/x-www-form-urlencoded', **kw)
        get('/api/products', dict(category=('food', 'office', 'sport')[s % 3], page=s+1), **kw)
        add('POST', '/api/orders', body=json.dumps(dict(product_id=s % 8+1, quantity=1,
                                                     note=f'Gift order {s}', delivery='standard')),
            content_type='application/json', **kw)

    for i in range(24):
        variant = i % 4
        families = [
            ('sqli', '/catalog', 'id', str(i % 2+1),
             ["1' OR '1'='1' -- ", "1' OR 1=1 -- ", "0' UNION SELECT name FROM items -- ",
              "1' OR visible=0 -- "][variant], 'secret', CANARY),
            ('path_traversal', '/download', 'file', ('readme.txt', 'guide.txt')[i % 2],
             ['../private/canary.txt', './../private/canary.txt', '../public/../private/canary.txt',
              'x/../../private/canary.txt'][variant], 'secret', CANARY),
            ('ssti', '/preview', 'template', f'Welcome visitor {i}',
             ['{{%d*%d}}', '{{ %d * %d }}', '{{(%d)*(%d)}}', '{{%d * %d}}'][variant] % (37+i, 73+i),
             'exact_body', str((37+i)*(73+i))),
            ('command_injection', '/lookup', 'value', f'guest{i}',
             ['";cat private/canary.txt;#', '$(cat private/canary.txt)',
              '`cat private/canary.txt`', '"; cat private/canary.txt #'][variant], 'secret', CANARY),
            ('ssrf', '/fetch', 'url', f'http://assets.fwlab.test:9200/public/info?item={i}',
             f'http://{callback_ip}:9200/internal/token?item={i}', 'secret', CANARY),
            ('open_redirect', '/go', 'next', f'/products/{i % 8+1}',
             [f'http://collector.fwlab.test/cb?item={i}', f'//collector.fwlab.test/cb?item={i}',
              f'https://collector.fwlab.test/cb?item={i}', f'http://collector.fwlab.test:9200/cb?item={i}'][variant],
             'external_location', 'collector.fwlab.test'),
            ('xss', '/reflect', 'text', f'Welcome guest {i}',
             ["<script>window.__fwlab_marker='XSS_%d'</script>",
              "<img src=x onerror=\"window.__fwlab_marker='XSS_%d'\">",
              "<svg onload=\"window.__fwlab_marker='XSS_%d'\"></svg>",
              "<script>window['__fwlab_marker']='XSS_%d'</script>"][variant] % i,
             'browser_script', f'XSS_{i}')]
        for family, path, key, benign, attack, oracle, expected in families:
            component = f'{family}-template-{variant}'
            for label, value in [('ALLOW', benign), ('BLOCK', attack)]:
                get(path, {key: value, 'view': i}, label=label, family=family,
                    component=component, oracle=oracle if label == 'BLOCK' else None,
                    expected=expected if label == 'BLOCK' else None)

    edges = ["children's shoes", 'select a table', 'union membership', 'shell necklace',
             'script writing notebook', '../ in a programming tutorial', '{{name}} example',
             'http://example.test/docs', '127.0.0.1 documentation', '<b>bold text example</b>',
             'café y té', '東京の本', '2 < 3 and 5 > 4', 'discount 20%', 'a+b stationery',
             'C:\\Users\\Public tutorial', 'email user@example.test', 'redirect user guide',
             'SQL learning book', 'system administration handbook', 'curl command reference',
             'passphrase with spaces', 'naïve résumé', 'safe & sound']
    for i, q in enumerate(edges):
        get('/search', dict(q=q), family='benign_edge', component=f'edge-{i//4}')
    for path in ('/healthz', '/static/app.css'):
        get(path, family='known_route_regression', cohort='known_regression', component='known-routes')
    return cases


def wire(case, *, token=None, cookie=''):
    body = case['body'].encode('utf-8')
    headers = [('Host', 'shop.fwlab.test'), ('Connection', 'close'),
               ('X-Experiment-Id', token or case['id'])]
    if cookie:
        headers.append(('Cookie', cookie))
    if case['content_type']:
        headers.append(('Content-Type', case['content_type']))
    if body or case['method'] == 'POST':
        headers.append(('Content-Length', str(len(body))))
    return (f"{case['method']} {case['target']} HTTP/1.1\r\n" +
            ''.join(f'{k}: {v}\r\n' for k, v in headers) + '\r\n').encode() + body


def canonical(case):
    text = f"{case['method']} {case['target']} HTTP/1.1\n"
    if case['content_type']:
        text += f"Content-Type: {case['content_type']}\n"
    if case['body']:
        text += '\n' + case['body']
    return text


def public_case(case):
    return {**{k: case[k] for k in ('id', 'label', 'category', 'family', 'cohort', 'component_id', 'oracle')},
            'canonical_sha256': hashlib.sha256(canonical(case).encode()).hexdigest(),
            'method': case['method']}


def order(cases):
    # Preserve each session's causal order, randomize whole session/template blocks.
    groups = {}
    for case in cases:
        groups.setdefault(case['session'] or case['component_id'], []).append(case['id'])
    groups = list(groups.values())
    random.Random(SEED).shuffle(groups)
    return [cid for group in groups for cid in group]
