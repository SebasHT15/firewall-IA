"""Disposable, deliberately vulnerable LOCAL experiment target, never a deployment app.

Extends the existing inert shop without modifying it. All files and SQL data are
synthetic; fetches are restricted to this experiment's callback container.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import threading
import time
import urllib.parse
import urllib.request

from flask import jsonify, redirect, render_template_string, request

ROOT = Path('/tmp/fwlab-eval')
ROOT.mkdir(exist_ok=True)
(ROOT / 'public').mkdir(exist_ok=True)
(ROOT / 'private').mkdir(exist_ok=True)
CANARY = 'FWLAB_SYNTHETIC_SECRET_92f730b1'
(ROOT / 'public' / 'readme.txt').write_text('Public product documentation\n')
(ROOT / 'public' / 'guide.txt').write_text('Public shopping guide\n')
(ROOT / 'private' / 'canary.txt').write_text(CANARY)
LOG = Path('/evidence/application.jsonl')
LOCK = threading.Lock()

spec = importlib.util.spec_from_file_location('original_shop', '/srv/app.py')
shop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shop)
app = shop.app


@app.before_request
def independent_receipt():
    request.environ['experiment_received_at'] = time.time()
    # Capture before Flask parses form fields, which consumes the input stream.
    request.environ['experiment_body_sha256'] = hashlib.sha256(request.get_data(cache=True)).hexdigest()


@app.after_request
def independent_outcome(response):
    body = response.get_data()
    row = dict(id=request.headers.get('X-Experiment-Id'), method=request.method,
               raw_target=request.environ.get('RAW_URI', request.full_path),
               body_sha256=request.environ['experiment_body_sha256'],
               response_status=response.status_code,
               response_sha256=hashlib.sha256(body).hexdigest(),
               secret_in_response=CANARY.encode() in body,
               received_at=request.environ.get('experiment_received_at'),
               finished_at=time.time())
    with LOCK, LOG.open('a') as fh:
        fh.write(json.dumps(row, sort_keys=True) + '\n')
    return response


@app.get('/catalog')
def catalog():
    # Intentionally vulnerable string SQL, isolated in a fresh in-memory DB.
    conn = sqlite3.connect(':memory:')
    try:
        conn.execute('CREATE TABLE items(id TEXT, name TEXT, visible INTEGER)')
        conn.executemany('INSERT INTO items VALUES(?,?,?)',
                         [('1', 'keyboard', 1), ('2', 'coffee', 1), ('3', CANARY, 0)])
        query = "SELECT name FROM items WHERE id='" + request.args.get('id', '1') + "' AND visible=1"
        return jsonify(items=[r[0] for r in conn.execute(query)])
    except sqlite3.Error:
        return jsonify(error='invalid query'), 400
    finally:
        conn.close()


@app.get('/download')
def download():
    path = (ROOT / 'public' / request.args.get('file', 'readme.txt')).resolve()
    # The vulnerability crosses public -> private, never beyond synthetic ROOT.
    if not path.is_relative_to(ROOT) or not path.is_file():
        return 'not found', 404
    return app.response_class(path.read_bytes(), mimetype='text/plain')


@app.get('/preview')
def preview():
    return render_template_string(request.args.get('template', 'Hello visitor'))


@app.get('/lookup')
def lookup():
    # Deliberate shell interpolation; container has no host files or outbound net.
    value = request.args.get('value', 'guest')
    result = subprocess.run('printf "%s" "' + value + '"', shell=True,
                            capture_output=True, timeout=1, cwd=str(ROOT))
    return app.response_class(result.stdout, mimetype='text/plain')


@app.get('/fetch')
def fetch():
    url = request.args.get('url', 'http://assets.fwlab.test:9200/public/info')
    parsed = urllib.parse.urlsplit(url)
    allowed = {'assets.fwlab.test', os.environ['CALLBACK_IP']}
    if parsed.scheme != 'http' or parsed.hostname not in allowed or parsed.port != 9200:
        return 'outside disposable laboratory', 400
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=1) as response:
            return app.response_class(response.read(), mimetype='text/plain')
    except OSError:
        return 'callback unavailable', 502


@app.get('/go')
def go():
    return redirect(request.args.get('next', '/products'), code=302)


@app.get('/reflect')
def reflect():
    return app.response_class('<!doctype html><html><body>' + request.args.get('text', 'hello')
                              + '</body></html>', mimetype='text/html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9100, threaded=True, debug=False, use_reloader=False)
