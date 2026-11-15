"""Execute actual response documents in offline Chromium; no network access."""
import json
import sys
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
    for line in sys.stdin:
        item = json.loads(line)
        page = browser.new_page()
        try:
            page.route('**/*', lambda route: route.abort())
            page.set_content(item['html'], wait_until='load', timeout=5000)
            page.wait_for_timeout(100)
            marker = page.evaluate('window.__fwlab_marker || null')
            print(json.dumps(dict(id=item['id'], marker=marker,
                                  effect=marker == item['expected'])), flush=True)
        finally:
            page.close()
    browser.close()
