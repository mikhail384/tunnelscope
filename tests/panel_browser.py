#!/usr/bin/env python3
"""Browser checks against embedded HTML with deterministic, local API fixtures.

Requires Python playwright and Chromium. No server, credentials or network needed.
Run: python3 tests/panel_browser.py [directory-for-screenshots]
"""
import html
import json
from pathlib import Path
import re
import shutil
import sys
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "rust-server/web"
CLIENT = dict(name="Мой планшет", password="test-password", link="csqtt://sealed-fixture-modern",
              legacy_link="csqtt://connect?v=2&host=203.0.113.8&peer=46000&password=test-password&hashes=call-one",
              ios_link="vkturnproxy://import?data=fixture-ios", requires_vk_hashes=False,
              sub_uuid="test-client", active=True, expires=0, active_sessions=1, up=1024, down=4096,
              ip="10.66.67.3", group_id="", vk_hashes="call-one", peer_port=46000)
QRCODE = re.search(r'const QRCODE_JS: &str = r##"(.*?)"##;', (ROOT / "rust-server/web_panel.rs").read_text(), re.S)[1]


def template(name):
    text = (WEB / (name + ".html")).read_text()
    replacements = {"__PANEL_STYLE__": (WEB / "panel.css").read_text(),
                    "__CLIENT_PROFILE_JS__": (WEB / "client-profile.js").read_text(),
                    "__CLIENT_NAME__": "Мой планшет", "__GROUP_NAME__": "Семья", "__CLIENTS_COUNT__": "1",
                    "__CLIENTS_JSON__": json.dumps([CLIENT]), "__REQUIRES_VK_HASHES__": "false",
                    "__CSQTT_LINK__": html.escape(CLIENT['link'], quote=True),
                    "__LEGACY_LINK__": html.escape(CLIENT['legacy_link'], quote=True),
                    "__IOS_LINK__": html.escape(CLIENT['ios_link'], quote=True)}
    for key, value in replacements.items():
        text = text.replace(key, value)
    return text


def route(request):
    path = urlparse(request.request.url).path.rstrip('/')
    if path.endswith('/qrcode.min.js'):
        request.fulfill(body=QRCODE, content_type='application/javascript'); return
    pages = {'/secret': 'panel', '/test-client/sub': 'client-sub', '/test-group/sub-group': 'group-sub',
             '/test-admin/admin': 'group-admin', '/login': 'login'}
    if path in pages:
        request.fulfill(body=template(pages[path]), content_type='text/html'); return
    if '/api' in path:
        if path.endswith('/clients') or path.endswith('/links'):
            value = [CLIENT]
        elif path.endswith('/groups') or path.endswith('/routing-rules'):
            value = []
        elif path.endswith('/data'):
            value = dict(ok=True, group=dict(name='Семья', workers=0), clients=[CLIENT])
        elif path.endswith('/settings'):
            value = dict(main_password='test-main', dns_provider='yandex', dns_primary='77.88.8.8', dns_secondary='77.88.8.1')
        elif path.endswith('/local-proxy'):
            value = dict(profiles=[], enabled=False, active=False)
        else:
            value = {}
        request.fulfill(json=value); return
    request.fulfill(status=204)


def no_overflow(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'page overflows viewport'


def check_link(page, expected):
    expect(page.locator('#qrDlgLink')).to_have_value(expected)
    expect(page.locator('#qrDlgConnectBtn')).to_have_attribute('href', expected)
    expect(page.locator('#qrCodeContainer svg')).to_have_count(1)


def run():
    screenshots = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if screenshots:
        screenshots.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=shutil.which('chromium'), args=['--no-sandbox'])
        context = browser.new_context(viewport={'width': 1024, 'height': 768}, service_workers='block')
        context.route('**/*', route)
        context.add_init_script("Object.defineProperty(navigator, 'clipboard', {value: {writeText: async text => {window.copied = text;}}});")
        page = context.new_page()
        errors = []
        page.on('pageerror', lambda error: errors.append(error.stack or str(error)))

        page.goto('https://panel.test/secret')
        expect(page.locator('.device-connect')).to_have_count(1)
        page.get_by_role('button', name='＋ Создать доступ', exact=True).click()
        expect(page.locator('#newDlg')).to_be_visible()
        expect(page.locator('#cname')).not_to_have_value('')
        page.evaluate("document.getElementById('newDlg').close()")
        page.locator('[data-profile-controls]').first.locator('[data-version="2.1.9"]').click()
        page.locator('.device-connect').click()
        check_link(page, CLIENT['legacy_link'])
        first_qr = page.locator('#qrCodeContainer').inner_html()
        page.locator('#qrDlg [data-version="2.5.0"]').click()
        check_link(page, CLIENT['link'])
        assert first_qr != page.locator('#qrCodeContainer').inner_html()
        page.locator('#qrDlgCopyBtn').click()
        assert page.evaluate('window.copied') == CLIENT['link']
        page.locator('#qrDlg select').select_option('apple')
        check_link(page, CLIENT['ios_link'])
        expect(page.locator('#qrDlg [data-version="2.5.0"]')).to_be_disabled()
        page.evaluate("document.getElementById('qrDlg').close()")
        page.reload()
        expect(page.locator('[data-profile-controls]').first.locator('select')).to_have_value('apple')
        page.locator('.device-connect').click()
        check_link(page, CLIENT['ios_link'])
        page.evaluate("document.getElementById('qrDlg').close()")
        page.locator('[data-profile-controls]').first.locator('select').select_option('android')
        page.locator('[data-profile-controls]').first.locator('[data-version="2.5.0"]').click()
        page.locator('.client-sub-btn').click()
        assert page.evaluate('window.copied') == 'https://panel.test/test-client/sub?version=2.5.0&device=android'
        no_overflow(page)
        if screenshots:
            page.locator('#toastContainer').evaluate('(el) => el.replaceChildren()')
            page.evaluate('scrollTo(0, 0)')
            page.screenshot(path=str(screenshots / 'panel-tablet.png'), full_page=True)

        page.goto('https://panel.test/test-client/sub?version=2.1.9&device=android')
        check_link(page, CLIENT['legacy_link'])
        page.locator('[data-version="2.5.0"]').click()
        check_link(page, CLIENT['link'])
        page.locator('select').select_option('windows')
        check_link(page, CLIENT['legacy_link'])
        page.locator('select').select_option('apple')
        check_link(page, CLIENT['ios_link'])
        page.locator('#qrDlgCopyBtn').click()
        assert page.evaluate('window.copied') == CLIENT['ios_link']
        page.evaluate("CSQTTProfile.showClient({...window.fixture, requires_vk_hashes: true})".replace('...window.fixture', '...' + json.dumps(CLIENT)))
        expect(page.locator('#profileWarning')).to_be_visible()
        page.set_viewport_size({'width': 390, 'height': 844})
        no_overflow(page)
        if screenshots:
            page.screenshot(path=str(screenshots / 'subscription-mobile.png'), full_page=True)

        page.goto('https://panel.test/test-group/sub-group?device=android&version=2.5.0')
        expect(page.locator('.link-copy-row input')).to_have_value(CLIENT['link'])
        page.locator('[data-version="2.1.9"]').click()
        expect(page.locator('.link-copy-row input')).to_have_value(CLIENT['legacy_link'])
        page.locator('select').select_option('apple')
        expect(page.locator('.connect-button')).to_have_attribute('href', CLIENT['ios_link'])
        no_overflow(page)

        page.goto('https://panel.test/test-admin/admin?device=android&version=2.1.9')
        page.wait_for_function('typeof currentData !== "undefined" && currentData?.clients?.length === 1')
        page.evaluate("openQrModalForClient('test-password')")
        check_link(page, CLIENT['legacy_link'])
        page.locator('#qrDlg select').select_option('apple')
        check_link(page, CLIENT['ios_link'])

        # Malformed storage and unknown query input must not disable the page.
        page.evaluate("localStorage.setItem('csqtt-client-profile-v1', 'null')")
        page.goto('https://panel.test/test-client/sub?version=malicious&device=unknown')
        check_link(page, CLIENT['link'])
        page.goto('https://panel.test/secret')
        no_overflow(page)
        page.goto('https://panel.test/login')
        no_overflow(page)
        # Browsers that deny localStorage still support profile selection.
        page.add_init_script("Object.defineProperty(window, 'localStorage', {get() { throw new Error('storage denied'); }});")
        page.goto('https://panel.test/test-client/sub?version=2.1.9&device=android')
        check_link(page, CLIENT['legacy_link'])
        page.locator('[data-version="2.5.0"]').click()
        check_link(page, CLIENT['link'])
        assert not errors, errors
        browser.close()
    print('PASS: tablet/mobile layouts; both versions; Android/Windows/iPad; QR/copy/open; subscription links; group/admin; persistence; invalid storage')


if __name__ == '__main__':
    run()
