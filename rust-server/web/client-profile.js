/* A client profile selects an import format. The server accepts both versions concurrently. */
window.CSQTTProfile = (() => {
    const key = 'csqtt-client-profile-v1';
    const versions = ['2.5.0', '2.1.9'];
    const devices = ['android', 'windows', 'apple'];
    function normalize(value) {
        const device = devices.includes(value?.device) ? value.device : 'android';
        return { device, version: device === 'android' && versions.includes(value?.version) ? value.version : device === 'android' ? '2.5.0' : '2.1.9' };
    }
    let saved = {};
    try { saved = JSON.parse(localStorage.getItem(key) || '{}'); } catch (_) {}
    if (!saved || typeof saved !== 'object' || Array.isArray(saved)) saved = {};
    const query = new URLSearchParams(location.search);
    if (versions.includes(query.get('version'))) saved.version = query.get('version');
    if (devices.includes(query.get('device'))) saved.device = query.get('device');
    let state = normalize(saved);
    let activeClient = null;
    let nextId = 0;

    function appName() {
        return state.device === 'apple' ? 'VK TURN Proxy' : state.device === 'windows' ? 'focsq' : 'CSQTT ' + state.version;
    }
    function linkFor(client) {
        if (!client) return '';
        return (state.device === 'apple' ? client.ios_link : state.version === '2.1.9' ? client.legacy_link : client.link) || '';
    }
    function subscriptionUrl(uuid, group = false) {
        const url = new URL('/' + encodeURIComponent(uuid) + (group ? '/sub-group' : '/sub'), location.origin);
        url.searchParams.set('version', state.version);
        url.searchParams.set('device', state.device);
        return url.href;
    }
    function renderQr(container, link) {
        container.replaceChildren();
        if (!link) { container.textContent = 'Ссылка для этого приложения недоступна.'; return; }
        try {
            const qr = qrcode(0, 'L');
            qr.addData(link);
            qr.make();
            container.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
        } catch (_) { container.textContent = 'Ссылка слишком длинная для QR-кода. Используйте копирование.'; }
    }
    function updateClient() {
        if (!activeClient) return;
        const link = linkFor(activeClient);
        const input = document.getElementById('qrDlgLink');
        if (input) input.value = link;
        const container = document.getElementById('qrCodeContainer');
        if (container) renderQr(container, link);
        const connect = document.getElementById('qrDlgConnectBtn');
        if (connect) {
            if (link) connect.setAttribute('href', link); else connect.removeAttribute('href');
            connect.textContent = 'Открыть ' + appName();
            connect.setAttribute('aria-disabled', String(!link));
        }
        const warning = document.getElementById('profileWarning');
        if (warning) warning.hidden = !(state.version === '2.1.9' && activeClient.requires_vk_hashes !== false);
        const download = document.getElementById('profileAppLink');
        if (download) {
            download.href = state.device === 'apple' ? 'https://github.com/anton48/vk-turn-proxy-ios' : state.device === 'windows' ? 'https://github.com/luminescq/focsq/releases' : 'https://github.com/amurcanov/csqtt/releases';
            download.textContent = 'Приложение ' + appName();
        }
    }
    function syncControls() {
        document.querySelectorAll('[data-profile-controls]').forEach(root => {
            root.querySelector('select').value = state.device;
            root.querySelectorAll('[data-version]').forEach(button => {
                button.setAttribute('aria-pressed', String(button.dataset.version === state.version));
                button.disabled = state.device !== 'android' && button.dataset.version === '2.5.0';
            });
            root.querySelector('[data-profile-description]').textContent = state.device === 'android'
                ? 'Выберите версию, установленную на телефоне или планшете.'
                : appName() + ' использует совместимый формат 2.1.9.';
        });
        document.querySelectorAll('[data-profile-label]').forEach(el => { el.textContent = appName(); });
        updateClient();
    }
    function set(patch) {
        state = normalize({ ...state, ...patch });
        try { localStorage.setItem(key, JSON.stringify(state)); } catch (_) {}
        syncControls();
        document.dispatchEvent(new Event('csqtt-profile-change'));
    }
    function mount() {
        document.querySelectorAll('[data-profile-controls]').forEach(root => {
            if (root.dataset.mounted) return;
            root.dataset.mounted = 'true';
            const id = 'profile-device-' + (++nextId);
            root.innerHTML = `<div class="profile-fields"><div><label for="${id}">Устройство</label><select id="${id}" aria-label="Устройство"><option value="android">Android · телефон / планшет</option><option value="windows">Windows / Linux · focsq</option><option value="apple">iPhone / iPad · VK TURN Proxy</option></select></div><div><span class="profile-label">Версия приложения</span><div class="version-switch" role="group" aria-label="Версия приложения"><button type="button" data-version="2.5.0" aria-pressed="false">2.5.0</button><button type="button" data-version="2.1.9" aria-pressed="false">2.1.9</button></div></div></div><p class="profile-description" data-profile-description></p>`;
            root.querySelector('select').addEventListener('change', event => set({ device: event.target.value }));
            root.querySelectorAll('[data-version]').forEach(button => button.addEventListener('click', () => set({ version: button.dataset.version })));
        });
        syncControls();
    }
    document.addEventListener('DOMContentLoaded', mount);
    return {
        linkFor, subscriptionUrl, appName, renderQr, set,
        showClient(client) { activeClient = client; updateClient(); },
        get state() { return { ...state }; }
    };
})();
