"""Browser fingerprint randomization (ported from 7836246/aws-builder-id).

Наш базовый spoofer (spoofers/profile.py) задаёт timezone, user-agent,
geolocation и hide-webdriver. Этого мало: AWS смотрит ещё и на Canvas,
WebGL, AudioContext, Screen, navigator.hardwareConcurrency и WebRTC.
Если эти API возвращают одинаковое на каждом запуске — fingerprint
идентичен между попытками и AWS метит источник как bot-farm.

Этот модуль генерит уникальные JS-скрипты на каждый запуск и инжектит
их в DrissionPage CDP-сессию до первого navigation (чтобы spoof
применился к первому запросу к awsapps.com, не только к последующим).
"""

from __future__ import annotations

import random
from typing import Any


def _canvas_noise_script() -> str:
    nr, ng, nb = random.randint(1, 10), random.randint(1, 10), random.randint(1, 10)
    return f"""
(function() {{
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    const origToBlob = HTMLCanvasElement.prototype.toBlob;
    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    const addNoise = (canvas) => {{
        try {{
            const ctx = canvas.getContext('2d');
            const d = ctx.getImageData(0, 0, canvas.width, canvas.height);
            for (let i = 0; i < d.data.length; i += 4) {{
                d.data[i] += {nr}; d.data[i+1] += {ng}; d.data[i+2] += {nb};
            }}
            ctx.putImageData(d, 0, 0);
        }} catch (e) {{}}
    }};
    HTMLCanvasElement.prototype.toDataURL = function() {{ addNoise(this); return origToDataURL.apply(this, arguments); }};
    HTMLCanvasElement.prototype.toBlob = function() {{ addNoise(this); return origToBlob.apply(this, arguments); }};
    CanvasRenderingContext2D.prototype.getImageData = function() {{
        const d = origGetImageData.apply(this, arguments);
        for (let i = 0; i < d.data.length; i += 4) {{
            d.data[i] += {nr}; d.data[i+1] += {ng}; d.data[i+2] += {nb};
        }}
        return d;
    }};
}})();"""


def _webgl_noise_script() -> str:
    vendor = random.choice(['Intel Inc.', 'NVIDIA Corporation', 'AMD', 'Apple Inc.'])
    renderer = random.choice([
        'Intel(R) UHD Graphics 620',
        'NVIDIA GeForce GTX 1660',
        'AMD Radeon RX 580',
        'Apple M1',
        'Intel(R) Iris(R) Plus Graphics',
    ])
    return f"""
(function() {{
    const gp = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(p) {{
        if (p === 37445) return '{vendor}';
        if (p === 37446) return '{renderer}';
        return gp.call(this, p);
    }};
    if (window.WebGL2RenderingContext) {{
        const gp2 = WebGL2RenderingContext.prototype.getParameter;
        WebGL2RenderingContext.prototype.getParameter = function(p) {{
            if (p === 37445) return '{vendor}';
            if (p === 37446) return '{renderer}';
            return gp2.call(this, p);
        }};
    }}
}})();"""


def _audio_noise_script() -> str:
    noise = random.uniform(0.00001, 0.0001)
    return f"""
(function() {{
    const AC = window.AudioContext || window.webkitAudioContext;
    if (AC && AC.prototype.createOscillator) {{
        const orig = AC.prototype.createOscillator;
        AC.prototype.createOscillator = function() {{
            const osc = orig.call(this);
            const origStart = osc.start;
            osc.start = function() {{
                try {{ osc.frequency.value += {noise}; }} catch(e) {{}}
                return origStart.apply(this, arguments);
            }};
            return osc;
        }};
    }}
}})();"""


def _navigator_override_script() -> str:
    hc = random.choice([2, 4, 6, 8, 12, 16])
    mem = random.choice([4, 8, 16, 32])
    mt = random.choice([0, 1, 5, 10])
    return f"""
(function() {{
    try {{ Object.defineProperty(navigator, 'hardwareConcurrency', {{ get: () => {hc} }}); }} catch(e) {{}}
    try {{ Object.defineProperty(navigator, 'deviceMemory', {{ get: () => {mem} }}); }} catch(e) {{}}
    try {{ Object.defineProperty(navigator, 'maxTouchPoints', {{ get: () => {mt} }}); }} catch(e) {{}}
    try {{ Object.defineProperty(navigator, 'webdriver', {{ get: () => undefined }}); }} catch(e) {{}}
    try {{
        const pl = ['Chrome PDF Plugin', 'Chrome PDF Viewer', 'Native Client'];
        Object.defineProperty(navigator, 'plugins', {{ get: () => pl }});
    }} catch(e) {{}}
}})();"""


def _screen_randomize_script() -> str:
    res = random.choice([
        (1920, 1080), (1366, 768), (1440, 900), (1536, 864), (2560, 1440),
    ])
    cd = random.choice([24, 32])
    w, h = res
    return f"""
(function() {{
    try {{ Object.defineProperty(screen, 'width', {{ get: () => {w} }}); }} catch(e) {{}}
    try {{ Object.defineProperty(screen, 'height', {{ get: () => {h} }}); }} catch(e) {{}}
    try {{ Object.defineProperty(screen, 'availWidth', {{ get: () => {w} }}); }} catch(e) {{}}
    try {{ Object.defineProperty(screen, 'availHeight', {{ get: () => {h - 40} }}); }} catch(e) {{}}
    try {{ Object.defineProperty(screen, 'colorDepth', {{ get: () => {cd} }}); }} catch(e) {{}}
    try {{ Object.defineProperty(screen, 'pixelDepth', {{ get: () => {cd} }}); }} catch(e) {{}}
}})();"""


def _webrtc_protect_script() -> str:
    return """
(function() {
    if (window.RTCPeerConnection) {
        const orig = window.RTCPeerConnection;
        window.RTCPeerConnection = function(config) {
            config = config || {};
            config.iceServers = config.iceServers || [];
            config.iceCandidatePoolSize = 0;
            return new orig(config);
        };
    }
})();"""


def get_combined_spoof_script() -> str:
    """Единый JS-скрипт со всеми уровнями fingerprint-spoofing.

    Вызывается на каждой новой странице (addScriptToEvaluateOnNewDocument).
    Каждый вызов функции — новые случайные значения, поэтому между попытками
    fingerprint разный.
    """
    return "\n".join([
        _canvas_noise_script(),
        _webgl_noise_script(),
        _audio_noise_script(),
        _navigator_override_script(),
        _screen_randomize_script(),
        _webrtc_protect_script(),
    ])


def inject_into_drissionpage(page: Any) -> bool:
    """Инжектит fingerprint-spoof через DrissionPage CDP.

    DrissionPage имеет page.run_cdp(method, **params) — это эквивалент
    Selenium's execute_cdp_cmd. Используем Page.addScriptToEvaluateOnNewDocument
    чтобы spoof применился до первого navigation.
    """
    try:
        script = get_combined_spoof_script()
        # DrissionPage 4.x: метод называется run_cdp
        page.run_cdp('Page.addScriptToEvaluateOnNewDocument', source=script)
        return True
    except Exception as e:
        print(f"[FP-EXTRA] inject failed: {e}")
        return False
