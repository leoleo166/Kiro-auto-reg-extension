"""Headless-Chrome stealth patches.

Disagnostics on bot.sannysoft.com revealed 4 detection signals AWS likely
uses via FWCIM (fraud detection):

  1. WebDriver (New) = FAIL
       Our Object.defineProperty(navigator, 'webdriver', ...) hides the
       value but leaves the *descriptor* on the prototype. Real Chrome
       has NO own-property at all — descriptor probing (getOwnPropertyDescriptor)
       sees our leak. Fix: delete from prototype, re-define on instance
       with configurable=false.

  2. Permissions (New) = prompt
       Headless Chrome returns {state: 'prompt'} for every query. Real
       Chrome returns varied values (notifications → 'denied' unless
       granted, geolocation → 'prompt', etc). Fix: patch query() to
       return expected-by-origin values.

  3. Plugins is of type PluginArray = FAIL
       Our navigator override was `plugins: () => [...]` — an Array.
       Real Chrome returns PluginArray instance. Fix: construct PluginArray
       from the nav_pluginProperties() hack.

  4. HEADCHR_PERMISSIONS = FAIL
       Notification.permission reports 'denied' in headless even when
       permissions.query says 'prompt'. This mismatch is the tell.
       Fix: patch permissions.query to coerce notifications to 'prompt'.

These are ported from puppeteer-extra-plugin-stealth evasions.
"""

from __future__ import annotations

from typing import Any


STEALTH_SCRIPT = r"""
(function() {
    'use strict';

    // --- Fix 1: True webdriver deletion ---
    // sannysoft "WebDriver (New)" FAIL = descriptor exists anywhere
    // on navigator prototype chain. Previous version did delete + redefine
    // (with get:()=>undefined), but the redefine itself creates a
    // detectable descriptor. Correct fix: delete from every prototype
    // level and do NOT redefine.
    try {
        var proto = Object.getPrototypeOf(navigator);
        while (proto) {
            try { delete proto.webdriver; } catch(e) {}
            proto = Object.getPrototypeOf(proto);
        }
        try { delete navigator.webdriver; } catch(e) {}
    } catch(e) {}

    // --- Fix: Notification.permission must match permissions.query ---
    // Headless Chrome returns Notification.permission='denied' but
    // permissions.query returns 'prompt'. Real Chrome is consistent.
    // Force Notification.permission to 'default' (the real-browser value
    // when user has not interacted with notifications yet).
    try {
        if (window.Notification) {
            Object.defineProperty(Notification, 'permission', {
                get: function() { return 'default'; },
                configurable: true,
            });
        }
    } catch(e) {}

    // --- Fix 2: navigator.plugins as real PluginArray ---
    // Create mimic PluginArray with Chrome's default plugins.
    try {
        function makePlugin(name, filename, description) {
            var plugin = Object.create(Plugin.prototype);
            Object.defineProperties(plugin, {
                name: { value: name, writable: false, enumerable: false, configurable: true },
                filename: { value: filename, writable: false, enumerable: false, configurable: true },
                description: { value: description, writable: false, enumerable: false, configurable: true },
                length: { value: 1, writable: false, enumerable: false, configurable: true },
            });
            return plugin;
        }
        var plugins = [
            makePlugin('PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'),
            makePlugin('Chrome PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'),
            makePlugin('Chromium PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'),
            makePlugin('Microsoft Edge PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'),
            makePlugin('WebKit built-in PDF', 'internal-pdf-viewer', 'Portable Document Format'),
        ];
        var pluginArray = Object.create(PluginArray.prototype);
        plugins.forEach(function(p, i) { pluginArray[i] = p; pluginArray[p.name] = p; });
        Object.defineProperty(pluginArray, 'length', {
            value: plugins.length, writable: false, enumerable: false, configurable: false
        });
        Object.defineProperty(navigator, 'plugins', {
            get: function() { return pluginArray; },
            configurable: true,
        });
    } catch(e) {}

    // --- Fix 3 + 4: Permissions API + Notification.permission consistency ---
    // Headless leaks: Notification.permission is 'denied' while
    // permissions.query({name: 'notifications'}) returns 'prompt'.
    // Real Chrome: both return 'default'/'prompt'. Fix: unify via query patch.
    try {
        if (navigator.permissions && navigator.permissions.query) {
            var origQuery = navigator.permissions.query.bind(navigator.permissions);
            navigator.permissions.query = function(params) {
                if (params && params.name === 'notifications') {
                    return Promise.resolve({
                        state: Notification.permission === 'denied' ? 'prompt' : Notification.permission,
                        onchange: null,
                    });
                }
                return origQuery(params);
            };
        }
    } catch(e) {}

    // --- Extra: chrome.runtime object (some bot-checks look for its shape) ---
    try {
        if (!window.chrome) { window.chrome = {}; }
        if (!window.chrome.runtime) { window.chrome.runtime = {}; }
        // Chrome normally exposes these read-only fields; puppeteer-stealth
        // mimics them to pass bot.sannysoft's "chrome (runtime)" test.
        if (!window.chrome.runtime.PlatformOs) {
            window.chrome.runtime.PlatformOs = {
                MAC: 'mac', WIN: 'win', ANDROID: 'android',
                CROS: 'cros', LINUX: 'linux', OPENBSD: 'openbsd',
            };
        }
    } catch(e) {}

    // --- Extra: outerWidth/outerHeight non-zero check ---
    // Some detectors read outerWidth — in pure headless mode it's 0.
    // Our spoofer already sets --window-size, but old code paths may
    // still see 0. Patch defensively.
    try {
        if (window.outerWidth === 0) {
            Object.defineProperty(window, 'outerWidth', { get: () => window.innerWidth });
        }
        if (window.outerHeight === 0) {
            Object.defineProperty(window, 'outerHeight', { get: () => window.innerHeight + 74 });
        }
    } catch(e) {}
})();
"""


def inject_stealth(page: Any) -> bool:
    """Inject the stealth patches via CDP addScriptToEvaluateOnNewDocument.

    Must be called BEFORE the first .get() to AWS so the patches apply
    to the initial page load (when AWS FWCIM first samples the navigator).
    """
    try:
        page.run_cdp('Page.addScriptToEvaluateOnNewDocument', source=STEALTH_SCRIPT)
        return True
    except Exception as e:
        print(f"[STEALTH] inject failed: {e}")
        return False
