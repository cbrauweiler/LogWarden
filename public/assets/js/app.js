/*
 * LogWarden frontend behaviour.
 *
 * Progressive enhancement only: every page works without this file. It adds a
 * theme toggle and a live preview for the branding settings, both of which are
 * conveniences rather than requirements.
 */
(function () {
    'use strict';

    /* --- Theme toggle ---------------------------------------------------- */

    var STORAGE_KEY = 'lw.theme';

    function currentTheme() {
        var explicit = document.documentElement.getAttribute('data-theme');
        if (explicit) {
            return explicit;
        }
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    // A stored preference only applies where the server left the choice open;
    // an administrator pinning light or dark must not be overridable by a
    // stale value in someone's browser.
    try {
        var stored = localStorage.getItem(STORAGE_KEY);
        if (stored && !document.documentElement.hasAttribute('data-theme')) {
            document.documentElement.setAttribute('data-theme', stored);
        }
    } catch (e) {
        /* private mode or blocked storage: the server default stands */
    }

    document.querySelectorAll('[data-theme-toggle]').forEach(function (button) {
        button.addEventListener('click', function () {
            var next = currentTheme() === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            try {
                localStorage.setItem(STORAGE_KEY, next);
            } catch (e) { /* nothing to do */ }
        });
    });

    /* --- Branding settings ----------------------------------------------- */

    var form = document.querySelector('[data-branding-form]');
    if (!form) {
        return;
    }

    // Native colour input and hex field are two views of one value.
    form.querySelectorAll('input[type="color"][data-sync]').forEach(function (swatch) {
        var field = document.getElementById(swatch.getAttribute('data-sync'));
        if (!field) {
            return;
        }

        swatch.addEventListener('input', function () {
            field.value = swatch.value;
            field.dispatchEvent(new Event('input', { bubbles: true }));
        });

        field.addEventListener('input', function () {
            if (/^#[0-9a-fA-F]{6}$/.test(field.value)) {
                swatch.value = field.value;
            }
        });
    });

    var preview = form.querySelector('[data-preview]');
    if (!preview) {
        return;
    }

    /* The same readability rule the server applies, mirrored here so the
       preview matches what will be saved. Kept in sync with Web\Color. */
    function channel(value) {
        var c = value / 255;
        return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    }

    function luminance(hex) {
        var m = /^#?([0-9a-f]{6})$/i.exec(hex);
        if (!m) {
            return 0;
        }
        var n = parseInt(m[1], 16);
        return 0.2126 * channel((n >> 16) & 255)
             + 0.7152 * channel((n >> 8) & 255)
             + 0.0722 * channel(n & 255);
    }

    function contrast(a, b) {
        var la = luminance(a), lb = luminance(b);
        return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    }

    function inkOn(background) {
        return contrast(background, '#ffffff') >= contrast(background, '#11110f') ? '#ffffff' : '#11110f';
    }

    function mix(hex, towards, weight) {
        var a = /^#?([0-9a-f]{6})$/i.exec(hex);
        var b = /^#?([0-9a-f]{6})$/i.exec(towards);
        if (!a || !b) {
            return hex;
        }
        var x = parseInt(a[1], 16), y = parseInt(b[1], 16), out = 0;
        for (var shift = 16; shift >= 0; shift -= 8) {
            var value = Math.round(((x >> shift) & 255) * (1 - weight) + ((y >> shift) & 255) * weight);
            out |= value << shift;
        }
        return '#' + ('000000' + (out >>> 0).toString(16)).slice(-6);
    }

    function readableOn(brand, surface) {
        if (contrast(brand, surface) >= 4.5) {
            return brand;
        }
        var towards = luminance(surface) > 0.5 ? '#000000' : '#ffffff';
        var candidate = brand;
        for (var step = 1; step <= 20; step++) {
            candidate = mix(brand, towards, step * 0.05);
            if (contrast(candidate, surface) >= 4.5) {
                return candidate;
            }
        }
        return candidate;
    }

    var brandField   = form.querySelector('[data-preview-brand]');
    var sidebarField = form.querySelector('[data-preview-sidebar]');
    var nameField    = form.querySelector('[data-preview-name]');
    var titleEl      = preview.querySelector('[data-preview-title]');
    var markEl       = preview.querySelector('[data-preview-mark]');

    function repaint() {
        if (brandField && /^#[0-9a-fA-F]{6}$/.test(brandField.value)) {
            preview.style.setProperty('--preview-brand', brandField.value);
            preview.style.setProperty('--preview-brand-ink', inkOn(brandField.value));
            preview.style.setProperty('--preview-brand-text', readableOn(brandField.value, '#fcfcfb'));
        }
        if (sidebarField && /^#[0-9a-fA-F]{6}$/.test(sidebarField.value)) {
            preview.style.setProperty('--preview-sidebar', sidebarField.value);
        }
        if (nameField) {
            var name = nameField.value.trim() || 'LogWarden';
            if (titleEl) { titleEl.textContent = name; }
            if (markEl)  { markEl.textContent = name.slice(0, 2).toUpperCase(); }
        }
    }

    [brandField, sidebarField, nameField].forEach(function (field) {
        if (field) {
            field.addEventListener('input', repaint);
        }
    });

    repaint();
}());
