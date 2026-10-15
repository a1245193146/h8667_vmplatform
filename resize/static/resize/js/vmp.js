/* 平台共用交互脚本（无外部依赖，内网离线可用）。
 *
 * 只放三类东西：toast 提示、表格行内展开、带 CSRF 的 fetch 封装。
 * 各页面不再各写一份——重复实现正是"点起来不一致"的来源。
 */
(function () {
    'use strict';

    var LEVEL_CLASS = {ok: 'is-ok', success: 'is-ok', warn: 'is-warn',
                       warning: 'is-warn', bad: 'is-bad', error: 'is-bad',
                       danger: 'is-bad', info: ''};

    function wrap() {
        var w = document.querySelector('.vmp-toast-wrap');
        if (!w) {
            w = document.createElement('div');
            w.className = 'vmp-toast-wrap';
            document.body.appendChild(w);
        }
        return w;
    }

    /* toast(msg, level, ms)：右上角浮出提示，到时自动淡出。
     * level ∈ ok/warn/bad/info。默认 4 秒；错误类默认 8 秒（要来得及读完）。 */
    window.vmpToast = function (msg, level, ms) {
        if (!msg) { return; }
        level = level || 'info';
        var el = document.createElement('div');
        el.className = 'vmp-toast ' + (LEVEL_CLASS[level] || '');
        el.setAttribute('role', 'status');
        el.textContent = String(msg);
        el.addEventListener('click', function () { dismiss(el); });
        wrap().appendChild(el);
        var ttl = ms || (LEVEL_CLASS[level] === 'is-bad' ? 8000 : 4000);
        setTimeout(function () { dismiss(el); }, ttl);
    };

    function dismiss(el) {
        if (!el || el.classList.contains('is-out')) { return; }
        el.classList.add('is-out');
        setTimeout(function () { if (el.parentNode) { el.parentNode.removeChild(el); } }, 240);
    }

    /* 行内展开：点带 data-vmp-toggle="#id" 的行，切换目标元素的显隐。
     * 比"跳详情页"轻，比"全展开"省地方——列表页看概要、需要时才看正文。 */
    document.addEventListener('click', function (ev) {
        var row = ev.target.closest('[data-vmp-toggle]');
        if (!row) { return; }
        var target = document.querySelector(row.getAttribute('data-vmp-toggle'));
        if (!target) { return; }
        var hidden = target.hasAttribute('hidden');
        if (hidden) { target.removeAttribute('hidden'); } else { target.setAttribute('hidden', ''); }
        row.setAttribute('aria-expanded', hidden ? 'true' : 'false');
    });

    /* vmpFetch(url, opts)：自动带 CSRF token 与 JSON 头，返回 Promise<Response>。
     * 每个页面自己拼 X-CSRFToken 迟早会漏一个，漏了就是 403。 */
    window.vmpFetch = function (url, opts) {
        opts = opts || {};
        var headers = opts.headers || {};
        var token = (document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/) || [])[1];
        if (token) { headers['X-CSRFToken'] = decodeURIComponent(token); }
        if (opts.body && !(opts.body instanceof FormData)) {
            headers['Content-Type'] = headers['Content-Type'] || 'application/json';
        }
        opts.headers = headers;
        opts.credentials = opts.credentials || 'same-origin';
        return fetch(url, opts);
    };
})();
