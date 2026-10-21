(function () {
  'use strict';

  const C = window.C = window.C || {};
  const SVG_NS = 'http://www.w3.org/2000/svg';

  function append(parent, child) {
    if (child == null || child === false || child === true) return;
    if (Array.isArray(child)) {
      child.forEach(function (item) { append(parent, item); });
      return;
    }
    if (child instanceof Node) {
      parent.appendChild(child);
      return;
    }
    parent.appendChild(document.createTextNode(String(child)));
  }

  function el(tag, attrs) {
    const node = document.createElement(tag);
    const options = attrs || {};
    Object.keys(options).forEach(function (key) {
      const value = options[key];
      if (value == null || value === false) return;
      if (key === 'class') {
        node.className = value;
      } else if (key === 'text') {
        node.textContent = value;
      } else if (key === 'dataset') {
        Object.keys(value).forEach(function (name) { node.dataset[name] = value[name]; });
      } else if (key === 'style' && typeof value === 'object') {
        Object.assign(node.style, value);
      } else if (key === 'value') {
        node.value = value;
      } else if (key === 'checked' || key === 'disabled' || key === 'selected') {
        node[key] = Boolean(value);
      } else if (key.slice(0, 2) === 'on' && typeof value === 'function') {
        node.addEventListener(key.slice(2).toLowerCase(), value);
      } else if (value === true) {
        node.setAttribute(key, '');
      } else {
        node.setAttribute(key, String(value));
      }
    });
    for (let i = 2; i < arguments.length; i += 1) {
      append(node, arguments[i]);
    }
    return node;
  }

  function svgIcon(name, className) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('class', 'icon' + (className ? ' ' + className : ''));
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    const use = document.createElementNS(SVG_NS, 'use');
    use.setAttribute('href', '#i-' + name);
    svg.appendChild(use);
    return svg;
  }

  function clear(node) {
    if (node) {
      while (node.firstChild) node.removeChild(node.firstChild);
    }
  }

  function replace(node, child) {
    clear(node);
    append(node, child);
  }

  function qs(selector, root) {
    return (root || document).querySelector(selector);
  }

  function qsa(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  function debounce(fn, wait) {
    let timer = null;
    return function () {
      const args = arguments;
      const context = this;
      clearTimeout(timer);
      timer = setTimeout(function () { fn.apply(context, args); }, wait || 150);
    };
  }

  function formatBytes(bytes) {
    const n = Number(bytes);
    if (!Number.isFinite(n) || n < 0) return '—';
    if (n < 1024) return n + ' B';
    const units = ['KB', 'MB', 'GB', 'TB'];
    let value = n / 1024;
    let i = 0;
    while (value >= 1024 && i < units.length - 1) {
      value /= 1024;
      i += 1;
    }
    return (value >= 10 ? value.toFixed(1) : value.toFixed(2)) + ' ' + units[i];
  }

  function fallbackCopy(text) {
    const area = el('textarea', { class: 'visually-hidden', readonly: true });
    area.value = text;
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (error) { ok = false; }
    document.body.removeChild(area);
    if (!ok) throw new Error('copy command failed');
  }

  async function copyText(text, label, options) {
    const opts = options || {};
    const value = String(text == null ? '' : text);
    try {
      if (navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
      } else {
        fallbackCopy(value);
      }
      if (!opts.silent) toast('Copied ' + (label || 'value'), 'ok');
      return true;
    } catch (error) {
      try {
        fallbackCopy(value);
        if (!opts.silent) toast('Copied ' + (label || 'value'), 'ok');
        return true;
      } catch (fallbackError) {
        toast('Could not copy to clipboard', 'error');
        return false;
      }
    }
  }

  function toast(message, type, duration) {
    const root = qs('#toast-root');
    if (!root) return;
    const kind = type || 'ok';
    const iconName = kind === 'error' ? 'x-circle' : kind === 'warning' ? 'alert-triangle' : kind === 'info' ? 'info' : 'check';
    const node = el('div', { class: 'toast ' + kind, role: 'status' },
      svgIcon(iconName),
      el('span', { text: message })
    );
    root.appendChild(node);
    const timeout = duration == null ? 3400 : duration;
    if (timeout > 0) {
      setTimeout(function () {
        node.style.opacity = '0';
        node.style.transform = 'translateY(4px)';
        node.style.transition = 'opacity 140ms ease, transform 140ms ease';
        setTimeout(function () { if (node.parentNode) node.parentNode.removeChild(node); }, 160);
      }, timeout);
    }
  }

  let modalState = null;

  function closeModal() {
    if (!modalState) return;
    const state = modalState;
    modalState = null;
    document.removeEventListener('keydown', state.onKeyDown, true);
    if (state.backdrop.parentNode) state.backdrop.parentNode.removeChild(state.backdrop);
    document.body.classList.remove('modal-open');
    if (state.restoreFocus && state.restoreFocus.focus) {
      try { state.restoreFocus.focus(); } catch (error) {}
    }
  }

  function modal(options) {
    closeModal();
    const opts = options || {};
    const previousFocus = document.activeElement;
    const backdrop = el('div', { class: 'modal-backdrop' });
    const dialog = el('div', {
      class: 'modal' + (opts.wide ? ' wide' : ''),
      role: 'dialog',
      'aria-modal': 'true',
      'aria-label': opts.title || 'Dialog'
    });
    const head = el('div', { class: 'modal-head' },
      svgIcon(opts.icon || 'alert-triangle'),
      el('div', { class: 'modal-title', text: opts.title || '' }),
      el('button', {
        class: 'icon-btn modal-close',
        type: 'button',
        'aria-label': 'Close dialog',
        onClick: closeModal
      }, svgIcon('x'))
    );
    const body = el('div', { class: 'modal-body' });
    if (opts.body instanceof Node) {
      body.appendChild(opts.body);
    } else if (Array.isArray(opts.body)) {
      opts.body.forEach(function (item) { append(body, item); });
    } else if (opts.body != null) {
      body.appendChild(el('p', { text: String(opts.body) }));
    }
    const foot = el('div', { class: 'modal-foot' });
    const actions = opts.actions || [{ label: 'Close', variant: 'btn-ghost' }];
    actions.forEach(function (action) {
      const button = el('button', {
        class: 'btn ' + (action.variant || 'btn-ghost'),
        type: 'button',
        onClick: function () {
          if (action.onClick) action.onClick();
          if (action.close !== false) closeModal();
        }
      }, action.icon ? svgIcon(action.icon) : null, action.label);
      foot.appendChild(button);
    });
    dialog.appendChild(head);
    dialog.appendChild(body);
    if (foot.childNodes.length) dialog.appendChild(foot);
    backdrop.appendChild(dialog);
    backdrop.addEventListener('mousedown', function (event) {
      if (event.target === backdrop) closeModal();
    });

    const onKeyDown = function (event) {
      if (event.key === 'Escape') {
        event.preventDefault();
        closeModal();
        return;
      }
      if (event.key === 'Tab') {
        const focusables = qsa('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])', dialog)
          .filter(function (node) { return !node.disabled && node.offsetParent !== null; });
        if (!focusables.length) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };

    document.getElementById('modal-root').appendChild(backdrop);
    document.body.classList.add('modal-open');
    document.addEventListener('keydown', onKeyDown, true);
    modalState = { backdrop: backdrop, restoreFocus: previousFocus, onKeyDown: onKeyDown };
    const focusTarget = qs('button', foot) || qs('button', head);
    if (focusTarget) focusTarget.focus();
    return { close: closeModal };
  }

  function safeUrl(value) {
    try {
      const url = new URL(String(value), document.baseURI);
      if (url.protocol === 'http:' || url.protocol === 'https:') return url.href;
    } catch (error) {}
    return null;
  }

  function launchUrl(url) {
    const safe = safeUrl(url);
    if (!safe) {
      toast('Blocked an unsafe URL', 'error');
      return false;
    }
    const anchor = document.createElement('a');
    anchor.href = safe;
    anchor.target = '_blank';
    anchor.rel = 'noopener noreferrer';
    anchor.style.display = 'none';
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    return true;
  }

  function externalUrl(url, options) {
    const opts = options || {};
    const safe = safeUrl(url);
    if (!safe) {
      if (!opts.silent) toast('Blocked an unsafe URL', 'error');
      return null;
    }
    if (!opts.warn) {
      launchUrl(safe);
      return safe;
    }
    let display = safe;
    if (C.format && C.state && C.state.prefs && C.state.prefs.defang) {
      display = C.format.defang(safe, 'url');
    }
    const body = el('div');
    body.appendChild(el('p', {
      text: 'This is a direct link from the report. It may point to a live phishing, malware, or disinformation site. Open it only in an isolated browser session.'
    }));
    body.appendChild(el('div', { class: 'modal-url' }, el('bdi', { text: display })));
    if (opts.source) {
      body.appendChild(el('p', { class: 'small muted mt-10', text: 'Source: ' + opts.source }));
    }
    modal({
      title: 'Open potentially malicious URL?',
      icon: 'alert-triangle',
      body: body,
      actions: [
        {
          label: 'Copy URL',
          variant: 'btn-ghost',
          icon: 'copy',
          close: false,
          onClick: function () { copyText(safe, 'URL'); }
        },
        {
          label: 'Open anyway',
          variant: 'btn-danger',
          icon: 'external',
          onClick: function () { launchUrl(safe); }
        }
      ]
    });
    return safe;
  }

  function downloadFile(filename, content, mime) {
    const blob = content instanceof Blob ? content : new Blob([content], { type: mime || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.style.display = 'none';
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  }

  C.dom = {
    el: el,
    icon: svgIcon,
    clear: clear,
    replace: replace,
    qs: qs,
    qsa: qsa,
    append: append,
    debounce: debounce,
    copyText: copyText,
    toast: toast,
    modal: modal,
    closeModal: closeModal,
    safeUrl: safeUrl,
    launchUrl: launchUrl,
    externalUrl: externalUrl,
    downloadFile: downloadFile,
    formatBytes: formatBytes
  };
})();
